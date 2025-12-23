use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use rand::Rng;
use crate::ServerError;

pub fn encrypt(data: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, ServerError> {
    let key_slice = Key::<Aes256Gcm>::from_slice(key);
    let cipher = Aes256Gcm::new(&key_slice);
    let nonce_bytes = rand::thread_rng().gen::<[u8; 12]>();
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, data)
        .map_err(|e| ServerError::Encryption(e.to_string()))?;
    let mut result = nonce_bytes.to_vec();
    result.extend(ciphertext);
    Ok(result)
}

pub fn decrypt(data: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, ServerError> {
    if data.len() < 12 {
        return Err(ServerError::Decryption("Data too short".to_string()));
    }
    let key_slice = Key::<Aes256Gcm>::from_slice(key);
    let cipher = Aes256Gcm::new(&key_slice);
    let (nonce_bytes, ciphertext) = data.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| ServerError::Decryption("Decryption failed".to_string()))
}