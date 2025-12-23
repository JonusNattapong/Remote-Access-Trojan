use serde::Deserialize;
use std::fs;
use toml;

#[derive(Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    pub security: SecurityConfig,
}

#[derive(Deserialize)]
pub struct ServerConfig {
    pub port: u16,
}

#[derive(Deserialize)]
pub struct SecurityConfig {
    pub encryption_key: String,
}

pub fn load_config() -> Result<Config, crate::ServerError> {
    let content = fs::read_to_string("config.toml")?;
    let config = toml::from_str(&content)?;
    Ok(config)
}