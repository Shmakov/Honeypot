//! Configuration management

use anyhow::Result;
use serde::Deserialize;
use std::path::Path;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    pub geoip: GeoIpConfig,
    pub logging: LoggingConfig,
    pub emulation: EmulationConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    pub host: String,
    pub http_port: u16,
    pub https_port: u16,
    pub tls_cert: String,
    pub tls_key: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DatabaseConfig {
    pub driver: String,
    pub url: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct GeoIpConfig {
    pub database: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct LoggingConfig {
    pub level: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct EmulationConfig {
    pub ssh_banner: String,
    pub ftp_banner: String,
    pub mysql_version: String,
}

impl Config {
    pub fn load() -> Result<Self> {
        let config_path = "config.toml";
        
        let builder = config::Config::builder()
            .add_source(config::File::with_name(config_path))
            .add_source(config::Environment::with_prefix("HONEYPOT"));

        let settings = builder.build()?;
        let config: Config = settings.try_deserialize()?;
        
        Ok(config)
    }

    pub fn tls_enabled(&self) -> bool {
        !self.server.tls_cert.is_empty() && !self.server.tls_key.is_empty()
    }
}
