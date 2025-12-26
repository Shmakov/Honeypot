//! Configuration management

use anyhow::Result;
use serde::Deserialize;

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
    /// Public URL for redirects (e.g., "https://honeypot.example.com")
    #[serde(default)]
    pub public_url: String,
    /// Max ports to listen on (default: 128 for debug, all for release)
    #[serde(default = "default_max_ports")]
    pub max_ports: usize,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DatabaseConfig {
    pub driver: String,
    pub url: String,
    /// SQLite page cache size in MB (default: 16). With cache=shared, this is the total
    /// shared cache across all pool connections. Set based on available server memory.
    #[serde(default = "default_cache_size_mb")]
    pub cache_size_mb: u32,
}

fn default_cache_size_mb() -> u32 {
    16
}

fn default_max_ports() -> usize {
    if cfg!(debug_assertions) {
        128 // Limit for local development
    } else {
        0 // 0 means all ports in release
    }
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
        
        // Validate configuration
        config.validate()?;
        
        Ok(config)
    }

    /// Validate configuration values
    pub fn validate(&self) -> Result<()> {
        // Validate server config
        if self.server.http_port == 0 {
            anyhow::bail!("Invalid http_port: 0 is not allowed");
        }
        if self.server.host.is_empty() {
            anyhow::bail!("Server host cannot be empty");
        }
        
        // Validate database config
        if self.database.url.is_empty() {
            anyhow::bail!("Database URL cannot be empty");
        }
        if self.database.driver != "sqlite" && self.database.driver != "postgres" {
            anyhow::bail!("Invalid database driver '{}'. Must be 'sqlite' or 'postgres'", self.database.driver);
        }
        
        // Validate TLS (both or neither must be set)
        let has_cert = !self.server.tls_cert.is_empty();
        let has_key = !self.server.tls_key.is_empty();
        if has_cert != has_key {
            anyhow::bail!("TLS configuration incomplete: both tls_cert and tls_key must be set, or neither");
        }
        
        // Validate logging level
        let valid_levels = ["trace", "debug", "info", "warn", "error"];
        if !valid_levels.contains(&self.logging.level.to_lowercase().as_str()) {
            anyhow::bail!("Invalid logging level '{}'. Must be one of: {:?}", self.logging.level, valid_levels);
        }
        
        Ok(())
    }

    pub fn tls_enabled(&self) -> bool {
        !self.server.tls_cert.is_empty() && !self.server.tls_key.is_empty()
    }
}
