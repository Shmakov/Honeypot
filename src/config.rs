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
    #[serde(default)]
    pub map: MapConfig,
    #[serde(default)]
    pub limits: LimitsConfig,
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
    /// Days to retain raw rows in `requests` before pruning (default: 30; 0 disables pruning).
    /// Daily summaries in `stats_daily` are always kept indefinitely.
    #[serde(default = "default_retention_days")]
    pub retention_days: u32,
}

fn default_cache_size_mb() -> u32 {
    16
}

fn default_retention_days() -> u32 {
    30
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
    #[serde(default = "default_asn_database")]
    pub asn_database: String,
}

fn default_asn_database() -> String {
    "data/GeoLite2-ASN.mmdb".to_string()
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
    #[serde(default = "default_hostname")]
    pub hostname: String,
    #[serde(default = "default_persona")]
    pub persona: String,
}

fn default_hostname() -> String {
    "prod-web-01".to_string()
}

fn default_persona() -> String {
    "ubuntu".to_string()
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct MapConfig {
    #[serde(default)]
    pub carto_api_key: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct LimitsConfig {
    #[serde(default = "default_max_connections_per_ip")]
    pub max_connections_per_ip: usize,
    #[serde(default = "default_max_total_connections")]
    pub max_total_connections: usize,
    #[serde(default = "default_write_buffer_capacity")]
    pub write_buffer_capacity: usize,
    #[serde(default = "default_udp_enabled")]
    pub udp_enabled: bool,
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            max_connections_per_ip: default_max_connections_per_ip(),
            max_total_connections: default_max_total_connections(),
            write_buffer_capacity: default_write_buffer_capacity(),
            udp_enabled: default_udp_enabled(),
        }
    }
}

fn default_max_connections_per_ip() -> usize {
    128
}

fn default_max_total_connections() -> usize {
    4096
}

fn default_write_buffer_capacity() -> usize {
    10_000
}

fn default_udp_enabled() -> bool {
    true
}

impl Config {
    pub fn load() -> Result<Self> {
        let config_path = "config.toml";
        
        let builder = config::Config::builder()
            .add_source(config::File::with_name(config_path))
            .add_source(
                config::Environment::with_prefix("HONEYPOT")
                    .prefix_separator("_")
                    .separator("__"),
            );

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_overrides_map_carto_api_key_without_toml_section() {
        let minimal_toml = r#"
[server]
host = "0.0.0.0"
http_port = 80
https_port = 443
tls_cert = ""
tls_key = ""

[database]
driver = "sqlite"
url = "honeypot.db"

[geoip]
database = "data/GeoLite2-City.mmdb"

[logging]
level = "info"

[emulation]
ssh_banner = "SSH-2.0-Test"
ftp_banner = "220 Test"
mysql_version = "5.7"
"#;

        // SAFETY: Test-only env var mutation; no other tests read these HONEYPOT_* variables.
        unsafe {
            std::env::set_var("HONEYPOT_MAP__CARTO_API_KEY", "test_key_123");
            std::env::set_var("HONEYPOT_DATABASE__RETENTION_DAYS", "45");
        }
        let settings = config::Config::builder()
            .add_source(config::File::from_str(minimal_toml, config::FileFormat::Toml))
            .add_source(
                config::Environment::with_prefix("HONEYPOT")
                    .prefix_separator("_")
                    .separator("__"),
            )
            .build()
            .unwrap();
        let cfg_default_check: Config = config::Config::builder()
            .add_source(config::File::from_str(minimal_toml, config::FileFormat::Toml))
            .build()
            .unwrap()
            .try_deserialize()
            .unwrap();
        let cfg: Config = settings.try_deserialize().unwrap();
        // SAFETY: Clean up test-only env vars immediately after deserialization.
        unsafe {
            std::env::remove_var("HONEYPOT_MAP__CARTO_API_KEY");
            std::env::remove_var("HONEYPOT_DATABASE__RETENTION_DAYS");
        }

        assert_eq!(cfg_default_check.database.retention_days, 30);
        assert_eq!(cfg_default_check.geoip.asn_database, "data/GeoLite2-ASN.mmdb");
        assert_eq!(cfg_default_check.emulation.hostname, "prod-web-01");
        assert_eq!(cfg_default_check.emulation.persona, "ubuntu");
        assert_eq!(cfg_default_check.limits.max_connections_per_ip, 128);
        assert_eq!(cfg_default_check.limits.max_total_connections, 4096);
        assert_eq!(cfg_default_check.limits.write_buffer_capacity, 10_000);
        assert!(cfg_default_check.limits.udp_enabled);
        assert_eq!(cfg.database.retention_days, 45);
        assert_eq!(cfg.map.carto_api_key, "test_key_123");
    }
}
