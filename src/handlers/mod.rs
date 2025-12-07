//! Protocol handlers module

pub mod tcp;
pub mod ssh;
pub mod ftp;
pub mod telnet;
pub mod icmp;

use anyhow::Result;
use std::sync::Arc;
use tracing::info;

use crate::config::Config;
use crate::db::Database;
use crate::events::EventBus;

/// TCP ports to listen on (most common)
pub const TCP_PORTS: &[(u16, &str)] = &[
    (21, "ftp"),
    (22, "ssh"),
    (23, "telnet"),
    (25, "smtp"),
    (53, "dns"),
    (110, "pop3"),
    (111, "rpcbind"),
    (135, "msrpc"),
    (139, "netbios"),
    (143, "imap"),
    (445, "smb"),
    (465, "smtps"),
    (514, "shell"),
    (587, "submission"),
    (993, "imaps"),
    (995, "pop3s"),
    (1433, "mssql"),
    (1521, "oracle"),
    (1723, "pptp"),
    (2049, "nfs"),
    (3306, "mysql"),
    (3389, "rdp"),
    (5432, "postgresql"),
    (5900, "vnc"),
    (5901, "vnc"),
    (6379, "redis"),
    (6667, "irc"),
    (8000, "http-alt"),
    (8080, "http-proxy"),
    (8443, "https-alt"),
    (8888, "http-alt"),
    (9000, "php-fpm"),
    (9090, "prometheus"),
    (9200, "elasticsearch"),
    (11211, "memcached"),
    (27017, "mongodb"),
];

/// Start all protocol handlers
pub async fn start_all(config: &Config, event_bus: EventBus, db: Database) -> Result<()> {
    let config = Arc::new(config.clone());
    let event_bus = Arc::new(event_bus);
    let db = Arc::new(db);

    // Start TCP listeners for each port (skip 80/443 as those will be web server)
    for (port, service) in TCP_PORTS {
        let port = *port;
        let service = service.to_string();
        let config = config.clone();
        let event_bus = event_bus.clone();
        let db = db.clone();

        tokio::spawn(async move {
            match service.as_str() {
                "ssh" => {
                    if let Err(e) = ssh::start(port, config, event_bus, db).await {
                        tracing::debug!("SSH handler on port {} failed: {}", port, e);
                    }
                }
                "ftp" => {
                    if let Err(e) = ftp::start(port, config, event_bus, db).await {
                        tracing::debug!("FTP handler on port {} failed: {}", port, e);
                    }
                }
                "telnet" => {
                    if let Err(e) = telnet::start(port, config, event_bus, db).await {
                        tracing::debug!("Telnet handler on port {} failed: {}", port, e);
                    }
                }
                _ => {
                    if let Err(e) = tcp::start(port, &service, config, event_bus, db).await {
                        tracing::debug!("{} handler on port {} failed: {}", service, port, e);
                    }
                }
            }
        });
    }

    // ICMP handler (optional, requires CAP_NET_RAW)
    let event_bus_icmp = event_bus.clone();
    let db_icmp = db.clone();
    tokio::spawn(async move {
        if let Err(e) = icmp::start(event_bus_icmp, db_icmp).await {
            tracing::debug!("ICMP handler failed: {}", e);
        }
    });

    info!("Started {} protocol handlers", TCP_PORTS.len());
    Ok(())
}
