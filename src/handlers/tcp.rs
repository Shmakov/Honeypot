//! Generic TCP handler with protocol emulation banners

use anyhow::Result;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tracing::{debug, info, warn};

use crate::config::Config;
use crate::db::{AttackEvent, Database};
use crate::events::EventBus;

/// Protocol-specific banners for emulation
fn get_banner(service: &str, config: &Config) -> Option<String> {
    match service {
        "mysql" => Some(format!(
            "\x4a\x00\x00\x00\x0a{}\x00",
            config.emulation.mysql_version
        )),
        "redis" => Some("-ERR unknown command\r\n".to_string()),
        "mongodb" => Some("".to_string()), // MongoDB uses binary protocol
        "smtp" | "submission" => Some("220 mail.example.com ESMTP\r\n".to_string()),
        "pop3" | "pop3s" => Some("+OK POP3 server ready\r\n".to_string()),
        "imap" | "imaps" => Some("* OK IMAP4rev1 Service Ready\r\n".to_string()),
        "http" | "http-alt" | "http-proxy" | "https-alt" => None, // HTTP handled by web server
        "vnc" | "vnc-http" => Some("RFB 003.008\n".to_string()),
        "memcached" => Some("VERSION 1.6.9\r\n".to_string()),
        "elasticsearch" => Some("{\"error\":\"unauthorized\"}\n".to_string()),
        _ => None,
    }
}

pub async fn start(
    port: u16,
    service: &str,
    config: Arc<Config>,
    event_bus: Arc<EventBus>,
    db: Arc<Database>,
) -> Result<()> {
    let addr = format!("{}:{}", config.server.host, port);
    let listener = match TcpListener::bind(&addr).await {
        Ok(l) => l,
        Err(e) => {
            debug!("Cannot bind to {}: {}", addr, e);
            return Ok(());
        }
    };

    info!("TCP listener started on port {} ({})", port, service);
    let service = service.to_string();
    let banner = get_banner(&service, &config);

    loop {
        match listener.accept().await {
            Ok((mut socket, peer_addr)) => {
                let ip = peer_addr.ip().to_string();
                let service = service.clone();
                let banner = banner.clone();
                let event_bus = event_bus.clone();
                let db = db.clone();

                tokio::spawn(async move {
                    // Send banner if available
                    if let Some(ref banner) = banner {
                        let _ = socket.write_all(banner.as_bytes()).await;
                    }

                    // Read any data sent by attacker
                    let mut buf = vec![0u8; 4096];
                    let timeout = tokio::time::timeout(
                        std::time::Duration::from_secs(30),
                        socket.read(&mut buf),
                    );

                    let payload = match timeout.await {
                        Ok(Ok(n)) if n > 0 => Some(buf[..n].to_vec()),
                        _ => None,
                    };

                    // Create event
                    let request = format!(
                        "Connection from {}:{} to port {}",
                        ip,
                        peer_addr.port(),
                        port
                    );
                    let mut event = AttackEvent::new(ip, service, port, request);
                    if let Some(p) = payload {
                        event = event.with_payload(p);
                    }

                    // Store and broadcast
                    if let Err(e) = db.insert_event(&event).await {
                        warn!("Failed to store event: {}", e);
                    }
                    event_bus.publish(event);
                });
            }
            Err(e) => {
                warn!("Accept error on port {}: {}", port, e);
            }
        }
    }
}
