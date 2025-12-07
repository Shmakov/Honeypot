//! SSH honeypot handler

use anyhow::Result;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tracing::{debug, info, warn};

use crate::config::Config;
use crate::db::{AttackEvent, Database};
use crate::events::EventBus;

/// Simple SSH banner response that accepts any credentials
pub async fn start(
    port: u16,
    config: Arc<Config>,
    event_bus: Arc<EventBus>,
    db: Arc<Database>,
) -> Result<()> {
    let addr = format!("{}:{}", config.server.host, port);
    let listener = match TcpListener::bind(&addr).await {
        Ok(l) => l,
        Err(e) => {
            debug!("Cannot bind SSH to {}: {}", addr, e);
            return Ok(());
        }
    };

    info!("SSH honeypot started on port {}", port);
    let banner = format!("{}\r\n", config.emulation.ssh_banner);

    loop {
        match listener.accept().await {
            Ok((mut socket, peer_addr)) => {
                let ip = peer_addr.ip().to_string();
                let event_bus = event_bus.clone();
                let db = db.clone();
                let banner = banner.clone();

                tokio::spawn(async move {
                    // Send SSH banner
                    let _ = socket.write_all(banner.as_bytes()).await;

                    // Read client banner
                    let mut buf = vec![0u8; 4096];
                    let mut payload = Vec::new();

                    let timeout = tokio::time::timeout(
                        std::time::Duration::from_secs(30),
                        socket.read(&mut buf),
                    );

                    if let Ok(Ok(n)) = timeout.await {
                        if n > 0 {
                            payload.extend_from_slice(&buf[..n]);
                        }
                    }

                    // Try to extract client info from banner
                    let client_banner = String::from_utf8_lossy(&payload);
                    let request = format!("SSH {} -> port {}: {}", ip, port, client_banner.trim());

                    let mut event = AttackEvent::new(ip, "ssh".to_string(), port, request);
                    if !payload.is_empty() {
                        event = event.with_payload(payload);
                    }

                    // For a more complete SSH honeypot, we would use russh library
                    // to properly handle the SSH handshake and capture credentials.
                    // This is a simplified version that just captures the banner exchange.

                    if let Err(e) = db.insert_event(&event).await {
                        warn!("Failed to store SSH event: {}", e);
                    }
                    event_bus.publish(event);
                });
            }
            Err(e) => {
                warn!("SSH accept error on port {}: {}", port, e);
            }
        }
    }
}
