//! Generic TCP handler with protocol emulation banners and concurrency limits

use anyhow::Result;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tracing::{debug, info, warn};

use crate::classifier;
use crate::config::Config;
use crate::db::{AttackEvent, WriteSender};
use crate::events::EventBus;
use crate::geoip::SharedGeoIp;
use crate::limits::ConnectionLimiter;

/// Protocol-specific banners for emulation
fn get_banner(service: &str, config: &Config) -> Option<String> {
    match service {
        "pop3" | "pop3s" => Some("+OK POP3 server ready\r\n".to_string()),
        "imap" | "imaps" => Some("* OK IMAP4rev1 Service Ready\r\n".to_string()),
        "http" | "http-alt" | "http-proxy" | "https-alt" => None,
        "vnc" | "vnc-http" => Some("RFB 003.008\n".to_string()),
        "memcached" => Some("VERSION 1.6.22\r\n".to_string()),
        "mongodb" => Some(String::new()),
        _ if service.contains("smtp") => Some(format!(
            "220 mail.{} ESMTP Postfix\r\n",
            config.emulation.hostname
        )),
        _ => None,
    }
}

pub async fn start(
    port: u16,
    service: &str,
    config: Arc<Config>,
    event_bus: Arc<EventBus>,
    write_tx: WriteSender,
    geoip: SharedGeoIp,
    limiter: Arc<ConnectionLimiter>,
) -> Result<()> {
    let addr = format!("{}:{}", config.server.host, port);
    let listener = match TcpListener::bind(&addr).await {
        Ok(l) => l,
        Err(e) => {
            warn!("Cannot bind to {} ({}): {} - skipping", addr, service, e);
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
                let Some(permit) = limiter.try_acquire(&ip) else {
                    debug!("TCP connection rejected (concurrency limit) from {} on {}", ip, port);
                    drop(socket);
                    continue;
                };

                let service = service.clone();
                let banner = banner.clone();
                let event_bus = event_bus.clone();
                let write_tx = write_tx.clone();
                let geoip = geoip.clone();

                tokio::spawn(async move {
                    let _permit = permit;
                    if let Some(ref banner) = banner {
                        if !banner.is_empty() {
                            let _ = socket.write_all(banner.as_bytes()).await;
                        }
                    }

                    let mut buf = vec![0u8; 4096];
                    let timeout = tokio::time::timeout(
                        std::time::Duration::from_secs(10),
                        socket.read(&mut buf),
                    );

                    let payload = match timeout.await {
                        Ok(Ok(n)) if n > 0 => Some(buf[..n].to_vec()),
                        _ => None,
                    };

                    let request = format!(
                        "Connection from {}:{} to port {}",
                        ip,
                        peer_addr.port(),
                        port
                    );
                    let mut event = AttackEvent::new(ip, service, port, request);
                    let request_size = payload.as_ref().map(|p| p.len() as u32).unwrap_or(0);
                    event = event.with_request_size(request_size);

                    if let Some(p) = payload {
                        event = event.with_payload(p);
                    }

                    classifier::record_event(event, &geoip, &write_tx, &event_bus);
                });
            }
            Err(e) => {
                warn!("Accept error on port {}: {}", port, e);
            }
        }
    }
}
