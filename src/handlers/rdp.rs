//! RDP honeypot handler (TPKT + X.224 Connection Request with mstshash username capture)

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
use crate::limits::{ConnectionLimiter, ConnectionPermit};

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
            warn!("Cannot bind RDP to {}: {} - skipping", addr, e);
            return Ok(());
        }
    };

    info!("RDP honeypot started on port {} ({})", port, service);
    let service = service.to_string();

    loop {
        match listener.accept().await {
            Ok((socket, peer_addr)) => {
                let ip = peer_addr.ip().to_string();
                let Some(permit) = limiter.try_acquire(&ip) else {
                    debug!("RDP connection rejected (concurrency limit) from {}", ip);
                    drop(socket);
                    continue;
                };
                let service = service.clone();
                let event_bus = event_bus.clone();
                let write_tx = write_tx.clone();
                let geoip = geoip.clone();
                tokio::spawn(async move {
                    handle_rdp_session(socket, ip, port, service, event_bus, write_tx, geoip, permit)
                        .await;
                });
            }
            Err(e) => warn!("RDP accept error on port {}: {}", port, e),
        }
    }
}

fn extract_mstshash(data: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(data);
    let marker = "Cookie: mstshash=";
    let pos = text.find(marker)?;
    let rest = &text[pos + marker.len()..];
    let end = rest.find(['\r', '\n']).unwrap_or(rest.len());
    let user = rest[..end].trim().to_string();
    if user.is_empty() { None } else { Some(user) }
}

#[allow(clippy::too_many_arguments)]
async fn handle_rdp_session(
    mut socket: tokio::net::TcpStream,
    ip: String,
    port: u16,
    service: String,
    event_bus: Arc<EventBus>,
    write_tx: WriteSender,
    geoip: SharedGeoIp,
    _permit: ConnectionPermit,
) {
    let mut buf = vec![0u8; 2048];
    let read_res = tokio::time::timeout(
        std::time::Duration::from_secs(15),
        socket.read(&mut buf),
    )
    .await;

    let payload = match read_res {
        Ok(Ok(n)) if n > 0 => Some(buf[..n].to_vec()),
        _ => None,
    };

    let mut username: Option<String> = None;
    if let Some(ref raw) = payload {
        username = extract_mstshash(raw);
        // Minimal X.224 Connection Confirm (CC) TPKT response
        if raw.len() >= 11 && raw[0] == 0x03 {
            let x224_cc: [u8; 19] = [
                0x03, 0x00, 0x00, 0x13, // TPKT len 19
                0x0e, 0xd0, 0x00, 0x00, 0x12, 0x34, 0x00, // X.224 CC
                0x02, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, // RDP Negotiation Response
            ];
            let _ = socket.write_all(&x224_cc).await;
        }
    }

    let request = match &username {
        Some(u) => format!("RDP connection (mstshash={}) from {}", u, ip),
        None => format!("RDP connection from {}", ip),
    };

    let req_size = payload.as_ref().map(|p| p.len() as u32).unwrap_or(0);
    let mut event = AttackEvent::new(ip, service, port, request).with_request_size(req_size);
    if let Some(u) = username {
        event = event.with_credentials(u, String::new());
    }
    if let Some(p) = payload {
        event = event.with_payload(p);
    }

    classifier::record_event(event, &geoip, &write_tx, &event_bus);
}
