//! PostgreSQL honeypot handler (SSLRequest + StartupMessage + CleartextPassword capture)

use anyhow::Result;
use std::collections::HashMap;
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
            warn!("Cannot bind PostgreSQL to {}: {} - skipping", addr, e);
            return Ok(());
        }
    };

    info!("PostgreSQL honeypot started on port {} ({})", port, service);
    let service = service.to_string();

    loop {
        match listener.accept().await {
            Ok((socket, peer_addr)) => {
                let ip = peer_addr.ip().to_string();
                let Some(permit) = limiter.try_acquire(&ip) else {
                    debug!("Postgres connection rejected (concurrency limit) from {}", ip);
                    drop(socket);
                    continue;
                };
                let service = service.clone();
                let event_bus = event_bus.clone();
                let write_tx = write_tx.clone();
                let geoip = geoip.clone();
                tokio::spawn(async move {
                    handle_pg_session(socket, ip, port, service, event_bus, write_tx, geoip, permit)
                        .await;
                });
            }
            Err(e) => warn!("Postgres accept error on port {}: {}", port, e),
        }
    }
}

fn parse_startup_params(body: &[u8]) -> HashMap<String, String> {
    let mut map = HashMap::new();
    // Skip 4-byte protocol version (0x00030000)
    if body.len() <= 4 {
        return map;
    }
    let parts: Vec<&[u8]> = body[4..].split(|&b| b == 0).collect();
    let mut i = 0;
    while i + 1 < parts.len() {
        let k = String::from_utf8_lossy(parts[i]).into_owned();
        let v = String::from_utf8_lossy(parts[i + 1]).into_owned();
        if !k.is_empty() {
            map.insert(k, v);
        }
        i += 2;
    }
    map
}

fn build_error_response(user: &str) -> Vec<u8> {
    let mut body = Vec::new();
    body.push(b'S');
    body.extend_from_slice(b"FATAL\0");
    body.push(b'C');
    body.extend_from_slice(b"28P01\0");
    body.push(b'M');
    body.extend_from_slice(
        format!("password authentication failed for user \"{}\"\0", user).as_bytes(),
    );
    body.push(0);

    let len = (4 + body.len()) as u32;
    let mut pkt = Vec::with_capacity(1 + len as usize);
    pkt.push(b'E');
    pkt.extend_from_slice(&len.to_be_bytes());
    pkt.extend_from_slice(&body);
    pkt
}

async fn read_startup_packet(socket: &mut tokio::net::TcpStream) -> Option<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    socket.read_exact(&mut len_buf).await.ok()?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if !(8..=8192).contains(&len) {
        return None;
    }
    let mut body = vec![0u8; len - 4];
    socket.read_exact(&mut body).await.ok()?;
    Some(body)
}

#[allow(clippy::too_many_arguments)]
async fn handle_pg_session(
    mut socket: tokio::net::TcpStream,
    ip: String,
    port: u16,
    service: String,
    event_bus: Arc<EventBus>,
    write_tx: WriteSender,
    geoip: SharedGeoIp,
    _permit: ConnectionPermit,
) {
    let mut username: Option<String> = None;
    let mut password: Option<String> = None;
    let mut params: HashMap<String, String> = HashMap::new();
    let mut raw_bytes: Vec<u8> = Vec::new();

    let _ = tokio::time::timeout(std::time::Duration::from_secs(15), async {
        let Some(mut body) = read_startup_packet(&mut socket).await else {
            return;
        };
        raw_bytes.extend_from_slice(&body);

        // Handle SSLRequest (80877103 = 0x04d2162f)
        if body.len() == 4 && u32::from_be_bytes([body[0], body[1], body[2], body[3]]) == 80877103 {
            if socket.write_all(b"N").await.is_err() {
                return;
            }
            let Some(next_body) = read_startup_packet(&mut socket).await else {
                return;
            };
            body = next_body;
            raw_bytes.extend_from_slice(&body);
        }

        params = parse_startup_params(&body);
        if let Some(u) = params.get("user") {
            username = Some(u.clone());
        }

        // Send AuthenticationCleartextPassword ('R', len=8, auth_type=3)
        let auth_req: [u8; 9] = [b'R', 0, 0, 0, 8, 0, 0, 0, 3];
        if socket.write_all(&auth_req).await.is_err() {
            return;
        }

        // Read PasswordMessage ('p', 4-byte length, nul-terminated password)
        let mut hdr = [0u8; 5];
        if socket.read_exact(&mut hdr).await.is_ok() && hdr[0] == b'p' {
            let msg_len = u32::from_be_bytes([hdr[1], hdr[2], hdr[3], hdr[4]]) as usize;
            if (4..=4096).contains(&msg_len) {
                let mut pbuf = vec![0u8; msg_len - 4];
                if socket.read_exact(&mut pbuf).await.is_ok() {
                    raw_bytes.extend_from_slice(&pbuf);
                    let pwd = String::from_utf8_lossy(
                        pbuf.split(|&b| b == 0).next().unwrap_or(&[]),
                    )
                    .into_owned();
                    password = Some(pwd);
                }
            }
        }

        let err = build_error_response(username.as_deref().unwrap_or("postgres"));
        let _ = socket.write_all(&err).await;
    })
    .await;

    let db_str = params.get("database").map(|s| s.as_str()).unwrap_or("");
    let request = match (&username, &password) {
        (Some(u), Some(p)) => format!("Postgres login: {}:{} (db: {}) from {}", u, p, db_str, ip),
        (Some(u), None) => format!("Postgres startup: {} (db: {}) from {}", u, db_str, ip),
        _ => format!("Postgres connection from {}", ip),
    };

    let mut event =
        AttackEvent::new(ip, service, port, request).with_request_size(raw_bytes.len() as u32);
    if let Some(u) = username {
        event = event.with_credentials(u, password.unwrap_or_default());
    }
    if !raw_bytes.is_empty() {
        event = event.with_payload(raw_bytes);
    }
    if let Some(app) = params.get("application_name") {
        event = event.with_user_agent(app.clone());
    }

    classifier::record_event(event, &geoip, &write_tx, &event_bus);
}
