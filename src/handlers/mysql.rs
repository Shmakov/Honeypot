//! MySQL honeypot handler (Protocol v10 handshake + username/database capture)

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
            warn!("Cannot bind MySQL to {}: {} - skipping", addr, e);
            return Ok(());
        }
    };

    info!("MySQL honeypot started on port {} ({})", port, service);
    let service = service.to_string();
    let version = config.emulation.mysql_version.clone();

    loop {
        match listener.accept().await {
            Ok((socket, peer_addr)) => {
                let ip = peer_addr.ip().to_string();
                let Some(permit) = limiter.try_acquire(&ip) else {
                    debug!("MySQL connection rejected (concurrency limit) from {}", ip);
                    drop(socket);
                    continue;
                };
                let service = service.clone();
                let version = version.clone();
                let event_bus = event_bus.clone();
                let write_tx = write_tx.clone();
                let geoip = geoip.clone();
                tokio::spawn(async move {
                    handle_mysql_session(
                        socket, ip, port, service, version, event_bus, write_tx, geoip, permit,
                    )
                    .await;
                });
            }
            Err(e) => warn!("MySQL accept error on port {}: {}", port, e),
        }
    }
}

fn build_handshake_v10(version: &str) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.push(0x0a); // protocol version 10
    payload.extend_from_slice(version.as_bytes());
    payload.push(0x00);
    payload.extend_from_slice(&1u32.to_le_bytes()); // connection id
    payload.extend_from_slice(b"12345678"); // auth-plugin-data-part-1
    payload.push(0x00); // filler
    payload.extend_from_slice(&0xf7ffu16.to_le_bytes()); // capability flags lower 2 bytes
    payload.push(0x21); // utf8 charset
    payload.extend_from_slice(&0x0002u16.to_le_bytes()); // status flags
    payload.extend_from_slice(&0x807fu16.to_le_bytes()); // capability flags upper 2 bytes
    payload.push(21); // auth plugin data len
    payload.extend_from_slice(&[0u8; 10]); // reserved
    payload.extend_from_slice(b"901234567890\0"); // auth-plugin-data-part-2
    payload.extend_from_slice(b"mysql_native_password\0");

    let len = payload.len();
    let mut pkt = Vec::with_capacity(4 + len);
    pkt.push((len & 0xff) as u8);
    pkt.push(((len >> 8) & 0xff) as u8);
    pkt.push(((len >> 16) & 0xff) as u8);
    pkt.push(0x00); // sequence id 0
    pkt.extend_from_slice(&payload);
    pkt
}

fn build_access_denied(user: &str, ip: &str, seq: u8) -> Vec<u8> {
    let msg = format!("Access denied for user '{}'@'{}' (using password: YES)", user, ip);
    let mut payload = Vec::new();
    payload.push(0xff); // ERR packet
    payload.extend_from_slice(&1045u16.to_le_bytes());
    payload.push(b'#');
    payload.extend_from_slice(b"28000");
    payload.extend_from_slice(msg.as_bytes());

    let len = payload.len();
    let mut pkt = Vec::with_capacity(4 + len);
    pkt.push((len & 0xff) as u8);
    pkt.push(((len >> 8) & 0xff) as u8);
    pkt.push(((len >> 16) & 0xff) as u8);
    pkt.push(seq);
    pkt.extend_from_slice(&payload);
    pkt
}

/// Extract username from MySQL client HandshakeResponse41 packet.
fn parse_handshake_response(pkt: &[u8]) -> Option<(String, Option<String>)> {
    // 4-byte packet header + 4 cap flags + 4 max packet + 1 charset + 23 reserved = 36 bytes
    if pkt.len() <= 36 {
        return None;
    }

    // Validate MySQL packet framing: 3-byte LE payload length, sequence id == 1, 23 zero reserved bytes
    let pkt_len = (pkt[0] as usize) | ((pkt[1] as usize) << 8) | ((pkt[2] as usize) << 16);
    if pkt[3] != 1 || !(32..=4096).contains(&pkt_len) {
        return None;
    }
    if !pkt[13..36].iter().all(|&b| b == 0) {
        return None;
    }

    let rest = &pkt[36..];
    let nul_pos = rest.iter().position(|&b| b == 0)?;
    let user_str = std::str::from_utf8(&rest[..nul_pos]).ok()?;
    if user_str.is_empty()
        || user_str.len() > 64
        || !user_str.bytes().all(|b| (0x20..=0x7e).contains(&b))
    {
        return None;
    }
    let user = user_str.to_string();
    let after_user = &rest[nul_pos + 1..];

    // Check CLIENT_CONNECT_WITH_DB (0x0008)
    let cap_flags = u32::from_le_bytes([pkt[4], pkt[5], pkt[6], pkt[7]]);
    let mut db_name = None;
    if (cap_flags & 0x0008) != 0 && !after_user.is_empty() {
        let auth_len = after_user[0] as usize;
        if after_user.len() > 1 + auth_len {
            let db_slice = &after_user[1 + auth_len..];
            if let Some(db_nul) = db_slice.iter().position(|&b| b == 0) {
                if let Ok(d) = std::str::from_utf8(&db_slice[..db_nul]) {
                    if !d.is_empty() && d.len() <= 64 && d.bytes().all(|b| (0x20..=0x7e).contains(&b))
                    {
                        db_name = Some(d.to_string());
                    }
                }
            }
        }
    }

    Some((user, db_name))
}

#[allow(clippy::too_many_arguments)]
async fn handle_mysql_session(
    mut socket: tokio::net::TcpStream,
    ip: String,
    port: u16,
    service: String,
    version: String,
    event_bus: Arc<EventBus>,
    write_tx: WriteSender,
    geoip: SharedGeoIp,
    _permit: ConnectionPermit,
) {
    let handshake = build_handshake_v10(&version);
    if socket.write_all(&handshake).await.is_err() {
        return;
    }

    let mut buf = vec![0u8; 4096];
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
    let mut db_name: Option<String> = None;
    if let Some(ref raw) = payload {
        if let Some((u, db)) = parse_handshake_response(raw) {
            let err_pkt = build_access_denied(&u, &ip, 2);
            let _ = socket.write_all(&err_pkt).await;
            username = Some(u);
            db_name = db;
        }
    }

    let request = match (&username, &db_name) {
        (Some(u), Some(db)) => format!("MySQL login: {} (db: {}) from {}", u, db, ip),
        (Some(u), None) => format!("MySQL login: {} from {}", u, ip),
        _ => format!("MySQL connection from {}", ip),
    };

    let req_size = payload.as_ref().map(|p| p.len() as u32).unwrap_or(0);
    let mut event = AttackEvent::new(ip, service, port, request).with_request_size(req_size);
    if let Some(u) = username {
        if !u.is_empty() {
            event.username = Some(u);
        }
    }
    if let Some(p) = payload {
        event = event.with_payload(p);
    }

    classifier::record_event(event, &geoip, &write_tx, &event_bus);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_tls_client_hello_and_parses_valid_handshake() {
        // TLS 1.2 ClientHello bytes
        let tls_hello = [
            0x16, 0x03, 0x01, 0x00, 0xfc, 0x01, 0x00, 0x00, 0xf8, 0x03, 0x03, 0x9f, 0x56, 0xce,
            0xe5, 0x8b, 0x22, 0xe3, 0x3a, 0x5f, 0x08, 0xae, 0x4e, 0xf2, 0x76, 0x9d, 0x65, 0x83,
            0xb5, 0x80, 0xf5, 0x52, 0xf7, 0x28, 0xe9, 0xfd, 0xc9, 0xe6, 0x20, 0x00,
        ];
        assert!(parse_handshake_response(&tls_hello).is_none());

        let mut valid = vec![0u8; 4];
        valid.extend_from_slice(&0x0000_0008u32.to_le_bytes()); // CLIENT_CONNECT_WITH_DB
        valid.extend_from_slice(&[0u8; 28]); // max_packet (4) + charset (1) + reserved (23)
        valid.extend_from_slice(b"root\0");
        valid.push(0); // auth_len = 0
        valid.extend_from_slice(b"appdb\0");
        let len = (valid.len() - 4) as u32;
        valid[0] = (len & 0xff) as u8;
        valid[3] = 1;
        assert_eq!(
            parse_handshake_response(&valid),
            Some(("root".to_string(), Some("appdb".to_string())))
        );
    }
}
