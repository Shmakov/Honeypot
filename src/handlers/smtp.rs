//! SMTP honeypot handler supporting EHLO, AUTH PLAIN/LOGIN, MAIL FROM, RCPT TO, DATA

use anyhow::Result;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tracing::{debug, info, warn};

use crate::classifier;
use crate::config::Config;
use crate::db::{AttackEvent, WriteSender};
use crate::events::EventBus;
use crate::geoip::SharedGeoIp;
use crate::ioc;
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
            warn!("Cannot bind SMTP to {}: {} - skipping", addr, e);
            return Ok(());
        }
    };

    info!("SMTP honeypot started on port {} ({})", port, service);
    let service = service.to_string();
    let hostname = config.emulation.hostname.clone();

    loop {
        match listener.accept().await {
            Ok((socket, peer_addr)) => {
                let ip = peer_addr.ip().to_string();
                let Some(permit) = limiter.try_acquire(&ip) else {
                    debug!("SMTP connection rejected (concurrency limit) from {}", ip);
                    drop(socket);
                    continue;
                };
                let service = service.clone();
                let hostname = hostname.clone();
                let event_bus = event_bus.clone();
                let write_tx = write_tx.clone();
                let geoip = geoip.clone();
                tokio::spawn(async move {
                    handle_smtp_session(
                        socket, ip, port, service, hostname, event_bus, write_tx, geoip, permit,
                    )
                    .await;
                });
            }
            Err(e) => warn!("SMTP accept error on port {}: {}", port, e),
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_smtp_session(
    socket: tokio::net::TcpStream,
    ip: String,
    port: u16,
    service: String,
    hostname: String,
    event_bus: Arc<EventBus>,
    write_tx: WriteSender,
    geoip: SharedGeoIp,
    _permit: ConnectionPermit,
) {
    let (reader, mut writer) = socket.into_split();
    let mut reader = BufReader::new(reader);

    let greeting = format!("220 mail.{} ESMTP Postfix\r\n", hostname);
    if writer.write_all(greeting.as_bytes()).await.is_err() {
        return;
    }

    let mut transcript: Vec<String> = Vec::new();
    let mut username: Option<String> = None;
    let mut password: Option<String> = None;
    let mut in_data = false;
    let mut auth_login_step = 0u8; // 1 = expecting user, 2 = expecting pass
    let mut total_bytes: u32 = 0;

    let _ = tokio::time::timeout(std::time::Duration::from_secs(45), async {
        let mut line = String::new();
        for _ in 0..200 {
            line.clear();
            match reader.read_line(&mut line).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    total_bytes += n as u32;
                    let trimmed = line.trim_end_matches(['\r', '\n']).to_string();

                    if transcript.len() < 100 && total_bytes <= 16384 {
                        transcript.push(trimmed.clone());
                    }

                    if in_data {
                        if trimmed == "." {
                            in_data = false;
                            let _ = writer.write_all(b"250 2.0.0 Ok: queued as 9A1B2C3D\r\n").await;
                        }
                        continue;
                    }

                    if auth_login_step == 1 {
                        if let Some(bytes) = ioc::decode_base64(&trimmed) {
                            username = Some(String::from_utf8_lossy(&bytes).into_owned());
                        } else {
                            username = Some(trimmed);
                        }
                        auth_login_step = 2;
                        let _ = writer.write_all(b"334 UGFzc3dvcmQ6\r\n").await; // Password:
                        continue;
                    }
                    if auth_login_step == 2 {
                        if let Some(bytes) = ioc::decode_base64(&trimmed) {
                            password = Some(String::from_utf8_lossy(&bytes).into_owned());
                        } else {
                            password = Some(trimmed);
                        }
                        auth_login_step = 0;
                        let _ = writer
                            .write_all(b"235 2.7.0 Authentication successful\r\n")
                            .await;
                        continue;
                    }

                    let upper = trimmed.to_ascii_uppercase();
                    if upper.starts_with("EHLO") {
                        let resp = format!(
                            "250-mail.{}\r\n250-PIPELINING\r\n250-SIZE 10240000\r\n250 AUTH PLAIN LOGIN\r\n",
                            hostname
                        );
                        let _ = writer.write_all(resp.as_bytes()).await;
                    } else if upper.starts_with("HELO") {
                        let _ = writer
                            .write_all(format!("250 mail.{}\r\n", hostname).as_bytes())
                            .await;
                    } else if upper.starts_with("AUTH PLAIN") {
                        let payload = trimmed[10..].trim();
                        if let Some(decoded) = ioc::decode_base64(payload) {
                            let parts: Vec<&[u8]> = decoded.split(|&b| b == 0).collect();
                            if parts.len() >= 3 {
                                username = Some(String::from_utf8_lossy(parts[1]).into_owned());
                                password = Some(String::from_utf8_lossy(parts[2]).into_owned());
                            } else if parts.len() == 2 {
                                username = Some(String::from_utf8_lossy(parts[0]).into_owned());
                                password = Some(String::from_utf8_lossy(parts[1]).into_owned());
                            }
                        }
                        let _ = writer
                            .write_all(b"235 2.7.0 Authentication successful\r\n")
                            .await;
                    } else if upper.starts_with("AUTH LOGIN") {
                        let rest = trimmed[10..].trim();
                        if !rest.is_empty() {
                            if let Some(bytes) = ioc::decode_base64(rest) {
                                username = Some(String::from_utf8_lossy(&bytes).into_owned());
                            }
                            auth_login_step = 2;
                            let _ = writer.write_all(b"334 UGFzc3dvcmQ6\r\n").await;
                        } else {
                            auth_login_step = 1;
                            let _ = writer.write_all(b"334 VXNlcm5hbWU6\r\n").await; // Username:
                        }
                    } else if upper.starts_with("MAIL FROM") || upper.starts_with("RCPT TO") || upper == "RSET" || upper == "NOOP" {
                        let _ = writer.write_all(b"250 2.1.0 Ok\r\n").await;
                    } else if upper == "DATA" {
                        in_data = true;
                        let _ = writer
                            .write_all(b"354 End data with <CR><LF>.<CR><LF>\r\n")
                            .await;
                    } else if upper == "QUIT" {
                        let _ = writer.write_all(b"221 2.0.0 Bye\r\n").await;
                        break;
                    } else {
                        let _ = writer.write_all(b"502 Error: command not implemented\r\n").await;
                    }
                }
            }
        }
    })
    .await;

    let request = match (&username, &password) {
        (Some(u), Some(p)) => format!("SMTP AUTH {}:{} from {}", u, p, ip),
        _ => transcript
            .first()
            .cloned()
            .unwrap_or_else(|| format!("SMTP connection from {}", ip)),
    };

    let mut event = AttackEvent::new(ip, service, port, request).with_request_size(total_bytes);
    if let Some(u) = username {
        event = event.with_credentials(u, password.unwrap_or_default());
    }
    if !transcript.is_empty() {
        event = event.with_payload(transcript.join("\n").into_bytes());
    }

    classifier::record_event(event, &geoip, &write_tx, &event_bus);
}
