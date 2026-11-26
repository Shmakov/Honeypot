//! Redis honeypot handler (RESP + inline command parser)

use anyhow::Result;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
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
            warn!("Cannot bind Redis to {}: {} - skipping", addr, e);
            return Ok(());
        }
    };

    info!("Redis honeypot started on port {}", port);

    loop {
        match listener.accept().await {
            Ok((socket, peer_addr)) => {
                let ip = peer_addr.ip().to_string();
                let Some(permit) = limiter.try_acquire(&ip) else {
                    debug!("Redis connection rejected (concurrency limit) from {}", ip);
                    drop(socket);
                    continue;
                };
                let event_bus = event_bus.clone();
                let write_tx = write_tx.clone();
                let geoip = geoip.clone();
                tokio::spawn(async move {
                    handle_redis_session(socket, ip, port, event_bus, write_tx, geoip, permit)
                        .await;
                });
            }
            Err(e) => warn!("Redis accept error on port {}: {}", port, e),
        }
    }
}

async fn read_resp_command<R: tokio::io::AsyncRead + Unpin>(
    reader: &mut BufReader<R>,
) -> Option<Vec<String>> {
    let mut line = String::new();
    if reader.read_line(&mut line).await.ok()? == 0 {
        return None;
    }
    let trimmed = line.trim();
    if let Some(count_str) = trimmed.strip_prefix('*') {
        let count: usize = count_str.parse().ok()?;
        let count = count.min(32);
        let mut args = Vec::with_capacity(count);
        for _ in 0..count {
            let mut len_line = String::new();
            if reader.read_line(&mut len_line).await.ok()? == 0 {
                return None;
            }
            let len: usize = len_line.trim().strip_prefix('$')?.parse().ok()?;
            let bounded = len.min(8192);
            let mut buf = vec![0u8; bounded];
            reader.read_exact(&mut buf).await.ok()?;
            // Discard excess if truncated + CRLF
            if len > bounded {
                let mut skip = vec![0u8; (len - bounded).min(65536)];
                let _ = reader.read_exact(&mut skip).await;
            }
            let mut crlf = [0u8; 2];
            let _ = reader.read_exact(&mut crlf).await;
            args.push(String::from_utf8_lossy(&buf).into_owned());
        }
        Some(args)
    } else if !trimmed.is_empty() {
        Some(
            trimmed
                .split_whitespace()
                .map(|s| s.to_string())
                .collect(),
        )
    } else {
        Some(Vec::new())
    }
}

async fn handle_redis_session(
    socket: tokio::net::TcpStream,
    ip: String,
    port: u16,
    event_bus: Arc<EventBus>,
    write_tx: WriteSender,
    geoip: SharedGeoIp,
    _permit: ConnectionPermit,
) {
    let (reader, mut writer) = socket.into_split();
    let mut reader = BufReader::new(reader);

    let mut commands: Vec<String> = Vec::new();
    let mut captured_password: Option<String> = None;
    let mut total_bytes: u32 = 0;

    let _ = tokio::time::timeout(std::time::Duration::from_secs(30), async {
        for _ in 0..50 {
            let Some(args) = read_resp_command(&mut reader).await else {
                break;
            };
            if args.is_empty() {
                continue;
            }
            let line = args.join(" ");
            total_bytes += line.len() as u32 + 2;
            commands.push(line);

            let cmd = args[0].to_ascii_uppercase();
            match cmd.as_str() {
                "PING" => {
                    let _ = writer.write_all(b"+PONG\r\n").await;
                }
                "AUTH" => {
                    if let Some(pwd) = args.last() {
                        captured_password = Some(pwd.clone());
                    }
                    let _ = writer.write_all(b"+OK\r\n").await;
                }
                "INFO" => {
                    let info = "# Server\r\nredis_version:7.0.12\r\nos:Linux 5.15.0-105-generic x86_64\r\nrole:master\r\n";
                    let resp = format!("${}\r\n{}\r\n", info.len(), info);
                    let _ = writer.write_all(resp.as_bytes()).await;
                }
                "CONFIG" => {
                    if args.get(1).map(|s| s.eq_ignore_ascii_case("GET")).unwrap_or(false) {
                        let key = args.get(2).map(|s| s.as_str()).unwrap_or("dir");
                        let val = "/var/lib/redis";
                        let resp = format!(
                            "*2\r\n${}\r\n{}\r\n${}\r\n{}\r\n",
                            key.len(),
                            key,
                            val.len(),
                            val
                        );
                        let _ = writer.write_all(resp.as_bytes()).await;
                    } else {
                        let _ = writer.write_all(b"+OK\r\n").await;
                    }
                }
                "KEYS" => {
                    let _ = writer.write_all(b"*2\r\n$7\r\nsession\r\n$6\r\nconfig\r\n").await;
                }
                "GET" => {
                    let _ = writer.write_all(b"$-1\r\n").await;
                }
                "QUIT" => {
                    let _ = writer.write_all(b"+OK\r\n").await;
                    break;
                }
                _ => {
                    let _ = writer.write_all(b"+OK\r\n").await;
                }
            }
        }
    })
    .await;

    let summary = commands
        .first()
        .cloned()
        .unwrap_or_else(|| format!("Redis connection from {}", ip));
    let mut event = AttackEvent::new(ip, "redis".to_string(), port, summary)
        .with_request_size(total_bytes);

    if let Some(pwd) = captured_password {
        event = event.with_credentials("default".to_string(), pwd);
    }
    if !commands.is_empty() {
        event = event.with_payload(commands.join("\n").into_bytes());
    }

    classifier::record_event(event, &geoip, &write_tx, &event_bus);
}
