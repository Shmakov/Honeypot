//! FTP honeypot handler

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
            warn!("Cannot bind FTP to {}: {} - skipping", addr, e);
            return Ok(());
        }
    };

    info!("FTP honeypot started on port {}", port);
    let banner = config.emulation.ftp_banner.clone();

    loop {
        match listener.accept().await {
            Ok((socket, peer_addr)) => {
                let ip = peer_addr.ip().to_string();
                let Some(permit) = limiter.try_acquire(&ip) else {
                    debug!("FTP connection rejected (concurrency limit) from {}", ip);
                    drop(socket);
                    continue;
                };

                let event_bus = event_bus.clone();
                let write_tx = write_tx.clone();
                let banner = banner.clone();
                let geoip = geoip.clone();

                tokio::spawn(async move {
                    handle_ftp_session(
                        socket, ip, port, banner, event_bus, write_tx, geoip, permit,
                    )
                    .await;
                });
            }
            Err(e) => {
                warn!("FTP accept error on port {}: {}", port, e);
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_ftp_session(
    socket: tokio::net::TcpStream,
    ip: String,
    port: u16,
    banner: String,
    event_bus: Arc<EventBus>,
    write_tx: WriteSender,
    geoip: SharedGeoIp,
    _permit: ConnectionPermit,
) {
    let (reader, mut writer) = socket.into_split();
    let mut reader = BufReader::new(reader);

    let _ = writer
        .write_all(format!("{}\r\n", banner).as_bytes())
        .await;

    let mut username = String::new();
    let mut password = String::new();
    let mut commands = Vec::new();

    let timeout = tokio::time::timeout(std::time::Duration::from_secs(60), async {
        let mut line = String::new();
        loop {
            line.clear();
            match reader.read_line(&mut line).await {
                Ok(0) => break,
                Ok(_) => {
                    if line.len() > 2048 {
                        break;
                    }
                    let cmd = line.trim().to_string();

                    if commands.len() < 100 {
                        commands.push(cmd.clone());
                    }

                    let parts: Vec<&str> = cmd.splitn(2, ' ').collect();
                    let command = parts.first().map(|s| s.to_uppercase()).unwrap_or_default();
                    let arg = parts.get(1).map(|s| s.to_string()).unwrap_or_default();

                    match command.as_str() {
                        "USER" => {
                            username = arg;
                            let _ = writer.write_all(b"331 Password required\r\n").await;
                        }
                        "PASS" => {
                            password = arg;
                            let _ = writer.write_all(b"230 Login successful\r\n").await;
                            break;
                        }
                        "QUIT" => {
                            let _ = writer.write_all(b"221 Goodbye\r\n").await;
                            break;
                        }
                        "SYST" => {
                            let _ = writer.write_all(b"215 UNIX Type: L8\r\n").await;
                        }
                        "PWD" => {
                            let _ = writer
                                .write_all(b"257 \"/\" is current directory\r\n")
                                .await;
                        }
                        "LIST" | "NLST" => {
                            let _ = writer.write_all(b"150 Opening data connection\r\n").await;
                            let _ = writer.write_all(b"226 Transfer complete\r\n").await;
                        }
                        "TYPE" => {
                            let _ = writer.write_all(b"200 Type set\r\n").await;
                        }
                        "PASV" => {
                            let _ = writer
                                .write_all(b"227 Entering Passive Mode (127,0,0,1,100,100)\r\n")
                                .await;
                        }
                        _ => {
                            let _ = writer.write_all(b"502 Command not implemented\r\n").await;
                        }
                    }
                }
                Err(_) => break,
            }
        }
    });

    let _ = timeout.await;

    let request = if !username.is_empty() {
        format!("FTP login: {}:{} from {}", username, password, ip)
    } else {
        format!("FTP connection from {}", ip)
    };

    let mut event = AttackEvent::new(ip, "ftp".to_string(), port, request);
    let request_size: u32 = commands.iter().map(|c| c.len() as u32 + 2).sum();
    event = event.with_request_size(request_size);

    if !username.is_empty() {
        event = event.with_credentials(username, password);
    }
    if !commands.is_empty() {
        event = event.with_payload(commands.join("\n").into_bytes());
    }

    classifier::record_event(event, &geoip, &write_tx, &event_bus);
}
