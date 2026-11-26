//! Telnet honeypot handler with IAC negotiation and stateful FakeShell

use anyhow::Result;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufWriter};
use tokio::net::TcpListener;
use tracing::{debug, info, warn};

use crate::classifier;
use crate::config::Config;
use crate::db::{AttackEvent, WriteSender};
use crate::events::EventBus;
use crate::geoip::SharedGeoIp;
use crate::handlers::shell_fs::FakeShell;
use crate::ioc::IocItem;
use crate::limits::{ConnectionLimiter, ConnectionPermit};

const IAC: u8 = 255;
const WILL: u8 = 251;
const WONT: u8 = 252;
const DO: u8 = 253;
const DONT: u8 = 254;
const SB: u8 = 250;
const SE: u8 = 240;

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
            warn!("Cannot bind Telnet to {}: {} - skipping", addr, e);
            return Ok(());
        }
    };

    info!("Telnet honeypot started on port {} ({})", port, service);
    let service = service.to_string();

    loop {
        match listener.accept().await {
            Ok((socket, peer_addr)) => {
                let ip = peer_addr.ip().to_string();
                let Some(permit) = limiter.try_acquire(&ip) else {
                    debug!("Telnet connection rejected (concurrency limit) from {}", ip);
                    drop(socket);
                    continue;
                };

                let service = service.clone();
                let hostname = config.emulation.hostname.clone();
                let persona = config.emulation.persona.clone();
                let event_bus = event_bus.clone();
                let write_tx = write_tx.clone();
                let geoip = geoip.clone();

                tokio::spawn(async move {
                    handle_telnet_session(
                        socket, ip, port, service, hostname, persona, event_bus, write_tx, geoip,
                        permit,
                    )
                    .await;
                });
            }
            Err(e) => {
                warn!("Telnet accept error on port {}: {}", port, e);
            }
        }
    }
}

/// Read a line from the socket, filtering out telnet IAC commands (bounded to 4KB)
async fn read_telnet_line(
    socket: &mut tokio::net::tcp::OwnedReadHalf,
    ip: &str,
) -> Option<String> {
    const MAX_LINE: usize = 4096;
    let mut result = Vec::new();
    let mut buf = [0u8; 1];
    let mut in_iac = false;
    let mut in_subneg = false;

    let timeout = tokio::time::timeout(std::time::Duration::from_secs(30), async {
        loop {
            match socket.read(&mut buf).await {
                Ok(0) => {
                    debug!("Telnet EOF from {}", ip);
                    return None;
                }
                Ok(_) => {
                    let byte = buf[0];

                    if in_subneg {
                        if byte == IAC {
                            in_iac = true;
                        } else if in_iac && byte == SE {
                            in_subneg = false;
                            in_iac = false;
                        } else {
                            in_iac = false;
                        }
                        continue;
                    }

                    if in_iac {
                        match byte {
                            IAC => {
                                if result.len() < MAX_LINE {
                                    result.push(255);
                                }
                                in_iac = false;
                            }
                            WILL | WONT | DO | DONT => {
                                in_iac = false;
                                if socket.read(&mut buf).await.is_err() {
                                    return None;
                                }
                            }
                            SB => {
                                in_subneg = true;
                                in_iac = false;
                            }
                            _ => {
                                in_iac = false;
                            }
                        }
                        continue;
                    }

                    if byte == IAC {
                        in_iac = true;
                        continue;
                    }

                    if byte == b'\n' || byte == b'\r' {
                        if result.is_empty() {
                            continue;
                        }
                        break;
                    }

                    if (32..127).contains(&byte) && result.len() < MAX_LINE {
                        result.push(byte);
                    }
                }
                Err(e) => {
                    debug!("Telnet read error from {}: {}", ip, e);
                    return None;
                }
            }
        }

        Some(String::from_utf8_lossy(&result).to_string())
    });

    timeout.await.ok().flatten()
}

#[allow(clippy::too_many_arguments)]
async fn handle_telnet_session(
    socket: tokio::net::TcpStream,
    ip: String,
    port: u16,
    service: String,
    hostname: String,
    persona: String,
    event_bus: Arc<EventBus>,
    write_tx: WriteSender,
    geoip: SharedGeoIp,
    _permit: ConnectionPermit,
) {
    let (mut reader, writer) = socket.into_split();
    let mut writer = BufWriter::new(writer);

    let login_header = format!("\r\n{} login: ", hostname);
    if writer.write_all(b"\r\nUbuntu 22.04.4 LTS\r\n").await.is_err()
        || writer.write_all(login_header.as_bytes()).await.is_err()
        || writer.flush().await.is_err()
    {
        return;
    }

    let mut username = String::new();
    let mut password = String::new();
    let mut commands = Vec::new();
    let mut extracted_iocs: Vec<IocItem> = Vec::new();
    let mut canary_triggered = false;
    let mut shell: Option<FakeShell> = None;
    let mut state = 0;

    let session_timeout = tokio::time::timeout(std::time::Duration::from_secs(120), async {
        loop {
            let Some(input) = read_telnet_line(&mut reader, &ip).await else {
                break;
            };

            match state {
                0 => {
                    username = input;
                    if writer.write_all(b"Password: ").await.is_err()
                        || writer.flush().await.is_err()
                    {
                        break;
                    }
                    state = 1;
                }
                1 => {
                    password = input;
                    let fs = FakeShell::new(&hostname, &persona, &username);
                    let banner = fs.welcome_banner(&ip);
                    let prompt = fs.prompt();
                    shell = Some(fs);

                    if writer.write_all(b"\r\n").await.is_err()
                        || writer.write_all(banner.as_bytes()).await.is_err()
                        || writer.write_all(prompt.as_bytes()).await.is_err()
                        || writer.flush().await.is_err()
                    {
                        break;
                    }
                    state = 2;
                }
                2 => {
                    commands.push(input.clone());
                    let Some(ref mut fs) = shell else {
                        break;
                    };

                    let res = fs.execute_line(&input);
                    if res.canary_triggered {
                        canary_triggered = true;
                    }
                    for item in res.extracted_iocs {
                        if !extracted_iocs.iter().any(|e| e == &item) {
                            extracted_iocs.push(item);
                        }
                    }

                    if !res.output.is_empty() {
                        let _ = writer.write_all(res.output.as_bytes()).await;
                    }
                    if res.should_exit {
                        let _ = writer.flush().await;
                        break;
                    }

                    let prompt = fs.prompt();
                    let _ = writer.write_all(prompt.as_bytes()).await;
                    let _ = writer.flush().await;

                    if commands.len() >= 50 {
                        break;
                    }
                }
                _ => break,
            }
        }
    });

    let _ = session_timeout.await;

    let request = if !username.is_empty() {
        format!("Telnet login: {}:{} from {}", username, password, ip)
    } else {
        format!("Telnet connection from {}", ip)
    };

    let mut event = AttackEvent::new(ip.clone(), service, port, request);
    let request_size: u32 = username.len() as u32
        + password.len() as u32
        + commands.iter().map(|c| c.len() as u32 + 2).sum::<u32>();
    event = event.with_request_size(request_size);

    if !username.is_empty() {
        event = event.with_credentials(username, password);
    }
    if !commands.is_empty() {
        event = event.with_payload(commands.join("\n").into_bytes());
    }
    if !extracted_iocs.is_empty() {
        event = event.with_iocs(extracted_iocs);
    }
    if canary_triggered {
        event = event.with_tag("canary-triggered");
    }

    classifier::record_event(event, &geoip, &write_tx, &event_bus);
}
