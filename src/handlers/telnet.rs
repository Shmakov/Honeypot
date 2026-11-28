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
const MAX_LINE: usize = 4096;

enum TelnetReadResult {
    Line(String, usize),
    BinaryProbe(usize),
    Eof(usize),
}

fn is_binary_byte(byte: u8) -> bool {
    matches!(
        byte,
        0x01..=0x02 | 0x05..=0x07 | 0x0b..=0x0c | 0x0e..=0x1a | 0x1c..=0x1f | 0x80..=0xfe
    )
}

pub(crate) fn is_http_header_line(line: &str) -> bool {
    let lower = line.trim().to_ascii_lowercase();
    const PREFIXES: &[&str] = &[
        "host:",
        "user-agent:",
        "accept:",
        "accept-encoding:",
        "accept-language:",
        "connection:",
        "content-type:",
        "content-length:",
        "cache-control:",
        "cookie:",
        "authorization:",
        "upgrade-insecure-requests:",
        "sec-",
        "x-forwarded-",
    ];
    PREFIXES.iter().any(|prefix| lower.starts_with(prefix))
}

pub(crate) fn detect_non_telnet_probe(line: &str) -> Option<&'static str> {
    let trimmed = line.trim();
    let upper = trimmed.to_ascii_uppercase();

    const HTTP_METHODS: &[&str] = &[
        "GET ",
        "POST ",
        "HEAD ",
        "PUT ",
        "DELETE ",
        "OPTIONS ",
        "PATCH ",
        "CONNECT ",
        "TRACE ",
        "PROPFIND ",
        "PRI *",
    ];

    if upper.contains(" HTTP/")
        || HTTP_METHODS.iter().any(|m| upper.starts_with(m))
        || is_http_header_line(trimmed)
    {
        return Some("HTTP");
    }

    if upper.starts_with("SSH-") {
        return Some("SSH");
    }

    if upper.contains(" RTSP/") {
        return Some("RTSP");
    }

    if upper.contains(" SIP/") {
        return Some("SIP");
    }

    if upper.starts_with("EHLO ") || upper.starts_with("HELO ") || upper.starts_with("MAIL FROM:") {
        return Some("SMTP");
    }

    if upper.starts_with("PROXY ") {
        return Some("PROXY");
    }

    if upper.starts_with("MGLNDD_") {
        return Some("scanner");
    }

    if trimmed.starts_with('{') || trimmed.starts_with('<') {
        return Some("non-telnet");
    }

    None
}

pub(crate) fn is_suspicious_telnet_username(username: &str) -> bool {
    detect_non_telnet_probe(username).is_some()
        || username.len() > 64
        || username.bytes().any(|b| {
            b.is_ascii_whitespace()
                || matches!(
                    b,
                    b'<' | b'>' | b'"' | b'`' | b'|' | b'{' | b'}' | b'[' | b']' | b';' | b'&' | b'$'
                )
        })
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

/// Read a line from the socket, filtering out telnet IAC commands and rejecting binary probes
async fn read_telnet_line(
    socket: &mut tokio::net::tcp::OwnedReadHalf,
    ip: &str,
) -> TelnetReadResult {
    let mut result = Vec::new();
    let mut buf = [0u8; 1];
    let mut in_iac = false;
    let mut in_subneg = false;
    let mut bytes_read = 0usize;

    let timeout = tokio::time::timeout(std::time::Duration::from_secs(30), async {
        loop {
            match socket.read(&mut buf).await {
                Ok(0) => {
                    debug!("Telnet EOF from {}", ip);
                    return TelnetReadResult::Eof(bytes_read);
                }
                Ok(_) => {
                    bytes_read += 1;
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
                                    return TelnetReadResult::Eof(bytes_read);
                                }
                                bytes_read += 1;
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

                    if is_binary_byte(byte) {
                        debug!("Telnet binary probe byte 0x{:02x} from {}", byte, ip);
                        return TelnetReadResult::BinaryProbe(bytes_read);
                    }

                    if byte == b'\n' || byte == b'\r' {
                        if result.is_empty() {
                            continue;
                        }
                        return TelnetReadResult::Line(
                            String::from_utf8_lossy(&result).to_string(),
                            bytes_read,
                        );
                    }

                    if (32..127).contains(&byte) && result.len() < MAX_LINE {
                        result.push(byte);
                    }
                }
                Err(e) => {
                    debug!("Telnet read error from {}: {}", ip, e);
                    return TelnetReadResult::Eof(bytes_read);
                }
            }
        }
    });

    timeout
        .await
        .unwrap_or(TelnetReadResult::Eof(bytes_read))
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
    let mut raw_bytes_read: usize = 0;
    let mut aborted_probe: Option<(&'static str, Option<String>)> = None;

    let session_timeout = tokio::time::timeout(std::time::Duration::from_secs(120), async {
        loop {
            let input = match read_telnet_line(&mut reader, &ip).await {
                TelnetReadResult::Line(line, n) => {
                    raw_bytes_read += n;
                    line
                }
                TelnetReadResult::BinaryProbe(n) => {
                    raw_bytes_read += n;
                    if state < 2 {
                        aborted_probe = Some(("binary", None));
                    }
                    break;
                }
                TelnetReadResult::Eof(n) => {
                    raw_bytes_read += n;
                    break;
                }
            };

            match state {
                0 => {
                    if is_suspicious_telnet_username(&input) {
                        let kind = detect_non_telnet_probe(&input).unwrap_or("non-telnet");
                        let snippet: String = input.chars().take(120).collect();
                        aborted_probe = Some((kind, Some(snippet)));
                        break;
                    }
                    username = input;
                    if writer.write_all(b"Password: ").await.is_err()
                        || writer.flush().await.is_err()
                    {
                        break;
                    }
                    state = 1;
                }
                1 => {
                    if is_http_header_line(&input) || detect_non_telnet_probe(&input).is_some() {
                        let kind = detect_non_telnet_probe(&input).unwrap_or("HTTP");
                        let snippet: String = input.chars().take(120).collect();
                        username.clear();
                        aborted_probe = Some((kind, Some(snippet)));
                        break;
                    }
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

    let has_valid_creds = state >= 2 && !username.is_empty() && aborted_probe.is_none();
    let request = if let Some((kind, snippet)) = &aborted_probe {
        match snippet {
            Some(s) => format!("Telnet non-telnet probe ({}): {} from {}", kind, s, ip),
            None => format!("Telnet non-telnet probe ({}) from {}", kind, ip),
        }
    } else if has_valid_creds {
        format!("Telnet login: {}:{} from {}", username, password, ip)
    } else {
        format!("Telnet connection from {}", ip)
    };

    let mut event = AttackEvent::new(ip.clone(), service, port, request);
    let computed_size: u32 = username.len() as u32
        + password.len() as u32
        + commands.iter().map(|c| c.len() as u32 + 2).sum::<u32>();
    let request_size = (raw_bytes_read as u32).max(computed_size);
    event = event.with_request_size(request_size);

    if has_valid_creds {
        event = event.with_credentials(username, password);
    }
    if !commands.is_empty() && aborted_probe.is_none() {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_http_scanner_and_shell_probes_as_telnet_usernames() {
        assert!(is_suspicious_telnet_username("GET / HTTP/1.1"));
        assert!(is_suspicious_telnet_username("Host: 192.0.2.1:23"));
        assert!(is_suspicious_telnet_username("MGLNDD_192.0.2.1_2323"));
        assert!(is_suspicious_telnet_username(
            "id;for t in curl wget;do command -v $t;done"
        ));
        assert!(is_http_header_line("Host: example.com:23"));
        assert!(!is_suspicious_telnet_username("root"));
        assert!(!is_suspicious_telnet_username("telecomadmin"));
    }
}
