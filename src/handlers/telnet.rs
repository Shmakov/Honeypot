//! Telnet honeypot handler with proper IAC negotiation

use anyhow::Result;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufWriter};
use tokio::net::TcpListener;
use tracing::{debug, info, warn};

use crate::config::Config;
use crate::db::{AttackEvent, WriteSender};
use crate::events::EventBus;
use crate::geoip::SharedGeoIp;

// Telnet command bytes
const IAC: u8 = 255;  // Interpret As Command
const WILL: u8 = 251;
const WONT: u8 = 252;
const DO: u8 = 253;
const DONT: u8 = 254;
const SB: u8 = 250;   // Subnegotiation Begin
const SE: u8 = 240;   // Subnegotiation End

const MAX_LINE_LEN: usize = 4096;

enum TelnetReadResult {
    Line(String, usize),    // (line, raw_bytes_read)
    BinaryProbe(u8, usize), // (first_offending_byte, raw_bytes_read)
    Eof(usize),             // raw_bytes_read
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
                || matches!(b, b'<' | b'>' | b'"' | b'`' | b'|' | b'{' | b'}' | b'[' | b']')
        })
}

pub async fn start(
    port: u16,
    config: Arc<Config>,
    event_bus: Arc<EventBus>,
    write_tx: WriteSender,
    geoip: SharedGeoIp,
) -> Result<()> {
    let addr = format!("{}:{}", config.server.host, port);
    let listener = match TcpListener::bind(&addr).await {
        Ok(l) => l,
        Err(e) => {
            warn!("Cannot bind Telnet to {}: {} - skipping", addr, e);
            return Ok(());
        }
    };

    info!("Telnet honeypot started on port {}", port);

    loop {
        match listener.accept().await {
            Ok((socket, peer_addr)) => {
                let ip = peer_addr.ip().to_string();
                let event_bus = event_bus.clone();
                let write_tx = write_tx.clone();
                let geoip = geoip.clone();

                tokio::spawn(async move {
                    handle_telnet_session(socket, ip, port, event_bus, write_tx, geoip).await;
                });
            }
            Err(e) => {
                warn!("Telnet accept error on port {}: {}", port, e);
            }
        }
    }
}

/// Read a line from the socket, filtering out telnet IAC commands and rejecting binary probes
async fn read_telnet_line(socket: &mut tokio::net::tcp::OwnedReadHalf, ip: &str) -> TelnetReadResult {
    let mut result = Vec::new();
    let mut buf = [0u8; 1];
    let mut in_iac = false;
    let mut in_subneg = false;
    let mut iac_cmd = 0u8;
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

                    // Handle IAC sequences
                    if in_subneg {
                        // Skip until we see IAC SE
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
                                // Escaped IAC (255 255) = literal 255
                                if result.len() < MAX_LINE_LEN {
                                    result.push(255);
                                }
                                in_iac = false;
                            }
                            WILL | WONT | DO | DONT => {
                                // These are followed by one option byte
                                iac_cmd = byte;
                                in_iac = false;
                                // Read and discard the option byte
                                match socket.read(&mut buf).await {
                                    Ok(0) | Err(_) => return TelnetReadResult::Eof(bytes_read),
                                    Ok(_) => {
                                        bytes_read += 1;
                                    }
                                }
                                debug!("Telnet IAC {:?} option {} from {}", iac_cmd, buf[0], ip);
                            }
                            SB => {
                                // Subnegotiation - skip until SE
                                in_subneg = true;
                                in_iac = false;
                            }
                            _ => {
                                // Other IAC command, ignore
                                in_iac = false;
                            }
                        }
                        continue;
                    }

                    if byte == IAC {
                        in_iac = true;
                        continue;
                    }

                    // Handle line endings
                    if byte == b'\n' || byte == b'\r' {
                        // Skip empty lines caused by \r\n sequences
                        if result.is_empty() {
                            continue;
                        }
                        // We have a complete line
                        break;
                    }

                    if is_binary_byte(byte) {
                        debug!("Telnet binary probe byte 0x{:02x} from {}", byte, ip);
                        return TelnetReadResult::BinaryProbe(byte, bytes_read);
                    }

                    // Regular character
                    if (32..127).contains(&byte) {
                        if result.len() < MAX_LINE_LEN {
                            result.push(byte);
                        } else {
                            break;
                        }
                    }
                }
                Err(e) => {
                    debug!("Telnet read error from {}: {}", ip, e);
                    return TelnetReadResult::Eof(bytes_read);
                }
            }
        }

        TelnetReadResult::Line(String::from_utf8_lossy(&result).to_string(), bytes_read)
    });

    match timeout.await {
        Ok(res) => res,
        Err(_) => {
            debug!("Telnet read timeout from {}", ip);
            TelnetReadResult::Eof(bytes_read)
        }
    }
}

async fn handle_telnet_session(
    socket: tokio::net::TcpStream,
    ip: String,
    port: u16,
    event_bus: Arc<EventBus>,
    write_tx: WriteSender,
    geoip: SharedGeoIp,
) {
    debug!("Telnet session started from {}", ip);
    
    let (mut reader, writer) = socket.into_split();
    let mut writer = BufWriter::new(writer);

    // Send login banner
    if let Err(e) = writer.write_all(b"\r\nUbuntu 20.04 LTS\r\n").await {
        debug!("Telnet write banner failed for {}: {}", ip, e);
        return;
    }
    if let Err(e) = writer.write_all(b"login: ").await {
        debug!("Telnet write login prompt failed for {}: {}", ip, e);
        return;
    }
    if let Err(e) = writer.flush().await {
        debug!("Telnet flush failed for {}: {}", ip, e);
        return;
    }
    debug!("Telnet sent login prompt to {}", ip);

    let mut username = String::new();
    let mut password = String::new();
    let mut commands = Vec::new();
    let mut total_bytes_read: usize = 0;
    let mut probe_request: Option<String> = None;

    // State machine: 0=login, 1=password, 2=shell
    let mut state = 0;
    
    let session_timeout = tokio::time::timeout(std::time::Duration::from_secs(120), async {
        loop {
            match state {
                0 => match read_telnet_line(&mut reader, &ip).await {
                    TelnetReadResult::BinaryProbe(first_byte, n) => {
                        total_bytes_read += n;
                        let kind = if first_byte == 0x16 { "TLS" } else { "binary" };
                        probe_request = Some(format!("Telnet {} probe from {}", kind, ip));
                        break;
                    }
                    TelnetReadResult::Line(input, n) => {
                        total_bytes_read += n;
                        debug!("Telnet received from {} in state {}: {:?}", ip, state, input);
                        if let Some(proto) = detect_non_telnet_probe(&input) {
                            let preview: String = input.trim().chars().take(120).collect();
                            probe_request = Some(format!(
                                "Telnet {} probe: {} from {}",
                                proto, preview, ip
                            ));
                            break;
                        }
                        if is_suspicious_telnet_username(&input) {
                            probe_request = Some(format!("Telnet non-telnet probe from {}", ip));
                            break;
                        }
                        username = input;
                        debug!("Telnet got username '{}' from {}", username, ip);
                        if let Err(e) = writer.write_all(b"Password: ").await {
                            debug!("Telnet write password prompt failed for {}: {}", ip, e);
                            break;
                        }
                        if let Err(e) = writer.flush().await {
                            debug!("Telnet flush password prompt failed for {}: {}", ip, e);
                            break;
                        }
                        state = 1;
                    }
                    TelnetReadResult::Eof(n) => {
                        total_bytes_read += n;
                        break;
                    }
                },
                1 => match read_telnet_line(&mut reader, &ip).await {
                    TelnetReadResult::BinaryProbe(_, n) => {
                        total_bytes_read += n;
                        username.clear();
                        probe_request = Some(format!("Telnet binary probe from {}", ip));
                        break;
                    }
                    TelnetReadResult::Line(input, n) => {
                        total_bytes_read += n;
                        debug!("Telnet received from {} in state {}: {:?}", ip, state, input);
                        if is_http_header_line(&input) {
                            username.clear();
                            probe_request = Some(format!("Telnet HTTP probe from {}", ip));
                            break;
                        }
                        password = input;
                        debug!("Telnet got password from {}", ip);
                        if let Err(e) = writer.write_all(b"\r\nWelcome to Ubuntu 20.04 LTS\r\n").await {
                            debug!("Telnet write welcome failed for {}: {}", ip, e);
                            break;
                        }
                        if let Err(e) = writer.write_all(format!("{}@ubuntu:~$ ", username).as_bytes()).await {
                            debug!("Telnet write prompt failed for {}: {}", ip, e);
                            break;
                        }
                        if let Err(e) = writer.flush().await {
                            debug!("Telnet flush shell prompt failed for {}: {}", ip, e);
                            break;
                        }
                        state = 2;
                    }
                    TelnetReadResult::Eof(n) => {
                        total_bytes_read += n;
                        break;
                    }
                },
                2 => match read_telnet_line(&mut reader, &ip).await {
                    TelnetReadResult::BinaryProbe(_, n) => {
                        total_bytes_read += n;
                        break;
                    }
                    TelnetReadResult::Line(input, n) => {
                        total_bytes_read += n;
                        debug!("Telnet received from {} in state {}: {:?}", ip, state, input);
                        commands.push(input.clone());

                        // Simulate some basic commands
                        let response = match input.split_whitespace().next() {
                            Some("exit") | Some("quit") | Some("logout") => {
                                debug!("Telnet exit command from {}", ip);
                                break;
                            }
                            Some("pwd") => "/home/user\r\n",
                            Some("whoami") => &format!("{}\r\n", username),
                            Some("id") => "uid=1000(user) gid=1000(user) groups=1000(user)\r\n",
                            Some("uname") => "Linux ubuntu 5.4.0-42-generic x86_64 GNU/Linux\r\n",
                            Some("ls") => "Desktop  Documents  Downloads\r\n",
                            Some("cat") => "",
                            Some("cd") => "",
                            _ => "bash: command not found\r\n",
                        };

                        let _ = writer.write_all(response.as_bytes()).await;
                        let _ = writer.write_all(format!("{}@ubuntu:~$ ", username).as_bytes()).await;
                        let _ = writer.flush().await;

                        // Limit interaction
                        if commands.len() >= 20 {
                            debug!("Telnet command limit reached for {}", ip);
                            break;
                        }
                    }
                    TelnetReadResult::Eof(n) => {
                        total_bytes_read += n;
                        break;
                    }
                },
                _ => break,
            }
        }
    });

    let _ = session_timeout.await;

    // Create event
    let request = if let Some(desc) = probe_request {
        desc
    } else if !username.is_empty() {
        format!("Telnet login: {}:{} from {}", username, password, ip)
    } else {
        format!("Telnet connection from {}", ip)
    };

    let mut event = AttackEvent::new(ip.clone(), "telnet".to_string(), port, request);

    let request_size = total_bytes_read.min(u32::MAX as usize) as u32;
    event = event.with_request_size(request_size);

    if !username.is_empty() {
        event = event.with_credentials(username, password);
    }

    if !commands.is_empty() {
        event = event.with_payload(commands.join("\n").into_bytes());
    }

    // Add GeoIP info
    if let Some(loc) = geoip.lookup(&ip) {
        event = event.with_geo(loc.country_code, loc.latitude, loc.longitude);
    }

    // Send to write buffer (non-blocking) and broadcast
    let _ = write_tx.send(event.clone());
    event_bus.publish(event);
    debug!("Telnet session ended from {}", ip);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::geoip::GeoIp;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpStream;
    use tokio::sync::{broadcast, mpsc};

    #[test]
    fn test_probe_and_username_detection() {
        // HTTP request lines & headers
        assert_eq!(detect_non_telnet_probe("GET / HTTP/1.1"), Some("HTTP"));
        assert_eq!(detect_non_telnet_probe("POST /login HTTP/1.0"), Some("HTTP"));
        assert_eq!(detect_non_telnet_probe("PRI * HTTP/2.0"), Some("HTTP"));
        assert_eq!(detect_non_telnet_probe("Host: 35.212.148.194:23"), Some("HTTP"));
        assert_eq!(detect_non_telnet_probe("User-Agent: Mozilla/5.0"), Some("HTTP"));
        assert!(is_http_header_line("Host: 35.212.148.194:23"));
        assert!(is_http_header_line("user-agent: Mozilla/5.0"));
        assert!(is_http_header_line("Accept-Encoding: gzip"));
        assert!(is_http_header_line("Connection: close"));

        // Other protocols
        assert_eq!(detect_non_telnet_probe("SSH-2.0-OpenSSH_8.9"), Some("SSH"));

        // Binary-stripped garbage / suspicious usernames
        assert!(is_suspicious_telnet_username("GET / HTTP/1.1"));
        assert!(is_suspicious_telnet_username("[A|\"0OLw>djp`T>& IAU"));

        // Valid Telnet usernames
        for valid in ["root", "admin", "ubnt", "anonymous", "IEUser@", "user.name", "user_1"] {
            assert_eq!(detect_non_telnet_probe(valid), None, "false positive for {}", valid);
            assert!(!is_suspicious_telnet_username(valid), "false positive username {}", valid);
        }
    }

    async fn run_telnet_client_payload(payload: &[u8]) -> AttackEvent {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let (event_tx, _) = broadcast::channel(16);
        let event_bus = Arc::new(EventBus::new(event_tx));
        let (write_tx, mut write_rx) = mpsc::unbounded_channel();
        let geoip = Arc::new(GeoIp::new(""));

        let server_task = tokio::spawn(async move {
            let (socket, peer) = listener.accept().await.unwrap();
            handle_telnet_session(socket, peer.ip().to_string(), 23, event_bus, write_tx, geoip).await;
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        client.write_all(payload).await.unwrap();
        client.shutdown().await.unwrap();

        server_task.await.unwrap();
        write_rx.recv().await.unwrap()
    }

    #[tokio::test]
    async fn test_telnet_rejects_http_probe() {
        let http_probe = b"GET / HTTP/1.1\r\nHost: 35.212.148.194:23\r\nUser-Agent: Mozilla/5.0\r\nAccept-Encoding: gzip\r\nConnection: close\r\n\r\n";
        let event = run_telnet_client_payload(http_probe).await;

        assert_eq!(event.service, "telnet");
        assert_eq!(event.username, None);
        assert_eq!(event.password, None);
        assert_eq!(event.payload, None);
        assert!(event.request.contains("HTTP probe"), "unexpected request: {}", event.request);
        assert!(event.request_size > 0);
    }

    #[tokio::test]
    async fn test_telnet_rejects_tls_probe() {
        let tls_probe = b"\x16\x03\x01\x00\x20[A|\"0OLw>djp\nrest\n";
        let event = run_telnet_client_payload(tls_probe).await;

        assert_eq!(event.service, "telnet");
        assert_eq!(event.username, None);
        assert_eq!(event.password, None);
        assert_eq!(event.payload, None);
        assert!(event.request.contains("TLS probe"), "unexpected request: {}", event.request);
        assert!(event.request_size > 0);
    }

    #[tokio::test]
    async fn test_telnet_accepts_real_session_with_iac() {
        let telnet_session = b"\xff\xfb\x1froot\r\nsecret123\r\nwhoami\r\nexit\r\n";
        let event = run_telnet_client_payload(telnet_session).await;

        assert_eq!(event.service, "telnet");
        assert_eq!(event.username.as_deref(), Some("root"));
        assert_eq!(event.password.as_deref(), Some("secret123"));
        let decoded = String::from_utf8(hex::decode(event.payload.unwrap()).unwrap()).unwrap();
        assert_eq!(decoded, "whoami\nexit");
    }
}
