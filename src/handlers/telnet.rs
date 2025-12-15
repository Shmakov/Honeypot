//! Telnet honeypot handler with proper IAC negotiation

use anyhow::Result;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufWriter};
use tokio::net::TcpListener;
use tracing::{debug, info, warn};

use crate::config::Config;
use crate::db::{AttackEvent, Database};
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

pub async fn start(
    port: u16,
    config: Arc<Config>,
    event_bus: Arc<EventBus>,
    db: Arc<Database>,
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
                let db = db.clone();
                let geoip = geoip.clone();

                tokio::spawn(async move {
                    handle_telnet_session(socket, ip, port, event_bus, db, geoip).await;
                });
            }
            Err(e) => {
                warn!("Telnet accept error on port {}: {}", port, e);
            }
        }
    }
}

/// Read a line from the socket, filtering out telnet IAC commands
async fn read_telnet_line(socket: &mut tokio::net::tcp::OwnedReadHalf, ip: &str) -> Option<String> {
    let mut result = Vec::new();
    let mut buf = [0u8; 1];
    let mut in_iac = false;
    let mut in_subneg = false;
    let mut iac_cmd = 0u8;
    
    let timeout = tokio::time::timeout(std::time::Duration::from_secs(30), async {
        loop {
            match socket.read(&mut buf).await {
                Ok(0) => {
                    debug!("Telnet EOF from {}", ip);
                    return None;
                }
                Ok(_) => {
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
                                result.push(255);
                                in_iac = false;
                            }
                            WILL | WONT | DO | DONT => {
                                // These are followed by one option byte
                                iac_cmd = byte;
                                in_iac = false;
                                // Read and discard the option byte
                                if socket.read(&mut buf).await.is_err() {
                                    return None;
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
                    
                    // Regular character
                    if byte >= 32 && byte < 127 {
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
    
    match timeout.await {
        Ok(line) => line,
        Err(_) => {
            debug!("Telnet read timeout from {}", ip);
            None
        }
    }
}

async fn handle_telnet_session(
    socket: tokio::net::TcpStream,
    ip: String,
    port: u16,
    event_bus: Arc<EventBus>,
    db: Arc<Database>,
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

    // State machine: 0=login, 1=password, 2=shell
    let mut state = 0;
    
    let session_timeout = tokio::time::timeout(std::time::Duration::from_secs(120), async {
        loop {
            let input = match read_telnet_line(&mut reader, &ip).await {
                Some(line) => line,
                None => break,
            };
            
            debug!("Telnet received from {} in state {}: {:?}", ip, state, input);
            
            match state {
                0 => {
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
                1 => {
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
                2 => {
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
                _ => break,
            }
        }
    });

    let _ = session_timeout.await;

    // Create event
    let request = if !username.is_empty() {
        format!("Telnet login: {}:{} from {}", username, password, ip)
    } else {
        format!("Telnet connection from {}", ip)
    };

    let mut event = AttackEvent::new(ip.clone(), "telnet".to_string(), port, request);
    
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

    if let Err(e) = db.insert_event(&event).await {
        warn!("Failed to store Telnet event: {}", e);
    }
    event_bus.publish(event);
    debug!("Telnet session ended from {}", ip);
}
