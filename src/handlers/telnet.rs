//! Telnet honeypot handler

use anyhow::Result;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, BufWriter};
use tokio::net::TcpListener;
use tracing::{debug, info, warn};

use crate::config::Config;
use crate::db::{AttackEvent, Database};
use crate::events::EventBus;
use crate::geoip::SharedGeoIp;

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

async fn handle_telnet_session(
    socket: tokio::net::TcpStream,
    ip: String,
    port: u16,
    event_bus: Arc<EventBus>,
    db: Arc<Database>,
    geoip: SharedGeoIp,
) {
    debug!("Telnet session started from {}", ip);
    
    let (reader, writer) = socket.into_split();
    let mut reader = BufReader::new(reader);
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

    let timeout = tokio::time::timeout(std::time::Duration::from_secs(60), async {
        let mut line = String::new();
        let mut state = 0; // 0: waiting for user, 1: waiting for pass, 2: shell

        loop {
            line.clear();
            match reader.read_line(&mut line).await {
                Ok(0) => {
                    debug!("Telnet EOF from {} in state {}", ip, state);
                    break;
                }
                Ok(n) => {
                    debug!("Telnet received {} bytes from {} in state {}: {:?}", n, ip, state, line.trim());
                    let input = line.trim().to_string();
                    
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
                                    return;
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
                Err(e) => {
                    debug!("Telnet read error from {} in state {}: {}", ip, state, e);
                    break;
                }
            }
        }
    });

    let _ = timeout.await;

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
}
