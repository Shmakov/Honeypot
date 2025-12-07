//! FTP honeypot handler

use anyhow::Result;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
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
            debug!("Cannot bind FTP to {}: {}", addr, e);
            return Ok(());
        }
    };

    info!("FTP honeypot started on port {}", port);
    let banner = config.emulation.ftp_banner.clone();

    loop {
        match listener.accept().await {
            Ok((socket, peer_addr)) => {
                let ip = peer_addr.ip().to_string();
                let event_bus = event_bus.clone();
                let db = db.clone();
                let banner = banner.clone();
                let geoip = geoip.clone();

                tokio::spawn(async move {
                    handle_ftp_session(socket, ip, port, banner, event_bus, db, geoip).await;
                });
            }
            Err(e) => {
                warn!("FTP accept error on port {}: {}", port, e);
            }
        }
    }
}

async fn handle_ftp_session(
    socket: tokio::net::TcpStream,
    ip: String,
    port: u16,
    banner: String,
    event_bus: Arc<EventBus>,
    db: Arc<Database>,
    geoip: SharedGeoIp,
) {
    let (reader, mut writer) = socket.into_split();
    let mut reader = BufReader::new(reader);

    // Send welcome banner
    let _ = writer.write_all(format!("{}\r\n", banner).as_bytes()).await;

    let mut username = String::new();
    let mut password = String::new();
    let mut commands = Vec::new();

    // Read FTP commands with timeout
    let timeout = tokio::time::timeout(std::time::Duration::from_secs(60), async {
        let mut line = String::new();
        loop {
            line.clear();
            match reader.read_line(&mut line).await {
                Ok(0) => break, // Connection closed
                Ok(_) => {
                    let cmd = line.trim().to_string();
                    commands.push(cmd.clone());

                    let parts: Vec<&str> = cmd.splitn(2, ' ').collect();
                    let command = parts.get(0).map(|s| s.to_uppercase()).unwrap_or_default();
                    let arg = parts.get(1).map(|s| s.to_string()).unwrap_or_default();

                    match command.as_str() {
                        "USER" => {
                            username = arg;
                            let _ = writer.write_all(b"331 Password required\r\n").await;
                        }
                        "PASS" => {
                            password = arg;
                            let _ = writer.write_all(b"230 Login successful\r\n").await;
                            // After capturing credentials, we can close
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
                            let _ = writer.write_all(b"257 \"/\" is current directory\r\n").await;
                        }
                        "LIST" | "NLST" => {
                            let _ = writer.write_all(b"150 Opening data connection\r\n").await;
                            let _ = writer.write_all(b"226 Transfer complete\r\n").await;
                        }
                        "TYPE" => {
                            let _ = writer.write_all(b"200 Type set\r\n").await;
                        }
                        "PASV" => {
                            // Fake passive mode response
                            let _ = writer.write_all(b"227 Entering Passive Mode (127,0,0,1,100,100)\r\n").await;
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

    // Create event
    let request = if !username.is_empty() {
        format!("FTP login: {}:{} from {}", username, password, ip)
    } else {
        format!("FTP connection from {}", ip)
    };

    let mut event = AttackEvent::new(ip.clone(), "ftp".to_string(), port, request);
    
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
        warn!("Failed to store FTP event: {}", e);
    }
    event_bus.publish(event);
}
