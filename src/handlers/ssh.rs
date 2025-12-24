//! SSH honeypot handler using russh for proper protocol implementation
//! Captures real authentication credentials from attackers

use anyhow::Result;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, info, warn};

use russh::server::{Auth, Config, Handler, Server};
use russh::MethodKind;
use russh::keys::PrivateKey;

use crate::config::Config as AppConfig;
use crate::db::{AttackEvent, WriteSender};
use crate::events::EventBus;
use crate::geoip::SharedGeoIp;

/// SSH honeypot server
struct SshServer {
    event_bus: Arc<EventBus>,
    write_tx: WriteSender,
    geoip: SharedGeoIp,
}

impl Server for SshServer {
    type Handler = SshSession;

    fn new_client(&mut self, addr: Option<SocketAddr>) -> Self::Handler {
        let ip = addr.map(|a| a.ip().to_string()).unwrap_or_else(|| "unknown".to_string());
        debug!("SSH connection from {}", ip);
        
        SshSession {
            ip,
            event_bus: self.event_bus.clone(),
            write_tx: self.write_tx.clone(),
            geoip: self.geoip.clone(),
            username: None,
        }
    }

    fn handle_session_error(&mut self, error: <Self::Handler as Handler>::Error) {
        debug!("SSH session error: {:?}", error);
    }
}

/// SSH session handler - captures credentials
struct SshSession {
    ip: String,
    event_bus: Arc<EventBus>,
    write_tx: WriteSender,
    geoip: SharedGeoIp,
    username: Option<String>,
}

impl SshSession {
    /// Log credentials to write buffer and event bus
    fn log_credentials(&self, username: &str, password: &str) {
        let request = format!("SSH auth: {}:{} from {}", username, password, self.ip);
        
        // Calculate request size: SSH auth packet overhead + credentials
        // Approximate: username length + password length + SSH protocol overhead (~50 bytes)
        let request_size = (username.len() + password.len() + 50) as u32;
        
        let mut event = AttackEvent::new(
            self.ip.clone(),
            "ssh".to_string(),
            22,
            request,
        );
        
        event = event.with_credentials(username.to_string(), password.to_string());
        event = event.with_request_size(request_size);
        
        // Add GeoIP info
        if let Some(loc) = self.geoip.lookup(&self.ip) {
            event = event.with_geo(loc.country_code, loc.latitude, loc.longitude);
        }
        
        // Send to write buffer (non-blocking) and broadcast
        let _ = self.write_tx.send(event.clone());
        self.event_bus.publish(event);
        
        info!("SSH credentials: {}:{} from {}", username, password, self.ip);
    }
}

impl Handler for SshSession {
    type Error = anyhow::Error;

    /// Handle password authentication - capture and reject
    fn auth_password(
        &mut self,
        user: &str,
        password: &str,
    ) -> impl std::future::Future<Output = Result<Auth, Self::Error>> + Send {
        debug!("SSH auth_password: {}:{} from {}", user, password, self.ip);
        
        self.username = Some(user.to_string());
        
        // Log to write buffer and event stream (synchronous send to channel)
        self.log_credentials(user, password);
        
        // Always reject - this is a honeypot
        std::future::ready(Ok(Auth::Reject { proceed_with_methods: None, partial_success: false }))
    }

    /// Reject "none" auth and require password
    fn auth_none(
        &mut self,
        user: &str,
    ) -> impl std::future::Future<Output = Result<Auth, Self::Error>> + Send {
        debug!("SSH auth_none from {} as '{}'", self.ip, user);
        self.username = Some(user.to_string());
        
        // Reject none auth but allow password attempts
        std::future::ready(Ok(Auth::Reject { 
            proceed_with_methods: Some(russh::MethodSet::from(&[MethodKind::Password][..])),
            partial_success: false,
        }))
    }
}

/// Generate or load SSH host key
fn get_or_create_host_key(key_path: &str) -> Result<PrivateKey> {
    use std::path::Path;
    use std::fs;
    use russh::keys::Algorithm;
    
    let path = Path::new(key_path);
    
    if path.exists() {
        // Load existing key
        debug!("Loading SSH host key from {}", key_path);
        let key = PrivateKey::read_openssh_file(path)
            .map_err(|e| anyhow::anyhow!("Failed to load SSH key: {}", e))?;
        Ok(key)
    } else {
        // Generate new Ed25519 key
        info!("Generating new SSH host key at {}", key_path);
        
        // Ensure directory exists
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        
        // Generate Ed25519 key using the new russh 0.54 API
        let mut rng = rand::thread_rng();
        let key = PrivateKey::random(&mut rng, Algorithm::Ed25519)
            .map_err(|e| anyhow::anyhow!("Failed to generate SSH key: {}", e))?;
        
        // Save the key in OpenSSH format
        key.write_openssh_file(path, russh::keys::ssh_key::LineEnding::LF)
            .map_err(|e| anyhow::anyhow!("Failed to save SSH key: {}", e))?;
        
        Ok(key)
    }
}

/// Start the SSH honeypot server
pub async fn start(
    port: u16,
    config: Arc<AppConfig>,
    event_bus: Arc<EventBus>,
    write_tx: WriteSender,
    geoip: SharedGeoIp,
) -> Result<()> {
    // Determine key path (use data/ directory)
    let key_path = "data/ssh_host_key";
    
    let host_key = match get_or_create_host_key(key_path) {
        Ok(key) => key,
        Err(e) => {
            warn!("Failed to load/generate SSH host key: {}. Generating in-memory key.", e);
            // Fallback to in-memory Ed25519 key
            let mut rng = rand::thread_rng();
            PrivateKey::random(&mut rng, russh::keys::Algorithm::Ed25519)
                .expect("Failed to generate in-memory SSH key")
        }
    };

    // Configure the SSH server
    let ssh_config = Config {
        inactivity_timeout: Some(Duration::from_secs(300)),
        auth_rejection_time: Duration::from_secs(1),
        auth_rejection_time_initial: Some(Duration::from_secs(0)),
        keys: vec![host_key],
        ..Default::default()
    };

    let ssh_config = Arc::new(ssh_config);
    
    let mut server = SshServer {
        event_bus,
        write_tx,
        geoip,
    };

    let addr = format!("{}:{}", config.server.host, port);
    
    info!("SSH honeypot starting on {}", addr);
    
    // Run the russh server
    server.run_on_address(ssh_config, &addr).await?;

    Ok(())
}
