//! SSH honeypot handler using russh for proper protocol implementation
//! Captures real authentication credentials from attackers

use anyhow::Result;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, info, warn};

use russh::server::{Auth, Config, Handler, Server};
use russh_keys::key::KeyPair;

use crate::config::Config as AppConfig;
use crate::db::{AttackEvent, Database};
use crate::events::EventBus;
use crate::geoip::SharedGeoIp;

/// SSH honeypot server
struct SshServer {
    event_bus: Arc<EventBus>,
    db: Arc<Database>,
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
            db: self.db.clone(),
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
    db: Arc<Database>,
    geoip: SharedGeoIp,
    username: Option<String>,
}

impl SshSession {
    /// Log credentials to database and event bus
    async fn log_credentials(&self, username: &str, password: &str) {
        let request = format!("SSH auth: {}:{} from {}", username, password, self.ip);
        
        let mut event = AttackEvent::new(
            self.ip.clone(),
            "ssh".to_string(),
            22,
            request,
        );
        
        event = event.with_credentials(username.to_string(), password.to_string());
        
        // Add GeoIP info
        if let Some(loc) = self.geoip.lookup(&self.ip) {
            event = event.with_geo(loc.country_code, loc.latitude, loc.longitude);
        }
        
        if let Err(e) = self.db.insert_event(&event).await {
            warn!("Failed to store SSH event: {}", e);
        }
        self.event_bus.publish(event);
        
        info!("SSH credentials: {}:{} from {}", username, password, self.ip);
    }
}

use async_trait::async_trait;

#[async_trait]
impl Handler for SshSession {
    type Error = anyhow::Error;

    /// Handle password authentication - capture and reject
    async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth, Self::Error> {
        debug!("SSH auth_password: {}:{} from {}", user, password, self.ip);
        
        self.username = Some(user.to_string());
        
        // Log to database and event stream
        self.log_credentials(user, password).await;
        
        // Always reject - this is a honeypot
        Ok(Auth::Reject { proceed_with_methods: None })
    }

    /// Reject "none" auth and require password
    async fn auth_none(&mut self, user: &str) -> Result<Auth, Self::Error> {
        debug!("SSH auth_none from {} as '{}'", self.ip, user);
        self.username = Some(user.to_string());
        
        // Reject none auth but allow password attempts
        Ok(Auth::Reject { 
            proceed_with_methods: Some(russh::MethodSet::PASSWORD) 
        })
    }
}

/// Generate or load SSH host key
fn get_or_create_host_key(key_path: &str) -> Result<KeyPair> {
    use std::path::Path;
    use std::fs;
    
    let path = Path::new(key_path);
    
    if path.exists() {
        // Load existing key
        debug!("Loading SSH host key from {}", key_path);
        let key = russh_keys::load_secret_key(key_path, None)?;
        Ok(key)
    } else {
        // Generate new Ed25519 key
        info!("Generating new SSH host key at {}", key_path);
        
        // Ensure directory exists
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        
        // Generate Ed25519 key (returns KeyPair directly in russh-keys 0.46)
        let key = KeyPair::generate_ed25519();
        
        // Save the key in PKCS8 PEM format
        let mut file = fs::File::create(key_path)?;
        russh_keys::encode_pkcs8_pem(&key, &mut file)?;
        
        Ok(key)
    }
}

/// Start the SSH honeypot server
pub async fn start(
    port: u16,
    config: Arc<AppConfig>,
    event_bus: Arc<EventBus>,
    db: Arc<Database>,
    geoip: SharedGeoIp,
) -> Result<()> {
    // Determine key path (use data/ directory)
    let key_path = "data/ssh_host_key";
    
    let host_key = match get_or_create_host_key(key_path) {
        Ok(key) => key,
        Err(e) => {
            warn!("Failed to load/generate SSH host key: {}. Generating in-memory key.", e);
            // Fallback to in-memory Ed25519 key
            KeyPair::generate_ed25519()
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
        db,
        geoip,
    };

    let addr = format!("{}:{}", config.server.host, port);
    
    info!("SSH honeypot starting on {}", addr);
    
    // Run the russh server
    server.run_on_address(ssh_config, &addr).await?;

    Ok(())
}
