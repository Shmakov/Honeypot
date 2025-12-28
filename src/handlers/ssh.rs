//! SSH honeypot handler using russh for proper protocol implementation
//! Accepts all authentication and provides a fake interactive shell to capture commands

use anyhow::Result;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, info};

use russh::server::{Auth, Config, Handler, Msg, Server, Session};
use russh::{Channel, ChannelId, Pty};
use russh::keys::{HashAlg, PrivateKey};

use crate::config::Config as AppConfig;
use crate::db::{AttackEvent, WriteSender};
use crate::events::EventBus;
use crate::geoip::SharedGeoIp;

/// Maximum line buffer size (4KB) to prevent memory exhaustion
const MAX_LINE_BUFFER: usize = 4096;
/// Maximum channels per session to prevent resource abuse
const MAX_CHANNELS_PER_SESSION: usize = 5;
/// Maximum commands before auto-disconnect
const MAX_COMMANDS: usize = 100;

/// SSH honeypot server
struct SshServer {
    event_bus: Arc<EventBus>,
    write_tx: WriteSender,
    geoip: SharedGeoIp,
}

impl russh::server::Server for SshServer {
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
            auth_method: None,
            channels: HashMap::new(),
        }
    }

    fn handle_session_error(&mut self, error: <Self::Handler as Handler>::Error) {
        debug!("SSH session error: {:?}", error);
    }
}

/// Channel state for tracking shell sessions
struct ChannelState {
    line_buffer: String,
    commands: Vec<String>,
    shell_active: bool,
}

impl Default for ChannelState {
    fn default() -> Self {
        Self {
            line_buffer: String::new(),
            commands: Vec::new(),
            shell_active: false,
        }
    }
}

/// SSH session handler - accepts all auth, provides fake shell
struct SshSession {
    ip: String,
    event_bus: Arc<EventBus>,
    write_tx: WriteSender,
    geoip: SharedGeoIp,
    username: Option<String>,
    auth_method: Option<String>,
    channels: HashMap<ChannelId, ChannelState>,
}

impl SshSession {
    /// Log credentials to write buffer and event bus
    fn log_auth_event(&self, username: &str, auth_detail: &str) {
        let request = format!("SSH auth ({}): {} from {}", 
            self.auth_method.as_deref().unwrap_or("unknown"), 
            auth_detail, 
            self.ip
        );
        
        let request_size = (username.len() + auth_detail.len() + 50) as u32;
        
        let mut event = AttackEvent::new(
            self.ip.clone(),
            "ssh".to_string(),
            22,
            request,
        );
        
        // For password auth, store credentials
        if self.auth_method.as_deref() == Some("password") {
            if let Some(password) = auth_detail.strip_prefix(&format!("{}:", username)) {
                event = event.with_credentials(username.to_string(), password.to_string());
            }
        }
        
        event = event.with_request_size(request_size);
        
        if let Some(loc) = self.geoip.lookup(&self.ip) {
            event = event.with_geo(loc.country_code, loc.latitude, loc.longitude);
        }
        
        let _ = self.write_tx.send(event.clone());
        self.event_bus.publish(event);
        
        info!("SSH auth ({}): {} from {}", 
            self.auth_method.as_deref().unwrap_or("unknown"),
            auth_detail, 
            self.ip
        );
    }

    /// Log commands when session ends or periodically
    fn log_commands(&self, channel: ChannelId) {
        if let Some(state) = self.channels.get(&channel) {
            if state.commands.is_empty() {
                return;
            }
            
            let commands_str = state.commands.join("\n");
            let request = format!("SSH shell commands from {} (user: {})", 
                self.ip, 
                self.username.as_deref().unwrap_or("unknown")
            );
            
            let request_size = commands_str.len() as u32;
            
            let mut event = AttackEvent::new(
                self.ip.clone(),
                "ssh".to_string(),
                22,
                request,
            );
            
            event = event.with_payload(commands_str.as_bytes().to_vec());
            event = event.with_request_size(request_size);
            
            if let Some(loc) = self.geoip.lookup(&self.ip) {
                event = event.with_geo(loc.country_code, loc.latitude, loc.longitude);
            }
            
            let _ = self.write_tx.send(event.clone());
            self.event_bus.publish(event);
            
            info!("SSH commands from {}: {:?}", self.ip, state.commands);
        }
    }

    /// Generate fake output for a command (static to avoid borrow checker issues)
    fn generate_fake_output(cmd: &str) -> String {
        let cmd_lower = cmd.trim().to_lowercase();
        let cmd_parts: Vec<&str> = cmd_lower.split_whitespace().collect();
        let base_cmd = cmd_parts.first().map(|s| *s).unwrap_or("");
        
        match base_cmd {
            "whoami" => "root\r\n".to_string(),
            "id" => "uid=0(root) gid=0(root) groups=0(root)\r\n".to_string(),
            "pwd" => "/root\r\n".to_string(),
            "hostname" => "honeypot\r\n".to_string(),
            "uname" => {
                if cmd_lower.contains("-a") {
                    "Linux honeypot 5.15.0-generic #1 SMP PREEMPT_DYNAMIC x86_64 GNU/Linux\r\n".to_string()
                } else {
                    "Linux\r\n".to_string()
                }
            }
            "uptime" => " 12:34:56 up 42 days,  3:21,  1 user,  load average: 0.00, 0.01, 0.05\r\n".to_string(),
            "w" => " 12:34:56 up 42 days,  3:21,  1 user,  load average: 0.00, 0.01, 0.05\r\nUSER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT\r\nroot     pts/0    -                12:34    0.00s  0.00s  0.00s w\r\n".to_string(),
            "ls" => {
                if cmd_lower.contains("/etc") {
                    "passwd\r\nshadow\r\nhosts\r\nresolv.conf\r\nssh\r\n".to_string()
                } else if cmd_lower.contains("-la") || cmd_lower.contains("-al") {
                    "total 32\r\ndrwx------  4 root root 4096 Dec 20 10:00 .\r\ndrwxr-xr-x 18 root root 4096 Dec 15 08:00 ..\r\n-rw-------  1 root root  512 Dec 20 10:00 .bash_history\r\n-rw-r--r--  1 root root 3106 Dec 15 08:00 .bashrc\r\ndrwxr-xr-x  2 root root 4096 Dec 15 08:00 .ssh\r\n".to_string()
                } else {
                    ".bash_history  .bashrc  .ssh\r\n".to_string()
                }
            }
            "cat" => {
                if cmd_lower.contains("/etc/passwd") {
                    "root:x:0:0:root:/root:/bin/bash\r\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\r\nbin:x:2:2:bin:/bin:/usr/sbin/nologin\r\nsys:x:3:3:sys:/dev:/usr/sbin/nologin\r\nnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\r\n".to_string()
                } else if cmd_lower.contains("/etc/shadow") {
                    "cat: /etc/shadow: Permission denied\r\n".to_string()
                } else {
                    "cat: No such file or directory\r\n".to_string()
                }
            }
            "ps" => "  PID TTY          TIME CMD\r\n    1 ?        00:00:03 systemd\r\n  942 ?        00:00:00 sshd\r\n 1337 pts/0    00:00:00 bash\r\n 1338 pts/0    00:00:00 ps\r\n".to_string(),
            "netstat" | "ss" => "Netstat exec failed: No such file or directory\r\n".to_string(),
            "ifconfig" => "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\r\n        inet 10.0.0.1  netmask 255.255.255.0  broadcast 10.0.0.255\r\n".to_string(),
            "ip" => {
                if cmd_lower.contains("addr") || cmd_lower.contains("a") {
                    "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536\r\n    inet 127.0.0.1/8 scope host lo\r\n2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500\r\n    inet 10.0.0.1/24 brd 10.0.0.255 scope global eth0\r\n".to_string()
                } else {
                    "Usage: ip [ OPTIONS ] OBJECT\r\n".to_string()
                }
            }
            "curl" | "wget" => {
                format!("bash: {}: command not found\r\n", base_cmd)
            }
            "cd" => String::new(), // Silent success
            "echo" => {
                let output = cmd.trim().strip_prefix("echo").unwrap_or("").trim();
                format!("{}\r\n", output)
            }
            "exit" | "quit" | "logout" => String::new(), // Handled specially
            "help" => "GNU bash, version 5.1.16\r\nType 'help' to see this list.\r\n".to_string(),
            "history" => "    1  ls -la\r\n    2  cat /etc/passwd\r\n    3  whoami\r\n".to_string(),
            "env" | "printenv" => "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\r\nHOME=/root\r\nUSER=root\r\nSHELL=/bin/bash\r\n".to_string(),
            "" => String::new(),
            _ => format!("bash: {}: command not found\r\n", base_cmd),
        }
    }

    /// Get the shell prompt
    fn get_prompt(&self) -> String {
        format!("root@honeypot:~# ")
    }
}

impl Handler for SshSession {
    type Error = anyhow::Error;

    /// Accept password authentication - capture credentials
    fn auth_password(
        &mut self,
        user: &str,
        password: &str,
    ) -> impl std::future::Future<Output = Result<Auth, Self::Error>> + Send {
        debug!("SSH auth_password: {}:{} from {}", user, password, self.ip);
        
        self.username = Some(user.to_string());
        self.auth_method = Some("password".to_string());
        
        // Log credentials
        self.log_auth_event(user, &format!("{}:{}", user, password));
        
        // Accept authentication - this is a honeypot!
        std::future::ready(Ok(Auth::Accept))
    }

    /// Accept "none" authentication
    fn auth_none(
        &mut self,
        user: &str,
    ) -> impl std::future::Future<Output = Result<Auth, Self::Error>> + Send {
        debug!("SSH auth_none from {} as '{}'", self.ip, user);
        self.username = Some(user.to_string());
        self.auth_method = Some("none".to_string());
        
        self.log_auth_event(user, user);
        
        // Accept - let them in!
        std::future::ready(Ok(Auth::Accept))
    }

    /// Accept public key authentication - log the key fingerprint
    fn auth_publickey(
        &mut self,
        user: &str,
        public_key: &russh::keys::PublicKey,
    ) -> impl std::future::Future<Output = Result<Auth, Self::Error>> + Send {
        let fingerprint = public_key.fingerprint(HashAlg::Sha256);
        debug!("SSH auth_publickey from {} as '{}' with key {}", self.ip, user, fingerprint);
        
        self.username = Some(user.to_string());
        self.auth_method = Some("publickey".to_string());
        
        self.log_auth_event(user, &format!("{}@{}", user, fingerprint));
        
        // Accept public key auth
        std::future::ready(Ok(Auth::Accept))
    }

    /// Accept public key offer (pre-signature check)
    fn auth_publickey_offered(
        &mut self,
        user: &str,
        public_key: &russh::keys::PublicKey,
    ) -> impl std::future::Future<Output = Result<Auth, Self::Error>> + Send {
        debug!("SSH publickey offered from {} as '{}': {}", self.ip, user, public_key.fingerprint(HashAlg::Sha256));
        // Accept the offered key - we'll log it when auth_publickey is called
        std::future::ready(Ok(Auth::Accept))
    }

    /// Accept session channel open
    fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        _session: &mut Session,
    ) -> impl std::future::Future<Output = Result<bool, Self::Error>> + Send {
        debug!("SSH channel_open_session from {}", self.ip);
        
        // Security: Limit channels per session
        if self.channels.len() >= MAX_CHANNELS_PER_SESSION {
            debug!("SSH channel limit reached for {}", self.ip);
            return std::future::ready(Ok(false));
        }
        
        self.channels.insert(channel.id(), ChannelState::default());
        std::future::ready(Ok(true))
    }

    /// Accept PTY request
    fn pty_request(
        &mut self,
        channel: ChannelId,
        _term: &str,
        _col_width: u32,
        _row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        _modes: &[(Pty, u32)],
        session: &mut Session,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send {
        debug!("SSH pty_request from {}", self.ip);
        session.channel_success(channel);
        std::future::ready(Ok(()))
    }

    /// Handle shell request - send welcome and prompt
    fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send {
        debug!("SSH shell_request from {}", self.ip);
        
        if let Some(state) = self.channels.get_mut(&channel) {
            state.shell_active = true;
        }
        
        // Send welcome banner
        let banner = format!(
            "Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-generic x86_64)\r\n\r\n * Documentation:  https://help.ubuntu.com\r\n * Management:     https://landscape.canonical.com\r\n * Support:        https://ubuntu.com/advantage\r\n\r\nLast login: {} from {}\r\n",
            chrono::Local::now().format("%a %b %d %H:%M:%S %Y"),
            self.ip
        );
        session.data(channel, banner.into());
        
        // Send prompt
        let prompt = self.get_prompt();
        session.data(channel, prompt.into());
        
        session.channel_success(channel);
        std::future::ready(Ok(()))
    }

    /// Handle exec request - single command execution
    fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send {
        let command = String::from_utf8_lossy(data).to_string();
        debug!("SSH exec_request from {}: {}", self.ip, command);
        
        // Store command
        if let Some(state) = self.channels.get_mut(&channel) {
            state.commands.push(command.clone());
        }
        
        // Generate and send fake output
        let output = Self::generate_fake_output(&command);
        if !output.is_empty() {
            session.data(channel, output.into());
        }
        
        // Log commands immediately for exec requests
        self.log_commands(channel);
        
        // Send exit status and close
        session.exit_status_request(channel, 0);
        session.channel_success(channel);
        session.close(channel);
        
        std::future::ready(Ok(()))
    }

    /// Handle data from client - interactive shell input
    fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send {
        let input = String::from_utf8_lossy(data);
        debug!("SSH data from {}: {:?}", self.ip, input);
        
        let mut should_close = false;
        
        if let Some(state) = self.channels.get_mut(&channel) {
            for ch in input.chars() {
                match ch {
                    '\r' | '\n' => {
                        // Echo newline
                        session.data(channel, "\r\n".to_string().into());
                        
                        let cmd = state.line_buffer.trim().to_string();
                        if !cmd.is_empty() {
                            state.commands.push(cmd.clone());
                            
                            // Check for exit commands
                            let cmd_lower = cmd.to_lowercase();
                            if cmd_lower == "exit" || cmd_lower == "quit" || cmd_lower == "logout" {
                                should_close = true;
                            } else {
                                // Generate and send fake output
                                let output = Self::generate_fake_output(&cmd);
                                if !output.is_empty() {
                                    session.data(channel, output.into());
                                }
                            }
                        }
                        
                        state.line_buffer.clear();
                        
                        if !should_close {
                            // Send new prompt
                            let prompt = "root@honeypot:~# ".to_string();
                            session.data(channel, prompt.into());
                        }
                    }
                    '\x7f' | '\x08' => {
                        // Backspace
                        if !state.line_buffer.is_empty() {
                            state.line_buffer.pop();
                            // Echo backspace sequence
                            session.data(channel, "\x08 \x08".to_string().into());
                        }
                    }
                    '\x03' => {
                        // Ctrl+C
                        session.data(channel, "^C\r\n".to_string().into());
                        state.line_buffer.clear();
                        let prompt = "root@honeypot:~# ".to_string();
                        session.data(channel, prompt.into());
                    }
                    '\x04' => {
                        // Ctrl+D - logout
                        session.data(channel, "\r\nlogout\r\n".to_string().into());
                        should_close = true;
                    }
                    _ if ch.is_ascii() && !ch.is_control() => {
                        // Regular character - add to buffer and echo
                        // Security: Limit line buffer size
                        if state.line_buffer.len() < MAX_LINE_BUFFER {
                            state.line_buffer.push(ch);
                            session.data(channel, ch.to_string().into());
                        }
                        // Silently ignore characters beyond limit
                    }
                    _ => {
                        // Ignore other control characters
                    }
                }
            }
            
            // Security: Limit command count
            if state.commands.len() >= MAX_COMMANDS {
                should_close = true;
            }
        }
        
        if should_close {
            self.log_commands(channel);
            session.exit_status_request(channel, 0);
            session.close(channel);
        }
        
        std::future::ready(Ok(()))
    }

    /// Handle channel close
    fn channel_close(
        &mut self,
        channel: ChannelId,
        _session: &mut Session,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send {
        debug!("SSH channel_close from {}", self.ip);
        self.log_commands(channel);
        self.channels.remove(&channel);
        std::future::ready(Ok(()))
    }

    /// Handle channel EOF
    fn channel_eof(
        &mut self,
        channel: ChannelId,
        _session: &mut Session,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send {
        debug!("SSH channel_eof from {}", self.ip);
        self.log_commands(channel);
        std::future::ready(Ok(()))
    }
}

/// Generate or load SSH host key
fn get_or_create_host_key(key_path: &str) -> Result<PrivateKey> {
    use std::path::Path;
    use std::fs;
    use russh::keys::Algorithm;
    
    let path = Path::new(key_path);
    
    if path.exists() {
        debug!("Loading SSH host key from {}", key_path);
        let key = PrivateKey::read_openssh_file(path)
            .map_err(|e| anyhow::anyhow!("Failed to load SSH key: {}", e))?;
        Ok(key)
    } else {
        info!("Generating new SSH host key at {}", key_path);
        
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        
        let mut rng = rand::thread_rng();
        let key = PrivateKey::random(&mut rng, Algorithm::Ed25519)
            .map_err(|e| anyhow::anyhow!("Failed to generate SSH key: {}", e))?;
        
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
    let key_path = "data/ssh_host_key";
    
    let host_key = match get_or_create_host_key(key_path) {
        Ok(key) => key,
        Err(e) => {
            tracing::warn!("Failed to load/generate SSH host key: {}. Generating in-memory key.", e);
            let mut rng = rand::thread_rng();
            PrivateKey::random(&mut rng, russh::keys::Algorithm::Ed25519)
                .expect("Failed to generate in-memory SSH key")
        }
    };

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
    
    info!("SSH honeypot starting on {} (fake shell enabled)", addr);
    
    server.run_on_address(ssh_config, &addr).await?;

    Ok(())
}
