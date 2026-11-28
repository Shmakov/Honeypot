//! SSH honeypot handler using russh with custom server banner, client banner capture,
//! stateful virtual filesystem shell, IOC extraction, and per-IP concurrency limits.

use anyhow::Result;
use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tracing::{debug, info, warn};

use russh::keys::{HashAlg, PrivateKey};
use russh::server::{
    Auth, ChannelOpenHandle, Config, Handler, Msg, PublicKeyOffer, Session, VerifiedPublicKey,
};
use russh::{Channel, ChannelId, ChannelOpenFailure, MethodKind, MethodSet, Pty, SshId};

use crate::classifier;
use crate::config::Config as AppConfig;
use crate::db::{AttackEvent, WriteSender};
use crate::events::EventBus;
use crate::geoip::SharedGeoIp;
use crate::handlers::shell_fs::FakeShell;
use crate::ioc::IocItem;
use crate::limits::{ConnectionLimiter, ConnectionPermit};

const MAX_LINE_BUFFER: usize = 4096;
const MAX_CHANNELS_PER_SESSION: usize = 5;
const MAX_COMMANDS: usize = 100;

struct ChannelState {
    line_buffer: String,
    commands: Vec<String>,
    iocs: Vec<IocItem>,
    canary_triggered: bool,
    shell_active: bool,
    logged: bool,
    shell: FakeShell,
}

impl ChannelState {
    fn new(hostname: &str, persona: &str, username: &str) -> Self {
        Self {
            line_buffer: String::new(),
            commands: Vec::new(),
            iocs: Vec::new(),
            canary_triggered: false,
            shell_active: false,
            logged: false,
            shell: FakeShell::new(hostname, persona, username),
        }
    }
}

struct PendingAuth {
    username: String,
    method: String,
    detail: String,
    password: Option<String>,
}

struct SshSession {
    ip: String,
    port: u16,
    service: String,
    hostname: String,
    persona: String,
    event_bus: Arc<EventBus>,
    write_tx: WriteSender,
    geoip: SharedGeoIp,
    username: Option<String>,
    client_banner: Option<String>,
    pending_auth: Option<PendingAuth>,
    channels: HashMap<ChannelId, ChannelState>,
    _permit: ConnectionPermit,
}

impl SshSession {
    fn flush_pending_auth(&mut self) {
        let Some(auth) = self.pending_auth.take() else {
            return;
        };
        let request = format!("SSH auth ({}): {} from {}", auth.method, auth.detail, self.ip);
        let request_size = (auth.username.len() + auth.detail.len() + 50) as u32;

        let mut event = AttackEvent::new(
            self.ip.clone(),
            self.service.clone(),
            self.port,
            request,
        );
        if let Some(pwd) = auth.password {
            event = event.with_credentials(auth.username, pwd);
        }
        if let Some(ref ua) = self.client_banner {
            event = event.with_user_agent(ua.clone());
        }
        event = event.with_request_size(request_size);

        classifier::record_event(event, &self.geoip, &self.write_tx, &self.event_bus);
        info!(
            "SSH auth ({}) on port {}: {} from {}",
            auth.method, self.port, auth.detail, self.ip
        );
    }

    fn log_commands(&mut self, channel: ChannelId) {
        let Some(state) = self.channels.get_mut(&channel) else {
            return;
        };
        if state.logged || state.commands.is_empty() {
            return;
        }
        state.logged = true;

        let commands_str = state.commands.join("\n");
        let request = format!(
            "SSH shell commands from {} (user: {})",
            self.ip,
            self.username.as_deref().unwrap_or("unknown")
        );
        let request_size = commands_str.len() as u32;

        let mut event = AttackEvent::new(
            self.ip.clone(),
            self.service.clone(),
            self.port,
            request,
        );
        event = event
            .with_payload(commands_str.as_bytes().to_vec())
            .with_request_size(request_size);

        if let Some(ref ua) = self.client_banner {
            event = event.with_user_agent(ua.clone());
        }
        if !state.iocs.is_empty() {
            event = event.with_iocs(state.iocs.clone());
        }
        if state.canary_triggered {
            event = event.with_tag("canary-triggered");
        }

        classifier::record_event(event, &self.geoip, &self.write_tx, &self.event_bus);
        info!(
            "SSH commands on port {} from {}: {:?}",
            self.port, self.ip, state.commands
        );
    }
}

impl Drop for SshSession {
    fn drop(&mut self) {
        self.flush_pending_auth();
        let ids: Vec<ChannelId> = self.channels.keys().copied().collect();
        for ch in ids {
            self.log_commands(ch);
        }
    }
}

impl Handler for SshSession {
    type Error = anyhow::Error;

    async fn auth_password(
        &mut self,
        user: &str,
        password: &str,
    ) -> Result<Auth, Self::Error> {
        debug!("SSH auth_password: {}:{} from {}", user, password, self.ip);
        self.username = Some(user.to_string());
        self.pending_auth = Some(PendingAuth {
            username: user.to_string(),
            method: "password".to_string(),
            detail: format!("{}:{}", user, password),
            password: Some(password.to_string()),
        });
        Ok(Auth::Accept)
    }

    async fn auth_none(&mut self, user: &str) -> Result<Auth, Self::Error> {
        debug!("SSH auth_none from {} as '{}' (prompting password/publickey)", self.ip, user);
        self.username = Some(user.to_string());
        Ok(Auth::Reject {
            proceed_with_methods: Some(MethodSet::from(
                &[MethodKind::Password, MethodKind::PublicKey][..],
            )),
            partial_success: false,
        })
    }

    async fn auth_publickey(
        &mut self,
        user: &str,
        key: VerifiedPublicKey<'_>,
    ) -> Result<Auth, Self::Error> {
        let fingerprint = key.public_key.fingerprint(HashAlg::Sha256);
        debug!(
            "SSH auth_publickey from {} as '{}' with key {}",
            self.ip, user, fingerprint
        );
        self.username = Some(user.to_string());
        self.pending_auth = Some(PendingAuth {
            username: user.to_string(),
            method: "publickey".to_string(),
            detail: format!("{}@{}", user, fingerprint),
            password: None,
        });
        Ok(Auth::Accept)
    }

    async fn auth_publickey_offered(
        &mut self,
        user: &str,
        offer: PublicKeyOffer<'_>,
    ) -> Result<Auth, Self::Error> {
        debug!(
            "SSH publickey offered from {} as '{}': {}",
            self.ip,
            user,
            offer.public_key.fingerprint(HashAlg::Sha256)
        );
        Ok(Auth::Accept)
    }

    async fn auth_succeeded(&mut self, session: &mut Session) -> Result<(), Self::Error> {
        let raw_sshid = String::from_utf8_lossy(session.remote_sshid())
            .trim()
            .to_string();
        if !raw_sshid.is_empty() {
            self.client_banner = Some(raw_sshid);
        }
        self.flush_pending_auth();
        Ok(())
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if self.channels.len() >= MAX_CHANNELS_PER_SESSION {
            debug!("SSH channel limit reached for {}", self.ip);
            let _ = reply.reject(ChannelOpenFailure::AdministrativelyProhibited).await;
            return Ok(());
        }

        let user = self.username.as_deref().unwrap_or("root");
        self.channels.insert(
            channel.id(),
            ChannelState::new(&self.hostname, &self.persona, user),
        );
        let _ = reply.accept().await;
        Ok(())
    }

    async fn pty_request(
        &mut self,
        channel: ChannelId,
        _term: &str,
        _col_width: u32,
        _row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        _modes: &[(Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let _ = session.channel_success(channel);
        Ok(())
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if let Some(state) = self.channels.get_mut(&channel) {
            state.shell_active = true;
            let banner = state.shell.welcome_banner(&self.ip);
            let _ = session.data(channel, banner);
            let prompt = state.shell.prompt();
            let _ = session.data(channel, prompt);
        }
        let _ = session.channel_success(channel);
        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let command = String::from_utf8_lossy(data).to_string();
        debug!("SSH exec_request from {}: {}", self.ip, command);

        let output = if let Some(state) = self.channels.get_mut(&channel) {
            state.commands.push(command.clone());
            let res = state.shell.execute_line(&command);
            if res.canary_triggered {
                state.canary_triggered = true;
            }
            for item in res.extracted_iocs {
                if !state.iocs.iter().any(|e| e == &item) {
                    state.iocs.push(item);
                }
            }
            res.output
        } else {
            String::new()
        };

        if !output.is_empty() {
            let _ = session.data(channel, output);
        }

        self.log_commands(channel);

        let _ = session.exit_status_request(channel, 0);
        let _ = session.channel_success(channel);
        let _ = session.close(channel);
        Ok(())
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let input = String::from_utf8_lossy(data);
        let mut should_close = false;

        if let Some(state) = self.channels.get_mut(&channel) {
            for ch in input.chars() {
                match ch {
                    '\r' | '\n' => {
                        let _ = session.data(channel, "\r\n");
                        let cmd = state.line_buffer.trim().to_string();
                        state.line_buffer.clear();

                        if !cmd.is_empty() {
                            state.commands.push(cmd.clone());
                            let res = state.shell.execute_line(&cmd);
                            if res.canary_triggered {
                                state.canary_triggered = true;
                            }
                            for item in res.extracted_iocs {
                                if !state.iocs.iter().any(|e| e == &item) {
                                    state.iocs.push(item);
                                }
                            }
                            if !res.output.is_empty() {
                                let _ = session.data(channel, res.output);
                            }
                            if res.should_exit {
                                should_close = true;
                                break;
                            }
                        }

                        if !should_close {
                            let prompt = state.shell.prompt();
                            let _ = session.data(channel, prompt);
                        }
                    }
                    '\x7f' | '\x08' => {
                        if !state.line_buffer.is_empty() {
                            state.line_buffer.pop();
                            let _ = session.data(channel, "\x08 \x08");
                        }
                    }
                    '\x03' => {
                        let _ = session.data(channel, "^C\r\n");
                        state.line_buffer.clear();
                        let prompt = state.shell.prompt();
                        let _ = session.data(channel, prompt);
                    }
                    '\x04' => {
                        let _ = session.data(channel, "\r\nlogout\r\n");
                        should_close = true;
                        break;
                    }
                    _ if ch.is_ascii() && !ch.is_control() => {
                        if state.line_buffer.len() < MAX_LINE_BUFFER {
                            state.line_buffer.push(ch);
                            let _ = session.data(channel, ch.to_string());
                        }
                    }
                    _ => {}
                }
            }

            if state.commands.len() >= MAX_COMMANDS {
                should_close = true;
            }
        }

        if should_close {
            self.log_commands(channel);
            let _ = session.exit_status_request(channel, 0);
            let _ = session.close(channel);
        }

        Ok(())
    }

    async fn channel_close(
        &mut self,
        channel: ChannelId,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.log_commands(channel);
        self.channels.remove(&channel);
        Ok(())
    }

    async fn channel_eof(
        &mut self,
        channel: ChannelId,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.log_commands(channel);
        Ok(())
    }
}

fn get_or_create_host_key(key_path: &str) -> Result<PrivateKey> {
    use russh::keys::Algorithm;
    use std::fs;
    use std::path::Path;

    let path = Path::new(key_path);
    if path.exists() {
        debug!("Loading SSH host key from {}", key_path);
        PrivateKey::read_openssh_file(path)
            .map_err(|e| anyhow::anyhow!("Failed to load SSH key: {}", e))
    } else {
        info!("Generating new SSH host key at {}", key_path);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut rng = rand::rng();
        let key = PrivateKey::random(&mut rng, Algorithm::Ed25519)
            .map_err(|e| anyhow::anyhow!("Failed to generate SSH key: {}", e))?;
        key.write_openssh_file(path, russh::keys::ssh_key::LineEnding::LF)
            .map_err(|e| anyhow::anyhow!("Failed to save SSH key: {}", e))?;
        Ok(key)
    }
}

pub fn build_ssh_config(banner: &str, host_key: PrivateKey) -> Arc<Config> {
    let clean_banner = banner.trim();
    let server_id = if clean_banner.starts_with("SSH-") {
        SshId::Standard(Cow::Owned(clean_banner.to_string()))
    } else {
        SshId::Standard(Cow::Borrowed("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4"))
    };

    Arc::new(Config {
        server_id,
        inactivity_timeout: Some(Duration::from_secs(300)),
        auth_rejection_time: Duration::from_secs(1),
        auth_rejection_time_initial: Some(Duration::from_secs(0)),
        keys: vec![host_key],
        ..Default::default()
    })
}

/// Start the SSH honeypot server on `port`
pub async fn start(
    port: u16,
    service: &str,
    config: Arc<AppConfig>,
    event_bus: Arc<EventBus>,
    write_tx: WriteSender,
    geoip: SharedGeoIp,
    limiter: Arc<ConnectionLimiter>,
) -> Result<()> {
    let key_path = "data/ssh_host_key";
    let host_key = match get_or_create_host_key(key_path) {
        Ok(key) => key,
        Err(e) => {
            warn!(
                "Failed to load/generate SSH host key: {}. Generating in-memory key.",
                e
            );
            let mut rng = rand::rng();
            PrivateKey::random(&mut rng, russh::keys::Algorithm::Ed25519)
                .expect("Failed to generate in-memory SSH key")
        }
    };

    let ssh_config = build_ssh_config(&config.emulation.ssh_banner, host_key);
    let addr = format!("{}:{}", config.server.host, port);
    let listener = match TcpListener::bind(&addr).await {
        Ok(l) => l,
        Err(e) => {
            warn!("Cannot bind SSH to {}: {} - skipping", addr, e);
            return Ok(());
        }
    };

    info!(
        "SSH honeypot started on {} ({}, banner: {})",
        addr, service, config.emulation.ssh_banner
    );

    let service = service.to_string();
    loop {
        match listener.accept().await {
            Ok((socket, peer_addr)) => {
                let ip = peer_addr.ip().to_string();
                let Some(permit) = limiter.try_acquire(&ip) else {
                    debug!("SSH connection rejected (rate/concurrency limit) from {}", ip);
                    drop(socket);
                    continue;
                };

                let ssh_config = ssh_config.clone();
                let service = service.clone();
                let hostname = config.emulation.hostname.clone();
                let persona = config.emulation.persona.clone();
                let event_bus = event_bus.clone();
                let write_tx = write_tx.clone();
                let geoip = geoip.clone();

                tokio::spawn(async move {
                    let handler = SshSession {
                        ip: ip.clone(),
                        port,
                        service,
                        hostname,
                        persona,
                        event_bus,
                        write_tx,
                        geoip,
                        username: None,
                        client_banner: None,
                        pending_auth: None,
                        channels: HashMap::new(),
                        _permit: permit,
                    };

                    match russh::server::run_stream(ssh_config, socket, handler).await {
                        Ok(session) => {
                            if let Err(e) = session.await {
                                debug!("SSH session ended for {}: {:?}", ip, e);
                            }
                        }
                        Err(e) => {
                            debug!("SSH handshake error from {}: {:?}", ip, e);
                        }
                    }
                });
            }
            Err(e) => {
                warn!("SSH accept error on port {}: {}", port, e);
            }
        }
    }
}
