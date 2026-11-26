//! Passive UDP honeypot listeners (zero-amplification: strictly capture-only, never replies)

use chrono::Utc;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::net::UdpSocket;
use tracing::{info, warn};

use crate::classifier;
use crate::config::Config;
use crate::db::{AttackEvent, WriteSender};
use crate::events::EventBus;
use crate::geoip::SharedGeoIp;

pub const UDP_PORTS: &[(u16, &str)] = &[
    (53, "dns-udp"),
    (123, "ntp-udp"),
    (161, "snmp-udp"),
    (1900, "ssdp-udp"),
    (5060, "sip-udp"),
    (11211, "memcached-udp"),
];

/// Simple per-IP 10-second sliding cap to protect against UDP packet floods.
struct UdpRateGuard {
    window_start: i64,
    counts: HashMap<String, u32>,
}

impl UdpRateGuard {
    fn new() -> Self {
        Self {
            window_start: Utc::now().timestamp(),
            counts: HashMap::new(),
        }
    }

    fn allow(&mut self, ip: &str) -> bool {
        let now = Utc::now().timestamp();
        if now - self.window_start >= 10 {
            self.window_start = now;
            self.counts.clear();
        }
        let c = self.counts.entry(ip.to_string()).or_insert(0);
        if *c >= 20 {
            return false;
        }
        *c += 1;
        true
    }
}

pub fn start_all(
    config: Arc<Config>,
    event_bus: Arc<EventBus>,
    write_tx: WriteSender,
    geoip: SharedGeoIp,
) {
    let guard = Arc::new(Mutex::new(UdpRateGuard::new()));

    for &(port, service) in UDP_PORTS {
        let config = config.clone();
        let event_bus = event_bus.clone();
        let write_tx = write_tx.clone();
        let geoip = geoip.clone();
        let guard = guard.clone();

        tokio::spawn(async move {
            let addr = format!("{}:{}", config.server.host, port);
            let socket = match UdpSocket::bind(&addr).await {
                Ok(s) => s,
                Err(e) => {
                    warn!("Cannot bind UDP {} ({}): {} - skipping", addr, service, e);
                    return;
                }
            };

            info!("Passive UDP listener started on port {} ({})", port, service);
            let mut buf = vec![0u8; 4096];

            loop {
                match socket.recv_from(&mut buf).await {
                    Ok((len, peer_addr)) => {
                        let ip = peer_addr.ip().to_string();
                        let allowed = guard
                            .lock()
                            .map(|mut g| g.allow(&ip))
                            .unwrap_or(false);
                        if !allowed {
                            continue;
                        }

                        let data = &buf[..len];
                        let summary = summarize_udp_packet(service, data, &ip, port);
                        let event = AttackEvent::new(ip, service.to_string(), port, summary)
                            .with_request_size(len as u32)
                            .with_payload(data.to_vec());

                        classifier::record_event(event, &geoip, &write_tx, &event_bus);
                    }
                    Err(e) => {
                        warn!("UDP recv error on port {}: {}", port, e);
                        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    }
                }
            }
        });
    }
}

fn summarize_udp_packet(service: &str, data: &[u8], ip: &str, port: u16) -> String {
    match service {
        "dns-udp" => {
            if let Some(qname) = parse_dns_qname(data) {
                return format!("DNS query {} from {}", qname, ip);
            }
        }
        "ntp-udp" => {
            if !data.is_empty() {
                let mode = data[0] & 0x07;
                let ver = (data[0] >> 3) & 0x07;
                return format!("NTP v{} mode {} ({} bytes) from {}", ver, mode, data.len(), ip);
            }
        }
        "snmp-udp" => {
            if let Some(comm) = extract_printable_token(data) {
                return format!("SNMP probe (community: {}) from {}", comm, ip);
            }
        }
        "sip-udp" | "ssdp-udp" | "memcached-udp" => {
            let text = String::from_utf8_lossy(data);
            if let Some(first_line) = text.lines().next() {
                let clean: String = first_line.trim().chars().take(120).collect();
                if !clean.is_empty() {
                    return format!("{} from {}", clean, ip);
                }
            }
        }
        _ => {}
    }
    format!("UDP packet ({} bytes) from {} to port {}", data.len(), ip, port)
}

fn parse_dns_qname(data: &[u8]) -> Option<String> {
    if data.len() < 13 {
        return None;
    }
    let mut idx = 12;
    let mut labels = Vec::new();
    while idx < data.len() {
        let len = data[idx] as usize;
        if len == 0 {
            break;
        }
        if len > 63 || idx + 1 + len > data.len() {
            return None;
        }
        let label = String::from_utf8_lossy(&data[idx + 1..idx + 1 + len]).into_owned();
        labels.push(label);
        idx += 1 + len;
    }
    if labels.is_empty() {
        None
    } else {
        Some(labels.join("."))
    }
}

fn extract_printable_token(data: &[u8]) -> Option<String> {
    // Simple ASN.1 OCTET STRING (tag 0x04) scan for SNMP community string
    for i in 0..data.len().saturating_sub(3) {
        if data[i] == 0x04 {
            let len = data[i + 1] as usize;
            if (1..=32).contains(&len) && i + 2 + len <= data.len() {
                let slice = &data[i + 2..i + 2 + len];
                if slice.iter().all(|b| (32..127).contains(b)) {
                    return Some(String::from_utf8_lossy(slice).into_owned());
                }
            }
        }
    }
    None
}
