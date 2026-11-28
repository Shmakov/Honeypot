//! Lightweight HTTP API honeypot for high-value non-80 targets:
//! Docker daemon (:2375), Elasticsearch (:9200), and Ollama LLM API (:11434).

use anyhow::Result;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tracing::{debug, info, warn};

use crate::classifier;
use crate::config::Config;
use crate::db::{AttackEvent, WriteSender};
use crate::events::EventBus;
use crate::geoip::SharedGeoIp;
use crate::limits::{ConnectionLimiter, ConnectionPermit};

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
            warn!("Cannot bind HTTP-API {} to {}: {} - skipping", service, addr, e);
            return Ok(());
        }
    };

    info!("HTTP API honeypot started on port {} ({})", port, service);
    let service = service.to_string();

    loop {
        match listener.accept().await {
            Ok((socket, peer_addr)) => {
                let ip = peer_addr.ip().to_string();
                let Some(permit) = limiter.try_acquire(&ip) else {
                    debug!("HTTP-API connection rejected from {} on {}", ip, port);
                    drop(socket);
                    continue;
                };
                let service = service.clone();
                let hostname = config.emulation.hostname.clone();
                let event_bus = event_bus.clone();
                let write_tx = write_tx.clone();
                let geoip = geoip.clone();
                tokio::spawn(async move {
                    handle_http_api_session(
                        socket, ip, port, service, hostname, event_bus, write_tx, geoip, permit,
                    )
                    .await;
                });
            }
            Err(e) => warn!("HTTP-API accept error on port {}: {}", port, e),
        }
    }
}

fn build_json_response(service: &str, path: &str, hostname: &str) -> (u16, String) {
    match service {
        "docker" | "docker-tls" => {
            if path.contains("version") {
                (
                    200,
                    r#"{"Version":"24.0.7","ApiVersion":"1.43","Os":"linux","Arch":"amd64"}"#
                        .to_string(),
                )
            } else if path.contains("info") {
                (
                    200,
                    format!(
                        r#"{{"ID":"4F8A:12BC:DE34","Containers":3,"ContainersRunning":2,"Name":"{}"}}"#,
                        hostname
                    ),
                )
            } else {
                (
                    200,
                    r#"[{"Id":"a91b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b","Names":["/api-gateway"],"Image":"nginx:1.25-alpine","State":"running","Status":"Up 14 days"}]"#
                        .to_string(),
                )
            }
        }
        "ollama" => {
            if path.starts_with("/api/tags") || path.starts_with("/v1/models") {
                (
                    200,
                    r#"{"models":[{"name":"llama3.2:latest","model":"llama3.2:latest","size":2019393189},{"name":"qwen2.5-coder:7b","model":"qwen2.5-coder:7b","size":4683087332}]}"#
                        .to_string(),
                )
            } else if path == "/" {
                (200, "Ollama is running".to_string())
            } else {
                (
                    200,
                    r#"{"model":"llama3.2:latest","done":true,"response":"OK"}"#.to_string(),
                )
            }
        }
        "elasticsearch" => {
            if path == "/" || path.is_empty() {
                (
                    200,
                    format!(
                        r#"{{"name":"{}","cluster_name":"prod-logs","version":{{"number":"8.11.3"}},"tagline":"You Know, for Search"}}"#,
                        hostname
                    ),
                )
            } else if path.contains("_cat/indices") {
                (
                    200,
                    r#"[{"health":"green","status":"open","index":"users-2026","docs.count":"14280"}]"#
                        .to_string(),
                )
            } else {
                (200, r#"{"acknowledged":true}"#.to_string())
            }
        }
        _ => (200, r#"{"status":"ok"}"#.to_string()),
    }
}

fn find_header_body_split(raw: &[u8]) -> Option<(usize, usize)> {
    if let Some(pos) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
        Some((pos, pos + 4))
    } else if let Some(pos) = raw.windows(2).position(|w| w == b"\n\n") {
        Some((pos, pos + 2))
    } else {
        None
    }
}

/// Parse an HTTP/1.x request into `(path, user_agent, optional_body)`.
/// Returns `None` for non-HTTP / TLS / binary probes so binary bytes never pollute `http_path`.
fn parse_http_request(raw: &[u8]) -> Option<(String, Option<String>, Option<Vec<u8>>)> {
    const METHODS: &[&str] = &[
        "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "CONNECT", "TRACE",
    ];

    let (hdr_end, body_start) = find_header_body_split(raw).unwrap_or((raw.len(), raw.len()));
    let header_text = std::str::from_utf8(&raw[..hdr_end]).ok()?;
    let first_line = header_text.lines().next()?.trim_end_matches('\r');
    let mut parts = first_line.split_whitespace();
    let method = parts.next()?;
    let path = parts.next()?;
    let version = parts.next()?;

    if !METHODS.contains(&method) || !version.starts_with("HTTP/") {
        return None;
    }
    if path.is_empty()
        || path.len() > 2048
        || !path.bytes().all(|b| (0x21..=0x7e).contains(&b))
    {
        return None;
    }

    let user_agent = header_text
        .lines()
        .skip(1)
        .find(|l| l.to_ascii_lowercase().starts_with("user-agent:"))
        .and_then(|l| l.split_once(':'))
        .map(|(_, v)| v.trim())
        .filter(|v| !v.is_empty() && v.bytes().all(|b| (0x20..=0x7e).contains(&b)))
        .map(|v| v.to_string());

    let body = if body_start < raw.len() {
        Some(raw[body_start..].to_vec())
    } else {
        None
    };

    Some((path.to_string(), user_agent, body))
}

#[allow(clippy::too_many_arguments)]
async fn handle_http_api_session(
    mut socket: tokio::net::TcpStream,
    ip: String,
    port: u16,
    service: String,
    hostname: String,
    event_bus: Arc<EventBus>,
    write_tx: WriteSender,
    geoip: SharedGeoIp,
    _permit: ConnectionPermit,
) {
    let mut buf = vec![0u8; 16384];
    let read_res = tokio::time::timeout(
        std::time::Duration::from_secs(15),
        socket.read(&mut buf),
    )
    .await;

    let raw = match read_res {
        Ok(Ok(n)) if n > 0 => buf[..n].to_vec(),
        _ => {
            let event = AttackEvent::new(
                ip.clone(),
                service,
                port,
                format!("Connection from {} to port {}", ip, port),
            );
            classifier::record_event(event, &geoip, &write_tx, &event_bus);
            return;
        }
    };

    let Some((path, user_agent, body)) = parse_http_request(&raw) else {
        let req_desc = format!(
            "Non-HTTP probe ({} bytes) from {} to port {}",
            raw.len(),
            ip,
            port
        );
        let event = AttackEvent::new(ip, service, port, req_desc)
            .with_request_size(raw.len() as u32)
            .with_payload(raw);
        classifier::record_event(event, &geoip, &write_tx, &event_bus);
        return;
    };

    let (status, resp_body) = build_json_response(&service, &path, &hostname);
    let content_type = if resp_body.starts_with('{') || resp_body.starts_with('[') {
        "application/json"
    } else {
        "text/plain"
    };
    let http_resp = format!(
        "HTTP/1.1 {} OK\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        status,
        content_type,
        resp_body.len(),
        resp_body
    );
    let _ = socket.write_all(http_resp.as_bytes()).await;

    let (hdr_end, _) = find_header_body_split(&raw).unwrap_or((raw.len(), raw.len()));
    let header_text = String::from_utf8_lossy(&raw[..hdr_end]).into_owned();

    let mut event = AttackEvent::new(ip, service, port, header_text)
        .with_request_size(raw.len() as u32);
    if let Some(b) = body {
        event = event.with_payload(b);
    }
    event.http_path = Some(path);
    if let Some(ua) = user_agent {
        event = event.with_user_agent(ua);
    }

    classifier::record_event(event, &geoip, &write_tx, &event_bus);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_tls_and_splits_http_headers_from_body() {
        let tls = b"\x16\x03\x01\x00\x20\x01\x00\x00\x1c\x03\x03abcd";
        assert!(parse_http_request(tls).is_none());

        let http = b"POST /api/chat HTTP/1.1\r\nHost: 127.0.0.1:11434\r\nUser-Agent: test/1.0\r\n\r\n{\"model\":\"llama3\"}";
        let (path, ua, body) = parse_http_request(http).unwrap();
        assert_eq!(path, "/api/chat");
        assert_eq!(ua.as_deref(), Some("test/1.0"));
        assert_eq!(body.as_deref(), Some(b"{\"model\":\"llama3\"}".as_slice()));
    }
}
