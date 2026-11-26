//! Custom middleware for HTTP request logging (with body & credential capture)

use axum::{
    body::Body,
    extract::ConnectInfo,
    http::{HeaderMap, Request},
    response::Response,
};
use futures::future::BoxFuture;
use std::{
    net::SocketAddr,
    sync::Arc,
    task::{Context, Poll},
};
use tower::{Layer, Service};

use super::decoys;
use super::AppState;
use crate::classifier;
use crate::db::AttackEvent;
use crate::ioc;

const EXCLUDED_PATHS: &[&str] = &[];
const MAX_CAPTURE_BODY: usize = 64 * 1024;

/// Get the real client IP address, checking proxy headers only when behind localhost proxy.
fn get_real_ip(headers: &HeaderMap, fallback_ip: &str) -> String {
    let trusted_proxy = fallback_ip == "127.0.0.1" || fallback_ip == "::1";
    if trusted_proxy {
        if let Some(real_ip) = headers.get("x-real-ip") {
            if let Ok(ip) = real_ip.to_str() {
                let ip = ip.trim();
                if !ip.is_empty() {
                    return ip.to_string();
                }
            }
        }

        if let Some(forwarded) = headers.get("x-forwarded-for") {
            if let Ok(ips) = forwarded.to_str() {
                if let Some(first_ip) = ips.split(',').next() {
                    let ip = first_ip.trim();
                    if !ip.is_empty() {
                        return ip.to_string();
                    }
                }
            }
        }
    }

    fallback_ip.to_string()
}

/// Get the real port from X-Forwarded-Port header when behind localhost proxy, defaulting to 80
fn get_real_port(headers: &HeaderMap, fallback_ip: &str) -> u16 {
    let trusted_proxy = fallback_ip == "127.0.0.1" || fallback_ip == "::1";
    if trusted_proxy {
        if let Some(port) = headers
            .get("x-forwarded-port")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.trim().parse().ok())
        {
            return port;
        }
    }
    80
}

#[derive(Clone)]
pub struct RequestLoggingLayer {
    state: Arc<AppState>,
}

impl RequestLoggingLayer {
    pub fn new(state: Arc<AppState>) -> Self {
        Self { state }
    }
}

impl<S> Layer<S> for RequestLoggingLayer {
    type Service = RequestLoggingMiddleware<S>;

    fn layer(&self, inner: S) -> Self::Service {
        RequestLoggingMiddleware {
            inner,
            state: self.state.clone(),
        }
    }
}

#[derive(Clone)]
pub struct RequestLoggingMiddleware<S> {
    inner: S,
    state: Arc<AppState>,
}

impl<S> Service<Request<Body>> for RequestLoggingMiddleware<S>
where
    S: Service<Request<Body>, Response = Response> + Send + Clone + 'static,
    S::Future: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: Request<Body>) -> Self::Future {
        let state = self.state.clone();
        let mut inner = self.inner.clone();

        Box::pin(async move {
            let method = request.method().to_string();
            let uri = request.uri().path().to_string();
            let query = request
                .uri()
                .query()
                .map(|q| format!("?{}", q))
                .unwrap_or_default();
            let full_uri = format!("{}{}", uri, query);
            let headers = request.headers().clone();

            let fallback_ip = request
                .extensions()
                .get::<ConnectInfo<SocketAddr>>()
                .map(|ConnectInfo(addr)| addr.ip().to_string())
                .unwrap_or_else(|| "unknown".to_string());
            let ip = get_real_ip(&headers, &fallback_ip);
            let port = get_real_port(&headers, &fallback_ip);

            let should_log = !EXCLUDED_PATHS.contains(&uri.as_str());

            // Buffer body for POST/PUT/PATCH so both logger & handler receive it
            let (request, captured_body) =
                if should_log && matches!(method.as_str(), "POST" | "PUT" | "PATCH") {
                    let (parts, body) = request.into_parts();
                    match axum::body::to_bytes(body, MAX_CAPTURE_BODY).await {
                        Ok(bytes) => {
                            let body_vec = if bytes.is_empty() {
                                None
                            } else {
                                Some(bytes.to_vec())
                            };
                            (Request::from_parts(parts, Body::from(bytes)), body_vec)
                        }
                        Err(_) => (Request::from_parts(parts, Body::empty()), None),
                    }
                } else {
                    (request, None)
                };

            if should_log {
                let state_clone = state.clone();
                let method_clone = method.clone();
                let full_uri_clone = full_uri.clone();
                let headers_clone = headers.clone();
                let ip_clone = ip.clone();
                let request_size = calculate_request_size(
                    &headers,
                    &method,
                    &full_uri,
                    captured_body.as_ref().map(|b| b.len()).unwrap_or(0),
                );

                tokio::spawn(async move {
                    log_http_event(
                        &state_clone,
                        ip_clone,
                        port,
                        &method_clone,
                        &full_uri_clone,
                        &headers_clone,
                        captured_body,
                        request_size,
                    );
                });
            }

            inner.call(request).await
        })
    }
}

fn format_headers(headers: &HeaderMap) -> String {
    headers
        .iter()
        .map(|(name, value)| {
            format!(
                "{}: {}",
                name.as_str(),
                value.to_str().unwrap_or("<binary>")
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn calculate_request_size(
    headers: &HeaderMap,
    method: &str,
    uri: &str,
    captured_body_len: usize,
) -> u32 {
    let request_line_size = method.len() + 1 + uri.len() + 11;
    let headers_size: usize = headers
        .iter()
        .map(|(k, v)| k.as_str().len() + 2 + v.len() + 2)
        .sum();
    let header_body_size: usize = headers
        .get("content-length")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let body_size = captured_body_len.max(header_body_size);

    (request_line_size + headers_size + 2 + body_size) as u32
}

fn extract_http_credentials(headers: &HeaderMap, body: Option<&[u8]>) -> Option<(String, String)> {
    // 1. Check Authorization: Basic ...
    if let Some(auth) = headers.get("authorization").and_then(|v| v.to_str().ok()) {
        if let Some(b64) = auth.strip_prefix("Basic ").or_else(|| auth.strip_prefix("basic ")) {
            if let Some(decoded) = ioc::decode_base64(b64.trim()) {
                let text = String::from_utf8_lossy(&decoded);
                if let Some((u, p)) = text.split_once(':') {
                    return Some((u.to_string(), p.to_string()));
                }
            }
        }
    }

    // 2. Check form-urlencoded login parameters in POST body
    let body_bytes = body?;
    let body_str = std::str::from_utf8(body_bytes).ok()?;
    let mut username: Option<String> = None;
    let mut password: Option<String> = None;

    for pair in body_str.split('&') {
        let Some((k, v)) = pair.split_once('=') else {
            continue;
        };
        let key = k.trim().to_ascii_lowercase();
        let val = percent_decode(v);
        match key.as_str() {
            "log" | "username" | "user" | "pma_username" | "email" => username = Some(val),
            "pwd" | "password" | "pass" | "pma_password" | "psd" => password = Some(val),
            _ => {}
        }
    }

    username.map(|u| (u, password.unwrap_or_default()))
}

fn percent_decode(input: &str) -> String {
    let replaced = input.replace('+', " ");
    let bytes = replaced.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(hi), Some(lo)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2])) {
                out.push((hi << 4) | lo);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[allow(clippy::too_many_arguments)]
fn log_http_event(
    state: &AppState,
    ip: String,
    port: u16,
    method: &str,
    uri: &str,
    headers: &HeaderMap,
    body: Option<Vec<u8>>,
    request_size: u32,
) {
    let headers_str = format_headers(headers);
    let request_str = format!("{} {}\n{}", method, uri, headers_str);

    let user_agent = headers
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let mut event = AttackEvent::new(ip.clone(), "http".to_string(), port, request_str);
    event.http_path = Some(uri.to_string());

    if let Some(ua) = user_agent {
        event = event.with_user_agent(ua);
    }

    if let Some((u, p)) = extract_http_credentials(headers, body.as_deref()) {
        event = event.with_credentials(u, p);
    }

    if let Some(b) = body {
        event = event.with_payload(b);
    }

    if decoys::is_canary_path(uri) {
        event = event.with_tag("canary-triggered");
    }

    event = event.with_request_size(request_size);

    classifier::record_event(event, &state.geoip, &state.write_tx, &state.event_bus);

    tracing::info!("HTTP {} {} from {}", method, uri, ip);
}
