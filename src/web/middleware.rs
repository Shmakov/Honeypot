//! Custom middleware for HTTP request logging
//!
//! This middleware logs all incoming HTTP requests to the database and broadcasts
//! them to the SSE event stream, replacing the need for individual wrapper functions.

use axum::{
    body::Body,
    extract::ConnectInfo,
    http::{HeaderMap, Request},
    response::Response,
};
use std::{net::SocketAddr, sync::Arc, task::{Context, Poll}};
use tower::{Layer, Service};
use futures::future::BoxFuture;

use crate::db::AttackEvent;
use super::AppState;

/// Paths to exclude from logging (internal endpoints)
const EXCLUDED_PATHS: &[&str] = &[];

/// Get the real client IP address, checking proxy headers first
/// Priority: X-Real-IP > X-Forwarded-For (first IP) > ConnectInfo
fn get_real_ip(headers: &HeaderMap, fallback_ip: &str) -> String {
    // Try X-Real-IP first (set by Caddy/nginx)
    if let Some(real_ip) = headers.get("x-real-ip") {
        if let Ok(ip) = real_ip.to_str() {
            let ip = ip.trim();
            if !ip.is_empty() {
                return ip.to_string();
            }
        }
    }
    
    // Try X-Forwarded-For (may contain chain of IPs, first is original client)
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
    
    // Fallback to direct connection IP
    fallback_ip.to_string()
}

/// Get the real port from X-Forwarded-Port header, defaulting to 80
fn get_real_port(headers: &HeaderMap) -> u16 {
    headers
        .get("x-forwarded-port")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(80)
}

/// Layer for HTTP request logging
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

/// Middleware service for HTTP request logging
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
            // Extract request info before passing to handler
            let method = request.method().to_string();
            let uri = request.uri().path().to_string();
            let query = request.uri().query().map(|q| format!("?{}", q)).unwrap_or_default();
            let full_uri = format!("{}{}", uri, query);
            let headers = request.headers().clone();
            
            // Get client IP - check proxy headers first, then fallback to socket
            let fallback_ip = request
                .extensions()
                .get::<ConnectInfo<SocketAddr>>()
                .map(|ConnectInfo(addr)| addr.ip().to_string())
                .unwrap_or_else(|| "unknown".to_string());
            let ip = get_real_ip(&headers, &fallback_ip);
            let port = get_real_port(&headers);
            
            // Check if this path should be logged
            let should_log = !EXCLUDED_PATHS.contains(&uri.as_str());
            
            // Log the request (non-blocking, spawn as background task)
            if should_log {
                let state_clone = state.clone();
                let method_clone = method.clone();
                let full_uri_clone = full_uri.clone();
                let headers_clone = headers.clone();
                let ip_clone = ip.clone();
                let request_size = calculate_request_size(&headers, &method, &full_uri);
                
                tokio::spawn(async move {
                    log_http_event(
                        &state_clone,
                        ip_clone,
                        port,
                        &method_clone,
                        &full_uri_clone,
                        &headers_clone,
                        request_size,
                    ).await;
                });
            }
            
            // Call the inner service
            inner.call(request).await
        })
    }
}

/// Format HTTP headers as a readable string
fn format_headers(headers: &HeaderMap) -> String {
    headers
        .iter()
        .map(|(name, value)| {
            format!("{}: {}", name.as_str(), value.to_str().unwrap_or("<binary>"))
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Calculate estimated request size from headers and request line
fn calculate_request_size(headers: &HeaderMap, method: &str, uri: &str) -> u32 {
    // Request line: "GET /path HTTP/1.1\r\n"
    let request_line_size = method.len() + 1 + uri.len() + 11; // " HTTP/1.1\r\n"
    
    // Headers size
    let headers_size: usize = headers.iter()
        .map(|(k, v)| k.as_str().len() + 2 + v.len() + 2) // "Key: Value\r\n"
        .sum();
    
    // Body size from Content-Length
    let body_size: usize = headers
        .get("content-length")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    
    (request_line_size + headers_size + 2 + body_size) as u32  // +2 for \r\n after headers
}

/// Log an HTTP request as an attack event
async fn log_http_event(
    state: &AppState,
    ip: String,
    port: u16,
    method: &str,
    uri: &str,
    headers: &HeaderMap,
    request_size: u32,
) {
    // Format request with method, path, and headers
    let headers_str = format_headers(headers);
    let request_str = format!("{} {}\n{}", method, uri, headers_str);
    
    // Extract User-Agent header
    let user_agent = headers
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    
    let mut event = AttackEvent::new(
        ip.clone(),
        "http".to_string(),
        port,
        request_str,
    );
    event.http_path = Some(uri.to_string());
    
    // Add User-Agent if present
    if let Some(ua) = user_agent {
        event = event.with_user_agent(ua);
    }
    
    // Set request size
    event = event.with_request_size(request_size);
    
    // Add GeoIP info
    if let Some(loc) = state.geoip.lookup(&ip) {
        event = event.with_geo(loc.country_code, loc.latitude, loc.longitude);
    }
    
    // Send to write buffer (non-blocking) and broadcast
    let _ = state.write_tx.send(event.clone());
    state.event_bus.publish(event);
    
    tracing::info!("HTTP {} {} from {}", method, uri, ip);
}
