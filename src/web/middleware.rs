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
const EXCLUDED_PATHS: &[&str] = &[
    "/robots.txt",
];

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
            
            // Get client IP from ConnectInfo extension
            let ip = request
                .extensions()
                .get::<ConnectInfo<SocketAddr>>()
                .map(|ConnectInfo(addr)| addr.ip().to_string())
                .unwrap_or_else(|| "unknown".to_string());
            
            // Check if this path should be logged
            let should_log = !EXCLUDED_PATHS.contains(&uri.as_str());
            
            // Log the request (non-blocking, spawn as background task)
            if should_log {
                let state_clone = state.clone();
                let method_clone = method.clone();
                let full_uri_clone = full_uri.clone();
                let headers_clone = headers.clone();
                let ip_clone = ip.clone();
                
                tokio::spawn(async move {
                    log_http_event(
                        &state_clone,
                        ip_clone,
                        &method_clone,
                        &full_uri_clone,
                        &headers_clone,
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

/// Log an HTTP request as an attack event
async fn log_http_event(
    state: &AppState,
    ip: String,
    method: &str,
    uri: &str,
    headers: &HeaderMap,
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
        80,
        request_str,
    );
    event.http_path = Some(uri.to_string());
    
    // Add User-Agent if present
    if let Some(ua) = user_agent {
        event = event.with_user_agent(ua);
    }
    
    // Add GeoIP info
    if let Some(loc) = state.geoip.lookup(&ip) {
        event = event.with_geo(loc.country_code, loc.latitude, loc.longitude);
    }
    
    if let Err(e) = state.db.insert_event(&event).await {
        tracing::warn!("Failed to store HTTP event: {}", e);
    }
    state.event_bus.publish(event);
    
    tracing::info!("HTTP {} {} from {}", method, uri, ip);
}
