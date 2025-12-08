//! Web server module

mod routes;
mod sse;

use anyhow::Result;
use axum::{
    body::Bytes,
    extract::{ConnectInfo, Request, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{any, get},
    Router,
};
use std::{net::SocketAddr, sync::Arc};
use tower_http::services::ServeDir;
use tracing::info;

use crate::config::Config;
use crate::db::{AttackEvent, Database};
use crate::events::EventBus;
use crate::geoip::SharedGeoIp;

pub struct AppState {
    pub event_bus: EventBus,
    pub db: Database,
    pub geoip: SharedGeoIp,
    pub public_url: String,
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
    body: Option<Bytes>,
) {
    // Format request with method, path, and headers
    let headers_str = format_headers(headers);
    let request_str = format!("{} {}\n{}", method, uri, headers_str);
    
    let mut event = AttackEvent::new(
        ip.clone(),
        "http".to_string(),
        80,
        request_str,
    );
    event.http_path = Some(uri.to_string());
    
    // Store body as payload if present
    if let Some(body_bytes) = body {
        if !body_bytes.is_empty() {
            event = event.with_payload(body_bytes.to_vec());
        }
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

/// Handler for homepage - serves page AND logs the request
async fn index_with_log(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let ip = addr.ip().to_string();
    log_http_event(&state, ip, "GET", "/", &headers, None).await;
    routes::index().await
}

/// Handler for stats page - serves page AND logs the request
async fn stats_with_log(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let ip = addr.ip().to_string();
    log_http_event(&state, ip, "GET", "/stats", &headers, None).await;
    routes::stats_page().await
}

/// Handler for all unknown paths - log as attack, echo request, redirect to home
async fn catch_all(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    request: Request,
) -> impl IntoResponse {
    let method = request.method().to_string();
    let uri = request.uri().to_string();
    let ip = addr.ip().to_string();
    let headers = request.headers().clone();
    
    // Extract body for POST/PUT/PATCH requests
    let body = if method == "POST" || method == "PUT" || method == "PATCH" {
        // Collect the body
        match axum::body::to_bytes(request.into_body(), 64 * 1024).await {
            Ok(bytes) => Some(bytes),
            Err(_) => None,
        }
    } else {
        None
    };
    
    // Format headers for display
    let headers_display = format_headers(&headers);
    let body_display = body.as_ref()
        .map(|b| String::from_utf8_lossy(b).to_string())
        .unwrap_or_default();
    
    log_http_event(&state, ip.clone(), &method, &uri, &headers, body).await;
    
    // Determine redirect URL
    let redirect_url = if state.public_url.is_empty() {
        "/".to_string()
    } else {
        format!("{}/", state.public_url.trim_end_matches('/'))
    };
    
    // Return echo response with meta redirect (200 OK to encourage bot interaction)
    let html = format!(r#"<!DOCTYPE html>
<html>
<head>
    <title>Request Received</title>
    <meta http-equiv="refresh" content="3;url={redirect_url}">
    <style>
        body {{ font-family: monospace; background: #1a1a2e; color: #e0e0e0; padding: 20px; }}
        h1 {{ color: #4ade80; }}
        pre {{ background: #0d0d1a; padding: 15px; border-radius: 8px; overflow-x: auto; white-space: pre-wrap; }}
        .label {{ color: #888; }}
        .redirect {{ color: #fbbf24; margin-top: 20px; }}
    </style>
</head>
<body>
    <h1>Request Echo</h1>
    <p class="label">Your IP:</p>
    <pre>{ip}</pre>
    <p class="label">Method:</p>
    <pre>{method}</pre>
    <p class="label">Path:</p>
    <pre>{uri}</pre>
    <p class="label">Headers:</p>
    <pre>{headers_display}</pre>
    {body_section}
    <p class="redirect">Redirecting to homepage in 3 seconds...</p>
    <script>setTimeout(function(){{ window.location.href = "{redirect_url}"; }}, 3000);</script>
</body>
</html>"#,
        redirect_url = redirect_url,
        ip = ip,
        method = method,
        uri = html_escape(&uri),
        headers_display = html_escape(&headers_display),
        body_section = if !body_display.is_empty() {
            format!(r#"<p class="label">Body:</p><pre>{}</pre>"#, html_escape(&body_display))
        } else {
            String::new()
        }
    );
    
    (StatusCode::OK, axum::response::Html(html))
}

/// Escape HTML special characters
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

pub async fn start_server(config: &Config, event_bus: EventBus, db: Database, geoip: SharedGeoIp) -> Result<()> {
    let state = Arc::new(AppState {
        event_bus,
        db,
        geoip,
        public_url: config.server.public_url.clone(),
    });

    let app = Router::new()
        // Pages (with logging)
        .route("/", get(index_with_log))
        .route("/stats", get(stats_with_log))
        // robots.txt (no logging)
        .route("/robots.txt", get(routes::robots_txt))
        // SSE endpoint (no logging - internal)
        .route("/events", get(sse::events_handler))
        // API endpoints (no logging - internal)
        .route("/api/stats", get(routes::api_stats))
        .route("/api/recent", get(routes::api_recent))
        .route("/api/countries", get(routes::api_countries))
        // Static files (no logging - assets)
        .nest_service("/static", ServeDir::new("static"))
        // Catch-all for any other path - log as attack
        .fallback(any(catch_all))
        .with_state(state);

    let addr = format!("{}:{}", config.server.host, config.server.http_port);
    info!("Web server starting on http://{}", addr);

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(
        listener, 
        app.into_make_service_with_connect_info::<SocketAddr>()
    ).await?;

    Ok(())
}
