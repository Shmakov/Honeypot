//! Web server module

mod middleware;
mod routes;
mod sse;

pub use routes::warm_cache;

use anyhow::Result;
use axum::{
    extract::{ConnectInfo, Request, State},
    http::{header, HeaderValue, Method, StatusCode},
    response::IntoResponse,
    routing::{any, get},
    Router,
};
use std::{net::SocketAddr, sync::Arc};
use tower_http::cors::CorsLayer;
use tower_http::set_header::SetResponseHeaderLayer;
use tracing::info;

use crate::config::Config;
use crate::db::Database;
use crate::events::EventBus;
use crate::geoip::SharedGeoIp;

pub struct AppState {
    pub event_bus: EventBus,
    pub db: Database,
    pub geoip: SharedGeoIp,
    pub public_url: String,
}

/// Format HTTP headers as a readable string
fn format_headers(headers: &axum::http::HeaderMap) -> String {
    headers
        .iter()
        .map(|(name, value)| {
            format!("{}: {}", name.as_str(), value.to_str().unwrap_or("<binary>"))
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Handler for static files
/// Security: Validates path to prevent directory traversal attacks
async fn static_files(
    axum::extract::Path(path): axum::extract::Path<String>,
) -> impl IntoResponse {
    // Build the file path
    let static_dir = std::path::Path::new("static");
    let requested_path = static_dir.join(&path);
    
    // Security: Canonicalize paths to resolve .. and symlinks checking
    // This effectively prevents directory traversal attacks
    let canonical_static = match static_dir.canonicalize() {
        Ok(p) => p,
        Err(_) => {
            return axum::response::Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(axum::body::Body::from("Server configuration error"))
                .unwrap();
        }
    };
    
    let canonical_requested = match requested_path.canonicalize() {
        Ok(p) => p,
        Err(_) => {
            // File doesn't exist or can't be accessed
            return axum::response::Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(axum::body::Body::from("Not Found"))
                .unwrap();
        }
    };
    
    // Security: Verify the canonical path starts with the canonical static directory
    if !canonical_requested.starts_with(&canonical_static) {
        tracing::warn!(
            "Path traversal attempt blocked: {} resolved to {:?}", 
            path, 
            canonical_requested
        );
        return axum::response::Response::builder()
            .status(StatusCode::FORBIDDEN)
            .body(axum::body::Body::from("Forbidden"))
            .unwrap();
    }
    
    // Safe to read the file now
    match tokio::fs::read(&canonical_requested).await {
        Ok(contents) => {
            // Determine content type from extension
            let content_type = if path.ends_with(".js") {
                "application/javascript"
            } else if path.ends_with(".css") {
                "text/css"
            } else if path.ends_with(".html") {
                "text/html"
            } else if path.ends_with(".svg") {
                "image/svg+xml"
            } else if path.ends_with(".png") {
                "image/png"
            } else if path.ends_with(".ico") {
                "image/x-icon"
            } else if path.ends_with(".txt") {
                "text/plain"
            } else {
                "application/octet-stream"
            };
            
            axum::response::Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", content_type)
                .body(axum::body::Body::from(contents))
                .unwrap()
        }
        Err(_) => {
            axum::response::Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(axum::body::Body::from("Not Found"))
                .unwrap()
        }
    }
}

/// Handler for all unknown paths - echo request, redirect to home
/// Note: Logging is handled by the middleware layer
async fn catch_all(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    request: Request,
) -> impl IntoResponse {
    let method = request.method().to_string();
    let uri = request.uri().to_string();
    let ip = addr.ip().to_string();
    let headers = request.headers().clone();
    
    // Extract body for POST/PUT/PATCH requests (for display purposes)
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
        uri = html_escape::encode_text(&uri),
        headers_display = html_escape::encode_text(&headers_display),
        body_section = if !body_display.is_empty() {
             format!(r#"<p class="label">Body:</p><pre>{}</pre>"#, html_escape::encode_text(&body_display))
        } else {
            String::new()
        }
    );
    
    (StatusCode::OK, axum::response::Html(html))
}

pub async fn start_server(config: &Config, event_bus: EventBus, db: Database, geoip: SharedGeoIp) -> Result<()> {
    let state = Arc::new(AppState {
        event_bus,
        db,
        geoip,
        public_url: config.server.public_url.clone(),
    });

    let app = Router::new()
        // Pages
        .route("/", get(routes::index))
        .route("/stats", get(routes::stats_page))
        // robots.txt
        .route("/robots.txt", get(routes::robots_txt))
        // SSE endpoint
        .route("/events", get(sse::events_handler))
        // API endpoints
        .route("/api/stats", get(routes::api_stats))
        .route("/api/recent", get(routes::api_recent))
        .route("/api/countries", get(routes::api_countries))
        .route("/api/locations", get(routes::api_locations))
        // Static files
        .route("/static/*path", get(static_files))
        // Catch-all for any other path
        .fallback(any(catch_all))
        .with_state(state.clone())
        // Request logging middleware - logs all HTTP requests
        .layer(middleware::RequestLoggingLayer::new(state))
        // Security: Add security headers
        .layer(SetResponseHeaderLayer::if_not_present(
            header::X_FRAME_OPTIONS,
            HeaderValue::from_static("DENY"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            header::REFERRER_POLICY,
            HeaderValue::from_static("strict-origin-when-cross-origin"),
        ))
        // Security: Same-origin only CORS - denies cross-origin API requests
        .layer(
            CorsLayer::new()
                .allow_methods([Method::GET])
                .allow_origin(tower_http::cors::AllowOrigin::exact(
                    HeaderValue::from_static("null"), // Only same-origin requests allowed
                ))
        );

    // Check if TLS is enabled
    if config.tls_enabled() {
        // Start HTTPS server
        let https_addr = format!("{}:{}", config.server.host, config.server.https_port);
        info!("Web server starting on https://{}", https_addr);
        
        let tls_config = axum_server::tls_rustls::RustlsConfig::from_pem_file(
            &config.server.tls_cert,
            &config.server.tls_key,
        ).await?;
        
        axum_server::bind_rustls(https_addr.parse()?, tls_config)
            .serve(app.into_make_service_with_connect_info::<SocketAddr>())
            .await?;
    } else {
        // Start HTTP server
        let addr = format!("{}:{}", config.server.host, config.server.http_port);
        info!("Web server starting on http://{}", addr);

        let listener = tokio::net::TcpListener::bind(&addr).await?;
        axum::serve(
            listener, 
            app.into_make_service_with_connect_info::<SocketAddr>()
        ).await?;
    }

    Ok(())
}
