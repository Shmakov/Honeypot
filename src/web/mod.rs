//! Web server module

mod routes;
mod sse;

use anyhow::Result;
use axum::{
    extract::{ConnectInfo, Request, State},
    http::StatusCode,
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
}

/// Log an HTTP request as an attack event
async fn log_http_event(state: &AppState, ip: String, method: &str, uri: &str) {
    let request_str = format!("{} {}", method, uri);
    let mut event = AttackEvent::new(
        ip.clone(),
        "http".to_string(),
        80,
        request_str,
    );
    event.http_path = Some(uri.to_string());
    
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
) -> impl IntoResponse {
    let ip = addr.ip().to_string();
    log_http_event(&state, ip, "GET", "/").await;
    routes::index().await
}

/// Handler for stats page - serves page AND logs the request
async fn stats_with_log(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> impl IntoResponse {
    let ip = addr.ip().to_string();
    log_http_event(&state, ip, "GET", "/stats").await;
    routes::stats_page().await
}

/// Handler for all unknown paths - log as attack and return fake response
async fn catch_all(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    request: Request,
) -> impl IntoResponse {
    let method = request.method().to_string();
    let uri = request.uri().to_string();
    let ip = addr.ip().to_string();
    
    log_http_event(&state, ip, &method, &uri).await;
    
    // Return a plausible 404 response
    (StatusCode::NOT_FOUND, "<!DOCTYPE html><html><head><title>404 Not Found</title></head><body><h1>Not Found</h1><p>The requested URL was not found on this server.</p></body></html>")
}

pub async fn start_server(config: &Config, event_bus: EventBus, db: Database, geoip: SharedGeoIp) -> Result<()> {
    let state = Arc::new(AppState {
        event_bus,
        db,
        geoip,
    });

    let app = Router::new()
        // Pages (with logging)
        .route("/", get(index_with_log))
        .route("/stats", get(stats_with_log))
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
