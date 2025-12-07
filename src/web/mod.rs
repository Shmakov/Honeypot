//! Web server module

mod routes;
mod sse;

use anyhow::Result;
use axum::{
    body::Body,
    extract::{ConnectInfo, Request, State},
    http::StatusCode,
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{any, get},
    Router,
};
use std::{net::SocketAddr, sync::Arc};
use tower_http::services::ServeDir;
use tracing::info;

use crate::config::Config;
use crate::db::{AttackEvent, Database};
use crate::events::EventBus;

pub struct AppState {
    pub event_bus: EventBus,
    pub db: Database,
    pub config: Config,
}

/// Middleware to log all HTTP requests as attack events
async fn log_request(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    request: Request,
    next: Next,
) -> Response {
    let method = request.method().to_string();
    let uri = request.uri().to_string();
    let ip = addr.ip().to_string();
    
    // Only skip internal endpoints (static files, SSE stream, API)
    let should_log = !uri.starts_with("/static") 
        && !uri.starts_with("/events") 
        && !uri.starts_with("/api");
    
    if should_log {
        let request_str = format!("{} {}", method, uri);
        let mut event = AttackEvent::new(
            ip.clone(),
            "http".to_string(),
            80,
            request_str,
        );
        event.http_path = Some(uri.clone());
        
        // Log and broadcast
        if let Err(e) = state.db.insert_event(&event).await {
            tracing::warn!("Failed to store HTTP event: {}", e);
        }
        state.event_bus.publish(event);
        
        tracing::info!("HTTP {} {} from {}", method, uri, ip);
    }
    
    next.run(request).await
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
    
    let request_str = format!("{} {}", method, uri);
    let mut event = AttackEvent::new(
        ip.clone(),
        "http".to_string(),
        80,
        request_str,
    );
    event.http_path = Some(uri.clone());
    
    // Log and broadcast
    if let Err(e) = state.db.insert_event(&event).await {
        tracing::warn!("Failed to store HTTP event: {}", e);
    }
    state.event_bus.publish(event);
    
    tracing::info!("HTTP {} {} from {} -> 404", method, uri, ip);
    
    // Return a plausible 404 response
    (StatusCode::NOT_FOUND, "<!DOCTYPE html><html><head><title>404 Not Found</title></head><body><h1>Not Found</h1><p>The requested URL was not found on this server.</p></body></html>")
}

pub async fn start_server(config: &Config, event_bus: EventBus, db: Database) -> Result<()> {
    let state = Arc::new(AppState {
        event_bus,
        db,
        config: config.clone(),
    });

    let app = Router::new()
        // Pages
        .route("/", get(routes::index))
        .route("/stats", get(routes::stats_page))
        // SSE endpoint
        .route("/events", get(sse::events_handler))
        // API endpoints
        .route("/api/stats", get(routes::api_stats))
        .route("/api/recent", get(routes::api_recent))
        .route("/api/countries", get(routes::api_countries))
        // Static files
        .nest_service("/static", ServeDir::new("static"))
        // Catch-all for any other path - log as attack
        .fallback(any(catch_all))
        // Add logging middleware
        .layer(middleware::from_fn_with_state(state.clone(), log_request))
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
