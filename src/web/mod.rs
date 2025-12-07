//! Web server module

mod routes;
mod sse;

use anyhow::Result;
use axum::{
    routing::{get, get_service},
    Router,
};
use std::sync::Arc;
use tower_http::services::ServeDir;
use tracing::info;

use crate::config::Config;
use crate::db::Database;
use crate::events::EventBus;

pub struct AppState {
    pub event_bus: EventBus,
    pub db: Database,
    pub config: Config,
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
        .nest_service("/static", get_service(ServeDir::new("static")))
        .with_state(state);

    let addr = format!("{}:{}", config.server.host, config.server.http_port);
    info!("Web server starting on http://{}", addr);

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
