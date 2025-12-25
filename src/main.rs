//! Honeypot - A modern network honeypot with real-time dashboard
//!
//! Captures attacks on 128 TCP ports and displays them with:
//! - Live attack map with GeoIP
//! - Protocol emulation (SSH, FTP, Telnet, etc.)
//! - Payload collection and analysis

mod config;
mod db;
mod events;
mod geoip;
mod handlers;
mod web;

use anyhow::Result;
use std::sync::Arc;
use tracing::{info, Level};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

#[tokio::main]
async fn main() -> Result<()> {
    // Load .env file if present (before any other initialization)
    let _ = dotenvy::dotenv();

    // Initialize logging based on LOG_FORMAT env var
    // Use LOG_FORMAT=gcp for structured GCP Cloud Logging
    let log_format = std::env::var("LOG_FORMAT").unwrap_or_default();
    if log_format == "gcp" {
        tracing_subscriber::registry()
            .with(tracing_subscriber::filter::LevelFilter::INFO)
            .with(tracing_stackdriver::layer())
            .init();
    } else {
        tracing_subscriber::fmt()
            .with_max_level(Level::INFO)
            .init();
    }

    info!("Starting Honeypot...");

    // Load configuration
    let config = config::Config::load()?;
    info!("Configuration loaded");

    // Initialize database
    let db = db::Database::new(&config.database).await?;
    db.run_migrations().await?;
    info!("Database initialized");

    // Initialize GeoIP
    let geoip = Arc::new(geoip::GeoIp::new(&config.geoip.database));
    if geoip.is_available() {
        info!("GeoIP enabled");
    } else {
        info!("GeoIP disabled (database not found)");
    }

    // Create event bus for broadcasting attacks
    let (event_tx, _) = tokio::sync::broadcast::channel(1000);
    let event_bus = events::EventBus::new(event_tx.clone());

    // Clone for handlers
    let handler_config = config.clone();
    let handler_event_bus = event_bus.clone();
    let handler_db = db.clone();
    let handler_geoip = geoip.clone();

    // Create write buffer for all event ingestion (shared between handlers and web)
    let db_arc = Arc::new(db.clone());
    let write_tx = db::start_write_buffer(db_arc.clone());
    let handler_write_tx = write_tx.clone();

    // Start protocol handlers in background
    tokio::spawn(async move {
        if let Err(e) = handlers::start_all(&handler_config, handler_event_bus, handler_db, handler_geoip, handler_write_tx).await {
            tracing::error!("Failed to start handlers: {}", e);
        }
    });
    info!("Protocol handlers starting...");

    // Start background tasks for rollup aggregation
    web::start_background_tasks(db_arc);

    // Warm the cache for default time ranges
    web::warm_cache(&db).await;

    // Start web server (blocking) - pass write_tx for HTTP event logging
    web::start_server(&config, event_bus, db, geoip, write_tx).await?;

    Ok(())
}
