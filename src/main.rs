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
use tracing_subscriber::FmtSubscriber;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .init();

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

    // Start protocol handlers in background
    tokio::spawn(async move {
        if let Err(e) = handlers::start_all(&handler_config, handler_event_bus, handler_db, handler_geoip).await {
            tracing::error!("Failed to start handlers: {}", e);
        }
    });
    info!("Protocol handlers starting...");

    // Warm the cache for default time ranges
    web::warm_cache(&db).await;

    // Start web server (blocking)
    web::start_server(&config, event_bus, db, geoip).await?;

    Ok(())
}
