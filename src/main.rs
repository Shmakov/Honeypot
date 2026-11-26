//! Honeypot - A modern network honeypot with real-time dashboard
//!
//! Captures attacks across 1024+ TCP ports, passive UDP listeners, HTTP/S, and ICMP:
//! - Live attack map with GeoIP City + ASN enrichment
//! - Stateful protocol emulation (SSH, Telnet, FTP, Redis, SMTP, MySQL, Postgres, RDP, HTTP APIs)
//! - Attack classification, IOC extraction, time-series wave detection, and analytics

mod classifier;
mod config;
mod db;
mod events;
mod geoip;
mod handlers;
#[cfg(test)]
mod integration_tests;
mod ioc;
mod limits;
mod web;

use anyhow::Result;
use std::sync::Arc;
use tracing::{info, Level};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

#[tokio::main]
async fn main() -> Result<()> {
    let _ = dotenvy::dotenv();

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

    let config = config::Config::load()?;
    info!("Configuration loaded");

    let db = db::Database::new(&config.database).await?;
    db.run_migrations().await?;
    info!("Database initialized");

    let geoip = Arc::new(geoip::GeoIp::new(
        &config.geoip.database,
        &config.geoip.asn_database,
    ));
    if geoip.is_available() {
        info!(
            "GeoIP enabled (ASN: {})",
            if geoip.is_asn_available() {
                "enabled"
            } else {
                "disabled"
            }
        );
    } else {
        info!("GeoIP disabled (database not found)");
    }

    let (event_tx, _) = tokio::sync::broadcast::channel(1000);
    let event_bus = events::EventBus::new(event_tx);

    let db_arc = Arc::new(db.clone());
    let write_tx = db::start_write_buffer(db_arc.clone(), config.limits.write_buffer_capacity);
    let limiter = limits::ConnectionLimiter::new(
        config.limits.max_connections_per_ip,
        config.limits.max_total_connections,
    );

    let handler_config = config.clone();
    let handler_event_bus = event_bus.clone();
    let handler_db = db.clone();
    let handler_geoip = geoip.clone();
    let handler_write_tx = write_tx.clone();
    let handler_limiter = limiter.clone();

    tokio::spawn(async move {
        if let Err(e) = handlers::start_all(
            &handler_config,
            handler_event_bus,
            handler_db,
            handler_geoip,
            handler_write_tx,
            handler_limiter,
        )
        .await
        {
            tracing::error!("Failed to start handlers: {}", e);
        }
    });
    info!("Protocol handlers starting...");

    web::start_background_tasks(db_arc, config.database.retention_days);

    let warm_db = db.clone();
    tokio::spawn(async move {
        web::warm_cache(&warm_db).await;
    });

    web::start_server(&config, event_bus, db, geoip, write_tx).await?;

    Ok(())
}
