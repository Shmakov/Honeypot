//! HTTP routes with response caching

use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{Html, IntoResponse, Response},
    Json,
};
use cached::proc_macro::cached;
use chrono::Datelike;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use super::AppState;
use crate::db::{AttackEvent, CountryStat, CredentialStat, Database, IpStat, LocationStat, StatsResponse};

/// API error response
#[derive(Debug, Serialize)]
pub struct ApiError {
    error: String,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (StatusCode::BAD_REQUEST, Json(self)).into_response()
    }
}

/// Serve the main dashboard page
pub async fn index() -> Html<&'static str> {
    Html(include_str!("../../static/index.html"))
}

/// Serve the statistics page
pub async fn stats_page() -> Html<&'static str> {
    Html(include_str!("../../static/stats.html"))
}

/// Serve robots.txt
pub async fn robots_txt() -> &'static str {
    include_str!("../../static/robots.txt")
}

#[derive(Debug, Deserialize)]
pub struct StatsQuery {
    #[serde(default = "default_hours")]
    pub hours: i64,
}

fn default_hours() -> i64 {
    720 // Default to 30 days (matches stats page default selection)
}

/// Allowed time ranges (in hours) - matches frontend dropdown options
/// 24h = yesterday rollup data
pub const ALLOWED_HOURS: [i64; 4] = [24, 168, 720, 8760];

/// Validate hours parameter - returns Ok(hours) or Err with API error
fn validate_hours(hours: i64) -> Result<i64, ApiError> {
    if ALLOWED_HOURS.contains(&hours) {
        Ok(hours)
    } else {
        Err(ApiError {
            error: format!("Invalid hours value '{}'. Allowed: 24, 168, 720, 8760", hours),
        })
    }
}

/// Cached stats query - 5 minute TTL (uses hybrid rollup + live)
#[cached(time = 300, key = "i64", convert = r#"{ hours }"#)]
async fn get_cached_stats(hours: i64, db: Database) -> StatsResponse {
    db.get_stats_hybrid(hours).await.unwrap_or_else(|_| StatsResponse {
        total: 0,
        services: vec![],
        credentials: vec![],
        paths: vec![],
    })
}

/// Cached countries query - 5 minute TTL
#[cached(time = 300, key = "i64", convert = r#"{ hours }"#)]
async fn get_cached_countries(hours: i64, db: Database) -> Vec<CountryStat> {
    db.get_country_stats(hours).await.unwrap_or_default()
}

/// Cached locations query - 5 minute TTL
#[cached(time = 300, key = "i64", convert = r#"{ hours }"#)]
async fn get_cached_locations(hours: i64, db: Database) -> Vec<LocationStat> {
    db.get_location_stats(hours, 2000).await.unwrap_or_default()
}

/// Cached recent credentials - 60 second TTL
#[cached(time = 60, key = "()", convert = r#"{ () }"#)]
async fn get_cached_recent_credentials(db: Database) -> Vec<(String, String)> {
    db.get_recent_credentials(10).await.unwrap_or_default()
}

/// Cached top IPs by request count - 5 minute TTL
#[cached(time = 300, key = "i64", convert = r#"{ hours }"#)]
async fn get_cached_top_ips_requests(hours: i64, db: Database) -> Vec<IpStat> {
    db.get_top_ips_by_requests(hours, 25).await.unwrap_or_default()
}

/// Cached top IPs by bandwidth - 5 minute TTL
#[cached(time = 300, key = "i64", convert = r#"{ hours }"#)]
async fn get_cached_top_ips_bandwidth(hours: i64, db: Database) -> Vec<IpStat> {
    db.get_top_ips_by_bandwidth(hours, 25).await.unwrap_or_default()
}

/// Cached total bytes - 5 minute TTL
#[cached(time = 300, key = "i64", convert = r#"{ hours }"#)]
async fn get_cached_total_bytes(hours: i64, db: Database) -> i64 {
    db.get_total_bytes(hours).await.unwrap_or(0)
}

/// API: Get statistics (cached for 5 minutes)
pub async fn api_stats(
    State(state): State<Arc<AppState>>,
    Query(query): Query<StatsQuery>,
) -> Result<Json<StatsResponse>, ApiError> {
    let hours = validate_hours(query.hours)?;
    Ok(Json(get_cached_stats(hours, state.db.clone()).await))
}

#[derive(Debug, Serialize)]
pub struct RecentResponse {
    pub total: i64,
    pub credentials: Vec<CredentialStat>,
    pub events: Vec<AttackEvent>,
}

/// API: Get recent data for dashboard (credentials cached 60s, events fresh)
pub async fn api_recent(State(state): State<Arc<AppState>>) -> Json<RecentResponse> {
    let total = state.db.get_total_count().await.unwrap_or(0);
    let creds = get_cached_recent_credentials(state.db.clone()).await;
    let events = state.db.get_recent_events(25).await.unwrap_or_default();
    
    let credentials: Vec<CredentialStat> = creds
        .into_iter()
        .map(|(username, password)| CredentialStat {
            username,
            password,
            count: 1,
        })
        .collect();

    Json(RecentResponse { total, credentials, events })
}

/// API: Get country statistics (cached for 5 minutes)
pub async fn api_countries(
    State(state): State<Arc<AppState>>,
    Query(query): Query<StatsQuery>,
) -> Result<Json<Vec<CountryStat>>, ApiError> {
    let hours = validate_hours(query.hours)?;
    Ok(Json(get_cached_countries(hours, state.db.clone()).await))
}

/// API: Get location data for map (cached for 5 minutes)
pub async fn api_locations(
    State(state): State<Arc<AppState>>,
    Query(query): Query<StatsQuery>,
) -> Result<Json<Vec<LocationStat>>, ApiError> {
    let hours = validate_hours(query.hours)?;
    Ok(Json(get_cached_locations(hours, state.db.clone()).await))
}

/// API: Get top IPs by request count (cached for 5 minutes)
pub async fn api_top_ips_requests(
    State(state): State<Arc<AppState>>,
    Query(query): Query<StatsQuery>,
) -> Result<Json<Vec<IpStat>>, ApiError> {
    let hours = validate_hours(query.hours)?;
    Ok(Json(get_cached_top_ips_requests(hours, state.db.clone()).await))
}

/// API: Get top IPs by bandwidth (cached for 5 minutes)
pub async fn api_top_ips_bandwidth(
    State(state): State<Arc<AppState>>,
    Query(query): Query<StatsQuery>,
) -> Result<Json<Vec<IpStat>>, ApiError> {
    let hours = validate_hours(query.hours)?;
    Ok(Json(get_cached_top_ips_bandwidth(hours, state.db.clone()).await))
}

/// API: Get total traffic bytes (cached for 5 minutes)
pub async fn api_total_bytes(
    State(state): State<Arc<AppState>>,
    Query(query): Query<StatsQuery>,
) -> Result<Json<i64>, ApiError> {
    let hours = validate_hours(query.hours)?;
    Ok(Json(get_cached_total_bytes(hours, state.db.clone()).await))
}

/// Warm the cache for the default time range (called on startup)
pub async fn warm_cache(db: &Database) {
    const DEFAULT_HOURS: i64 = 720; // 30 days - matches stats page default
    
    tracing::info!("Warming cache for {} hour time range...", DEFAULT_HOURS);
    
    // Warm all three caches in parallel
    let _ = tokio::join!(
        get_cached_stats(DEFAULT_HOURS, db.clone()),
        get_cached_countries(DEFAULT_HOURS, db.clone()),
        get_cached_locations(DEFAULT_HOURS, db.clone()),
        get_cached_recent_credentials(db.clone())
    );
    
    tracing::info!("Cache warmed successfully");
}

/// Run daily rollup backfill and start background aggregation task
pub fn start_background_tasks(db: Arc<Database>) {
    // Backfill any missing days first
    tokio::spawn({
        let db = db.clone();
        async move {
            tracing::info!("Checking for rollup backfill...");
            match db.get_days_needing_rollup().await {
                Ok(days) if days.is_empty() => {
                    tracing::info!("Rollup is up to date, no backfill needed");
                }
                Ok(days) => {
                    tracing::info!("Backfilling {} days of rollup data...", days.len());
                    for day in days {
                        if let Err(e) = db.aggregate_day(day).await {
                            tracing::warn!("Failed to aggregate day {}: {}", day, e);
                        }
                    }
                    tracing::info!("Rollup backfill complete");
                }
                Err(e) => {
                    tracing::warn!("Failed to check rollup status: {}", e);
                }
            }
        }
    });
    
    // Start periodic rollup check (every hour, aggregate yesterday if not done)
    // The aggregate_day function checks if already done, so this is cheap
    tokio::spawn({
        let db = db.clone();
        async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(3600));
            loop {
                interval.tick().await;
                
                // Aggregate yesterday (skips if already done)
                let now = chrono::Utc::now();
                let today = chrono::TimeZone::with_ymd_and_hms(
                    &chrono::Utc, now.year(), now.month(), now.day(), 0, 0, 0
                ).unwrap().timestamp_millis();
                let yesterday = today - 86400 * 1000;
                
                if let Err(e) = db.aggregate_day(yesterday).await {
                    tracing::debug!("Hourly rollup check: {}", e);
                }
                
                tracing::debug!("Hourly rollup check complete");
            }
        }
    });
}
