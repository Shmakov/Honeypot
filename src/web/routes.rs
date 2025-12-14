//! HTTP routes with response caching

use axum::{
    extract::{Query, State},
    response::Html,
    Json,
};
use cached::proc_macro::cached;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use super::AppState;
use crate::db::{AttackEvent, CountryStat, CredentialStat, Database, LocationStat, PathStat, ServiceStat};

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
    24
}

#[derive(Debug, Clone, Serialize)]
pub struct StatsResponse {
    pub total: i64,
    pub unique_ips: i64,
    pub services: Vec<ServiceStat>,
    pub credentials: Vec<CredentialStat>,
    pub paths: Vec<PathStat>,
}

/// Cached stats query - 5 minute TTL
#[cached(time = 300, key = "i64", convert = r#"{ hours }"#)]
async fn get_cached_stats(hours: i64, db: Database) -> StatsResponse {
    let (total, unique_ips, services, credentials, paths) = tokio::join!(
        db.get_filtered_count(hours),
        db.get_unique_ips(hours),
        db.get_service_stats(hours),
        db.get_top_credentials(hours, 50),
        db.get_top_paths(hours, 50)
    );

    StatsResponse {
        total: total.unwrap_or(0),
        unique_ips: unique_ips.unwrap_or(0),
        services: services.unwrap_or_default(),
        credentials: credentials.unwrap_or_default(),
        paths: paths.unwrap_or_default(),
    }
}

/// Cached countries query - 5 minute TTL
#[cached(time = 300, key = "i64", convert = r#"{ hours }"#)]
async fn get_cached_countries(hours: i64, db: Database) -> Vec<CountryStat> {
    db.get_country_stats(hours).await.unwrap_or_default()
}

/// Cached locations query - 5 minute TTL
#[cached(time = 300, key = "i64", convert = r#"{ hours }"#)]
async fn get_cached_locations(hours: i64, db: Database) -> Vec<LocationStat> {
    db.get_location_stats(hours, 500).await.unwrap_or_default()
}

/// Cached recent credentials - 60 second TTL
#[cached(time = 60, key = "()", convert = r#"{ () }"#)]
async fn get_cached_recent_credentials(db: Database) -> Vec<(String, String)> {
    db.get_recent_credentials(10).await.unwrap_or_default()
}

/// API: Get statistics (cached for 5 minutes)
pub async fn api_stats(
    State(state): State<Arc<AppState>>,
    Query(query): Query<StatsQuery>,
) -> Json<StatsResponse> {
    Json(get_cached_stats(query.hours, state.db.clone()).await)
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
) -> Json<Vec<CountryStat>> {
    Json(get_cached_countries(query.hours, state.db.clone()).await)
}

/// API: Get location data for map (cached for 5 minutes)
pub async fn api_locations(
    State(state): State<Arc<AppState>>,
    Query(query): Query<StatsQuery>,
) -> Json<Vec<LocationStat>> {
    Json(get_cached_locations(query.hours, state.db.clone()).await)
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
