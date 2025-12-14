//! HTTP routes

use axum::{
    extract::{Query, State},
    response::Html,
    Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use super::AppState;
use crate::db::{AttackEvent, CountryStat, CredentialStat, LocationStat, PathStat, ServiceStat};

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

#[derive(Debug, Serialize)]
pub struct StatsResponse {
    pub total: i64,
    pub unique_ips: i64,
    pub services: Vec<ServiceStat>,
    pub credentials: Vec<CredentialStat>,
    pub paths: Vec<PathStat>,
}

/// API: Get statistics
pub async fn api_stats(
    State(state): State<Arc<AppState>>,
    Query(query): Query<StatsQuery>,
) -> Json<StatsResponse> {
    let total = state.db.get_filtered_count(query.hours).await.unwrap_or(0);
    let unique_ips = state.db.get_unique_ips(query.hours).await.unwrap_or(0);
    let services = state.db.get_service_stats(query.hours).await.unwrap_or_default();
    let credentials = state.db.get_top_credentials(query.hours, 50).await.unwrap_or_default();
    let paths = state.db.get_top_paths(query.hours, 50).await.unwrap_or_default();

    Json(StatsResponse {
        total,
        unique_ips,
        services,
        credentials,
        paths,
    })
}

#[derive(Debug, Serialize)]
pub struct RecentResponse {
    pub total: i64,
    pub credentials: Vec<CredentialStat>,
    pub events: Vec<AttackEvent>,
}

/// API: Get recent data for dashboard (includes recent events)
pub async fn api_recent(State(state): State<Arc<AppState>>) -> Json<RecentResponse> {
    let total = state.db.get_total_count().await.unwrap_or(0);
    let creds = state.db.get_recent_credentials(10).await.unwrap_or_default();
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

/// API: Get country statistics
pub async fn api_countries(
    State(state): State<Arc<AppState>>,
    Query(query): Query<StatsQuery>,
) -> Json<Vec<CountryStat>> {
    let countries = state.db.get_country_stats(query.hours).await.unwrap_or_default();
    Json(countries)
}

/// API: Get location data for map (lat/lng clusters with counts, max 500 points)
pub async fn api_locations(
    State(state): State<Arc<AppState>>,
    Query(query): Query<StatsQuery>,
) -> Json<Vec<LocationStat>> {
    let locations = state.db.get_location_stats(query.hours, 500).await.unwrap_or_default();
    Json(locations)
}
