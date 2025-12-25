//! Database module

mod schema;
pub mod write_buffer;

use std::collections::HashMap;
use anyhow::Result;
use chrono::{DateTime, Utc, Datelike, TimeZone};
use serde::{Deserialize, Serialize};
use sqlx::{Pool, Sqlite, sqlite::SqlitePoolOptions};

use crate::config::DatabaseConfig;

pub use write_buffer::{WriteSender, start_write_buffer};

/// Represents an attack event captured by the honeypot
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackEvent {
    pub id: Option<i64>,
    pub timestamp: DateTime<Utc>,
    pub ip: String,
    pub country_code: Option<String>,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
    pub service: String,
    pub port: u16,
    pub request: String,
    pub payload: Option<String>,
    pub http_path: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub user_agent: Option<String>,
    pub request_size: u32,
}

impl AttackEvent {
    pub fn new(ip: String, service: String, port: u16, request: String) -> Self {
        Self {
            id: None,
            timestamp: Utc::now(),
            ip,
            country_code: None,
            latitude: None,
            longitude: None,
            service,
            port,
            request,
            payload: None,
            http_path: None,
            username: None,
            password: None,
            user_agent: None,
            request_size: 0,
        }
    }

    pub fn with_credentials(mut self, username: String, password: String) -> Self {
        self.username = Some(username);
        self.password = Some(password);
        self
    }

    pub fn with_payload(mut self, payload: Vec<u8>) -> Self {
        // Store as hex-encoded string for simplicity
        self.payload = Some(hex::encode(&payload));
        self
    }

    pub fn with_geo(mut self, country_code: String, lat: f64, lon: f64) -> Self {
        self.country_code = Some(country_code);
        self.latitude = Some(lat);
        self.longitude = Some(lon);
        self
    }

    pub fn with_user_agent(mut self, user_agent: String) -> Self {
        self.user_agent = Some(user_agent);
        self
    }

    pub fn with_request_size(mut self, size: u32) -> Self {
        self.request_size = size;
        self
    }
}

#[derive(Clone)]
pub struct Database {
    pool: Pool<Sqlite>,
}

impl Database {
    pub async fn new(config: &DatabaseConfig) -> Result<Self> {
        // Convert MB to KB for PRAGMA cache_size (negative value = KB)
        let cache_size_kb = (config.cache_size_mb as i32) * 1000;
        
        // Configure pool with settings for mixed read/write workload:
        // - max_connections: 8 allows parallel reads while reserving capacity for writes
        // - cache=shared: All connections share one page cache
        // - acquire_timeout: Increase to handle slow stats queries
        let pool = SqlitePoolOptions::new()
            .max_connections(8)
            .acquire_timeout(std::time::Duration::from_secs(30))
            .after_connect(move |conn, _meta| {
                Box::pin(async move {
                    // Performance: Reduce fsync calls (safe with WAL mode)
                    sqlx::query("PRAGMA synchronous = NORMAL")
                        .execute(&mut *conn)
                        .await?;
                    // Performance: Configurable page cache
                    sqlx::query(&format!("PRAGMA cache_size = -{}", cache_size_kb))
                        .execute(&mut *conn)
                        .await?;
                    // Performance: Keep temp tables in memory
                    sqlx::query("PRAGMA temp_store = MEMORY")
                        .execute(&mut *conn)
                        .await?;
                    Ok(())
                })
            })
            .connect(&format!("sqlite:{}?mode=rwc&cache=shared", config.url))
            .await?;
        Ok(Self { pool })
    }

    pub async fn run_migrations(&self) -> Result<()> {
        // Enable WAL mode for better concurrency (persists at database level)
        sqlx::query("PRAGMA journal_mode=WAL")
            .execute(&self.pool)
            .await?;
        
        // Create main table
        sqlx::query(schema::CREATE_TABLE)
            .execute(&self.pool)
            .await?;
        
        // Create rollup table
        sqlx::query(schema::CREATE_STATS_DAILY_TABLE)
            .execute(&self.pool)
            .await?;
        
        // Create optimized covering indexes
        sqlx::query(schema::CREATE_INDEX_TS_SERVICE)
            .execute(&self.pool)
            .await?;
        sqlx::query(schema::CREATE_INDEX_TS_COUNTRY)
            .execute(&self.pool)
            .await?;
        sqlx::query(schema::CREATE_INDEX_TS_HTTP_PATH)
            .execute(&self.pool)
            .await?;
        sqlx::query(schema::CREATE_INDEX_TS_LOCATION)
            .execute(&self.pool)
            .await?;
        sqlx::query(schema::CREATE_INDEX_IP)
            .execute(&self.pool)
            .await?;
        sqlx::query(schema::CREATE_INDEX_CREDENTIALS)
            .execute(&self.pool)
            .await?;
        sqlx::query(schema::CREATE_INDEX_TS_IP)
            .execute(&self.pool)
            .await?;
        
        Ok(())
    }

    // ==================== WRITE OPERATIONS ====================

    pub async fn insert_event(&self, event: &AttackEvent) -> Result<i64> {
        let result = sqlx::query(
            r#"
            INSERT INTO requests (timestamp, ip, country_code, latitude, longitude, service, port, request, payload, http_path, username, password, user_agent, request_size)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(event.timestamp.timestamp_millis())
        .bind(&event.ip)
        .bind(&event.country_code)
        .bind(event.latitude)
        .bind(event.longitude)
        .bind(&event.service)
        .bind(event.port as i32)
        .bind(&event.request)
        .bind(&event.payload)
        .bind(&event.http_path)
        .bind(&event.username)
        .bind(&event.password)
        .bind(&event.user_agent)
        .bind(event.request_size as i32)
        .execute(&self.pool)
        .await?;

        Ok(result.last_insert_rowid())
    }

    /// Batch insert events in a single transaction (much faster than individual inserts)
    pub async fn batch_insert_events(&self, events: &[AttackEvent]) -> Result<()> {
        if events.is_empty() {
            return Ok(());
        }

        let mut tx = self.pool.begin().await?;
        
        for event in events {
            sqlx::query(
                r#"
                INSERT INTO requests (timestamp, ip, country_code, latitude, longitude, service, port, request, payload, http_path, username, password, user_agent, request_size)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                "#,
            )
            .bind(event.timestamp.timestamp_millis())
            .bind(&event.ip)
            .bind(&event.country_code)
            .bind(event.latitude)
            .bind(event.longitude)
            .bind(&event.service)
            .bind(event.port as i32)
            .bind(&event.request)
            .bind(&event.payload)
            .bind(&event.http_path)
            .bind(&event.username)
            .bind(&event.password)
            .bind(&event.user_agent)
            .bind(event.request_size as i32)
            .execute(&mut *tx)
            .await?;
        }
        
        tx.commit().await?;
        Ok(())
    }

    // ==================== BASIC READ OPERATIONS ====================

    /// Get total request count using MAX(rowid) for O(1) performance.
    pub async fn get_total_count(&self) -> Result<i64> {
        let row: (Option<i64>,) = sqlx::query_as("SELECT MAX(rowid) FROM requests")
            .fetch_one(&self.pool)
            .await?;
        Ok(row.0.unwrap_or(0))
    }

    pub async fn get_recent_credentials(&self, limit: i32) -> Result<Vec<(String, String)>> {
        let rows: Vec<(String, String)> = sqlx::query_as(
            "SELECT username, password FROM requests WHERE username IS NOT NULL ORDER BY id DESC LIMIT ?"
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    pub async fn get_recent_events(&self, limit: i32) -> Result<Vec<AttackEvent>> {
        let rows: Vec<(i64, i64, String, Option<String>, Option<f64>, Option<f64>, String, i32, Option<String>, Option<String>, Option<String>, Option<String>, Option<String>, Option<String>, i32)> = sqlx::query_as(
            r#"
            SELECT id, timestamp, ip, country_code, latitude, longitude, service, port, request, payload, http_path, username, password, user_agent, COALESCE(request_size, 0)
            FROM requests
            ORDER BY id DESC
            LIMIT ?
            "#
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        
        Ok(rows.into_iter().map(|(id, ts, ip, country_code, latitude, longitude, service, port, request, payload, http_path, username, password, user_agent, request_size)| {
            AttackEvent {
                id: Some(id),
                timestamp: chrono::DateTime::from_timestamp_millis(ts).unwrap_or_else(|| Utc::now()),
                ip,
                country_code,
                latitude,
                longitude,
                service,
                port: port as u16,
                request: request.unwrap_or_default(),
                payload,
                http_path,
                username,
                password,
                user_agent,
                request_size: request_size as u32,
            }
        }).collect())
    }

    // ==================== STATS OPERATIONS (HYBRID: ROLLUP + LIVE) ====================

    /// Get stats using hybrid approach: rollup for complete days, live query for today (only for <24h range)
    /// 
    /// Special case: hours=24 returns yesterday's rollup only (fast, complete data)
    /// Note: First partial day is excluded from rollup (slight under-count is acceptable)
    pub async fn get_stats_hybrid(&self, since_hours: i64) -> Result<StatsResponse> {
        let now = Utc::now();
        let today_start = Utc.with_ymd_and_hms(now.year(), now.month(), now.day(), 0, 0, 0)
            .unwrap()
            .timestamp_millis();
        let yesterday_start = today_start - 86400 * 1000;
        
        // Special case: 24h = yesterday only (from rollup, fast)
        if since_hours == 24 {
            return self.get_rollup_stats(yesterday_start, today_start).await;
        }
        
        let since_ts = now.timestamp_millis() - (since_hours * 3600 * 1000);
        
        // Start rollup from the day AFTER since_ts to avoid partial day over-count
        let since_day_bucket = ts_to_day_bucket(since_ts);
        let first_complete_day = since_day_bucket + 86400 * 1000; // Next day midnight
        
        // Get rollup data for complete days (excludes partial first day)
        let rollup = if first_complete_day < today_start {
            self.get_rollup_stats(first_complete_day, today_start).await?
        } else {
            StatsResponse { total: 0, services: vec![], credentials: vec![], paths: vec![] }
        };
        
        Ok(rollup)
    }

    /// Get stats from rollup table for complete days
    async fn get_rollup_stats(&self, since_ts: i64, before_ts: i64) -> Result<StatsResponse> {
        let since_day = ts_to_day_bucket(since_ts);
        let before_day = ts_to_day_bucket(before_ts);
        
        let rows: Vec<(i64, Option<String>, Option<String>, Option<String>, Option<String>)> = sqlx::query_as(
            r#"
            SELECT total_requests, service_counts, credential_counts, path_counts, country_counts
            FROM stats_daily
            WHERE day_bucket >= ? AND day_bucket < ?
            "#
        )
        .bind(since_day)
        .bind(before_day)
        .fetch_all(&self.pool)
        .await?;
        
        if rows.is_empty() {
            // No rollup data, fall back to live query
            return self.get_live_stats(since_ts).await;
        }
        
        // Aggregate rollup data
        let mut total = 0i64;
        let mut services: HashMap<String, i64> = HashMap::new();
        let mut credentials: HashMap<(String, String), i64> = HashMap::new();
        let mut paths: HashMap<String, i64> = HashMap::new();
        
        for (req_count, service_json, cred_json, path_json, _) in rows {
            total += req_count;
            
            if let Some(json) = service_json {
                if let Ok(map) = serde_json::from_str::<HashMap<String, i64>>(&json) {
                    for (k, v) in map {
                        *services.entry(k).or_insert(0) += v;
                    }
                }
            }
            
            if let Some(json) = cred_json {
                if let Ok(list) = serde_json::from_str::<Vec<CredentialCount>>(&json) {
                    for c in list {
                        *credentials.entry((c.u, c.p)).or_insert(0) += c.c;
                    }
                }
            }
            
            if let Some(json) = path_json {
                if let Ok(map) = serde_json::from_str::<HashMap<String, i64>>(&json) {
                    for (k, v) in map {
                        *paths.entry(k).or_insert(0) += v;
                    }
                }
            }
        }
        
        // Convert to response format
        let total_for_pct = total as f64;
        let services: Vec<ServiceStat> = services.into_iter()
            .map(|(service, count)| ServiceStat {
                service,
                count,
                percentage: if total > 0 { (count as f64 / total_for_pct) * 100.0 } else { 0.0 },
            })
            .collect();
        
        let mut credentials: Vec<CredentialStat> = credentials.into_iter()
            .map(|((username, password), count)| CredentialStat { username, password, count })
            .collect();
        credentials.sort_by(|a, b| b.count.cmp(&a.count));
        credentials.truncate(50);
        
        let mut paths: Vec<PathStat> = paths.into_iter()
            .map(|(path, count)| PathStat { path, count })
            .collect();
        paths.sort_by(|a, b| b.count.cmp(&a.count));
        paths.truncate(50);
        
        Ok(StatsResponse { total, services, credentials, paths })
    }

    /// Get stats from live table (for today or fallback)
    async fn get_live_stats(&self, since_ts: i64) -> Result<StatsResponse> {
        let (total, services, credentials, paths) = tokio::join!(
            self.get_filtered_count(since_ts),
            self.get_service_stats_raw(since_ts),
            self.get_top_credentials_raw(since_ts, 50),
            self.get_top_paths_raw(since_ts, 50)
        );
        
        Ok(StatsResponse {
            total: total.unwrap_or(0),
            services: services.unwrap_or_default(),
            credentials: credentials.unwrap_or_default(),
            paths: paths.unwrap_or_default(),
        })
    }

    async fn get_filtered_count(&self, since_ts: i64) -> Result<i64> {
        let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM requests WHERE timestamp > ?")
            .bind(since_ts)
            .fetch_one(&self.pool)
            .await?;
        Ok(row.0)
    }

    async fn get_service_stats_raw(&self, since_ts: i64) -> Result<Vec<ServiceStat>> {
        let rows: Vec<(String, i64)> = sqlx::query_as(
            "SELECT service, COUNT(*) as count FROM requests WHERE timestamp > ? GROUP BY service ORDER BY count DESC"
        )
        .bind(since_ts)
        .fetch_all(&self.pool)
        .await?;
        
        let total: i64 = rows.iter().map(|(_, c)| c).sum();
        Ok(rows.into_iter().map(|(service, count)| ServiceStat {
            service,
            count,
            percentage: if total > 0 { (count as f64 / total as f64) * 100.0 } else { 0.0 },
        }).collect())
    }

    async fn get_top_credentials_raw(&self, since_ts: i64, limit: i32) -> Result<Vec<CredentialStat>> {
        let rows: Vec<(String, String, i64)> = sqlx::query_as(
            r#"
            SELECT username, password, COUNT(*) as count 
            FROM requests 
            WHERE timestamp > ? AND username IS NOT NULL 
            GROUP BY username, password 
            ORDER BY count DESC 
            LIMIT ?
            "#
        )
        .bind(since_ts)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        
        Ok(rows.into_iter().map(|(username, password, count)| CredentialStat {
            username,
            password,
            count,
        }).collect())
    }

    async fn get_top_paths_raw(&self, since_ts: i64, limit: i32) -> Result<Vec<PathStat>> {
        let rows: Vec<(String, i64)> = sqlx::query_as(
            r#"
            SELECT http_path, COUNT(*) as count 
            FROM requests 
            WHERE timestamp > ? AND http_path IS NOT NULL 
            GROUP BY http_path 
            ORDER BY count DESC 
            LIMIT ?
            "#
        )
        .bind(since_ts)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        
        Ok(rows.into_iter().map(|(path, count)| PathStat { path, count }).collect())
    }

    // ==================== COUNTRY & LOCATION STATS ====================

    pub async fn get_country_stats(&self, since_hours: i64) -> Result<Vec<CountryStat>> {
        let now = Utc::now();
        let today_start = Utc.with_ymd_and_hms(now.year(), now.month(), now.day(), 0, 0, 0)
            .unwrap()
            .timestamp_millis();
        let yesterday_start = today_start - 86400 * 1000;
        
        // Special case: 24h = yesterday only (from rollup, fast)
        let (query_start, query_end) = if since_hours == 24 {
            (yesterday_start, today_start)
        } else {
            let since_ts = now.timestamp_millis() - (since_hours * 3600 * 1000);
            let since_day_bucket = ts_to_day_bucket(since_ts);
            let first_complete_day = since_day_bucket + 86400 * 1000;
            (first_complete_day, ts_to_day_bucket(today_start))
        };
        
        let rollup_rows: Vec<(Option<String>,)> = sqlx::query_as(
            "SELECT country_counts FROM stats_daily WHERE day_bucket >= ? AND day_bucket < ?"
        )
        .bind(query_start)
        .bind(query_end)
        .fetch_all(&self.pool)
        .await?;
        
        let mut countries: HashMap<String, i64> = HashMap::new();
        
        // Aggregate rollup data
        for (json,) in rollup_rows {
            if let Some(json) = json {
                if let Ok(map) = serde_json::from_str::<HashMap<String, i64>>(&json) {
                    for (k, v) in map {
                        *countries.entry(k).or_insert(0) += v;
                    }
                }
            }
        }

        let mut result: Vec<CountryStat> = countries.into_iter()
            .map(|(country_code, count)| CountryStat { country_code, count })
            .collect();
        result.sort_by(|a, b| b.count.cmp(&a.count));
        
        Ok(result)
    }

    pub async fn get_location_stats(&self, since_hours: i64, limit: i32) -> Result<Vec<LocationStat>> {
        let now = Utc::now();
        let today_start = Utc.with_ymd_and_hms(now.year(), now.month(), now.day(), 0, 0, 0)
            .unwrap()
            .timestamp_millis();
        let yesterday_start = today_start - 86400 * 1000;
        
        // Special case: 24h = yesterday only (from rollup, fast)
        let (query_start, query_end) = if since_hours == 24 {
            (yesterday_start, today_start)
        } else {
            let since_ts = now.timestamp_millis() - (since_hours * 3600 * 1000);
            let since_day_bucket = ts_to_day_bucket(since_ts);
            let first_complete_day = since_day_bucket + 86400 * 1000;
            (first_complete_day, ts_to_day_bucket(today_start))
        };
        
        let rollup_rows: Vec<(Option<String>,)> = sqlx::query_as(
            "SELECT location_counts FROM stats_daily WHERE day_bucket >= ? AND day_bucket < ?"
        )
        .bind(query_start)
        .bind(query_end)
        .fetch_all(&self.pool)
        .await?;
        
        let mut locations: HashMap<(i64, i64), i64> = HashMap::new(); // (lat*10, lon*10) -> count
        
        for (json,) in rollup_rows {
            if let Some(json) = json {
                if let Ok(list) = serde_json::from_str::<Vec<LocationCount>>(&json) {
                    for loc in list {
                        let key = ((loc.lat * 10.0) as i64, (loc.lon * 10.0) as i64);
                        *locations.entry(key).or_insert(0) += loc.c;
                    }
                }
            }
        }

        let mut result: Vec<LocationStat> = locations.into_iter()
            .map(|((lat_key, lon_key), count)| LocationStat {
                lat: lat_key as f64 / 10.0,
                lon: lon_key as f64 / 10.0,
                count,
            })
            .collect();
        result.sort_by(|a, b| b.count.cmp(&a.count));
        result.truncate(limit as usize);
        
        Ok(result)
    }

    // ==================== IP STATS ====================

    /// Get top IPs by request count (rollup only)
    pub async fn get_top_ips_by_requests(&self, since_hours: i64, limit: i32) -> Result<Vec<IpStat>> {
        let now = Utc::now();
        let today_start = Utc.with_ymd_and_hms(now.year(), now.month(), now.day(), 0, 0, 0)
            .unwrap()
            .timestamp_millis();
        let yesterday_start = today_start - 86400 * 1000;
        
        // Special case: 24h = yesterday only (from rollup, fast)
        let (query_start, query_end) = if since_hours == 24 {
            (yesterday_start, today_start)
        } else {
            let since_ts = now.timestamp_millis() - (since_hours * 3600 * 1000);
            let since_day_bucket = ts_to_day_bucket(since_ts);
            let first_complete_day = since_day_bucket + 86400 * 1000;
            (first_complete_day, ts_to_day_bucket(today_start))
        };
        
        let rollup_rows: Vec<(Option<String>,)> = sqlx::query_as(
            "SELECT ip_request_counts FROM stats_daily WHERE day_bucket >= ? AND day_bucket < ?"
        )
        .bind(query_start)
        .bind(query_end)
        .fetch_all(&self.pool)
        .await?;
        
        let mut ip_counts: HashMap<String, i64> = HashMap::new();
        
        for (json,) in rollup_rows {
            if let Some(json) = json {
                if let Ok(map) = serde_json::from_str::<HashMap<String, i64>>(&json) {
                    for (ip, count) in map {
                        *ip_counts.entry(ip).or_insert(0) += count;
                    }
                }
            }
        }
        
        let mut result: Vec<IpStat> = ip_counts.into_iter()
            .map(|(ip, count)| IpStat { ip, count })
            .collect();
        result.sort_by(|a, b| b.count.cmp(&a.count));
        result.truncate(limit as usize);
        
        Ok(result)
    }

    /// Get top IPs by bandwidth (rollup only)
    pub async fn get_top_ips_by_bandwidth(&self, since_hours: i64, limit: i32) -> Result<Vec<IpStat>> {
        let now = Utc::now();
        let today_start = Utc.with_ymd_and_hms(now.year(), now.month(), now.day(), 0, 0, 0)
            .unwrap()
            .timestamp_millis();
        let yesterday_start = today_start - 86400 * 1000;
        
        // Special case: 24h = yesterday only (from rollup, fast)
        let (query_start, query_end) = if since_hours == 24 {
            (yesterday_start, today_start)
        } else {
            let since_ts = now.timestamp_millis() - (since_hours * 3600 * 1000);
            let since_day_bucket = ts_to_day_bucket(since_ts);
            let first_complete_day = since_day_bucket + 86400 * 1000;
            (first_complete_day, ts_to_day_bucket(today_start))
        };
        
        let rollup_rows: Vec<(Option<String>,)> = sqlx::query_as(
            "SELECT ip_bytes_counts FROM stats_daily WHERE day_bucket >= ? AND day_bucket < ?"
        )
        .bind(query_start)
        .bind(query_end)
        .fetch_all(&self.pool)
        .await?;
        
        let mut ip_bytes: HashMap<String, i64> = HashMap::new();
        
        for (json,) in rollup_rows {
            if let Some(json) = json {
                if let Ok(map) = serde_json::from_str::<HashMap<String, i64>>(&json) {
                    for (ip, bytes) in map {
                        *ip_bytes.entry(ip).or_insert(0) += bytes;
                    }
                }
            }
        }
        
        let mut result: Vec<IpStat> = ip_bytes.into_iter()
            .map(|(ip, count)| IpStat { ip, count })
            .collect();
        result.sort_by(|a, b| b.count.cmp(&a.count));
        result.truncate(limit as usize);
        
        Ok(result)
    }

    /// Get total bytes for a time range (rollup only)
    pub async fn get_total_bytes(&self, since_hours: i64) -> Result<i64> {
        let now = Utc::now();
        let today_start = Utc.with_ymd_and_hms(now.year(), now.month(), now.day(), 0, 0, 0)
            .unwrap()
            .timestamp_millis();
        let yesterday_start = today_start - 86400 * 1000;
        
        // Special case: 24h = yesterday only (from rollup, fast)
        let (query_start, query_end) = if since_hours == 24 {
            (yesterday_start, today_start)
        } else {
            let since_ts = now.timestamp_millis() - (since_hours * 3600 * 1000);
            let since_day_bucket = ts_to_day_bucket(since_ts);
            let first_complete_day = since_day_bucket + 86400 * 1000;
            (first_complete_day, ts_to_day_bucket(today_start))
        };
        
        let (rollup_bytes,): (i64,) = sqlx::query_as(
            "SELECT COALESCE(SUM(total_bytes), 0) FROM stats_daily WHERE day_bucket >= ? AND day_bucket < ?"
        )
        .bind(query_start)
        .bind(query_end)
        .fetch_one(&self.pool)
        .await
        .unwrap_or((0,));
        
        Ok(rollup_bytes)
    }

    // ==================== ROLLUP AGGREGATION (called by background task) ====================

    /// Aggregate a single day's data into stats_daily
    /// Skips if already aggregated (check stats_daily first)
    pub async fn aggregate_day(&self, day_bucket: i64) -> Result<()> {
        let day_start = day_bucket;
        let day_end = day_bucket + 86400 * 1000; // +1 day in ms
        
        // Check if already aggregated - skip expensive queries if so
        let (exists,): (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM stats_daily WHERE day_bucket = ?"
        )
        .bind(day_bucket)
        .fetch_one(&self.pool)
        .await?;
        
        if exists > 0 {
            return Ok(()); // Already aggregated, nothing to do
        }
        
        // Get total count and total bytes
        let (total, total_bytes): (i64, i64) = sqlx::query_as(
            "SELECT COUNT(*), COALESCE(SUM(request_size), 0) FROM requests WHERE timestamp >= ? AND timestamp < ?"
        )
        .bind(day_start)
        .bind(day_end)
        .fetch_one(&self.pool)
        .await?;
        
        if total == 0 {
            return Ok(()); // No data for this day
        }
        
        // Get service counts
        let service_rows: Vec<(String, i64)> = sqlx::query_as(
            "SELECT service, COUNT(*) FROM requests WHERE timestamp >= ? AND timestamp < ? GROUP BY service"
        )
        .bind(day_start)
        .bind(day_end)
        .fetch_all(&self.pool)
        .await?;
        let service_counts: HashMap<&str, i64> = service_rows.iter().map(|(s, c)| (s.as_str(), *c)).collect();
        let service_json = serde_json::to_string(&service_counts)?;
        
        // Get country counts
        let country_rows: Vec<(String, i64)> = sqlx::query_as(
            "SELECT country_code, COUNT(*) FROM requests WHERE timestamp >= ? AND timestamp < ? AND country_code IS NOT NULL GROUP BY country_code"
        )
        .bind(day_start)
        .bind(day_end)
        .fetch_all(&self.pool)
        .await?;
        let country_counts: HashMap<&str, i64> = country_rows.iter().map(|(s, c)| (s.as_str(), *c)).collect();
        let country_json = serde_json::to_string(&country_counts)?;
        
        // Get path counts (top 100)
        let path_rows: Vec<(String, i64)> = sqlx::query_as(
            "SELECT http_path, COUNT(*) as c FROM requests WHERE timestamp >= ? AND timestamp < ? AND http_path IS NOT NULL GROUP BY http_path ORDER BY c DESC LIMIT 100"
        )
        .bind(day_start)
        .bind(day_end)
        .fetch_all(&self.pool)
        .await?;
        let path_counts: HashMap<&str, i64> = path_rows.iter().map(|(s, c)| (s.as_str(), *c)).collect();
        let path_json = serde_json::to_string(&path_counts)?;
        
        // Get credential counts (top 100)
        let cred_rows: Vec<(String, String, i64)> = sqlx::query_as(
            r#"SELECT username, password, COUNT(*) as c FROM requests 
               WHERE timestamp >= ? AND timestamp < ? AND username IS NOT NULL 
               GROUP BY username, password ORDER BY c DESC LIMIT 100"#
        )
        .bind(day_start)
        .bind(day_end)
        .fetch_all(&self.pool)
        .await?;
        let cred_counts: Vec<CredentialCount> = cred_rows.iter()
            .map(|(u, p, c)| CredentialCount { u: u.clone(), p: p.clone(), c: *c })
            .collect();
        let cred_json = serde_json::to_string(&cred_counts)?;
        
        // Get location counts (rounded to 1 decimal, top 500)
        let loc_rows: Vec<(f64, f64, i64)> = sqlx::query_as(
            r#"SELECT ROUND(latitude, 1), ROUND(longitude, 1), COUNT(*) as c 
               FROM requests WHERE timestamp >= ? AND timestamp < ? 
               AND latitude IS NOT NULL GROUP BY ROUND(latitude, 1), ROUND(longitude, 1) 
               ORDER BY c DESC LIMIT 500"#
        )
        .bind(day_start)
        .bind(day_end)
        .fetch_all(&self.pool)
        .await?;
        let loc_counts: Vec<LocationCount> = loc_rows.iter()
            .map(|(lat, lon, c)| LocationCount { lat: *lat, lon: *lon, c: *c })
            .collect();
        let loc_json = serde_json::to_string(&loc_counts)?;
        
        // Get IP request counts (top 100)
        let ip_request_rows: Vec<(String, i64)> = sqlx::query_as(
            "SELECT ip, COUNT(*) as c FROM requests WHERE timestamp >= ? AND timestamp < ? GROUP BY ip ORDER BY c DESC LIMIT 100"
        )
        .bind(day_start)
        .bind(day_end)
        .fetch_all(&self.pool)
        .await?;
        let ip_request_counts: HashMap<&str, i64> = ip_request_rows.iter().map(|(ip, c)| (ip.as_str(), *c)).collect();
        let ip_request_json = serde_json::to_string(&ip_request_counts)?;
        
        // Get IP bytes counts (top 100)
        let ip_bytes_rows: Vec<(String, i64)> = sqlx::query_as(
            "SELECT ip, COALESCE(SUM(request_size), 0) as bytes FROM requests WHERE timestamp >= ? AND timestamp < ? GROUP BY ip ORDER BY bytes DESC LIMIT 100"
        )
        .bind(day_start)
        .bind(day_end)
        .fetch_all(&self.pool)
        .await?;
        let ip_bytes_counts: HashMap<&str, i64> = ip_bytes_rows.iter().map(|(ip, b)| (ip.as_str(), *b)).collect();
        let ip_bytes_json = serde_json::to_string(&ip_bytes_counts)?;
        
        // Upsert into stats_daily
        sqlx::query(
            r#"INSERT INTO stats_daily (day_bucket, total_requests, service_counts, country_counts, path_counts, credential_counts, location_counts, total_bytes, ip_request_counts, ip_bytes_counts)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(day_bucket) DO UPDATE SET
                 total_requests = excluded.total_requests,
                 service_counts = excluded.service_counts,
                 country_counts = excluded.country_counts,
                 path_counts = excluded.path_counts,
                 credential_counts = excluded.credential_counts,
                 location_counts = excluded.location_counts,
                 total_bytes = excluded.total_bytes,
                 ip_request_counts = excluded.ip_request_counts,
                 ip_bytes_counts = excluded.ip_bytes_counts"#
        )
        .bind(day_bucket)
        .bind(total)
        .bind(&service_json)
        .bind(&country_json)
        .bind(&path_json)
        .bind(&cred_json)
        .bind(&loc_json)
        .bind(total_bytes)
        .bind(&ip_request_json)
        .bind(&ip_bytes_json)
        .execute(&self.pool)
        .await?;
        
        Ok(())
    }


    /// Get days that need to be backfilled (have requests but no rollup)
    pub async fn get_days_needing_rollup(&self) -> Result<Vec<i64>> {
        // Find distinct days in requests that are not in stats_daily
        // Only consider complete days (not today)
        let today_start = {
            let now = Utc::now();
            Utc.with_ymd_and_hms(now.year(), now.month(), now.day(), 0, 0, 0)
                .unwrap()
                .timestamp_millis()
        };
        
        let rows: Vec<(i64,)> = sqlx::query_as(
            r#"
            SELECT DISTINCT (timestamp / 86400000) * 86400000 as day_bucket
            FROM requests
            WHERE timestamp < ?
            AND (timestamp / 86400000) * 86400000 NOT IN (SELECT day_bucket FROM stats_daily)
            ORDER BY day_bucket
            "#
        )
        .bind(today_start)
        .fetch_all(&self.pool)
        .await?;
        
        Ok(rows.into_iter().map(|(d,)| d).collect())
    }
}

// ==================== HELPER STRUCTS ====================

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CredentialCount {
    u: String,
    p: String,
    c: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LocationCount {
    lat: f64,
    lon: f64,
    c: i64,
}

fn ts_to_day_bucket(ts: i64) -> i64 {
    (ts / 86400000) * 86400000
}

fn merge_service_stats(mut rollup: Vec<ServiceStat>, live: Vec<ServiceStat>) -> Vec<ServiceStat> {
    let mut map: HashMap<String, i64> = HashMap::new();
    for s in rollup.drain(..).chain(live) {
        *map.entry(s.service).or_insert(0) += s.count;
    }
    let total: i64 = map.values().sum();
    let mut result: Vec<ServiceStat> = map.into_iter()
        .map(|(service, count)| ServiceStat {
            service,
            count,
            percentage: if total > 0 { (count as f64 / total as f64) * 100.0 } else { 0.0 },
        })
        .collect();
    result.sort_by(|a, b| b.count.cmp(&a.count));
    result
}

fn merge_credential_stats(mut rollup: Vec<CredentialStat>, live: Vec<CredentialStat>) -> Vec<CredentialStat> {
    let mut map: HashMap<(String, String), i64> = HashMap::new();
    for c in rollup.drain(..).chain(live) {
        *map.entry((c.username, c.password)).or_insert(0) += c.count;
    }
    let mut result: Vec<CredentialStat> = map.into_iter()
        .map(|((username, password), count)| CredentialStat { username, password, count })
        .collect();
    result.sort_by(|a, b| b.count.cmp(&a.count));
    result.truncate(50);
    result
}

fn merge_path_stats(mut rollup: Vec<PathStat>, live: Vec<PathStat>) -> Vec<PathStat> {
    let mut map: HashMap<String, i64> = HashMap::new();
    for p in rollup.drain(..).chain(live) {
        *map.entry(p.path).or_insert(0) += p.count;
    }
    let mut result: Vec<PathStat> = map.into_iter()
        .map(|(path, count)| PathStat { path, count })
        .collect();
    result.sort_by(|a, b| b.count.cmp(&a.count));
    result.truncate(50);
    result
}

// ==================== RESPONSE TYPES ====================

#[derive(Debug, Clone, Serialize)]
pub struct StatsResponse {
    pub total: i64,
    pub services: Vec<ServiceStat>,
    pub credentials: Vec<CredentialStat>,
    pub paths: Vec<PathStat>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ServiceStat {
    pub service: String,
    pub count: i64,
    pub percentage: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct CredentialStat {
    pub username: String,
    pub password: String,
    pub count: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct PathStat {
    pub path: String,
    pub count: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct CountryStat {
    pub country_code: String,
    pub count: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct LocationStat {
    pub lat: f64,
    pub lon: f64,
    pub count: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct IpStat {
    pub ip: String,
    pub count: i64,
}
