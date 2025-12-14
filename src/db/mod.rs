//! Database module

mod schema;

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{Pool, Sqlite, SqlitePool};

use crate::config::DatabaseConfig;

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
}



#[derive(Clone)]
pub struct Database {
    pool: Pool<Sqlite>,
}

impl Database {
    pub async fn new(config: &DatabaseConfig) -> Result<Self> {
        let pool = SqlitePool::connect(&format!("sqlite:{}?mode=rwc", config.url)).await?;
        Ok(Self { pool })
    }

    pub async fn run_migrations(&self) -> Result<()> {
        // Enable WAL mode for better concurrency
        sqlx::query("PRAGMA journal_mode=WAL")
            .execute(&self.pool)
            .await?;
        sqlx::query("PRAGMA synchronous=NORMAL")
            .execute(&self.pool)
            .await?;
        
        sqlx::query(schema::CREATE_TABLE)
            .execute(&self.pool)
            .await?;
        sqlx::query(schema::CREATE_INDEX_TIMESTAMP)
            .execute(&self.pool)
            .await?;
        sqlx::query(schema::CREATE_INDEX_SERVICE)
            .execute(&self.pool)
            .await?;
        sqlx::query(schema::CREATE_INDEX_IP)
            .execute(&self.pool)
            .await?;
        // Performance indexes for 100K+ rows
        sqlx::query(schema::CREATE_INDEX_COUNTRY)
            .execute(&self.pool)
            .await?;
        sqlx::query(schema::CREATE_INDEX_HTTP_PATH)
            .execute(&self.pool)
            .await?;
        sqlx::query(schema::CREATE_INDEX_TIMESTAMP_SERVICE)
            .execute(&self.pool)
            .await?;
        sqlx::query(schema::CREATE_INDEX_LOCATION)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn insert_event(&self, event: &AttackEvent) -> Result<i64> {
        let result = sqlx::query(
            r#"
            INSERT INTO requests (timestamp, ip, country_code, latitude, longitude, service, port, request, payload, http_path, username, password, user_agent)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
        .execute(&self.pool)
        .await?;

        Ok(result.last_insert_rowid())
    }

    pub async fn get_total_count(&self) -> Result<i64> {
        let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM requests")
            .fetch_one(&self.pool)
            .await?;
        Ok(row.0)
    }

    pub async fn get_filtered_count(&self, since_hours: i64) -> Result<i64> {
        let since = Utc::now().timestamp_millis() - (since_hours * 3600 * 1000);
        let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM requests WHERE timestamp > ?")
            .bind(since)
            .fetch_one(&self.pool)
            .await?;
        Ok(row.0)
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
        let rows: Vec<(i64, i64, String, Option<String>, Option<f64>, Option<f64>, String, i32, Option<String>, Option<String>, Option<String>, Option<String>, Option<String>, Option<String>)> = sqlx::query_as(
            r#"
            SELECT id, timestamp, ip, country_code, latitude, longitude, service, port, request, payload, http_path, username, password, user_agent
            FROM requests
            ORDER BY id DESC
            LIMIT ?
            "#
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        
        Ok(rows.into_iter().map(|(id, ts, ip, country_code, latitude, longitude, service, port, request, payload, http_path, username, password, user_agent)| {
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
            }
        }).collect())
    }

    pub async fn get_service_stats(&self, since_hours: i64) -> Result<Vec<ServiceStat>> {
        let since = Utc::now().timestamp_millis() - (since_hours * 3600 * 1000);
        let rows: Vec<(String, i64)> = sqlx::query_as(
            "SELECT service, COUNT(*) as count FROM requests WHERE timestamp > ? GROUP BY service ORDER BY count DESC"
        )
        .bind(since)
        .fetch_all(&self.pool)
        .await?;
        
        let total: i64 = rows.iter().map(|(_, c)| c).sum();
        Ok(rows.into_iter().map(|(service, count)| ServiceStat {
            service,
            count,
            percentage: if total > 0 { (count as f64 / total as f64) * 100.0 } else { 0.0 },
        }).collect())
    }

    pub async fn get_unique_ips(&self, since_hours: i64) -> Result<i64> {
        let since = Utc::now().timestamp_millis() - (since_hours * 3600 * 1000);
        let row: (i64,) = sqlx::query_as(
            "SELECT COUNT(DISTINCT ip) FROM requests WHERE timestamp > ?"
        )
        .bind(since)
        .fetch_one(&self.pool)
        .await?;
        Ok(row.0)
    }

    pub async fn get_top_credentials(&self, since_hours: i64, limit: i32) -> Result<Vec<CredentialStat>> {
        let since = Utc::now().timestamp_millis() - (since_hours * 3600 * 1000);
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
        .bind(since)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        
        Ok(rows.into_iter().map(|(username, password, count)| CredentialStat {
            username,
            password,
            count,
        }).collect())
    }

    pub async fn get_top_paths(&self, since_hours: i64, limit: i32) -> Result<Vec<PathStat>> {
        let since = Utc::now().timestamp_millis() - (since_hours * 3600 * 1000);
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
        .bind(since)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        
        Ok(rows.into_iter().map(|(path, count)| PathStat { path, count }).collect())
    }

    pub async fn get_country_stats(&self, since_hours: i64) -> Result<Vec<CountryStat>> {
        let since = Utc::now().timestamp_millis() - (since_hours * 3600 * 1000);
        let rows: Vec<(String, i64)> = sqlx::query_as(
            r#"
            SELECT country_code, COUNT(*) as count 
            FROM requests 
            WHERE timestamp > ? AND country_code IS NOT NULL 
            GROUP BY country_code 
            ORDER BY count DESC
            "#
        )
        .bind(since)
        .fetch_all(&self.pool)
        .await?;
        
        Ok(rows.into_iter().map(|(country_code, count)| CountryStat { country_code, count }).collect())
    }
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

impl Database {
    /// Get location data aggregated by rounded lat/lng for map display (performant for large datasets)
    pub async fn get_location_stats(&self, since_hours: i64, limit: i32) -> Result<Vec<LocationStat>> {
        let since = Utc::now().timestamp_millis() - (since_hours * 3600 * 1000);
        
        // Round lat/lng to 1 decimal place (~11km precision) for clustering
        let rows: Vec<(f64, f64, i64)> = sqlx::query_as(
            r#"
            SELECT 
                ROUND(latitude, 1) as lat, 
                ROUND(longitude, 1) as lon, 
                COUNT(*) as count 
            FROM requests 
            WHERE timestamp > ? AND latitude IS NOT NULL AND longitude IS NOT NULL 
            GROUP BY ROUND(latitude, 1), ROUND(longitude, 1) 
            ORDER BY count DESC 
            LIMIT ?
            "#
        )
        .bind(since)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        
        Ok(rows.into_iter().map(|(lat, lon, count)| LocationStat { lat, lon, count }).collect())
    }
}
