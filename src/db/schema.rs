//! Database schema definitions

pub const CREATE_TABLE: &str = r#"
CREATE TABLE IF NOT EXISTS requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp BIGINT NOT NULL,
    ip TEXT NOT NULL,
    country_code TEXT,
    latitude REAL,
    longitude REAL,
    service TEXT NOT NULL,
    port INTEGER,
    request TEXT,
    payload TEXT,
    http_path TEXT,
    username TEXT,
    password TEXT,
    user_agent TEXT,
    request_size INTEGER DEFAULT 0
)
"#;

// Daily rollup table for fast stats queries
pub const CREATE_STATS_DAILY_TABLE: &str = r#"
CREATE TABLE IF NOT EXISTS stats_daily (
    day_bucket INTEGER PRIMARY KEY,  -- Unix timestamp at midnight UTC
    total_requests INTEGER NOT NULL DEFAULT 0,
    country_counts TEXT,             -- JSON: {"US": 100, "CN": 50}
    service_counts TEXT,             -- JSON: {"HTTP": 200, "SSH": 100}
    path_counts TEXT,                -- JSON: {"/admin": 50, "/wp-login.php": 30}
    credential_counts TEXT,          -- JSON: [{"u": "root", "p": "123", "c": 10}]
    location_counts TEXT,            -- JSON: [{"lat": 40.7, "lon": -74.0, "c": 50}]
    total_bytes INTEGER DEFAULT 0,
    ip_request_counts TEXT,          -- JSON: {"1.2.3.4": 100, "5.6.7.8": 50}
    ip_bytes_counts TEXT             -- JSON: {"1.2.3.4": 50000, "5.6.7.8": 30000}
)
"#;

// === COVERING INDEXES (optimized for stats queries) ===

// For time-based filtering and service aggregation
pub const CREATE_INDEX_TS_SERVICE: &str = 
    "CREATE INDEX IF NOT EXISTS idx_ts_service ON requests(timestamp, service)";

// For country stats aggregation
pub const CREATE_INDEX_TS_COUNTRY: &str = 
    "CREATE INDEX IF NOT EXISTS idx_ts_country ON requests(timestamp, country_code)";

// For path stats aggregation  
pub const CREATE_INDEX_TS_HTTP_PATH: &str = 
    "CREATE INDEX IF NOT EXISTS idx_ts_http_path ON requests(timestamp, http_path)";

// For location/map queries
pub const CREATE_INDEX_TS_LOCATION: &str = 
    "CREATE INDEX IF NOT EXISTS idx_ts_location ON requests(timestamp, latitude, longitude)";

// === UTILITY INDEXES ===

// For IP lookups and deduplication
pub const CREATE_INDEX_IP: &str = 
    "CREATE INDEX IF NOT EXISTS idx_requests_ip ON requests(ip)";

// For credential queries (ORDER BY id DESC with username filter)
pub const CREATE_INDEX_CREDENTIALS: &str = 
    "CREATE INDEX IF NOT EXISTS idx_credentials ON requests(username, id DESC) WHERE username IS NOT NULL";

// For IP-based queries (top IPs by requests/bandwidth)
pub const CREATE_INDEX_TS_IP: &str = 
    "CREATE INDEX IF NOT EXISTS idx_ts_ip ON requests(timestamp, ip)";
