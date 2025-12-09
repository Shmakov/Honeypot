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
    user_agent TEXT
)
"#;

pub const CREATE_INDEX_TIMESTAMP: &str = 
    "CREATE INDEX IF NOT EXISTS idx_requests_timestamp ON requests(timestamp)";

pub const CREATE_INDEX_SERVICE: &str = 
    "CREATE INDEX IF NOT EXISTS idx_requests_service ON requests(service)";

pub const CREATE_INDEX_IP: &str = 
    "CREATE INDEX IF NOT EXISTS idx_requests_ip ON requests(ip)";

// Additional indexes for stats queries (important for 100K+ rows)
pub const CREATE_INDEX_COUNTRY: &str = 
    "CREATE INDEX IF NOT EXISTS idx_requests_country ON requests(country_code)";

pub const CREATE_INDEX_HTTP_PATH: &str = 
    "CREATE INDEX IF NOT EXISTS idx_requests_http_path ON requests(http_path)";

// Composite index for time-based stats queries
pub const CREATE_INDEX_TIMESTAMP_SERVICE: &str = 
    "CREATE INDEX IF NOT EXISTS idx_requests_ts_service ON requests(timestamp, service)";

// Index for location queries (map data)
pub const CREATE_INDEX_LOCATION: &str = 
    "CREATE INDEX IF NOT EXISTS idx_requests_location ON requests(timestamp, latitude, longitude)";
