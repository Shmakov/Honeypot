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
    password TEXT
)
"#;

pub const CREATE_INDEX_TIMESTAMP: &str = 
    "CREATE INDEX IF NOT EXISTS idx_requests_timestamp ON requests(timestamp)";

pub const CREATE_INDEX_SERVICE: &str = 
    "CREATE INDEX IF NOT EXISTS idx_requests_service ON requests(service)";

pub const CREATE_INDEX_IP: &str = 
    "CREATE INDEX IF NOT EXISTS idx_requests_ip ON requests(ip)";
