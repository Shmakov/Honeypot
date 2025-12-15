//! GeoIP lookup module using MaxMind GeoLite2 database

use maxminddb::{geoip2, Reader};
use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;
use tracing::{info, warn};

/// GeoIP lookup result
#[derive(Debug, Clone)]
pub struct GeoLocation {
    pub country_code: String,
    pub latitude: f64,
    pub longitude: f64,
}

/// GeoIP reader wrapper
pub struct GeoIp {
    reader: Option<Reader<Vec<u8>>>,
}

impl GeoIp {
    /// Create a new GeoIP instance, loading the database if available
    pub fn new(database_path: &str) -> Self {
        let path = Path::new(database_path);
        
        if !path.exists() {
            warn!("GeoIP database not found at: {}", database_path);
            warn!("Download GeoLite2-City.mmdb from MaxMind and place it at: {}", database_path);
            return Self { reader: None };
        }

        match Reader::open_readfile(path) {
            Ok(reader) => {
                info!("GeoIP database loaded: {}", database_path);
                Self { reader: Some(reader) }
            }
            Err(e) => {
                warn!("Failed to load GeoIP database: {}", e);
                Self { reader: None }
            }
        }
    }

    /// Look up an IP address and return location info
    pub fn lookup(&self, ip: &str) -> Option<GeoLocation> {
        let reader = self.reader.as_ref()?;
        
        let ip_addr: IpAddr = ip.parse().ok()?;
        
        // Skip private/local IPs
        if is_private_ip(&ip_addr) {
            return None;
        }
        
        let city: geoip2::City = reader.lookup(ip_addr).ok()?;
        
        let country_code = city.country
            .as_ref()
            .and_then(|c| c.iso_code)
            .unwrap_or("XX")
            .to_string();
        
        let location = city.location.as_ref()?;
        let latitude = location.latitude?;
        let longitude = location.longitude?;
        
        Some(GeoLocation {
            country_code,
            latitude,
            longitude,
        })
    }

    /// Check if the GeoIP database is loaded
    pub fn is_available(&self) -> bool {
        self.reader.is_some()
    }
}

/// Check if an IP address is private/local
fn is_private_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => {
            ipv4.is_private() 
            || ipv4.is_loopback() 
            || ipv4.is_link_local()
            || ipv4.is_broadcast()
            || ipv4.is_documentation()
            || ipv4.is_unspecified()
        }
        IpAddr::V6(ipv6) => {
            ipv6.is_loopback() 
            || ipv6.is_unspecified()
        }
    }
}

/// Thread-safe GeoIP wrapper
pub type SharedGeoIp = Arc<GeoIp>;
