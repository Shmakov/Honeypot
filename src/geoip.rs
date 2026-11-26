//! GeoIP lookup module using MaxMind GeoLite2 City and optional ASN databases

use maxminddb::{geoip2, Reader};
use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;
use tracing::{info, warn};

/// GeoIP City lookup result
#[derive(Debug, Clone)]
pub struct GeoLocation {
    pub country_code: String,
    pub latitude: f64,
    pub longitude: f64,
}

/// GeoIP ASN lookup result
#[derive(Debug, Clone)]
pub struct AsnInfo {
    pub number: u32,
    pub organization: String,
}

/// GeoIP reader wrapper (City + optional ASN)
pub struct GeoIp {
    reader: Option<Reader<Vec<u8>>>,
    asn_reader: Option<Reader<Vec<u8>>>,
}

impl GeoIp {
    /// Create a new GeoIP instance, loading City and optional ASN databases if available
    pub fn new(database_path: &str, asn_database_path: &str) -> Self {
        let reader = Self::open_reader(database_path, "GeoIP City", true);
        let asn_reader = if asn_database_path.is_empty() {
            None
        } else {
            Self::open_reader(asn_database_path, "GeoIP ASN", false)
        };

        Self { reader, asn_reader }
    }

    fn open_reader(path_str: &str, label: &str, warn_missing: bool) -> Option<Reader<Vec<u8>>> {
        let path = Path::new(path_str);
        if !path.exists() {
            if warn_missing {
                warn!("{} database not found at: {}", label, path_str);
                warn!(
                    "Download GeoLite2-City.mmdb from MaxMind and place it at: {}",
                    path_str
                );
            } else {
                info!("{} database not found at {} (ASN enrichment disabled)", label, path_str);
            }
            return None;
        }

        match Reader::open_readfile(path) {
            Ok(reader) => {
                info!("{} database loaded: {}", label, path_str);
                Some(reader)
            }
            Err(e) => {
                warn!("Failed to load {} database: {}", label, e);
                None
            }
        }
    }

    /// Look up an IP address and return City location info
    pub fn lookup(&self, ip: &str) -> Option<GeoLocation> {
        let reader = self.reader.as_ref()?;
        let ip_addr: IpAddr = ip.parse().ok()?;

        if is_private_ip(&ip_addr) {
            return None;
        }

        let city: geoip2::City = reader.lookup(ip_addr).ok()?.decode().ok()??;

        let country_code = city.country.iso_code.unwrap_or("XX").to_string();
        let latitude = city.location.latitude?;
        let longitude = city.location.longitude?;

        Some(GeoLocation {
            country_code,
            latitude,
            longitude,
        })
    }

    /// Look up an IP address and return ASN number & organization
    pub fn lookup_asn(&self, ip: &str) -> Option<AsnInfo> {
        let reader = self.asn_reader.as_ref()?;
        let ip_addr: IpAddr = ip.parse().ok()?;

        if is_private_ip(&ip_addr) {
            return None;
        }

        let asn: geoip2::Asn = reader.lookup(ip_addr).ok()?.decode().ok()??;
        let number = asn.autonomous_system_number?;
        let organization = asn
            .autonomous_system_organization
            .unwrap_or("Unknown")
            .to_string();

        Some(AsnInfo {
            number,
            organization,
        })
    }

    /// Check if the GeoIP City database is loaded
    pub fn is_available(&self) -> bool {
        self.reader.is_some()
    }

    /// Check if the GeoIP ASN database is loaded
    pub fn is_asn_available(&self) -> bool {
        self.asn_reader.is_some()
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
        IpAddr::V6(ipv6) => ipv6.is_loopback() || ipv6.is_unspecified(),
    }
}

/// Thread-safe GeoIP wrapper
pub type SharedGeoIp = Arc<GeoIp>;
