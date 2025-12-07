//! ICMP ping capture (placeholder - requires tcpdump or CAP_NET_RAW)

use anyhow::Result;
use std::sync::Arc;
use tracing::info;

use crate::db::Database;
use crate::events::EventBus;
use crate::geoip::SharedGeoIp;

pub async fn start(_event_bus: Arc<EventBus>, _db: Arc<Database>, _geoip: SharedGeoIp) -> Result<()> {
    // ICMP capture requires either:
    // 1. tcpdump installed and accessible
    // 2. CAP_NET_RAW capability for raw sockets
    // 
    // For now, this is a placeholder. Full implementation would use
    // pnet crate or spawn tcpdump subprocess.
    
    info!("ICMP handler: Disabled (requires tcpdump or CAP_NET_RAW)");
    
    // Keep task alive
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
    }
}
