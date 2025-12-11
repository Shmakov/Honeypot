//! ICMP ping capture using raw sockets (requires CAP_NET_RAW or root)

use anyhow::Result;
use std::sync::Arc;
use tracing::{info, warn, debug};

use pnet::packet::icmp::{IcmpPacket, IcmpTypes};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::Packet;
use pnet::transport::{transport_channel, TransportChannelType};

use crate::db::{AttackEvent, Database};
use crate::events::EventBus;
use crate::geoip::SharedGeoIp;

/// Start the ICMP handler to capture ping requests
pub async fn start(event_bus: Arc<EventBus>, db: Arc<Database>, geoip: SharedGeoIp) -> Result<()> {
    // Try to create transport channel for ICMP
    // This requires CAP_NET_RAW capability or root privileges
    let protocol = TransportChannelType::Layer3(IpNextHeaderProtocols::Icmp);
    
    let (_, mut rx) = match transport_channel(4096, protocol) {
        Ok((tx, rx)) => {
            info!("ICMP handler started (raw socket capture enabled)");
            (tx, rx)
        }
        Err(e) => {
            // Common case: not running as root or missing CAP_NET_RAW
            warn!("ICMP handler disabled: {} (requires root or CAP_NET_RAW)", e);
            // Keep task alive but don't process
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
            }
        }
    };

    // Use blocking task for the synchronous pnet receiver
    let event_bus_clone = event_bus.clone();
    let db_clone = db.clone();
    let geoip_clone = geoip.clone();
    
    tokio::task::spawn_blocking(move || {
        let mut iter = pnet::transport::icmp_packet_iter(&mut rx);
        
        loop {
            match iter.next() {
                Ok((packet, addr)) => {
                    // Only process Echo Requests (pings)
                    if let Some(icmp) = IcmpPacket::new(packet.packet()) {
                        if icmp.get_icmp_type() == IcmpTypes::EchoRequest {
                            let ip = addr.to_string();
                            debug!("ICMP Echo Request from {}", ip);
                            
                            // Create event
                            let request = format!("ICMP Echo Request (ping) from {}", ip);
                            let mut event = AttackEvent::new(
                                ip.clone(),
                                "icmp".to_string(),
                                0, // ICMP doesn't use ports
                                request,
                            );
                            
                            // Add GeoIP info
                            if let Some(loc) = geoip_clone.lookup(&ip) {
                                event = event.with_geo(loc.country_code, loc.latitude, loc.longitude);
                            }
                            
                            // Store and publish (blocking context)
                            let db = db_clone.clone();
                            let event_bus = event_bus_clone.clone();
                            let event_clone = event.clone();
                            
                            // Use a runtime handle to run async code from blocking context
                            if let Ok(handle) = tokio::runtime::Handle::try_current() {
                                handle.spawn(async move {
                                    if let Err(e) = db.insert_event(&event_clone).await {
                                        warn!("Failed to store ICMP event: {}", e);
                                    }
                                    event_bus.publish(event_clone);
                                });
                            }
                        }
                    }
                }
                Err(e) => {
                    warn!("ICMP receive error: {}", e);
                    // Brief pause before retrying
                    std::thread::sleep(std::time::Duration::from_millis(100));
                }
            }
        }
    }).await?;

    Ok(())
}
