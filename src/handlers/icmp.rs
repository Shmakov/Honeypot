//! ICMP ping capture using datalink layer (requires CAP_NET_RAW or root)
//! 
//! Uses pnet's datalink module to capture raw Ethernet frames and parse
//! ICMP Echo Request packets. This approach is more reliable than transport
//! layer raw sockets on some Linux configurations.

use anyhow::Result;
use std::sync::Arc;
use tracing::{info, warn, debug};

use pnet::datalink::{self, Channel, NetworkInterface};
use pnet::packet::ethernet::{EthernetPacket, EtherTypes};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::icmp::{IcmpPacket, IcmpTypes};
use pnet::packet::Packet;

use crate::db::{AttackEvent, Database};
use crate::events::EventBus;
use crate::geoip::SharedGeoIp;

/// Find the best network interface for ICMP capture
fn find_capture_interface() -> Option<NetworkInterface> {
    let interfaces = datalink::interfaces();
    
    // Prefer: up, not loopback, has IPv4, common names (eth0, ens*, enp*)
    for iface in interfaces.iter() {
        // Skip loopback and down interfaces
        if iface.is_loopback() || !iface.is_up() {
            continue;
        }
        
        // Must have at least one non-loopback IP
        let has_valid_ip = iface.ips.iter().any(|ip| !ip.ip().is_loopback());
        if !has_valid_ip {
            continue;
        }
        
        // Prefer common interface names
        let name = &iface.name;
        if name.starts_with("eth") || name.starts_with("ens") || name.starts_with("enp") 
           || name.starts_with("wlan") || name.starts_with("wlp") {
            return Some(iface.clone());
        }
    }
    
    // Fallback to any valid interface
    interfaces.into_iter()
        .find(|iface| !iface.is_loopback() && iface.is_up() && !iface.ips.is_empty())
}

/// Start the ICMP handler to capture ping requests
pub async fn start(event_bus: Arc<EventBus>, db: Arc<Database>, geoip: SharedGeoIp) -> Result<()> {
    // Find the best interface for capture
    let interface = match find_capture_interface() {
        Some(iface) => {
            info!("ICMP handler: using interface {} for capture", iface.name);
            iface
        }
        None => {
            warn!("ICMP handler disabled: no suitable network interface found");
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
            }
        }
    };

    // Create a datalink channel to receive packets
    let config = datalink::Config {
        read_timeout: Some(std::time::Duration::from_secs(1)),
        ..Default::default()
    };
    
    let (_tx, mut rx) = match datalink::channel(&interface, config)? {
        Channel::Ethernet(tx, rx) => {
            info!("ICMP handler started on {} (raw packet capture enabled)", interface.name);
            (tx, rx)
        }
        _ => {
            warn!("ICMP handler disabled: unsupported channel type for {}", interface.name);
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
        loop {
            match rx.next() {
                Ok(packet) => {
                    // Parse Ethernet frame
                    if let Some(ethernet) = EthernetPacket::new(packet) {
                        // Only process IPv4 packets
                        if ethernet.get_ethertype() != EtherTypes::Ipv4 {
                            continue;
                        }
                        
                        // Parse IPv4 header
                        if let Some(ipv4) = Ipv4Packet::new(ethernet.payload()) {
                            // Check if it's ICMP (protocol 1)
                            if ipv4.get_next_level_protocol().0 != 1 {
                                continue;
                            }
                            
                            // Parse ICMP header
                            if let Some(icmp) = IcmpPacket::new(ipv4.payload()) {
                                // Only process Echo Requests (pings to us)
                                if icmp.get_icmp_type() != IcmpTypes::EchoRequest {
                                    continue;
                                }
                                
                                let ip = ipv4.get_source().to_string();
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
                                
                                // Store and publish
                                let db = db_clone.clone();
                                let event_bus = event_bus_clone.clone();
                                let event_clone = event.clone();
                                
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
                }
                Err(e) => {
                    // Timeout is expected, only warn on real errors
                    if e.kind() != std::io::ErrorKind::TimedOut {
                        warn!("ICMP capture error: {}", e);
                    }
                }
            }
        }
    }).await?;

    Ok(())
}
