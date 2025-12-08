//! Protocol handlers module

pub mod tcp;
pub mod ssh;
pub mod ftp;
pub mod telnet;
pub mod icmp;

use anyhow::Result;
use std::sync::Arc;
use tracing::info;

use crate::config::Config;
use crate::db::Database;
use crate::events::EventBus;
use crate::geoip::SharedGeoIp;

/// TCP ports to listen on (excludes 80/443 used by web server)
pub const TCP_PORTS: &[(u16, &str)] = &[
    (21, "ftp"), (22, "ssh"), (23, "telnet"), (25, "smtp"), (53, "dns"),
    (81, "http"), (110, "pop3"), (111, "rpcbind"), (135, "msrpc"),
    (139, "netbios"), (143, "imap"), (445, "smb"), (465, "smtps"),
    (514, "shell"), (587, "submission"), (993, "imaps"), (995, "pop3s"),
    (1433, "mssql"), (1521, "oracle"), (1723, "pptp"), (2049, "nfs"),
    (3306, "mysql"), (3389, "rdp"), (5432, "postgresql"), (5900, "vnc"),
    (5901, "vnc"), (6379, "redis"), (6667, "irc"), (8000, "http-alt"),
    (8080, "http-proxy"), (8443, "https-alt"), (8888, "http-alt"),
    (9000, "php-fpm"), (9090, "prometheus"), (9200, "elasticsearch"),
    (11211, "memcached"), (27017, "mongodb"),
    // Additional common ports
    (7, "echo"), (13, "daytime"), (17, "qotd"), (19, "chargen"), (26, "rsftp"),
    (37, "time"), (79, "finger"), (82, "xfer"), (88, "kerberos"), (106, "pop3pw"),
    (113, "ident"), (119, "nntp"), (144, "news"), (179, "bgp"), (199, "smux"),
    (389, "ldap"), (427, "svrloc"), (444, "snpp"), (513, "login"), (515, "printer"),
    (543, "klogin"), (544, "kshell"), (548, "afp"), (554, "rtsp"), (631, "ipp"),
    (646, "ldp"), (873, "rsync"), (990, "ftps"), (1000, "cadlock"), (1024, "kdm"),
    (1025, "nfs-or-iis"), (1026, "lsa"), (1027, "iis"), (1028, "unknown"),
    (1029, "ms-lsa"), (1030, "iad1"), (1041, "danf-ak2"), (1048, "neod2"),
    (1049, "td-postman"), (1053, "remote-as"), (1054, "brvread"), (1056, "vfo"),
    (1064, "jstel"), (1065, "syscomlan"), (1110, "nfsd-status"), (1720, "h323"),
    (1755, "wms"), (1801, "msmq"), (1900, "upnp"), (2000, "cisco-sccp"),
    (2001, "dc"), (2103, "zephyr-clt"), (2107, "msmq-mgmt"), (2121, "ftp-proxy"),
    (2717, "pn-requester"), (2967, "symantec-av"), (3000, "ppp"), (3001, "nessus"),
    (3128, "squid-http"), (3703, "adobeserver"), (3986, "mapper-ws"), (4899, "radmin"),
    (5000, "upnp"), (5001, "commplex"), (5009, "airport-admin"), (5050, "mmcc"),
    (5051, "ida-agent"), (5060, "sip"), (5101, "admdog"), (5357, "wsdapi"),
    (5631, "pcanywheredata"), (5666, "nrpe"), (5800, "vnc-http"), (6000, "x11"),
    (6001, "x11"), (6004, "x11"), (6646, "unknown"), (7070, "realserver"),
    (8008, "http"), (8009, "ajp13"), (8031, "unknown"), (8081, "blackice"),
    (9100, "jetdirect"), (9999, "abyss"), (10000, "webmin"), (10010, "rxapi"),
    (32768, "filenet-tms"), (49152, "unknown"), (49153, "unknown"),
    (49154, "unknown"), (49155, "unknown"), (49156, "unknown"), (49157, "unknown"),
    // Additional high-value ports
    (2222, "ssh-alt"), (2375, "docker"), (2376, "docker-tls"), (4000, "remoteanything"),
    (4443, "pharos"), (5555, "freeciv"), (6006, "x11"), (7001, "weblogic"),
    (7002, "weblogic"), (8001, "http-alt"), (8082, "http-alt"), (8083, "http-alt"),
    (8084, "http-alt"), (8085, "http-alt"), (8086, "influxdb"), (8087, "http-alt"),
    (8089, "splunk"), (9001, "tor"), (9002, "dynamid"), (9003, "unknown"),
    // Complete to 128 ports
    (4444, "krb524"), (5222, "xmpp"), (5269, "xmpp-server"), (8088, "radan-http"),
    (8181, "http-alt"), (8880, "cddbp-alt"), (9080, "glrpc"), (9443, "tungsten-https"),
];

/// Start all protocol handlers
pub async fn start_all(config: &Config, event_bus: EventBus, db: Database, geoip: SharedGeoIp) -> Result<()> {
    let config = Arc::new(config.clone());
    let event_bus = Arc::new(event_bus);
    let db = Arc::new(db);

    // Start TCP listeners for each port (skip 80/443 as those will be web server)
    for (port, service) in TCP_PORTS {
        let port = *port;
        let service = service.to_string();
        let config = config.clone();
        let event_bus = event_bus.clone();
        let db = db.clone();
        let geoip = geoip.clone();

        tokio::spawn(async move {
            match service.as_str() {
                "ssh" => {
                    if let Err(e) = ssh::start(port, config, event_bus, db, geoip).await {
                        tracing::debug!("SSH handler on port {} failed: {}", port, e);
                    }
                }
                "ftp" => {
                    if let Err(e) = ftp::start(port, config, event_bus, db, geoip).await {
                        tracing::debug!("FTP handler on port {} failed: {}", port, e);
                    }
                }
                "telnet" => {
                    if let Err(e) = telnet::start(port, config, event_bus, db, geoip).await {
                        tracing::debug!("Telnet handler on port {} failed: {}", port, e);
                    }
                }
                _ => {
                    if let Err(e) = tcp::start(port, &service, config, event_bus, db, geoip).await {
                        tracing::debug!("{} handler on port {} failed: {}", service, port, e);
                    }
                }
            }
        });
    }

    // ICMP handler (optional, requires CAP_NET_RAW)
    let event_bus_icmp = event_bus.clone();
    let db_icmp = db.clone();
    let geoip_icmp = geoip.clone();
    tokio::spawn(async move {
        if let Err(e) = icmp::start(event_bus_icmp, db_icmp, geoip_icmp).await {
            tracing::debug!("ICMP handler failed: {}", e);
        }
    });

    info!("Started {} protocol handlers", TCP_PORTS.len());
    Ok(())
}
