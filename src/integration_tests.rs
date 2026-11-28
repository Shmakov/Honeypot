use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

use crate::config::*;
use crate::db::{start_write_buffer, Database};
use crate::events::EventBus;
use crate::geoip::GeoIp;
use crate::handlers;
use crate::limits::ConnectionLimiter;

struct TempTestEnv {
    db_path: PathBuf,
    db: Database,
    config: Config,
    event_bus: EventBus,
    geoip: Arc<GeoIp>,
    limiter: Arc<ConnectionLimiter>,
}

impl Drop for TempTestEnv {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.db_path);
        let _ = std::fs::remove_file(format!("{}-wal", self.db_path.display()));
        let _ = std::fs::remove_file(format!("{}-shm", self.db_path.display()));
    }
}

async fn setup_env() -> (TempTestEnv, crate::db::WriteSender) {
    let db_path =
        std::env::temp_dir().join(format!("honeypot_int_{}.db", uuid::Uuid::new_v4()));
    let config = Config {
        server: ServerConfig {
            host: "127.0.0.1".to_string(),
            http_port: 0,
            https_port: 0,
            tls_cert: String::new(),
            tls_key: String::new(),
            public_url: String::new(),
            max_ports: 0,
        },
        database: DatabaseConfig {
            driver: "sqlite".to_string(),
            url: db_path.to_string_lossy().into_owned(),
            cache_size_mb: 16,
            retention_days: 30,
        },
        geoip: GeoIpConfig {
            database: "nonexistent_city.mmdb".to_string(),
            asn_database: "nonexistent_asn.mmdb".to_string(),
        },
        logging: LoggingConfig {
            level: "info".to_string(),
        },
        emulation: EmulationConfig {
            ssh_banner: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4".to_string(),
            ftp_banner: "220 FTP ready".to_string(),
            mysql_version: "8.0.36-0ubuntu0.22.04.1".to_string(),
            hostname: "prod-web-01".to_string(),
            persona: "ubuntu".to_string(),
        },
        map: MapConfig::default(),
        limits: LimitsConfig::default(),
    };

    let db = Database::new(&config.database).await.unwrap();
    db.run_migrations().await.unwrap();
    let db_arc = Arc::new(db.clone());
    let write_tx = start_write_buffer(db_arc, 1000);
    let (tx, _) = tokio::sync::broadcast::channel(100);
    let event_bus = EventBus::new(tx);
    let geoip = Arc::new(GeoIp::new(
        &config.geoip.database,
        &config.geoip.asn_database,
    ));
    let limiter = ConnectionLimiter::new(20, 200);

    (
        TempTestEnv {
            db_path,
            db,
            config,
            event_bus,
            geoip,
            limiter,
        },
        write_tx,
    )
}

async fn free_port() -> u16 {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    listener.local_addr().unwrap().port()
}

async fn connect_retry(port: u16) -> TcpStream {
    for _ in 0..30 {
        if let Ok(stream) = TcpStream::connect(("127.0.0.1", port)).await {
            return stream;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    panic!("failed to connect to port {}", port);
}

#[tokio::test]
async fn integration_ssh_sends_configured_banner() {
    let (env, write_tx) = setup_env().await;
    let port = free_port().await;
    let cfg = Arc::new(env.config.clone());
    let bus = Arc::new(env.event_bus.clone());
    let geo = env.geoip.clone();
    let lim = env.limiter.clone();

    let handle = tokio::spawn(async move {
        let _ = handlers::ssh::start(port, "ssh-alt", cfg, bus, write_tx, geo, lim).await;
    });

    let mut stream = connect_retry(port).await;
    let mut buf = [0u8; 128];
    let n = tokio::time::timeout(std::time::Duration::from_secs(3), stream.read(&mut buf))
        .await
        .unwrap()
        .unwrap();
    let banner = String::from_utf8_lossy(&buf[..n]);
    assert!(
        banner.starts_with("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4"),
        "expected configured ssh_banner, got: {}",
        banner
    );
    drop(stream);
    handle.abort();
}

#[tokio::test]
async fn integration_redis_captures_auth_and_rce_tag() {
    let (env, write_tx) = setup_env().await;
    let port = free_port().await;
    let cfg = Arc::new(env.config.clone());
    let bus = Arc::new(env.event_bus.clone());
    let geo = env.geoip.clone();
    let lim = env.limiter.clone();

    let mut rx = env.event_bus.subscribe();
    let handle = tokio::spawn(async move {
        let _ = handlers::redis::start(port, cfg, bus, write_tx, geo, lim).await;
    });

    let mut stream = connect_retry(port).await;
    stream
        .write_all(b"*2\r\n$4\r\nAUTH\r\n$9\r\nredispass\r\nPING\r\nSLAVEOF 9.9.9.9 6379\r\nQUIT\r\n")
        .await
        .unwrap();
    let mut resp = vec![0u8; 256];
    let n = stream.read(&mut resp).await.unwrap();
    let resp_str = String::from_utf8_lossy(&resp[..n]);
    assert!(resp_str.contains("+OK"));
    assert!(resp_str.contains("+PONG"));
    drop(stream);

    let ev = tokio::time::timeout(std::time::Duration::from_secs(3), rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(ev.service, "redis");
    assert_eq!(ev.port, port);
    assert_eq!(ev.username.as_deref(), Some("default"));
    assert_eq!(ev.password.as_deref(), Some("redispass"));
    assert!(ev.tags.contains(&"redis-rce".to_string()));

    // Verify write_buffer flushes to SQLite cleanly
    tokio::time::sleep(std::time::Duration::from_millis(350)).await;
    let recent = env.db.get_recent_events(5).await.unwrap();
    assert!(!recent.is_empty());
    assert_eq!(recent[0].service, "redis");
    handle.abort();
}

#[tokio::test]
async fn integration_smtp_captures_auth_plain() {
    let (env, write_tx) = setup_env().await;
    let port = free_port().await;
    let cfg = Arc::new(env.config.clone());
    let bus = Arc::new(env.event_bus.clone());
    let geo = env.geoip.clone();
    let lim = env.limiter.clone();

    let mut rx = env.event_bus.subscribe();
    let handle = tokio::spawn(async move {
        let _ = handlers::smtp::start(port, "smtp", cfg, bus, write_tx, geo, lim).await;
    });

    let stream = connect_retry(port).await;
    let (r, mut w) = stream.into_split();
    let mut reader = BufReader::new(r);
    let mut line = String::new();
    reader.read_line(&mut line).await.unwrap();
    assert!(line.contains("220 mail.prod-web-01"));

    // "\0alice\0hunter2" in base64 -> AGFsaWNlAGh1bnRlcjI=
    w.write_all(b"EHLO scanner\r\nAUTH PLAIN AGFsaWNlAGh1bnRlcjI=\r\nQUIT\r\n")
        .await
        .unwrap();
    drop(w);

    let ev = tokio::time::timeout(std::time::Duration::from_secs(3), rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(ev.username.as_deref(), Some("alice"));
    assert_eq!(ev.password.as_deref(), Some("hunter2"));
    assert!(ev.tags.contains(&"smtp-auth".to_string()));
    handle.abort();
}

#[tokio::test]
async fn integration_mysql_and_postgres_and_rdp_and_ollama() {
    let (env, write_tx) = setup_env().await;

    // 1. MySQL
    let mysql_port = free_port().await;
    let mut rx = env.event_bus.subscribe();
    let h_mysql = tokio::spawn({
        let cfg = Arc::new(env.config.clone());
        let bus = Arc::new(env.event_bus.clone());
        let w = write_tx.clone();
        let g = env.geoip.clone();
        let l = env.limiter.clone();
        async move {
            let _ = handlers::mysql::start(mysql_port, "mysql", cfg, bus, w, g, l).await;
        }
    });
    let mut s = connect_retry(mysql_port).await;
    let mut hs = [0u8; 256];
    let n = s.read(&mut hs).await.unwrap();
    assert!(String::from_utf8_lossy(&hs[..n]).contains("8.0.36"));
    // Send minimal HandshakeResponse41 packet (36-byte prefix + "dbadmin\0")
    let mut resp = vec![0u8; 4];
    resp.extend_from_slice(&[0u8; 32]); // cap + max + charset + reserved
    resp.extend_from_slice(b"dbadmin\0");
    let pkt_len = (resp.len() - 4) as u32;
    resp[0] = (pkt_len & 0xff) as u8;
    resp[3] = 1;
    s.write_all(&resp).await.unwrap();
    let mut err_buf = [0u8; 128];
    let en = s.read(&mut err_buf).await.unwrap();
    assert!(String::from_utf8_lossy(&err_buf[..en]).contains("Access denied"));
    drop(s);
    let ev = tokio::time::timeout(std::time::Duration::from_secs(3), rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(ev.username.as_deref(), Some("dbadmin"));
    h_mysql.abort();

    // 2. Postgres
    let pg_port = free_port().await;
    let h_pg = tokio::spawn({
        let cfg = Arc::new(env.config.clone());
        let bus = Arc::new(env.event_bus.clone());
        let w = write_tx.clone();
        let g = env.geoip.clone();
        let l = env.limiter.clone();
        async move {
            let _ = handlers::postgres::start(pg_port, "postgresql", cfg, bus, w, g, l).await;
        }
    });
    let mut ps = connect_retry(pg_port).await;
    let mut startup = Vec::new();
    let mut body = Vec::new();
    body.extend_from_slice(&196608u32.to_be_bytes());
    body.extend_from_slice(b"user\0pgroot\0database\0prod\0\0");
    startup.extend_from_slice(&((body.len() + 4) as u32).to_be_bytes());
    startup.extend_from_slice(&body);
    ps.write_all(&startup).await.unwrap();
    let mut auth_buf = [0u8; 9];
    ps.read_exact(&mut auth_buf).await.unwrap();
    assert_eq!(auth_buf[0], b'R');
    let mut pwd_msg = vec![b'p'];
    let pwd = b"pgsecret\0";
    pwd_msg.extend_from_slice(&((4 + pwd.len()) as u32).to_be_bytes());
    pwd_msg.extend_from_slice(pwd);
    ps.write_all(&pwd_msg).await.unwrap();
    drop(ps);
    let ev = tokio::time::timeout(std::time::Duration::from_secs(3), rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(ev.username.as_deref(), Some("pgroot"));
    assert_eq!(ev.password.as_deref(), Some("pgsecret"));
    h_pg.abort();

    // 3. RDP
    let rdp_port = free_port().await;
    let h_rdp = tokio::spawn({
        let cfg = Arc::new(env.config.clone());
        let bus = Arc::new(env.event_bus.clone());
        let w = write_tx.clone();
        let g = env.geoip.clone();
        let l = env.limiter.clone();
        async move {
            let _ = handlers::rdp::start(rdp_port, "rdp", cfg, bus, w, g, l).await;
        }
    });
    let mut rs = connect_retry(rdp_port).await;
    let mut rdp_req = vec![0x03, 0x00, 0x00, 0x2c, 0x27, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00];
    rdp_req.extend_from_slice(b"Cookie: mstshash=admin\r\n");
    rs.write_all(&rdp_req).await.unwrap();
    let mut rdp_cc = [0u8; 19];
    rs.read_exact(&mut rdp_cc).await.unwrap();
    assert_eq!(rdp_cc[5], 0xd0);
    drop(rs);
    let ev = tokio::time::timeout(std::time::Duration::from_secs(3), rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(ev.request.contains("mstshash=admin"));
    assert!(ev.username.is_none());
    h_rdp.abort();

    // 4. Ollama HTTP API
    let ol_port = free_port().await;
    let h_ol = tokio::spawn({
        let cfg = Arc::new(env.config.clone());
        let bus = Arc::new(env.event_bus.clone());
        let w = write_tx.clone();
        let g = env.geoip.clone();
        let l = env.limiter.clone();
        async move {
            let _ = handlers::http_api::start(ol_port, "ollama", cfg, bus, w, g, l).await;
        }
    });
    let mut os = connect_retry(ol_port).await;
    os.write_all(b"GET /api/tags HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .unwrap();
    let mut o_resp = vec![0u8; 512];
    let on = os.read(&mut o_resp).await.unwrap();
    assert!(String::from_utf8_lossy(&o_resp[..on]).contains("llama3.2"));
    drop(os);
    let ev = tokio::time::timeout(std::time::Duration::from_secs(3), rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(ev.service, "ollama");
    assert!(ev.tags.contains(&"llm-probe".to_string()));
    h_ol.abort();
}
