# Honeypot 🍯

A modern, low-interaction network honeypot with real-time attack visualization.

![Rust](https://img.shields.io/badge/rust-1.70%2B-orange)
![License](https://img.shields.io/badge/license-MIT-blue)

## Features

- **Real-time Dashboard** - Live attack feed with SSE streaming
- **Protocol Emulation** - SSH, FTP, Telnet banners and basic responses
- **120+ Port Monitoring** - Listens on common attack targets
- **GeoIP Integration** - Attack origin mapping with MaxMind
- **Credential Capture** - Logs SSH/FTP/Telnet login attempts
- **Payload Collection** - Stores and displays raw attack payloads
- **Statistics Page** - Charts and tables for attack analysis
- **Mobile Responsive** - Modern dark theme with glassmorphism

## Quick Start

```bash
# Clone and build
git clone <repo>
cd honeypot
cargo build --release

# Download GeoIP database (optional)
# Get GeoLite2-City.mmdb from MaxMind and place in data/

# Run (requires elevated permissions for low ports)
sudo ./target/release/honeypot
```

## Configuration

Edit `config.toml`:

```toml
[server]
host = "0.0.0.0"
http_port = 80
public_url = "https://honeypot.example.com"  # for redirects

[database]
driver = "sqlite"
url = "honeypot.db"

[geoip]
database = "data/GeoLite2-City.mmdb"

[emulation]
ssh_banner = "SSH-2.0-OpenSSH_8.4p1"
ftp_banner = "220 FTP Server ready"
mysql_version = "5.7.36"
```

### Environment Variables

All config values can be overridden via environment variables. Prefix: `HONEYPOT_`, nested fields use `__`:

```bash
# Examples
export HONEYPOT_SERVER__PUBLIC_URL="https://honeypot.example.com"
export HONEYPOT_DATABASE__URL="honeypot.db"
export HONEYPOT_GEOIP__DATABASE="/path/to/GeoLite2-City.mmdb"
```

See `.env.example` for all available options.

## GeoIP Setup

1. Register at [MaxMind](https://www.maxmind.com/en/geolite2/signup)
2. Download GeoLite2-City.mmdb
3. Place in `data/GeoLite2-City.mmdb`
4. Restart the honeypot

## Ports Monitored

The honeypot listens on 120+ common ports including:
- **Services**: SSH (22), FTP (21), Telnet (23), SMTP (25)
- **Databases**: MySQL (3306), PostgreSQL (5432), MongoDB (27017), Redis (6379)
- **Web**: HTTP (80, 8080, 8000), HTTPS (443, 8443)
- **Remote**: RDP (3389), VNC (5900), X11 (6000)
- **And many more...**

## API Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /` | Dashboard |
| `GET /stats` | Statistics page |
| `GET /events` | SSE event stream |
| `GET /api/recent` | Recent events + credentials |
| `GET /api/stats?hours=24` | Attack statistics |
| `GET /api/countries?hours=24` | Country breakdown |

## Deployment

### Docker (coming soon)

```bash
docker build -t honeypot .
docker run -p 80:80 -p 21-9999:21-9999 honeypot
```

### GCP/Linux

```bash
# Build release binary
cargo build --release

# Set capability to bind low ports without root
sudo setcap 'cap_net_bind_service=+ep' ./target/release/honeypot

# Run
./target/release/honeypot
```

### Systemd Service

```ini
[Unit]
Description=Honeypot
After=network.target

[Service]
Type=simple
ExecStart=/opt/honeypot/honeypot
WorkingDirectory=/opt/honeypot
Restart=always

[Install]
WantedBy=multi-user.target
```

## Tech Stack

- **Backend**: Rust, Axum, SQLite, tokio
- **Frontend**: Vanilla JS, CSS (glassmorphism)
- **Real-time**: Server-Sent Events (SSE)
- **GeoIP**: MaxMind GeoLite2

## License

MIT
