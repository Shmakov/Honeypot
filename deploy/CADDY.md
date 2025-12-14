# Caddy TLS Setup

Caddy provides automatic HTTPS with Let's Encrypt for the honeypot dashboard.

## Architecture

```
Port 80  → Honeypot (HTTP attacks)
Port 443 → Caddy → Honeypot :80 (HTTPS dashboard)
```

## Install (Debian/Ubuntu)

```bash
sudo apt install -y debian-keyring debian-archive-keyring apt-transport-https curl
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | sudo gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | sudo tee /etc/apt/sources.list.d/caddy-stable.list
sudo apt update
sudo apt install caddy
```

## Configure

### 1. Caddy

```bash
sudo cp /opt/honeypot/deploy/Caddyfile /etc/caddy/Caddyfile
sudo nano /etc/caddy/Caddyfile  # Replace honeypot.example.com
```

### 2. Honeypot

Set the public URL in `/opt/honeypot/.env`:

```bash
HONEYPOT_SERVER__PUBLIC_URL=https://honeypot.example.com
```

### 3. Start

```bash
sudo systemctl restart honeypot
sudo systemctl enable --now caddy
```

## Verify

```bash
sudo systemctl status caddy
curl -I https://honeypot.example.com
```

## Troubleshooting

```bash
# Caddy logs
sudo journalctl -u caddy -f

# Check honeypot is running
ss -tlnp | grep 80

# DNS check
dig honeypot.example.com
```
