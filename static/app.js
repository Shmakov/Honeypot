/**
 * Honeypot Dashboard - Main JavaScript
 * Real-time attack feed using SSE
 */

class HoneypotDashboard {
    constructor() {
        this.eventSource = null;
        this.isPaused = false;
        this.sessionCount = 0;
        this.totalCount = 0;
        this.maxRows = 100;
        this.events = [];

        this.init();
    }

    init() {
        this.setupElements();
        this.loadInitialData();
        this.connectSSE();
        this.setupEventListeners();
    }

    setupElements() {
        this.feedBody = document.getElementById('feedBody');
        this.totalRequests = document.getElementById('totalRequests');
        this.sessionRequests = document.getElementById('sessionRequests');
        this.recentCredentials = document.getElementById('recentCredentials');
        this.connectionStatus = document.getElementById('connectionStatus');
        this.modalOverlay = document.getElementById('modalOverlay');
        this.mapOverlay = document.getElementById('mapOverlay');
    }

    async loadInitialData() {
        try {
            const response = await fetch('/api/recent');
            const data = await response.json();

            this.totalCount = data.total;
            this.totalRequests.textContent = this.formatNumber(this.totalCount);

            // Show recent credentials
            this.updateCredentialsList(data.credentials);

            // Populate table with recent events (oldest first so newest ends up on top)
            if (data.events && data.events.length > 0) {
                const reversedEvents = [...data.events].reverse();
                for (const event of reversedEvents) {
                    this.addTableRow(event, false); // false = no animation
                }
            }
        } catch (error) {
            console.error('Failed to load initial data:', error);
        }
    }

    connectSSE() {
        this.updateConnectionStatus('connecting');

        // Reset retry count on connect attempt
        if (!this.retryCount) this.retryCount = 0;

        this.eventSource = new EventSource('/events');

        this.eventSource.onopen = () => {
            this.updateConnectionStatus('connected');
            this.retryCount = 0; // Reset on successful connection
        };

        this.eventSource.addEventListener('attack', (event) => {
            if (!this.isPaused) {
                const data = JSON.parse(event.data);
                this.handleAttackEvent(data);
            }
        });

        this.eventSource.onerror = () => {
            this.updateConnectionStatus('error');
            this.eventSource.close(); // Explicitly close to prevent browser retries

            // Exponential backoff: 5s, 10s, 20s, 40s... max 60s
            this.retryCount = (this.retryCount || 0) + 1;
            const delay = Math.min(5000 * Math.pow(2, this.retryCount - 1), 60000);

            console.log(`Connection failed. Retrying in ${delay / 1000}s (attempt ${this.retryCount})`);
            setTimeout(() => this.connectSSE(), delay);
        };
    }

    handleAttackEvent(event) {
        this.sessionCount++;
        this.totalCount++;

        // Update counters
        this.sessionRequests.textContent = this.sessionCount;
        this.totalRequests.textContent = this.formatNumber(this.totalCount);

        // Add to events array
        this.events.unshift(event);
        if (this.events.length > this.maxRows) {
            this.events.pop();
        }

        // Add row to table
        this.addTableRow(event);

        // Update credentials if present
        if (event.username) {
            this.addCredential(event.username, event.password || '');
        }

        // Show on map (if GeoIP data available)
        if (event.latitude && event.longitude) {
            this.showAttackOnMap(event.latitude, event.longitude, event.ip, event.service);
        }
    }

    addTableRow(event, animate = true) {
        const row = document.createElement('tr');
        if (animate) {
            row.className = 'new-row';
        }
        row.dataset.event = JSON.stringify(event);

        const time = new Date(event.timestamp).toLocaleTimeString();
        const service = event.service || 'unknown';
        const serviceClass = this.getServiceClass(service);

        // Show only first line of request (e.g., "GET /path") not headers
        const requestFirstLine = (event.request || '').split('\n')[0];

        row.innerHTML = `
            <td class="px-6 py-3 text-sm text-gray-400">${time}</td>
            <td class="px-6 py-3 font-mono text-sm text-gray-300">${this.escapeHtml(event.ip)}</td>
            <td class="px-6 py-3 text-sm text-gray-400">${this.countryToFlag(event.country_code)} ${event.country_code || '-'}</td>
            <td class="px-6 py-3"><span class="px-2.5 py-1 rounded-full text-xs font-medium ${serviceClass}">${service}</span></td>
            <td class="px-6 py-3 text-sm text-gray-400 font-mono truncate max-w-xs" title="${this.escapeHtml(requestFirstLine)}">${this.escapeHtml(this.truncate(requestFirstLine, 50))}</td>
        `;

        row.addEventListener('click', () => this.showEventDetails(event));

        // Insert at top
        if (this.feedBody.firstChild) {
            this.feedBody.insertBefore(row, this.feedBody.firstChild);
        } else {
            this.feedBody.appendChild(row);
        }

        // Remove old rows
        while (this.feedBody.children.length > this.maxRows) {
            this.feedBody.removeChild(this.feedBody.lastChild);
        }

        // Remove animation class after animation completes
        if (animate) {
            setTimeout(() => row.classList.remove('new-row'), 300);
        }
    }

    getServiceClass(service) {
        const map = {
            'ssh': 'service-ssh',
            'ftp': 'service-ftp',
            'telnet': 'service-telnet',
            'http': 'service-http',
            'https': 'service-http',
            'http-proxy': 'service-http',
            'mysql': 'service-mysql',
        };
        return map[service.toLowerCase()] || 'service-default';
    }

    // Convert country code to flag emoji (e.g., 'US' -> 🇺🇸)
    countryToFlag(countryCode) {
        if (!countryCode || countryCode.length !== 2) return '';
        const code = countryCode.toUpperCase();
        // Each letter is offset from 'A' (65) to regional indicator 'A' (127462)
        const offset = 127397; // 127462 - 65
        return String.fromCodePoint(...[...code].map(c => c.charCodeAt(0) + offset));
    }

    showEventDetails(event) {
        document.getElementById('detailIp').textContent = event.ip;
        document.getElementById('detailCountry').textContent = event.country_code || 'Unknown';
        document.getElementById('detailService').textContent = event.service;
        document.getElementById('detailPort').textContent = event.port || '-';
        document.getElementById('detailTime').textContent = new Date(event.timestamp).toLocaleString();

        // Credentials
        const credRow = document.getElementById('credentialsRow');
        if (event.username) {
            credRow.style.display = 'flex';
            document.getElementById('detailCredentials').textContent = `${event.username}:${event.password || ''}`;
        } else {
            credRow.style.display = 'none';
        }

        // Request (contains method, path, headers)
        const requestEl = document.getElementById('detailRequest');
        if (event.request) {
            requestEl.textContent = event.request;
        } else {
            requestEl.textContent = 'No request data';
        }

        // Payload (hex-encoded body)
        const payloadSection = document.getElementById('payloadSection');
        const payloadEl = document.getElementById('detailPayload');
        if (event.payload) {
            payloadSection.style.display = 'block';
            try {
                // Decode hex to string
                const decoded = this.hexDecode(event.payload);
                payloadEl.textContent = decoded;
            } catch {
                // If hex decode fails, show as-is
                payloadEl.textContent = event.payload;
            }
        } else {
            payloadSection.style.display = 'none';
        }

        this.modalOverlay.classList.add('active');
    }

    // Decode hex string to text
    hexDecode(hex) {
        let str = '';
        for (let i = 0; i < hex.length; i += 2) {
            const byte = parseInt(hex.substr(i, 2), 16);
            // Replace non-printable chars with dots
            if (byte >= 32 && byte < 127) {
                str += String.fromCharCode(byte);
            } else if (byte === 10) {
                str += '\n';
            } else if (byte === 13) {
                str += '\r';
            } else if (byte === 9) {
                str += '\t';
            } else {
                str += '.';
            }
        }
        return str;
    }

    hideModal() {
        this.modalOverlay.classList.remove('active');
    }

    showAttackOnMap(lat, lon, ip, service) {
        // Use Leaflet map if available
        if (window.addAttackDot) {
            window.addAttackDot(lat, lon, ip, service);
        }
    }

    updateCredentialsList(credentials) {
        if (!credentials || credentials.length === 0) {
            this.recentCredentials.innerHTML = '<div class="credential-item">No credentials yet</div>';
            return;
        }

        this.recentCredentials.innerHTML = credentials
            .slice(0, 6)
            .map(c => `<div class="credential-item">${this.escapeHtml(c.username)}:${this.escapeHtml(c.password)}</div>`)
            .join('');
    }

    addCredential(username, password) {
        const item = document.createElement('div');
        item.className = 'credential-item';
        item.textContent = `${username}:${password}`;

        this.recentCredentials.insertBefore(item, this.recentCredentials.firstChild);

        // Keep only 6
        while (this.recentCredentials.children.length > 6) {
            this.recentCredentials.removeChild(this.recentCredentials.lastChild);
        }
    }

    updateConnectionStatus(status) {
        if (!this.connectionStatus) return;

        const dot = this.connectionStatus.querySelector('.status-dot');
        const text = this.connectionStatus.querySelector('.status-text');
        if (!dot || !text) return;

        // Reset classes
        dot.className = 'status-dot w-2 h-2 rounded-full';

        switch (status) {
            case 'connected':
                dot.classList.add('bg-green-500');
                text.textContent = 'Live';
                text.className = 'status-text text-xs text-green-500 font-medium';
                // Add pulsing animation
                dot.style.animation = 'pulse 2s infinite';
                break;
            case 'error':
                dot.classList.add('bg-red-500');
                text.textContent = 'Reconnecting...';
                text.className = 'status-text text-xs text-red-400';
                dot.style.animation = 'none';
                break;
            default:
                dot.classList.add('bg-yellow-500', 'animate-pulse');
                text.textContent = 'Connecting...';
                text.className = 'status-text text-xs text-gray-400';
                dot.style.animation = '';
        }
    }

    setupEventListeners() {
        // Pause button
        document.getElementById('pauseBtn').addEventListener('click', () => {
            this.isPaused = !this.isPaused;
            document.getElementById('pauseBtn').textContent = this.isPaused ? '▶' : '⏸';
        });

        // Clear button
        document.getElementById('clearBtn').addEventListener('click', () => {
            this.feedBody.innerHTML = '';
            this.events = [];
        });

        // Theme toggle is handled by theme.js

        // Modal close
        document.getElementById('modalClose').addEventListener('click', () => this.hideModal());
        document.getElementById('modalOverlay').addEventListener('click', (e) => {
            if (e.target === this.modalOverlay) {
                this.hideModal();
            }
        });

        // Escape key
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') {
                this.hideModal();
            }
        });
    }

    // Utilities
    formatNumber(num) {
        return num.toLocaleString();
    }

    truncate(str, len) {
        return str.length > len ? str.substring(0, len) + '...' : str;
    }

    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
}

// Initialize
document.addEventListener('DOMContentLoaded', () => {
    window.dashboard = new HoneypotDashboard();
});

// Attack Map using Leaflet.js
let attackMap = null;
let attackMarkers = [];
let currentTileLayer = null;
const MAX_MARKERS = 50;

// Tile URLs for different themes
const TILE_URLS = {
    dark: 'https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png',
    light: 'https://{s}.basemaps.cartocdn.com/light_all/{z}/{x}/{y}{r}.png'
};

function initAttackMap() {
    const mapElement = document.getElementById('attackMap');
    if (!mapElement || attackMap) return;

    try {
        // Initialize map centered on world
        attackMap = L.map('attackMap', {
            center: [25, 0],
            zoom: 2,
            minZoom: 1,
            maxZoom: 8,
            zoomControl: true,
            attributionControl: false
        });

        // Use theme-appropriate tiles
        const theme = window.currentTheme || 'dark';
        currentTileLayer = L.tileLayer(TILE_URLS[theme], {
            subdomains: 'abcd',
            maxZoom: 19
        }).addTo(attackMap);

        // Add subtle attribution
        L.control.attribution({
            position: 'bottomright',
            prefix: false
        }).addAttribution('© <a href="https://carto.com/" style="color:#888">CARTO</a>').addTo(attackMap);

        // Force map to recalculate size after a short delay
        setTimeout(() => {
            if (attackMap) {
                attackMap.invalidateSize();
            }
        }, 100);

    } catch (e) {
        console.error('Failed to initialize map:', e);
    }
}

// Update map tiles when theme changes
window.updateMapTheme = function (theme) {
    if (!attackMap || !currentTileLayer) return;

    attackMap.removeLayer(currentTileLayer);
    currentTileLayer = L.tileLayer(TILE_URLS[theme] || TILE_URLS.dark, {
        subdomains: 'abcd',
        maxZoom: 19
    }).addTo(attackMap);
};

// Add an attack dot to the map
function addAttackDot(lat, lon, ip, service) {
    if (!attackMap) return;

    // Create pulsing marker
    const attackIcon = L.divIcon({
        className: 'attack-marker',
        html: `<div class="attack-pulse"></div><div class="attack-dot" data-service="${service}"></div>`,
        iconSize: [24, 24],
        iconAnchor: [12, 12]
    });

    const marker = L.marker([lat, lon], { icon: attackIcon })
        .bindPopup(`<div style="font-family: inherit"><strong>${ip}</strong><br><span style="color: #888">${service}</span></div>`)
        .addTo(attackMap);

    attackMarkers.push(marker);

    // Remove old markers if too many
    if (attackMarkers.length > MAX_MARKERS) {
        const oldMarker = attackMarkers.shift();
        attackMap.removeLayer(oldMarker);
    }

    // Auto-remove after 30 seconds
    setTimeout(() => {
        const idx = attackMarkers.indexOf(marker);
        if (idx > -1) {
            attackMarkers.splice(idx, 1);
            attackMap.removeLayer(marker);
        }
    }, 30000);
}

// Expose for dashboard to call
window.addAttackDot = addAttackDot;

document.addEventListener('DOMContentLoaded', initAttackMap);

