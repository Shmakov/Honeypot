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

    // Convert country code to flag emoji - use shared utility
    countryToFlag(code) {
        return countryToFlag(code);
    }

    showEventDetails(event) {
        document.getElementById('detailIp').textContent = event.ip;
        document.getElementById('detailCountry').textContent = `${this.countryToFlag(event.country_code)} ${event.country_code || 'Unknown'}`;
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

        // User-Agent
        const uaRow = document.getElementById('userAgentRow');
        if (event.user_agent) {
            uaRow.classList.remove('hidden');
            document.getElementById('detailUserAgent').textContent = event.user_agent;
        } else {
            uaRow.classList.add('hidden');
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

    // Decode hex string to text - use shared utility
    hexDecode(hex) {
        return hexDecode(hex);
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

    // Utilities - use shared functions
    formatNumber(num) {
        return formatNumber(num);
    }

    truncate(str, len) {
        return truncate(str, len);
    }

    escapeHtml(text) {
        return escapeHtml(text);
    }
}

// Initialize
document.addEventListener('DOMContentLoaded', () => {
    window.dashboard = new HoneypotDashboard();
});

// Attack Map using Leaflet.js - uses shared map.js utilities
let attackMap = null;
let attackMarkers = [];
let markersByLocation = new Map(); // Track markers by location key for aggregation
let currentTileLayer = null;
const MAX_MARKERS = 500;
const MARKER_TIMEOUT = 90000; // 90 seconds

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

// Create location key for aggregation (round to 2 decimal places ~1km precision)
function getLocationKey(lat, lon) {
    return `${lat.toFixed(2)},${lon.toFixed(2)}`;
}

// Update marker icon with count badge
// Update marker icon with count badge
function updateMarkerIcon(markerData) {
    const { marker, count } = markerData;

    // Increase radius based on count (start at 3px, max 10px)
    const newRadius = Math.min(3 + Math.log2(count) * 2, 10);
    marker.setRadius(newRadius);

    // Update tooltip:
    // If count > 1, show permanent badge (mimicking the old UI)
    // If count == 1, keeping the existing hover tooltip (IP • Service)
    if (count === 2) {
        // Switching from single to multiple: Unbind hover tooltip, bind permanent badge
        marker.unbindTooltip();
        marker.bindTooltip(`${count}`, {
            permanent: true,
            direction: 'center',
            className: 'badge-tooltip',
            offset: [10, -10], // top-right
            pane: 'popupPane' // Ensure it stays visible/on top of map layers, though popups might still cover it if they overlap directly.
        });
    } else if (count > 2) {
        // Just update the content of the existing permanent badge
        marker.setTooltipContent(`${count > 99 ? '99+' : count}`);
    }
}

// Add an attack dot to the map
function addAttackDot(lat, lon, ip, service) {
    if (!attackMap) return;

    const locationKey = getLocationKey(lat, lon);

    // Check if we already have a marker at this location
    if (markersByLocation.has(locationKey)) {
        const markerData = markersByLocation.get(locationKey);
        markerData.count++;
        markerData.ips.add(ip);
        markerData.services.add(service);

        // Update the marker size/tooltip
        updateMarkerIcon(markerData);

        // Update popup content
        const uniqueIps = Array.from(markerData.ips).slice(-5); // Show last 5 IPs
        const ipList = uniqueIps.map(ip => `<div style="font-family: monospace; font-size: 12px;">${ip}</div>`).join('');
        const moreText = markerData.ips.size > 5 ? `<div style="color: #888; font-size: 11px;">+${markerData.ips.size - 5} more</div>` : '';

        markerData.marker.setPopupContent(`
            <div style="font-family: inherit; min-width: 120px;">
                <div style="font-weight: 600; margin-bottom: 4px; color: #ef4444;">${markerData.count} requests</div>
                ${ipList}
                ${moreText}
            </div>
        `);

        // Reset the timeout
        if (markerData.timeoutId) {
            clearTimeout(markerData.timeoutId);
        }
        markerData.timeoutId = setTimeout(() => removeMarkerByKey(locationKey), MARKER_TIMEOUT);

        return;
    }

    // Create new circleMarker (SVG-based, positions correctly at all zoom levels)
    const marker = L.circleMarker([lat, lon], {
        radius: 3,               // Smaller initial size (was 4)
        fillColor: '#ef4444',
        fillOpacity: 0.9,
        color: '#ef4444',
        weight: 1,
        opacity: 0.8,
        className: 'attack-circle-marker'
    })
        .bindPopup(`<div style="font-family: inherit"><strong>${ip}</strong><br><span style="color: #888">${service}</span></div>`)
        .bindTooltip(`${ip} • ${service}`, { direction: 'top', offset: [0, -2], className: 'map-tooltip' }) // Show info immediately
        .addTo(attackMap);

    const markerData = {
        marker,
        count: 1,
        ips: new Set([ip]),
        services: new Set([service]),
        locationKey,
        timeoutId: setTimeout(() => removeMarkerByKey(locationKey), MARKER_TIMEOUT)
    };

    attackMarkers.push(markerData);
    markersByLocation.set(locationKey, markerData);

    // Remove old markers if too many
    while (attackMarkers.length > MAX_MARKERS) {
        const oldMarkerData = attackMarkers.shift();
        removeMarkerByKey(oldMarkerData.locationKey, false);
    }
}

// Remove marker by location key
function removeMarkerByKey(locationKey, removeFromArray = true) {
    const markerData = markersByLocation.get(locationKey);
    if (!markerData) return;

    if (markerData.timeoutId) {
        clearTimeout(markerData.timeoutId);
    }

    attackMap.removeLayer(markerData.marker);
    markersByLocation.delete(locationKey);

    if (removeFromArray) {
        const idx = attackMarkers.findIndex(m => m.locationKey === locationKey);
        if (idx > -1) {
            attackMarkers.splice(idx, 1);
        }
    }
}

// Expose for dashboard to call
window.addAttackDot = addAttackDot;

document.addEventListener('DOMContentLoaded', initAttackMap);

