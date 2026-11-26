/**
 * Honeypot Dashboard - Main JavaScript
 * Real-time attack feed using SSE
 */

class HoneypotDashboard {
    constructor() {
        this.eventSource = null;
        this.isPaused = false;
        this.sessionCount = 0;
        this.monthlyCount = 0;
        this.totalCount = 0;
        this.serverRpm = 0;
        this.startedAt = Date.now();
        this.recentTimestamps = [];
        this.maxRows = 100;
        this.events = [];

        this.init();
    }

    init() {
        this.setupElements();
        this.loadInitialData();
        this.connectSSE();
        this.setupEventListeners();
        setInterval(() => this.updateRateDisplay(), 5000);
    }

    setupElements() {
        this.feedBody = document.getElementById('feedBody');
        this.monthlyRequests = document.getElementById('monthlyRequests');
        this.requestsPerMin = document.getElementById('requestsPerMin');
        this.totalRequests = document.getElementById('totalRequests');
        this.sessionRequests = document.getElementById('sessionRequests');
        this.recentCredentials = document.getElementById('recentCredentials');
        this.recentCommands = document.getElementById('recentCommands');
        this.connectionStatus = document.getElementById('connectionStatus');
        this.modalOverlay = document.getElementById('modalOverlay');
        this.mapOverlay = document.getElementById('mapOverlay');
    }

    async loadInitialData() {
        try {
            const response = await fetch('/api/recent');
            const data = await response.json();

            this.totalCount = data.total || 0;
            this.monthlyCount = data.last_30_days ?? this.totalCount;
            this.serverRpm = typeof data.requests_per_minute === 'number' ? data.requests_per_minute : 0;

            if (this.monthlyRequests) {
                this.monthlyRequests.textContent = this.formatNumber(this.monthlyCount);
            }
            this.totalRequests.textContent = this.formatNumber(this.totalCount);
            this.updateRateDisplay();

            // Show recent credentials and commands
            this.updateCredentialsList(data.credentials);
            this.updateCommandsList(data.commands);

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

    updateRateDisplay() {
        if (!this.requestsPerMin) return;
        const now = Date.now();
        const cutoff = now - 60000;
        this.recentTimestamps = this.recentTimestamps.filter(t => t > cutoff);

        const elapsedSec = (now - this.startedAt) / 1000;
        let rpm;
        if (elapsedSec < 60) {
            const liveRate = this.recentTimestamps.length * (60 / Math.max(elapsedSec, 5));
            const weight = elapsedSec / 60;
            rpm = (this.serverRpm * (1 - weight)) + (liveRate * weight);
        } else {
            rpm = this.recentTimestamps.length;
        }
        this.requestsPerMin.textContent = (Math.max(0, rpm)).toFixed(1);
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
        this.monthlyCount++;
        this.totalCount++;
        this.recentTimestamps.push(Date.now());

        // Update counters
        this.sessionRequests.textContent = this.formatNumber(this.sessionCount);
        if (this.monthlyRequests) {
            this.monthlyRequests.textContent = this.formatNumber(this.monthlyCount);
        }
        this.totalRequests.textContent = this.formatNumber(this.totalCount);
        this.updateRateDisplay();

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

        // Update commands if SSH/telnet event with payload
        if ((event.service === 'ssh' || event.service === 'ssh-alt' || event.service === 'telnet' || event.service === 'telnet-alt') && event.payload) {
            try {
                const decoded = this.hexDecode(event.payload);
                const commands = decoded.split('\n').filter(cmd => cmd.trim());
                for (const cmd of commands.slice(0, 3)) { // Add up to 3 commands per event
                    this.addCommand(cmd.trim());
                }
            } catch (e) {
                // Ignore decode errors
            }
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

        const tags = Array.isArray(event.tags) ? event.tags : [];
        const tagBadges = tags
            .slice(0, 2)
            .map(tag => {
                const isScanner = tag.startsWith('scanner:');
                const cls = isScanner ? 'tag-pill tag-scanner' : 'tag-pill tag-alert';
                return `<span class="${cls}">${this.escapeHtml(tag)}</span>`;
            })
            .join('');

        row.innerHTML = `
            <td class="px-6 py-3 text-sm text-gray-400">${time}</td>
            <td class="px-6 py-3 font-mono text-sm text-gray-300">${this.escapeHtml(event.ip)}</td>
            <td class="px-6 py-3 text-sm text-gray-400">${this.countryToFlag(event.country_code)} ${this.escapeHtml(event.country_code || '-')}</td>
            <td class="px-6 py-3"><span class="px-2.5 py-1 rounded-full text-xs font-medium ${serviceClass}">${this.escapeHtml(service)}</span></td>
            <td class="px-6 py-3 text-sm text-gray-400 font-mono truncate max-w-xs" title="${this.escapeHtml(requestFirstLine)}">${tagBadges ? `<span class="inline-flex items-center gap-1.5 mr-1.5">${tagBadges}</span>` : ''}${this.escapeHtml(this.truncate(requestFirstLine, 50))}</td>
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
        // Get full country name using Intl.DisplayNames
        let countryName = event.country_code || 'Unknown';
        if (event.country_code) {
            try {
                const regionNames = new Intl.DisplayNames(['en'], { type: 'region' });
                countryName = regionNames.of(event.country_code) || event.country_code;
            } catch (e) {
                countryName = event.country_code;
            }
        }
        document.getElementById('detailCountry').textContent = `${this.countryToFlag(event.country_code)} ${countryName}`;
        document.getElementById('detailService').textContent = event.service;
        document.getElementById('detailPort').textContent = event.port || '-';
        document.getElementById('detailSize').textContent = this.formatBytes(event.request_size || 0);
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

        // ASN / Org
        const asnRow = document.getElementById('asnRow');
        const asnEl = document.getElementById('detailAsn');
        if (asnRow && asnEl) {
            if (event.asn) {
                asnRow.classList.remove('hidden');
                asnEl.textContent = event.asn_org ? `AS${event.asn} (${event.asn_org})` : `AS${event.asn}`;
            } else {
                asnRow.classList.add('hidden');
            }
        }

        // Attack Tags
        const tagsRow = document.getElementById('tagsRow');
        const tagsEl = document.getElementById('detailTags');
        if (tagsRow && tagsEl) {
            const tags = Array.isArray(event.tags) ? event.tags : [];
            if (tags.length > 0) {
                tagsRow.classList.remove('hidden');
                tagsEl.innerHTML = tags
                    .map(t => `<span class="tag-pill ${t.startsWith('scanner:') ? 'tag-scanner' : 'tag-alert'}">${this.escapeHtml(t)}</span>`)
                    .join('');
            } else {
                tagsRow.classList.add('hidden');
                tagsEl.innerHTML = '';
            }
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

        // Extracted IOCs
        const iocsSection = document.getElementById('iocsSection');
        const iocsEl = document.getElementById('detailIocs');
        if (iocsSection && iocsEl) {
            const iocs = Array.isArray(event.iocs) ? event.iocs : [];
            if (iocs.length > 0) {
                iocsSection.classList.remove('hidden');
                iocsEl.innerHTML = iocs
                    .map(i => `<div class="flex items-start gap-2"><span class="px-1.5 py-0.5 rounded bg-red-500/20 text-red-300 uppercase text-[10px]">${this.escapeHtml(i.ioc_type)}</span><span class="break-all">${this.escapeHtml(window.defangValue ? window.defangValue(i.value) : i.value)}</span></div>`)
                    .join('');
            } else {
                iocsSection.classList.add('hidden');
                iocsEl.innerHTML = '';
            }
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
        // No limit - let items accumulate with scroll
    }

    updateCommandsList(commands) {
        if (!commands || commands.length === 0) {
            this.recentCommands.innerHTML = '<div class="command-item text-gray-600">No commands yet</div>';
            return;
        }

        this.recentCommands.innerHTML = commands
            .slice(0, 6)
            .map(c => `<div class="command-item text-cyan-400">$ ${this.escapeHtml(c)}</div>`)
            .join('');
    }

    addCommand(command) {
        const item = document.createElement('div');
        item.className = 'command-item text-cyan-400';
        item.textContent = `$ ${command}`;

        this.recentCommands.insertBefore(item, this.recentCommands.firstChild);
        // No limit - let items accumulate with scroll
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
        const pauseBtn = document.getElementById('pauseBtn');
        const PAUSE_ICON = '<svg class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="14" y="4" width="4" height="16" rx="1"/><rect x="6" y="4" width="4" height="16" rx="1"/></svg>';
        const PLAY_ICON = '<svg class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><polygon points="6 3 20 12 6 21 6 3"/></svg>';

        // Pause button
        pauseBtn.addEventListener('click', () => {
            this.isPaused = !this.isPaused;
            pauseBtn.innerHTML = this.isPaused ? PLAY_ICON : PAUSE_ICON;
            pauseBtn.setAttribute('title', this.isPaused ? 'Resume' : 'Pause');
            pauseBtn.setAttribute('aria-label', this.isPaused ? 'Resume feed' : 'Pause feed');
            pauseBtn.classList.toggle('text-amber-400', this.isPaused);
            pauseBtn.classList.toggle('border-amber-500/40', this.isPaused);
            pauseBtn.classList.toggle('bg-amber-500/10', this.isPaused);
            pauseBtn.classList.toggle('text-gray-400', !this.isPaused);
            pauseBtn.classList.toggle('border-gray-800', !this.isPaused);
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

    formatBytes(bytes) {
        if (bytes === 0) return '0 B';
        const k = 1024;
        const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
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

async function initAttackMap() {
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

        await loadMapConfig();

        // Use theme-appropriate tiles
        const theme = window.currentTheme || 'dark';
        currentTileLayer = createTileLayer(theme).addTo(attackMap);

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
    currentTileLayer = createTileLayer(theme).addTo(attackMap);
};

// Create location key for aggregation (round to 2 decimal places ~1km precision)
function getLocationKey(lat, lon) {
    return `${lat.toFixed(2)},${lon.toFixed(2)}`;
}

// Update marker radius and badge based on request count
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
        const ipList = uniqueIps.map(uip => `<div style="font-family: monospace; font-size: 12px;">${escapeHtml(uip)}</div>`).join('');
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
    const safeIp = escapeHtml(ip);
    const safeService = escapeHtml(service);
    const marker = L.circleMarker([lat, lon], {
        radius: 3,               // Smaller initial size (was 4)
        fillColor: '#ef4444',
        fillOpacity: 0.9,
        color: '#ef4444',
        weight: 1,
        opacity: 0.8,
        className: 'attack-circle-marker'
    })
        .bindPopup(`<div style="font-family: inherit"><strong>${safeIp}</strong><br><span style="color: #888">${safeService}</span></div>`)
        .bindTooltip(`${safeIp} • ${safeService}`, { direction: 'top', offset: [0, -2], className: 'map-tooltip' })
        .addTo(attackMap);

    // Apply entrance animation
    const markerElement = marker.getElement();
    if (markerElement) {
        // Add entrance class for pop-in effect
        markerElement.classList.add('marker-entering');
        // Set random stagger delay for ambient animation (0-4s range within 5s cycle)
        markerElement.style.setProperty('--stagger-delay', `${Math.random() * 4}s`);
        // Remove entrance class after animation completes to allow ambient glow
        setTimeout(() => {
            markerElement.classList.remove('marker-entering');
        }, 600); // Match CSS animation duration
    }

    // Handle tooltip/badge visibility on popup interactions
    marker.on('popupopen', () => {
        // Hide tooltip/badge when popup is open (user requested this behavior)
        marker.closeTooltip();
    });

    marker.on('popupclose', () => {
        // Restore tooltip/badge when popup closes
        // Only if it was supposed to be permanent (i.e. badge mode)
        if (marker.getTooltip() && marker.getTooltip().options.permanent) {
            marker.openTooltip();
        }
    });

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

