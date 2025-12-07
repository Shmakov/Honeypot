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

        this.eventSource = new EventSource('/events');

        this.eventSource.onopen = () => {
            this.updateConnectionStatus('connected');
        };

        this.eventSource.addEventListener('attack', (event) => {
            if (!this.isPaused) {
                const data = JSON.parse(event.data);
                this.handleAttackEvent(data);
            }
        });

        this.eventSource.onerror = () => {
            this.updateConnectionStatus('error');
            // Reconnect after 5 seconds
            setTimeout(() => this.connectSSE(), 5000);
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

        // Show on map
        if (event.latitude && event.longitude) {
            this.showAttackOnMap(event.latitude, event.longitude);
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

        row.innerHTML = `
            <td class="time-cell">${time}</td>
            <td class="ip-cell">${this.escapeHtml(event.ip)}</td>
            <td class="country-cell">${event.country_code || '-'}</td>
            <td><span class="service-badge ${serviceClass}">${service}</span></td>
            <td class="request-cell" title="${this.escapeHtml(event.request || '')}">${this.escapeHtml(this.truncate(event.request || '', 60))}</td>
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

        // Payload
        const payloadEl = document.getElementById('detailPayload');
        if (event.payload) {
            try {
                // Try to decode base64 and display
                const decoded = atob(event.payload);
                payloadEl.textContent = decoded;
            } catch {
                payloadEl.textContent = event.payload;
            }
        } else {
            payloadEl.textContent = 'No payload captured';
        }

        this.modalOverlay.classList.add('active');
    }

    hideModal() {
        this.modalOverlay.classList.remove('active');
    }

    showAttackOnMap(lat, lon) {
        // Simple map projection (Mercator-ish)
        const x = ((lon + 180) / 360) * 100;
        const y = ((90 - lat) / 180) * 100;

        const dot = document.createElement('div');
        dot.className = 'attack-dot';
        dot.style.left = `${x}%`;
        dot.style.top = `${y}%`;

        this.mapOverlay.appendChild(dot);

        // Remove after animation
        setTimeout(() => dot.remove(), 2000);
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
        const dot = this.connectionStatus.querySelector('.status-dot');
        const text = this.connectionStatus.querySelector('.status-text');

        dot.className = 'status-dot';

        switch (status) {
            case 'connected':
                dot.classList.add('connected');
                text.textContent = 'Live';
                break;
            case 'error':
                dot.classList.add('error');
                text.textContent = 'Reconnecting...';
                break;
            default:
                text.textContent = 'Connecting...';
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

// Load basic world map SVG
function loadWorldMap() {
    const svg = document.getElementById('mapSvg');
    // Simple world outline - you can replace with a proper world map SVG
    svg.innerHTML = `
        <defs>
            <linearGradient id="mapGradient" x1="0%" y1="0%" x2="100%" y2="100%">
                <stop offset="0%" style="stop-color:rgba(59,130,246,0.1)"/>
                <stop offset="100%" style="stop-color:rgba(139,92,246,0.1)"/>
            </linearGradient>
        </defs>
        <rect width="1000" height="500" fill="url(#mapGradient)"/>
        <g fill="none" stroke="rgba(255,255,255,0.1)" stroke-width="1">
            <!-- Grid lines -->
            <line x1="0" y1="250" x2="1000" y2="250"/>
            <line x1="500" y1="0" x2="500" y2="500"/>
            <line x1="0" y1="125" x2="1000" y2="125"/>
            <line x1="0" y1="375" x2="1000" y2="375"/>
            <line x1="250" y1="0" x2="250" y2="500"/>
            <line x1="750" y1="0" x2="750" y2="500"/>
        </g>
        <text x="500" y="260" text-anchor="middle" fill="rgba(255,255,255,0.2)" font-size="14">World Map</text>
    `;
}

document.addEventListener('DOMContentLoaded', loadWorldMap);
