/**
 * Honeypot Statistics Page
 */

// Allowed time ranges (in hours) - must match backend ALLOWED_HOURS
const ALLOWED_HOURS = [24, 168, 720, 8760];

// Map globals - uses shared TILE_URLS from map.js
let statsMap = null;
let countryMarkers = [];
let currentTileLayer = null;

class StatsPage {
    constructor() {
        this.countriesData = [];
        this.loadingOverlay = document.getElementById('loadingOverlay');
        this.init();
    }

    async init() {
        this.setupTimeFilter();
        this.initMap();
        await this.loadData();
    }

    initMap() {
        const mapElement = document.getElementById('statsMap');
        if (!mapElement || statsMap) return;

        try {
            statsMap = L.map('statsMap', {
                center: [25, 0],
                zoom: 2,
                minZoom: 1,
                maxZoom: 8,
                zoomControl: true,
                attributionControl: false
            });

            const theme = window.currentTheme || 'dark';
            currentTileLayer = L.tileLayer(TILE_URLS[theme], {
                subdomains: 'abcd',
                maxZoom: 19
            }).addTo(statsMap);

            L.control.attribution({
                position: 'bottomright',
                prefix: false
            }).addAttribution('© <a href="https://carto.com/" style="color:#888">CARTO</a>').addTo(statsMap);

            setTimeout(() => {
                if (statsMap) statsMap.invalidateSize();
            }, 100);

        } catch (e) {
            console.error('Failed to initialize stats map:', e);
        }
    }

    updateMapMarkers(locations) {
        if (!statsMap) return;

        // Clear existing markers
        countryMarkers.forEach(m => statsMap.removeLayer(m));
        countryMarkers = [];

        if (!locations || locations.length === 0) return;

        const maxCount = Math.max(...locations.map(l => l.count), 1);

        locations.forEach(loc => {
            // Skip invalid coordinates
            if (loc.lat == null || loc.lon == null) return;

            // Size based on count (min 6px, max 24px)
            const size = Math.max(6, Math.min(24, Math.sqrt(loc.count / maxCount) * 24));
            const opacity = Math.max(0.5, Math.min(0.9, Math.sqrt(loc.count / maxCount) * 0.9));

            const icon = L.divIcon({
                className: 'location-marker',
                html: `<div style="
                    width: ${size}px;
                    height: ${size}px;
                    background: rgba(239, 68, 68, ${opacity});
                    border-radius: 50%;
                    box-shadow: 0 0 ${size}px rgba(239, 68, 68, 0.6);
                "></div>`,
                iconSize: [size, size],
                iconAnchor: [size / 2, size / 2]
            });

            const marker = L.marker([loc.lat, loc.lon], { icon })
                .bindPopup(`<div style="font-family: inherit; text-align: center;">
                    <span style="color: #888;">${loc.count.toLocaleString()} requests</span>
                </div>`)
                .addTo(statsMap);

            countryMarkers.push(marker);
        });
    }

    setupTimeFilter() {
        const select = document.getElementById('timeRange');
        select.addEventListener('change', () => this.loadData());
    }

    async loadData() {
        const select = document.getElementById('timeRange');
        const hours = parseInt(select.value, 10);

        // Show loading overlay and disable select
        this.showLoading(true);
        select.disabled = true;

        try {
            const [statsResponse, countriesResponse, locationsResponse, topIpsRequestsResponse, topIpsBandwidthResponse, totalBytesResponse] = await Promise.all([
                fetch(`/api/stats?hours=${hours}`),
                fetch(`/api/countries?hours=${hours}`),
                fetch(`/api/locations?hours=${hours}`),
                fetch(`/api/top-ips-requests?hours=${hours}`),
                fetch(`/api/top-ips-bandwidth?hours=${hours}`),
                fetch(`/api/total-bytes?hours=${hours}`)
            ]);

            // Check for API errors (invalid hours returns 400)
            if (!statsResponse.ok || !countriesResponse.ok || !locationsResponse.ok) {
                const errorResp = await statsResponse.json().catch(() => ({}));
                throw new Error(errorResp.error || 'Failed to load statistics');
            }

            const stats = await statsResponse.json();
            const countries = await countriesResponse.json();
            const locations = await locationsResponse.json();
            const topIpsRequests = topIpsRequestsResponse.ok ? await topIpsRequestsResponse.json() : [];
            const topIpsBandwidth = topIpsBandwidthResponse.ok ? await topIpsBandwidthResponse.json() : [];
            const totalBytes = totalBytesResponse.ok ? await totalBytesResponse.json() : 0;

            this.countriesData = countries;
            this.updateOverview(stats, countries, totalBytes);
            this.updateServicesChart(stats.services);
            this.updateCountriesChart(countries);
            this.updateCredentialsTable(stats.credentials);
            this.updatePathsTable(stats.paths);
            this.updateMapMarkers(locations);
            this.updateTopIpsRequestsTable(topIpsRequests);
            this.updateTopIpsBandwidthTable(topIpsBandwidth);

        } catch (error) {
            console.error('Failed to load stats:', error);
            // Show error in a visible way
            const totalEl = document.getElementById('totalRequests');
            if (totalEl) totalEl.textContent = 'Error';
        } finally {
            // Hide loading overlay and re-enable select
            this.showLoading(false);
            select.disabled = false;
        }
    }

    /**
     * Show or hide the loading overlay
     */
    showLoading(show) {
        if (this.loadingOverlay) {
            if (show) {
                this.loadingOverlay.classList.add('active');
            } else {
                this.loadingOverlay.classList.remove('active');
            }
        }
    }

    updateOverview(stats, countries, totalBytes) {
        document.getElementById('totalRequests').textContent = stats.total.toLocaleString();
        document.getElementById('totalTraffic').textContent = this.formatBytes(totalBytes);
        document.getElementById('uniqueServices').textContent = stats.services.length;
        document.getElementById('uniqueCountries').textContent = countries.length;
    }

    /**
     * Format bytes to human-readable string (KB, MB, GB, etc.)
     */
    formatBytes(bytes) {
        if (bytes === 0) return '0 B';
        const k = 1024;
        const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
    }

    updateServicesChart(services) {
        const container = document.getElementById('servicesChart');

        if (!services || services.length === 0) {
            container.innerHTML = `
                <div class="flex flex-col items-center justify-center h-full text-gray-500">
                    <span class="text-2xl mb-2">🛡️</span>
                    <span>No service data available</span>
                </div>`;
            return;
        }

        // Sort by count descending to show top services first
        const sortedServices = [...services].sort((a, b) => b.count - a.count);
        const maxCount = Math.max(...sortedServices.map(s => s.count));

        container.innerHTML = sortedServices.map((s, i) => {
            const percentage = (s.count / maxCount) * 100;
            const opacity = Math.max(0.4, 1 - (i * 0.03)); // Fade out slightly for lower ranks

            return `
                <div class="stat-bar-item group">
                    <div class="flex items-center gap-3 py-2 px-3 rounded-lg hover:bg-gray-800/50 transition-colors">
                        <span class="text-gray-500 text-xs font-medium w-5 text-right">${i + 1}</span>
                        <div class="flex-1 min-w-0">
                            <div class="flex items-center justify-between mb-1">
                                <span class="text-sm font-medium text-gray-200 truncate">${this.escapeHtml(s.service)}</span>
                                <span class="text-xs text-gray-400 tabular-nums ml-2">${s.count.toLocaleString()}</span>
                            </div>
                            <div class="h-2 bg-gray-800 rounded-full overflow-hidden">
                                <div class="h-full rounded-full transition-all duration-300" 
                                     style="width: ${percentage}%; background: linear-gradient(90deg, rgba(245, 158, 11, ${opacity}), rgba(249, 115, 22, ${opacity}));"></div>
                            </div>
                        </div>
                    </div>
                </div>`;
        }).join('');
    }

    updateCountriesChart(countries) {
        const container = document.getElementById('countriesChart');

        if (!countries || countries.length === 0) {
            container.innerHTML = `
                <div class="flex flex-col items-center justify-center h-full text-gray-500">
                    <span class="text-2xl mb-2">🌎</span>
                    <span>No country data available</span>
                </div>`;
            return;
        }

        const maxCount = Math.max(...countries.map(c => c.count));

        // Use Intl.DisplayNames to get full country names
        const regionNames = new Intl.DisplayNames(['en'], { type: 'region' });

        container.innerHTML = countries.map((c, i) => {
            const percentage = (c.count / maxCount) * 100;
            const opacity = Math.max(0.4, 1 - (i * 0.02)); // Fade out slightly for lower ranks
            const flag = this.countryToFlag(c.country_code);
            // Get full country name, fallback to code if not found
            let name = 'Unknown';
            if (c.country_code) {
                try {
                    name = regionNames.of(c.country_code) || c.country_code;
                } catch {
                    name = c.country_code;
                }
            }

            return `
                <div class="stat-bar-item group">
                    <div class="flex items-center gap-3 py-2 px-3 rounded-lg hover:bg-gray-800/50 transition-colors">
                        <span class="text-gray-500 text-xs font-medium w-5 text-right">${i + 1}</span>
                        <div class="flex-1 min-w-0">
                            <div class="flex items-center justify-between mb-1">
                                <span class="text-sm font-medium text-gray-200 truncate">${flag} ${name}</span>
                                <span class="text-xs text-gray-400 tabular-nums ml-2">${c.count.toLocaleString()}</span>
                            </div>
                            <div class="h-2 bg-gray-800 rounded-full overflow-hidden">
                                <div class="h-full rounded-full transition-all duration-300" 
                                     style="width: ${percentage}%; background: linear-gradient(90deg, rgba(59, 130, 246, ${opacity}), rgba(99, 102, 241, ${opacity}));"></div>
                            </div>
                        </div>
                    </div>
                </div>`;
        }).join('');
    }

    /**
     * Formats a credential (username/password) for display.
     * Shows "(empty)" for empty strings and makes whitespace visible.
     */
    formatCredential(value, colorClass) {
        if (!value || value.length === 0) {
            return `<span class="text-gray-500 italic">(empty)</span>`;
        }

        // Check if it's whitespace-only
        if (value.trim().length === 0) {
            // Show spaces as visible dots
            const visibleSpaces = value.replace(/ /g, '·').replace(/\t/g, '→');
            return `<span class="${colorClass}" title="${value.length} whitespace character(s)">${this.escapeHtml(visibleSpaces)}</span>`;
        }

        // Check if it starts or ends with whitespace
        const hasLeadingSpace = value !== value.trimStart();
        const hasTrailingSpace = value !== value.trimEnd();

        if (hasLeadingSpace || hasTrailingSpace) {
            // Highlight the string with a subtle indicator
            let displayed = this.escapeHtml(value);
            if (hasLeadingSpace) {
                const leadingSpaces = value.length - value.trimStart().length;
                displayed = `<span class="text-gray-500">${'·'.repeat(leadingSpaces)}</span>${this.escapeHtml(value.trimStart())}`;
            }
            if (hasTrailingSpace) {
                const trailingSpaces = value.length - value.trimEnd().length;
                const base = hasLeadingSpace
                    ? `<span class="text-gray-500">${'·'.repeat(value.length - value.trimStart().length)}</span>${this.escapeHtml(value.trim())}`
                    : this.escapeHtml(value.trimEnd());
                displayed = `${base}<span class="text-gray-500">${'·'.repeat(trailingSpaces)}</span>`;
            }
            return `<span class="${colorClass}">${displayed}</span>`;
        }

        return `<span class="${colorClass}">${this.escapeHtml(value)}</span>`;
    }

    updateCredentialsTable(credentials) {
        const tbody = document.getElementById('credentialsTable');

        if (!credentials || credentials.length === 0) {
            tbody.innerHTML = `<tr>
                <td colspan="3" class="px-6 py-8 text-center text-gray-500">
                    <div class="flex flex-col items-center gap-2">
                        <span class="text-2xl">🔒</span>
                        <span>No credentials captured</span>
                    </div>
                </td>
            </tr>`;
            return;
        }

        tbody.innerHTML = credentials.map(c => `
            <tr class="hover:bg-gray-800/30 transition-colors">
                <td class="px-6 py-3 font-mono text-sm">${this.formatCredential(c.username, 'text-amber-400')}</td>
                <td class="px-6 py-3 font-mono text-sm">${this.formatCredential(c.password, 'text-red-400')}</td>
                <td class="px-6 py-3 text-sm text-gray-400 text-right tabular-nums">${c.count.toLocaleString()}</td>
            </tr>
        `).join('');
    }

    updatePathsTable(paths) {
        const tbody = document.getElementById('pathsTable');

        if (!paths || paths.length === 0) {
            tbody.innerHTML = `<tr>
                <td colspan="2" class="px-6 py-8 text-center text-gray-500">
                    <div class="flex flex-col items-center gap-2">
                        <span class="text-2xl">🌐</span>
                        <span>No HTTP paths captured</span>
                    </div>
                </td>
            </tr>`;
            return;
        }

        tbody.innerHTML = paths.map(p => `
            <tr class="hover:bg-gray-800/30 transition-colors">
                <td class="px-6 py-3 font-mono text-sm text-blue-400 truncate max-w-xs" title="${this.escapeHtml(p.path)}">${this.escapeHtml(this.truncate(p.path, 40))}</td>
                <td class="px-6 py-3 text-sm text-gray-400 text-right tabular-nums">${p.count.toLocaleString()}</td>
            </tr>
        `).join('');
    }

    // Utilities - use shared functions
    truncate(str, len) {
        return truncate(str, len);
    }

    escapeHtml(text) {
        return escapeHtml(text);
    }

    // Convert country code to flag emoji - use shared utility
    countryToFlag(code) {
        return countryToFlag(code);
    }

    updateTopIpsRequestsTable(ips) {
        const tbody = document.getElementById('topIpsRequestsTable');

        if (!ips || ips.length === 0) {
            tbody.innerHTML = `<tr>
                <td colspan="2" class="px-6 py-8 text-center text-gray-500">
                    <div class="flex flex-col items-center gap-2">
                        <span class="text-2xl">🔍</span>
                        <span>No IP data available</span>
                    </div>
                </td>
            </tr>`;
            return;
        }

        tbody.innerHTML = ips.map(ip => `
            <tr class="hover:bg-gray-800/30 transition-colors">
                <td class="px-6 py-3 font-mono text-sm text-cyan-400">${this.escapeHtml(ip.ip)}</td>
                <td class="px-6 py-3 text-sm text-gray-400 text-right tabular-nums">${ip.count.toLocaleString()}</td>
            </tr>
        `).join('');
    }

    updateTopIpsBandwidthTable(ips) {
        const tbody = document.getElementById('topIpsBandwidthTable');

        if (!ips || ips.length === 0) {
            tbody.innerHTML = `<tr>
                <td colspan="2" class="px-6 py-8 text-center text-gray-500">
                    <div class="flex flex-col items-center gap-2">
                        <span class="text-2xl">📊</span>
                        <span>No bandwidth data available</span>
                    </div>
                </td>
            </tr>`;
            return;
        }

        tbody.innerHTML = ips.map(ip => `
            <tr class="hover:bg-gray-800/30 transition-colors">
                <td class="px-6 py-3 font-mono text-sm text-purple-400">${this.escapeHtml(ip.ip)}</td>
                <td class="px-6 py-3 text-sm text-gray-400 text-right tabular-nums">${this.formatBytes(ip.count)}</td>
            </tr>
        `).join('');
    }
}

// Update map theme when changed
window.updateMapTheme = function (theme) {
    if (!statsMap || !currentTileLayer) return;

    statsMap.removeLayer(currentTileLayer);
    currentTileLayer = L.tileLayer(TILE_URLS[theme] || TILE_URLS.dark, {
        subdomains: 'abcd',
        maxZoom: 19
    }).addTo(statsMap);
};

// Initialize
document.addEventListener('DOMContentLoaded', () => {
    window.statsPage = new StatsPage();
});
