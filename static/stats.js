/**
 * Honeypot Statistics Page
 */

// Map globals
let statsMap = null;
let countryMarkers = [];

// Tile URLs for different themes
const TILE_URLS = {
    dark: 'https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png',
    light: 'https://{s}.basemaps.cartocdn.com/light_all/{z}/{x}/{y}{r}.png'
};
let currentTileLayer = null;

class StatsPage {
    constructor() {
        this.charts = {};
        this.countriesData = [];
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
        const hours = document.getElementById('timeRange').value;

        try {
            const [statsResponse, countriesResponse, locationsResponse] = await Promise.all([
                fetch(`/api/stats?hours=${hours}`),
                fetch(`/api/countries?hours=${hours}`),
                fetch(`/api/locations?hours=${hours}`)
            ]);

            const stats = await statsResponse.json();
            const countries = await countriesResponse.json();
            const locations = await locationsResponse.json();

            this.countriesData = countries;
            this.updateOverview(stats, countries);
            this.updateServicesChart(stats.services);
            this.updateCountriesChart(countries);
            this.updateCredentialsTable(stats.credentials);
            this.updatePathsTable(stats.paths);
            this.updateMapMarkers(locations);

        } catch (error) {
            console.error('Failed to load stats:', error);
        }
    }

    updateOverview(stats, countries) {
        document.getElementById('totalRequests').textContent = stats.total.toLocaleString();
        document.getElementById('uniqueServices').textContent = stats.services.length;
        document.getElementById('uniqueCountries').textContent = countries.length;

        // Calculate unique IPs if available
        const uniqueIpsEl = document.getElementById('uniqueIps');
        if (uniqueIpsEl) {
            uniqueIpsEl.textContent = stats.unique_ips ? stats.unique_ips.toLocaleString() : '-';
        }
    }

    updateServicesChart(services) {
        const ctx = document.getElementById('servicesChart').getContext('2d');

        if (this.charts.services) {
            this.charts.services.destroy();
        }

        const colors = [
            '#ef4444', '#f59e0b', '#8b5cf6', '#3b82f6', '#06b6d4',
            '#10b981', '#84cc16', '#ec4899', '#6366f1', '#14b8a6'
        ];

        this.charts.services = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: services.map(s => s.service),
                datasets: [{
                    data: services.map(s => s.count),
                    backgroundColor: services.map((_, i) => colors[i % colors.length]),
                    borderWidth: 0,
                    spacing: 2
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                cutout: '60%',
                plugins: {
                    legend: {
                        position: 'right',
                        labels: {
                            color: '#9ca3af',
                            font: { size: 12, family: 'Inter' },
                            padding: 16,
                            usePointStyle: true,
                            pointStyle: 'circle'
                        }
                    }
                }
            }
        });
    }

    updateCountriesChart(countries) {
        const ctx = document.getElementById('countriesChart').getContext('2d');

        if (this.charts.countries) {
            this.charts.countries.destroy();
        }

        const topCountries = countries.slice(0, 8);

        this.charts.countries = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: topCountries.map(c => `${this.countryToFlag(c.country_code)} ${c.country_code || 'Unknown'}`),
                datasets: [{
                    label: 'Requests',
                    data: topCountries.map(c => c.count),
                    backgroundColor: topCountries.map((_, i) => {
                        const opacity = 1 - (i * 0.08);
                        return `rgba(59, 130, 246, ${opacity})`;
                    }),
                    borderRadius: 6,
                    borderSkipped: false
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                indexAxis: 'y',
                plugins: {
                    legend: { display: false }
                },
                scales: {
                    x: {
                        grid: { color: 'rgba(255,255,255,0.05)' },
                        ticks: { color: '#9ca3af', font: { family: 'Inter' } }
                    },
                    y: {
                        grid: { display: false },
                        ticks: { color: '#9ca3af', font: { family: 'Inter', weight: '500' } }
                    }
                }
            }
        });
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

        tbody.innerHTML = credentials.slice(0, 10).map(c => `
            <tr class="hover:bg-gray-800/30 transition-colors">
                <td class="px-6 py-3 font-mono text-sm text-amber-400">${this.escapeHtml(c.username)}</td>
                <td class="px-6 py-3 font-mono text-sm text-red-400">${this.escapeHtml(c.password)}</td>
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

        tbody.innerHTML = paths.slice(0, 10).map(p => `
            <tr class="hover:bg-gray-800/30 transition-colors">
                <td class="px-6 py-3 font-mono text-sm text-blue-400 truncate max-w-xs" title="${this.escapeHtml(p.path)}">${this.escapeHtml(this.truncate(p.path, 40))}</td>
                <td class="px-6 py-3 text-sm text-gray-400 text-right tabular-nums">${p.count.toLocaleString()}</td>
            </tr>
        `).join('');
    }

    truncate(str, len) {
        return str.length > len ? str.substring(0, len) + '...' : str;
    }

    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text || '';
        return div.innerHTML;
    }

    // Convert country code to flag emoji (e.g., 'US' -> 🇺🇸)
    countryToFlag(countryCode) {
        if (!countryCode || countryCode.length !== 2) return '';
        const code = countryCode.toUpperCase();
        const offset = 127397;
        return String.fromCodePoint(...[...code].map(c => c.charCodeAt(0) + offset));
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
