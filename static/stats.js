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

    updateMapMarkers(countries) {
        if (!statsMap) return;

        // Clear existing markers
        countryMarkers.forEach(m => statsMap.removeLayer(m));
        countryMarkers = [];

        // Country centroids (approximate lat/lng)
        const centroids = {
            'US': [39.8, -98.6], 'CN': [35.9, 104.2], 'RU': [61.5, 105.3], 'BR': [-14.2, -51.9],
            'IN': [20.6, 79.0], 'DE': [51.2, 10.5], 'GB': [55.4, -3.4], 'FR': [46.6, 2.4],
            'JP': [36.2, 138.3], 'KR': [35.9, 127.8], 'NL': [52.1, 5.3], 'VN': [16.0, 108.0],
            'ID': [-0.8, 113.9], 'TW': [23.7, 121.0], 'SG': [1.3, 103.8], 'HK': [22.4, 114.1],
            'AU': [-25.3, 133.8], 'CA': [56.1, -106.3], 'MX': [23.6, -102.6], 'IT': [41.9, 12.6],
            'ES': [40.5, -3.7], 'PL': [51.9, 19.1], 'UA': [48.4, 31.2], 'TH': [15.9, 100.9],
            'PH': [12.9, 121.8], 'MY': [4.2, 101.9], 'AR': [-38.4, -63.6], 'ZA': [-30.6, 22.9],
            'EG': [26.8, 30.8], 'TR': [38.9, 35.2], 'IR': [32.4, 53.7], 'PK': [30.4, 69.3],
            'BD': [23.7, 90.4], 'NG': [9.1, 8.7], 'CO': [4.6, -74.3], 'CL': [-35.7, -71.5]
        };

        const maxCount = Math.max(...countries.map(c => c.count), 1);

        countries.slice(0, 20).forEach(country => {
            const coords = centroids[country.country_code];
            if (!coords) return;

            const size = Math.max(15, Math.min(50, (country.count / maxCount) * 50));
            const opacity = Math.max(0.4, Math.min(0.9, (country.count / maxCount) * 0.9));

            const icon = L.divIcon({
                className: 'country-marker',
                html: `<div style="
                    width: ${size}px;
                    height: ${size}px;
                    background: rgba(239, 68, 68, ${opacity});
                    border-radius: 50%;
                    box-shadow: 0 0 ${size / 2}px rgba(239, 68, 68, 0.5);
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    font-size: ${Math.max(10, size / 3)}px;
                    font-weight: 600;
                    color: white;
                ">${country.count > 999 ? Math.floor(country.count / 1000) + 'k' : country.count}</div>`,
                iconSize: [size, size],
                iconAnchor: [size / 2, size / 2]
            });

            const marker = L.marker(coords, { icon })
                .bindPopup(`<div style="font-family: inherit; text-align: center;">
                    <strong style="font-size: 16px;">${country.country_code}</strong><br>
                    <span style="color: #888;">${country.count.toLocaleString()} attacks</span>
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
            const [statsResponse, countriesResponse] = await Promise.all([
                fetch(`/api/stats?hours=${hours}`),
                fetch(`/api/countries?hours=${hours}`)
            ]);

            const stats = await statsResponse.json();
            const countries = await countriesResponse.json();

            this.countriesData = countries;
            this.updateOverview(stats, countries);
            this.updateServicesChart(stats.services);
            this.updateCountriesChart(countries);
            this.updateCredentialsTable(stats.credentials);
            this.updatePathsTable(stats.paths);
            this.updateMapMarkers(countries);

        } catch (error) {
            console.error('Failed to load stats:', error);
        }
    }

    updateOverview(stats, countries) {
        document.getElementById('totalAttacks').textContent = stats.total.toLocaleString();
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
                labels: topCountries.map(c => c.country_code || 'Unknown'),
                datasets: [{
                    label: 'Attacks',
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
