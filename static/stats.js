/**
 * Honeypot Statistics Page
 */

class StatsPage {
    constructor() {
        this.charts = {};
        this.init();
    }

    async init() {
        this.setupTimeFilter();
        await this.loadData();
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

            this.updateOverview(stats);
            this.updateServicesChart(stats.services);
            this.updateCountriesChart(countries);
            this.updateCredentialsTable(stats.credentials);
            this.updatePathsTable(stats.paths);

        } catch (error) {
            console.error('Failed to load stats:', error);
        }
    }

    updateOverview(stats) {
        document.getElementById('totalAttacks').textContent = stats.total.toLocaleString();
        document.getElementById('uniqueServices').textContent = stats.services.length;
        document.getElementById('uniqueCredentials').textContent = stats.credentials.length;
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
                    borderWidth: 0
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'right',
                        labels: {
                            color: '#9ca3af',
                            font: { size: 12 }
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

        const topCountries = countries.slice(0, 10);

        this.charts.countries = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: topCountries.map(c => c.country_code || 'Unknown'),
                datasets: [{
                    label: 'Attacks',
                    data: topCountries.map(c => c.count),
                    backgroundColor: 'rgba(59, 130, 246, 0.7)',
                    borderRadius: 4
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
                        ticks: { color: '#9ca3af' }
                    },
                    y: {
                        grid: { display: false },
                        ticks: { color: '#9ca3af' }
                    }
                }
            }
        });
    }

    updateCredentialsTable(credentials) {
        const tbody = document.getElementById('credentialsTable');

        if (credentials.length === 0) {
            tbody.innerHTML = '<tr><td colspan="3" style="text-align:center;color:#6b7280;">No credentials captured</td></tr>';
            return;
        }

        tbody.innerHTML = credentials.map(c => `
            <tr>
                <td style="color:#f59e0b;">${this.escapeHtml(c.username)}</td>
                <td style="color:#ef4444;">${this.escapeHtml(c.password)}</td>
                <td style="color:#9ca3af;">${c.count}</td>
            </tr>
        `).join('');
    }

    updatePathsTable(paths) {
        const tbody = document.getElementById('pathsTable');

        if (paths.length === 0) {
            tbody.innerHTML = '<tr><td colspan="2" style="text-align:center;color:#6b7280;">No HTTP paths captured</td></tr>';
            return;
        }

        tbody.innerHTML = paths.map(p => `
            <tr>
                <td style="color:#3b82f6;" title="${this.escapeHtml(p.path)}">${this.escapeHtml(this.truncate(p.path, 50))}</td>
                <td style="color:#9ca3af;">${p.count}</td>
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

// Initialize
document.addEventListener('DOMContentLoaded', () => {
    window.statsPage = new StatsPage();
});
