/**
 * Honeypot Statistics Page
 */

let statsMap = null;
let countryMarkers = [];
let currentTileLayer = null;

const SERVICE_PALETTE = [
    '#ef4444', // red
    '#3b82f6', // blue
    '#f59e0b', // amber
    '#8b5cf6', // violet
    '#06b6d4', // cyan
    '#6b7280', // gray (other)
];

const EMPTY_ICONS = {
    shield: '<svg class="w-6 h-6 text-gray-500" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"/></svg>',
    globe: '<svg class="w-6 h-6 text-gray-500" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="10"/><path d="M12 2a14.5 14.5 0 0 0 0 20 14.5 14.5 0 0 0 0-20"/><path d="M2 12h20"/></svg>',
    tag: '<svg class="w-6 h-6 text-gray-500" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12.586 2.586A2 2 0 0 0 11.172 2H4a2 2 0 0 0-2 2v7.172a2 2 0 0 0 .586 1.414l8.704 8.704a2.426 2.426 0 0 0 3.42 0l6.58-6.58a2.426 2.426 0 0 0 0-3.42z"/><circle cx="7.5" cy="7.5" r=".5" fill="currentColor"/></svg>',
    network: '<svg class="w-6 h-6 text-gray-500" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="16" y="16" width="6" height="6" rx="1"/><rect x="2" y="16" width="6" height="6" rx="1"/><rect x="9" y="2" width="6" height="6" rx="1"/><path d="M5 16v-3a1 1 0 0 1 1-1h12a1 1 0 0 1 1 1v3"/><path d="M12 12V8"/></svg>'
};

const ZAP_ICON = '<svg class="w-3.5 h-3.5 shrink-0" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M4 14a1 1 0 0 1-.78-1.63l9.9-10.2a.5.5 0 0 1 .86.46l-1.92 6.02A1 1 0 0 0 13 10h7a1 1 0 0 1 .78 1.63l-9.9 10.2a.5.5 0 0 1-.86-.46l1.92-6.02A1 1 0 0 0 11 14z"/></svg>';

class StatsPage {
    constructor() {
        this.countriesData = [];
        this.timeseriesData = null;
        this.barHitboxes = [];
        this.selectedHours = 720;
        this.loadingOverlay = document.getElementById('loadingOverlay');
        this.init();
    }

    async init() {
        this.setupTimeFilter();
        this.setupTimeseriesInteractions();
        await this.initMap();
        await this.loadData();
    }

    async initMap() {
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

            await loadMapConfig();

            const theme = window.currentTheme || 'dark';
            currentTileLayer = createTileLayer(theme).addTo(statsMap);

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

        countryMarkers.forEach(m => statsMap.removeLayer(m));
        countryMarkers = [];

        if (!locations || locations.length === 0) return;

        const maxCount = Math.max(...locations.map(l => l.count), 1);

        locations.forEach(loc => {
            if (loc.lat == null || loc.lon == null) return;

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
        const buttons = document.querySelectorAll('#timeRangeGroup button[data-hours]');

        const syncButtons = (hours) => {
            buttons.forEach(btn => {
                const isActive = parseInt(btn.dataset.hours, 10) === hours;
                btn.setAttribute('aria-pressed', isActive ? 'true' : 'false');
                btn.classList.toggle('active', isActive);
                btn.classList.toggle('bg-amber-500/15', isActive);
                btn.classList.toggle('text-amber-400', isActive);
                btn.classList.toggle('border', isActive);
                btn.classList.toggle('border-amber-500/30', isActive);
                btn.classList.toggle('text-gray-400', !isActive);
                btn.classList.toggle('hover:text-gray-200', !isActive);
            });
            if (select) select.value = String(hours);
        };

        buttons.forEach(btn => {
            btn.addEventListener('click', () => {
                const hours = parseInt(btn.dataset.hours, 10);
                if (hours === this.selectedHours) return;
                this.selectedHours = hours;
                syncButtons(hours);
                this.loadData();
            });
        });

        if (select) {
            select.addEventListener('change', () => {
                const hours = parseInt(select.value, 10);
                this.selectedHours = hours;
                syncButtons(hours);
                this.loadData();
            });
        }
    }

    setupTimeseriesInteractions() {
        const canvas = document.getElementById('timeseriesCanvas');
        const tooltip = document.getElementById('timeseriesTooltip');
        if (!canvas || !tooltip) return;

        canvas.addEventListener('mousemove', (e) => {
            if (!this.barHitboxes.length) return;
            const rect = canvas.getBoundingClientRect();
            const x = e.clientX - rect.left;
            const hit = this.barHitboxes.find(b => x >= b.x - b.pad && x <= b.x + b.w + b.pad);
            if (!hit) {
                tooltip.classList.add('hidden');
                return;
            }
            const p = hit.point;
            const series = this.timeseriesData;
            const keys = [...(series.top_services || [])];
            if (p.services && p.services.other) keys.push('other');

            const breakdown = keys
                .filter(k => (p.services?.[k] || 0) > 0)
                .map((k, idx) => {
                    const color = k === 'other' ? SERVICE_PALETTE[5] : SERVICE_PALETTE[idx % 5];
                    return `<div class="flex items-center justify-between gap-4">
                        <span class="flex items-center gap-1.5"><span class="w-2 h-2 rounded-sm inline-block" style="background:${color}"></span>${this.escapeHtml(k)}</span>
                        <span class="font-mono tabular-nums">${(p.services[k] || 0).toLocaleString()}</span>
                    </div>`;
                })
                .join('');

            const statusBadge = p.is_spike
                ? `<div class="inline-flex items-center gap-1 text-amber-400 font-semibold mt-1">${ZAP_ICON}<span>Wave detected (${p.multiplier.toFixed(1)}× baseline)</span></div>`
                : p.partial
                    ? `<div class="text-cyan-400 mt-1">In progress (live bucket)</div>`
                    : p.baseline > 0
                        ? `<div class="text-gray-400 mt-1">${p.multiplier.toFixed(1)}× baseline</div>`
                        : '';

            tooltip.innerHTML = `
                <div class="font-semibold mb-1">${this.escapeHtml(p.label)} • ${p.total.toLocaleString()} reqs</div>
                <div class="space-y-0.5">${breakdown || '<div class="text-gray-400">No requests</div>'}</div>
                ${statusBadge}
            `;
            tooltip.classList.remove('hidden');

            const tipX = Math.min(rect.width - 190, Math.max(8, x + 12));
            tooltip.style.left = `${tipX}px`;
            tooltip.style.top = '8px';
        });

        canvas.addEventListener('mouseleave', () => {
            tooltip.classList.add('hidden');
        });

        window.addEventListener('resize', () => {
            if (this.timeseriesData) {
                this.renderTimeseriesChart(this.timeseriesData);
            }
        });
    }

    async loadData() {
        const select = document.getElementById('timeRange');
        const buttons = document.querySelectorAll('#timeRangeGroup button[data-hours]');
        const hours = this.selectedHours || (select ? parseInt(select.value, 10) : 720);

        this.showLoading(true);
        if (select) select.disabled = true;
        buttons.forEach(btn => { btn.disabled = true; });

        try {
            const [
                statsResponse,
                countriesResponse,
                locationsResponse,
                topIpsRequestsResponse,
                topIpsBandwidthResponse,
                totalBytesResponse,
                timeseriesResponse,
                intelResponse
            ] = await Promise.all([
                fetch(`/api/stats?hours=${hours}`),
                fetch(`/api/countries?hours=${hours}`),
                fetch(`/api/locations?hours=${hours}`),
                fetch(`/api/top-ips-requests?hours=${hours}`),
                fetch(`/api/top-ips-bandwidth?hours=${hours}`),
                fetch(`/api/total-bytes?hours=${hours}`),
                fetch(`/api/timeseries?hours=${hours}`),
                fetch(`/api/intelligence?hours=${hours}`)
            ]);

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
            const timeseries = timeseriesResponse.ok ? await timeseriesResponse.json() : null;
            const intel = intelResponse.ok ? await intelResponse.json() : null;

            this.countriesData = countries;
            this.timeseriesData = timeseries;

            this.updateOverview(stats, countries, totalBytes);
            if (timeseries) {
                this.renderTimeseriesChart(timeseries);
            }
            this.updateServicesChart(stats.services);
            this.updateCountriesChart(countries);
            this.updateCredentialsTable(stats.credentials);
            this.updatePathsTable(stats.paths);
            this.updateMapMarkers(locations);
            this.updateTopIpsRequestsTable(topIpsRequests);
            this.updateTopIpsBandwidthTable(topIpsBandwidth);
            if (intel) {
                this.updateIntelligenceSection(intel, stats.total);
            }
        } catch (error) {
            console.error('Failed to load stats:', error);
            const totalEl = document.getElementById('totalRequests');
            if (totalEl) totalEl.textContent = 'Error';
        } finally {
            this.showLoading(false);
            if (select) select.disabled = false;
            buttons.forEach(btn => { btn.disabled = false; });
        }
    }

    renderTimeseriesChart(data) {
        const canvas = document.getElementById('timeseriesCanvas');
        const legend = document.getElementById('timeseriesLegend');
        const granBadge = document.getElementById('granularityBadge');
        const spikeBadge = document.getElementById('spikeBadge');
        if (!canvas) return;

        if (granBadge) {
            granBadge.textContent = data.granularity === 'hour' ? 'Hourly' : 'Daily';
        }

        if (spikeBadge) {
            if (data.spikes && data.spikes.count > 0) {
                spikeBadge.classList.remove('hidden');
                spikeBadge.classList.add('inline-flex');
                const waveLabel = `${data.spikes.count} wave${data.spikes.count > 1 ? 's' : ''} detected • Peak ${data.spikes.peak_multiplier.toFixed(1)}× baseline`;
                spikeBadge.innerHTML = `${ZAP_ICON}<span>${this.escapeHtml(waveLabel)}</span>`;
            } else {
                spikeBadge.classList.add('hidden');
                spikeBadge.classList.remove('inline-flex');
            }
        }

        const isLight = document.documentElement.getAttribute('data-theme') === 'light';
        const dpr = window.devicePixelRatio || 1;
        const rect = canvas.parentElement.getBoundingClientRect();
        const width = Math.max(300, Math.floor(rect.width));
        const height = Math.max(200, Math.floor(rect.height));

        canvas.width = width * dpr;
        canvas.height = height * dpr;
        const ctx = canvas.getContext('2d');
        ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
        ctx.clearRect(0, 0, width, height);

        const points = data.points || [];
        if (points.length === 0) {
            ctx.fillStyle = isLight ? '#64748b' : '#9ca3af';
            ctx.font = '14px Inter, system-ui, sans-serif';
            ctx.textAlign = 'center';
            ctx.fillText('No time-series activity in this range yet', width / 2, height / 2);
            this.barHitboxes = [];
            return;
        }

        const padLeft = 48;
        const padRight = 14;
        const padTop = 22;
        const padBottom = 28;
        const plotW = width - padLeft - padRight;
        const plotH = height - padTop - padBottom;

        const maxVal = Math.max(...points.map(p => p.total), data.spikes?.baseline_avg || 0, 1);
        const yMax = Math.ceil(maxVal * 1.15);

        // Gridlines & Y-axis labels
        const gridColor = isLight ? 'rgba(148, 163, 184, 0.25)' : 'rgba(75, 85, 99, 0.35)';
        const labelColor = isLight ? '#64748b' : '#9ca3af';
        ctx.strokeStyle = gridColor;
        ctx.fillStyle = labelColor;
        ctx.lineWidth = 1;
        ctx.font = '11px Inter, system-ui, sans-serif';
        ctx.textAlign = 'right';

        for (let i = 0; i <= 4; i++) {
            const val = (yMax * i) / 4;
            const y = padTop + plotH - (plotH * i) / 4;
            ctx.beginPath();
            ctx.moveTo(padLeft, y);
            ctx.lineTo(width - padRight, y);
            ctx.stroke();
            ctx.fillText(this.formatCompact(Math.round(val)), padLeft - 8, y + 4);
        }

        const topServices = data.top_services || [];
        const hasOther = points.some(p => (p.services?.other || 0) > 0);
        const seriesKeys = [...topServices];
        if (hasOther) seriesKeys.push('other');

        const slotW = plotW / points.length;
        const barW = Math.max(2, Math.min(28, slotW * 0.72));
        const gap = (slotW - barW) / 2;

        this.barHitboxes = [];
        const labelEvery = Math.max(1, Math.ceil(points.length / 8));

        points.forEach((p, idx) => {
            const x = padLeft + idx * slotW + gap;
            let currentY = padTop + plotH;

            seriesKeys.forEach((key, sIdx) => {
                const v = p.services?.[key] || 0;
                if (v <= 0) return;
                const segH = (v / yMax) * plotH;
                const color = key === 'other' ? SERVICE_PALETTE[5] : SERVICE_PALETTE[sIdx % 5];
                ctx.fillStyle = color;
                if (p.partial) {
                    ctx.globalAlpha = 0.55;
                }
                ctx.fillRect(x, currentY - segH, barW, segH);
                ctx.globalAlpha = 1.0;
                currentY -= segH;
            });

            if (p.partial && p.total > 0) {
                const totalH = (p.total / yMax) * plotH;
                ctx.save();
                ctx.setLineDash([3, 2]);
                ctx.strokeStyle = '#06b6d4';
                ctx.lineWidth = 1.2;
                ctx.strokeRect(x, padTop + plotH - totalH, barW, totalH);
                ctx.restore();
            }

            if (p.is_spike) {
                const topY = padTop + plotH - (p.total / yMax) * plotH;
                ctx.fillStyle = '#f59e0b';
                ctx.beginPath();
                ctx.arc(x + barW / 2, Math.max(8, topY - 7), 3.5, 0, Math.PI * 2);
                ctx.fill();
            }

            if (idx % labelEvery === 0 || idx === points.length - 1) {
                ctx.fillStyle = labelColor;
                ctx.font = '10px Inter, system-ui, sans-serif';
                ctx.textAlign = 'center';
                ctx.fillText(p.label, x + barW / 2, height - 8);
            }

            this.barHitboxes.push({ x, w: barW, pad: gap, point: p });
        });

        // Baseline average line
        if (data.spikes && data.spikes.baseline_avg > 0) {
            const baseY = padTop + plotH - (data.spikes.baseline_avg / yMax) * plotH;
            ctx.save();
            ctx.setLineDash([5, 4]);
            ctx.strokeStyle = isLight ? 'rgba(217, 119, 6, 0.7)' : 'rgba(251, 191, 36, 0.65)';
            ctx.lineWidth = 1.5;
            ctx.beginPath();
            ctx.moveTo(padLeft, baseY);
            ctx.lineTo(width - padRight, baseY);
            ctx.stroke();
            ctx.restore();
        }

        if (legend) {
            const legendItems = seriesKeys.map((k, idx) => {
                const color = k === 'other' ? SERVICE_PALETTE[5] : SERVICE_PALETTE[idx % 5];
                return `<span class="inline-flex items-center gap-1.5"><span class="w-2.5 h-2.5 rounded-sm inline-block" style="background:${color}"></span><span>${this.escapeHtml(k)}</span></span>`;
            });
            if (data.spikes && data.spikes.baseline_avg > 0) {
                legendItems.push(`<span class="inline-flex items-center gap-1.5"><span class="w-4 border-t-2 border-dashed border-amber-400 inline-block"></span><span>Baseline (${Math.round(data.spikes.baseline_avg).toLocaleString()})</span></span>`);
            }
            if (data.spikes && data.spikes.count > 0) {
                legendItems.push(`<span class="inline-flex items-center gap-1.5"><span class="w-2.5 h-2.5 rounded-full bg-amber-400 inline-block"></span><span>Wave / Spike</span></span>`);
            }
            legend.innerHTML = legendItems.join('');
        }
    }

    formatCompact(n) {
        if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
        if (n >= 1_000) return `${(n / 1_000).toFixed(1)}k`;
        return String(n);
    }

    showLoading(show) {
        if (this.loadingOverlay) {
            this.loadingOverlay.classList.toggle('active', show);
        }
    }

    updateOverview(stats, countries, totalBytes) {
        document.getElementById('totalRequests').textContent = stats.total.toLocaleString();
        document.getElementById('totalTraffic').textContent = this.formatBytes(totalBytes);
        document.getElementById('uniqueServices').textContent = stats.services.length;
        document.getElementById('uniqueCountries').textContent = countries.length;
    }

    formatBytes(bytes) {
        if (bytes === 0) return '0 B';
        const k = 1024;
        const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
    }

    renderBarList(containerId, items, emptyIcon, emptyLabel, gradientColors) {
        const container = document.getElementById(containerId);
        if (!container) return;

        if (!items || items.length === 0) {
            container.innerHTML = `
                <div class="flex flex-col items-center justify-center h-full text-gray-500 gap-2">
                    ${emptyIcon}
                    <span>${this.escapeHtml(emptyLabel)}</span>
                </div>`;
            return;
        }

        const maxCount = Math.max(...items.map(s => s.count), 1);
        container.innerHTML = items.map((item, i) => {
            const percentage = (item.count / maxCount) * 100;
            const opacity = Math.max(0.4, 1 - (i * 0.03));
            return `
                <div class="stat-bar-item group">
                    <div class="flex items-center gap-3 py-2 px-3 rounded-lg hover:bg-gray-800/50 transition-colors">
                        <span class="text-gray-500 text-xs font-medium w-5 text-right">${i + 1}</span>
                        <div class="flex-1 min-w-0">
                            <div class="flex items-center justify-between mb-1">
                                <span class="text-sm font-medium text-gray-200 truncate">${item.labelHtml}</span>
                                <span class="text-xs text-gray-400 tabular-nums ml-2">${item.count.toLocaleString()}</span>
                            </div>
                            <div class="h-2 bg-gray-800 rounded-full overflow-hidden">
                                <div class="h-full rounded-full transition-all duration-300"
                                     style="width: ${percentage}%; background: linear-gradient(90deg, rgba(${gradientColors[0]}, ${opacity}), rgba(${gradientColors[1]}, ${opacity}));"></div>
                            </div>
                        </div>
                    </div>
                </div>`;
        }).join('');
    }

    updateServicesChart(services) {
        const sorted = [...(services || [])].sort((a, b) => b.count - a.count);
        const items = sorted.map(s => ({ labelHtml: this.escapeHtml(s.service), count: s.count }));
        this.renderBarList('servicesChart', items, EMPTY_ICONS.shield, 'No service data available', ['245, 158, 11', '249, 115, 22']);
    }

    updateCountriesChart(countries) {
        const regionNames = new Intl.DisplayNames(['en'], { type: 'region' });
        const items = (countries || []).map(c => {
            const flag = this.countryToFlag(c.country_code);
            let name = 'Unknown';
            if (c.country_code) {
                try {
                    name = regionNames.of(c.country_code) || c.country_code;
                } catch {
                    name = c.country_code;
                }
            }
            return { labelHtml: `${flag} ${this.escapeHtml(name)}`, count: c.count };
        });
        this.renderBarList('countriesChart', items, EMPTY_ICONS.globe, 'No country data available', ['59, 130, 246', '99, 102, 241']);
    }

    updateIntelligenceSection(intel, totalRequests) {
        const scannerEl = document.getElementById('scannerSummary');
        if (scannerEl) {
            const pct = totalRequests > 0 ? ((intel.scanner_requests / totalRequests) * 100).toFixed(1) : '0.0';
            scannerEl.textContent = `${(intel.scanner_requests || 0).toLocaleString()} scanner requests (${pct}%)`;
        }

        this.renderBarList(
            'tagsChart',
            (intel.tags || []).map(t => ({ labelHtml: this.escapeHtml(t.name), count: t.count })),
            EMPTY_ICONS.tag,
            'No attack tags recorded in this window',
            ['239, 68, 68', '245, 158, 11']
        );

        this.renderBarList(
            'asnsChart',
            (intel.asns || []).map(a => ({ labelHtml: this.escapeHtml(a.name), count: a.count })),
            EMPTY_ICONS.network,
            'No ASN data captured yet',
            ['139, 92, 246', '99, 102, 241']
        );

        this.renderSimpleCountTable('commandsTable', intel.commands, 'No shell commands captured', 'text-cyan-400 font-mono');
        this.renderSimpleCountTable('userAgentsTable', intel.user_agents, 'No client banners captured', 'text-gray-300 font-mono');

        const iocsBody = document.getElementById('iocsTable');
        if (iocsBody) {
            const iocs = intel.recent_iocs || [];
            if (iocs.length === 0) {
                iocsBody.innerHTML = `<tr><td colspan="5" class="px-6 py-8 text-center text-gray-500">No IOCs captured in this window</td></tr>`;
            } else {
                iocsBody.innerHTML = iocs.map(item => `
                    <tr class="hover:bg-gray-800/30 transition-colors">
                        <td class="px-6 py-3 text-xs text-gray-400 whitespace-nowrap">${new Date(item.timestamp).toLocaleString()}</td>
                        <td class="px-6 py-3 font-mono text-xs text-cyan-400 whitespace-nowrap">${this.escapeHtml(item.ip)}</td>
                        <td class="px-6 py-3 text-xs text-gray-300">${this.escapeHtml(item.service)}</td>
                        <td class="px-6 py-3"><span class="tag-pill tag-alert">${this.escapeHtml(item.ioc_type)}</span></td>
                        <td class="px-6 py-3 font-mono text-xs text-red-300 break-all">${this.escapeHtml(item.defanged || item.value)}</td>
                    </tr>
                `).join('');
            }
        }
    }

    renderSimpleCountTable(tbodyId, rows, emptyText, textClass) {
        const tbody = document.getElementById(tbodyId);
        if (!tbody) return;
        if (!rows || rows.length === 0) {
            tbody.innerHTML = `<tr><td colspan="2" class="px-5 py-8 text-center text-gray-500 text-sm">${this.escapeHtml(emptyText)}</td></tr>`;
            return;
        }
        tbody.innerHTML = rows.map(r => `
            <tr class="hover:bg-gray-800/30 transition-colors">
                <td class="px-5 py-2.5 text-xs ${textClass} truncate max-w-[220px]" title="${this.escapeHtml(r.name)}">${this.escapeHtml(this.truncate(r.name, 48))}</td>
                <td class="px-5 py-2.5 text-xs text-gray-400 text-right tabular-nums">${r.count.toLocaleString()}</td>
            </tr>
        `).join('');
    }

    formatCredential(value, colorClass) {
        if (!value || value.length === 0) {
            return `<span class="text-gray-500 italic">(empty)</span>`;
        }
        if (value.trim().length === 0) {
            const visibleSpaces = value.replace(/ /g, '·').replace(/\t/g, '→');
            return `<span class="${colorClass}" title="${value.length} whitespace character(s)">${this.escapeHtml(visibleSpaces)}</span>`;
        }
        const hasLeadingSpace = value !== value.trimStart();
        const hasTrailingSpace = value !== value.trimEnd();
        if (hasLeadingSpace || hasTrailingSpace) {
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
            tbody.innerHTML = `<tr><td colspan="3" class="px-6 py-8 text-center text-gray-500">No credentials captured</td></tr>`;
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
            tbody.innerHTML = `<tr><td colspan="2" class="px-6 py-8 text-center text-gray-500">No HTTP paths captured</td></tr>`;
            return;
        }
        tbody.innerHTML = paths.map(p => `
            <tr class="hover:bg-gray-800/30 transition-colors">
                <td class="px-6 py-3 font-mono text-sm text-blue-400 truncate max-w-xs" title="${this.escapeHtml(p.path)}">${this.escapeHtml(this.truncate(p.path, 40))}</td>
                <td class="px-6 py-3 text-sm text-gray-400 text-right tabular-nums">${p.count.toLocaleString()}</td>
            </tr>
        `).join('');
    }

    truncate(str, len) { return truncate(str, len); }
    escapeHtml(text) { return escapeHtml(text); }
    countryToFlag(code) { return countryToFlag(code); }

    updateTopIpsRequestsTable(ips) {
        const tbody = document.getElementById('topIpsRequestsTable');
        if (!ips || ips.length === 0) {
            tbody.innerHTML = `<tr><td colspan="2" class="px-6 py-8 text-center text-gray-500">No IP data available</td></tr>`;
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
            tbody.innerHTML = `<tr><td colspan="2" class="px-6 py-8 text-center text-gray-500">No bandwidth data available</td></tr>`;
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

window.updateMapTheme = function (theme) {
    if (statsMap && currentTileLayer) {
        statsMap.removeLayer(currentTileLayer);
        currentTileLayer = createTileLayer(theme).addTo(statsMap);
    }
    if (window.statsPage && window.statsPage.timeseriesData) {
        window.statsPage.renderTimeseriesChart(window.statsPage.timeseriesData);
    }
};

document.addEventListener('DOMContentLoaded', () => {
    window.statsPage = new StatsPage();
});
