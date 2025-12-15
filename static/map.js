/**
 * Shared Map Utilities
 * Used by both app.js (dashboard) and stats.js (statistics page)
 * Requires Leaflet.js to be loaded
 */

// Tile URLs for different themes
const TILE_URLS = {
    dark: 'https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png',
    light: 'https://{s}.basemaps.cartocdn.com/light_all/{z}/{x}/{y}{r}.png'
};

/**
 * Default map options
 */
const DEFAULT_MAP_OPTIONS = {
    center: [25, 0],
    zoom: 2,
    minZoom: 1,
    maxZoom: 8,
    zoomControl: true,
    attributionControl: false
};

/**
 * Create and initialize a Leaflet map
 * @param {string} elementId - ID of the map container element
 * @param {object} options - Optional map options to override defaults
 * @returns {object} - Object containing map instance and tile layer
 */
function initMap(elementId, options = {}) {
    const mapElement = document.getElementById(elementId);
    if (!mapElement) {
        console.warn(`Map element ${elementId} not found`);
        return null;
    }

    try {
        const mapOptions = { ...DEFAULT_MAP_OPTIONS, ...options };
        const map = L.map(elementId, mapOptions);

        // Use theme-appropriate tiles
        const theme = window.currentTheme || 'dark';
        const tileLayer = L.tileLayer(TILE_URLS[theme], {
            subdomains: 'abcd',
            maxZoom: 19
        }).addTo(map);

        // Add subtle attribution
        L.control.attribution({
            position: 'bottomright',
            prefix: false
        }).addAttribution('© <a href="https://carto.com/" style="color:#888">CARTO</a>').addTo(map);

        // Force map to recalculate size after a short delay
        setTimeout(() => {
            if (map) map.invalidateSize();
        }, 100);

        return { map, tileLayer };

    } catch (e) {
        console.error(`Failed to initialize map ${elementId}:`, e);
        return null;
    }
}

/**
 * Update map tiles to match theme
 * @param {L.Map} map - Leaflet map instance
 * @param {L.TileLayer} currentTileLayer - Current tile layer
 * @param {string} theme - Theme name ('dark' or 'light')
 * @returns {L.TileLayer} - New tile layer
 */
function updateMapTileLayer(map, currentTileLayer, theme) {
    if (!map || !currentTileLayer) return currentTileLayer;

    map.removeLayer(currentTileLayer);
    const newTileLayer = L.tileLayer(TILE_URLS[theme] || TILE_URLS.dark, {
        subdomains: 'abcd',
        maxZoom: 19
    }).addTo(map);

    return newTileLayer;
}

/**
 * Create an attack dot icon for the dashboard map
 * @param {string} service - Service name for styling
 * @returns {L.DivIcon} - Leaflet div icon
 */
function createAttackIcon(service) {
    return L.divIcon({
        className: 'attack-marker',
        html: `<div class="attack-pulse"></div><div class="attack-dot" data-service="${service}"></div>`,
        iconSize: [24, 24],
        iconAnchor: [12, 12]
    });
}

/**
 * Create a location marker icon for the stats map
 * @param {number} count - Request count for this location
 * @param {number} maxCount - Maximum count for scaling
 * @returns {L.DivIcon} - Leaflet div icon
 */
function createLocationIcon(count, maxCount) {
    // Size based on count (min 6px, max 24px)
    const size = Math.max(6, Math.min(24, Math.sqrt(count / maxCount) * 24));
    const opacity = Math.max(0.5, Math.min(0.9, Math.sqrt(count / maxCount) * 0.9));

    return L.divIcon({
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
}

// Export for global use
if (typeof window !== 'undefined') {
    window.TILE_URLS = TILE_URLS;
    window.initMap = initMap;
    window.updateMapTileLayer = updateMapTileLayer;
    window.createAttackIcon = createAttackIcon;
    window.createLocationIcon = createLocationIcon;
}
