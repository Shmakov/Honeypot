/**
 * Shared Utility Functions
 * Used by both app.js (dashboard) and stats.js (statistics page)
 */

/**
 * Escape HTML special characters to prevent XSS
 * @param {string} text - The text to escape
 * @returns {string} - Escaped HTML string
 */
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text || '';
    return div.innerHTML;
}

/**
 * Truncate a string to specified length with ellipsis
 * @param {string} str - String to truncate
 * @param {number} len - Maximum length
 * @returns {string} - Truncated string
 */
function truncate(str, len) {
    if (!str) return '';
    return str.length > len ? str.substring(0, len) + '...' : str;
}

/**
 * Format a number with locale-specific thousands separators
 * @param {number} num - Number to format
 * @returns {string} - Formatted number string
 */
function formatNumber(num) {
    return (num || 0).toLocaleString();
}

/**
 * Convert country code to flag emoji (e.g., 'US' -> 🇺🇸)
 * @param {string} countryCode - Two-letter ISO country code
 * @returns {string} - Flag emoji or empty string
 */
function countryToFlag(countryCode) {
    if (!countryCode || countryCode.length !== 2) return '';
    const code = countryCode.toUpperCase();
    // Each letter is offset from 'A' (65) to regional indicator 'A' (127462)
    const offset = 127397; // 127462 - 65
    return String.fromCodePoint(...[...code].map(c => c.charCodeAt(0) + offset));
}

/**
 * Decode hex string to readable text
 * Non-printable characters are replaced with dots
 * @param {string} hex - Hex-encoded string
 * @returns {string} - Decoded string
 */
function hexDecode(hex) {
    if (!hex) return '';
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

// Export for use in modules (if using module system)
if (typeof window !== 'undefined') {
    window.escapeHtml = escapeHtml;
    window.truncate = truncate;
    window.formatNumber = formatNumber;
    window.countryToFlag = countryToFlag;
    window.hexDecode = hexDecode;
}
