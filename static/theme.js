/**
 * Theme management for Honeypot Dashboard
 * Syncs with system preference and persists user choice
 */

(function () {
    const themeToggle = document.getElementById('themeToggle');

    // Get theme: user preference > system preference > dark
    function getPreferredTheme() {
        const saved = localStorage.getItem('theme');
        if (saved) return saved;

        // Check system preference
        if (window.matchMedia('(prefers-color-scheme: light)').matches) {
            return 'light';
        }
        return 'dark';
    }

    // Apply theme
    function setTheme(theme) {
        if (theme === 'light') {
            document.documentElement.setAttribute('data-theme', 'light');
            document.body.classList.add('light');
            document.body.classList.remove('dark');
            if (themeToggle) themeToggle.textContent = '☀️';
        } else {
            document.documentElement.removeAttribute('data-theme');
            document.body.classList.remove('light');
            document.body.classList.add('dark');
            if (themeToggle) themeToggle.textContent = '🌙';
        }

        // Update map tiles if map exists
        if (window.updateMapTheme) {
            window.updateMapTheme(theme);
        }
    }

    // Initialize
    const currentTheme = getPreferredTheme();
    setTheme(currentTheme);

    // Store for map to access
    window.currentTheme = currentTheme;

    // Toggle handler
    if (themeToggle) {
        themeToggle.addEventListener('click', () => {
            const current = document.documentElement.getAttribute('data-theme');
            const newTheme = current === 'light' ? 'dark' : 'light';
            setTheme(newTheme);
            localStorage.setItem('theme', newTheme);
            window.currentTheme = newTheme;
        });
    }

    // Listen for system preference changes
    window.matchMedia('(prefers-color-scheme: light)').addEventListener('change', (e) => {
        // Only auto-switch if user hasn't set a preference
        if (!localStorage.getItem('theme')) {
            const newTheme = e.matches ? 'light' : 'dark';
            setTheme(newTheme);
            window.currentTheme = newTheme;
        }
    });
})();
