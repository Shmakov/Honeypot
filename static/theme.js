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

    const SUN_ICON = '<svg class="w-[18px] h-[18px]" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="4"/><path d="M12 2v2"/><path d="M12 20v2"/><path d="m4.93 4.93 1.41 1.41"/><path d="m17.66 17.66 1.41 1.41"/><path d="M2 12h2"/><path d="M20 12h2"/><path d="m6.34 17.66-1.41 1.41"/><path d="m19.07 4.93-1.41 1.41"/></svg>';
    const MOON_ICON = '<svg class="w-[18px] h-[18px]" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 3a6 6 0 0 0 9 9 9 9 0 1 1-9-9Z"/></svg>';

    // Apply theme
    function setTheme(theme) {
        if (theme === 'light') {
            document.documentElement.setAttribute('data-theme', 'light');
            document.body.classList.add('light');
            document.body.classList.remove('dark');
            if (themeToggle) {
                themeToggle.innerHTML = SUN_ICON;
                themeToggle.setAttribute('aria-label', 'Switch to dark mode');
                themeToggle.setAttribute('title', 'Switch to dark mode');
            }
        } else {
            document.documentElement.removeAttribute('data-theme');
            document.body.classList.remove('light');
            document.body.classList.add('dark');
            if (themeToggle) {
                themeToggle.innerHTML = MOON_ICON;
                themeToggle.setAttribute('aria-label', 'Switch to light mode');
                themeToggle.setAttribute('title', 'Switch to light mode');
            }
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
