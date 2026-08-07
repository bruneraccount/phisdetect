/**
 * theme.js — Theme Manager (Dark/Light)
 * PhisDetect — Terminal Dashboard
 *
 * Built from scratch. The theme is applied purely through the
 * `data-theme` attribute on <html>; all styling lives in CSS
 * custom properties, so there are no inline-style overrides.
 *
 * Persistence strategy (works even when a browser partitions
 * localStorage per file:// page, e.g. Chrome/Edge/Safari):
 *   1. URL query param  ->  ?theme=light  (carried between pages)
 *   2. localStorage     ->  phisdetect-theme
 *   3. default          ->  dark
 */

(function () {
    'use strict';

    const STORAGE_KEY = 'phisdetect-theme';
    const VALID_THEMES = ['dark', 'light'];
    const DEFAULT_THEME = 'dark';

    function readStoredTheme() {
        try {
            const stored = localStorage.getItem(STORAGE_KEY);
            if (VALID_THEMES.indexOf(stored) !== -1) return stored;
        } catch (e) {
            // localStorage unavailable — fall through to default
        }
        return null;
    }

    function readUrlTheme() {
        try {
            const fromUrl = new URLSearchParams(window.location.search).get('theme');
            if (VALID_THEMES.indexOf(fromUrl) !== -1) return fromUrl;
        } catch (e) {
            // URL parsing unavailable — fall through
        }
        return null;
    }

    function storeTheme(theme) {
        try {
            localStorage.setItem(STORAGE_KEY, theme);
        } catch (e) {
            // localStorage unavailable — theme just won't persist
        }
    }

    /**
     * Append/replace the ?theme= param on a relative page href while
     * preserving any existing query params and hash. External links,
     * protocol links and plain anchors are returned unchanged.
     */
    function withThemeParam(href, theme) {
        if (!href || href === '#') return href;
        if (/^(https?:|javascript:|mailto:|tel:|data:|file:|about:|\/\/|#)/i.test(href)) return href;

        let path = href;
        let hash = '';
        const hashIndex = href.indexOf('#');
        if (hashIndex !== -1) {
            hash = href.slice(hashIndex);
            path = href.slice(0, hashIndex);
        }

        let query = '';
        const queryIndex = path.indexOf('?');
        if (queryIndex !== -1) {
            query = path.slice(queryIndex + 1);
            path = path.slice(0, queryIndex);
        }

        const params = query
            ? query.split('&').filter((p) => p && p.split('=')[0] !== 'theme')
            : [];
        params.push('theme=' + theme);

        return path + '?' + params.join('&') + hash;
    }

    const ThemeManager = {
        current: DEFAULT_THEME,

        init() {
            this.current = readUrlTheme() || readStoredTheme() || DEFAULT_THEME;
            this.apply(this.current);
            this.bindToggle();
            this.syncAcrossTabs();
        },

        apply(theme, options) {
            const opts = options || {};
            if (VALID_THEMES.indexOf(theme) === -1) theme = DEFAULT_THEME;

            this.current = theme;
            document.documentElement.setAttribute('data-theme', theme);

            this.updateIcon();
            this.syncLinks();

            if (opts.persist !== false) {
                storeTheme(theme);
                this.syncUrl();
            }

            document.dispatchEvent(new CustomEvent('theme:change', {
                detail: { theme: theme }
            }));
        },

        toggle() {
            this.apply(this.current === 'dark' ? 'light' : 'dark');
        },

        getTheme() {
            return this.current;
        },

        /** Rewrite this page's URL to advertise the current theme. */
        syncUrl() {
            try {
                const params = new URLSearchParams(window.location.search);
                if (params.get('theme') === this.current) return;
                const url = new URL(window.location.href);
                url.searchParams.set('theme', this.current);
                window.history.replaceState(null, '', url.toString());
            } catch (e) {
                // ignore — URL rewrite is an enhancement only
            }
        },

        /** Stamp every in-page navigation link with the current theme. */
        syncLinks() {
            const links = document.querySelectorAll('a[href]');
            for (let i = 0; i < links.length; i++) {
                const href = links[i].getAttribute('href');
                const updated = withThemeParam(href, this.current);
                if (updated !== href) {
                    links[i].setAttribute('href', updated);
                }
            }
        },

        /** Public helper: return an href carrying the current theme. */
        linkHref(href) {
            return withThemeParam(href, this.current);
        },

        updateIcon() {
            const icon = document.querySelector('#themeToggle i');
            if (!icon) return;
            icon.className = this.current === 'dark'
                ? 'fa-solid fa-moon'
                : 'fa-solid fa-sun';
        },

        bindToggle() {
            const btn = document.getElementById('themeToggle');
            if (!btn || btn.dataset.themeBound) return;
            btn.dataset.themeBound = 'true';
            btn.addEventListener('click', () => this.toggle());
        },

        syncAcrossTabs() {
            if (window.__themeSyncBound) return;
            window.__themeSyncBound = true;
            window.addEventListener('storage', (e) => {
                if (e.key !== STORAGE_KEY) return;
                if (VALID_THEMES.indexOf(e.newValue) !== -1) {
                    this.apply(e.newValue, { persist: false });
                }
            });
        }
    };

    window.ThemeManager = ThemeManager;
    window.themeHref = function (href) {
        return ThemeManager.linkHref(href);
    };
})();
