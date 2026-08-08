/**
 * app.js — Main Application Initializer
 * PhisDetect — Terminal Dashboard
 */

(function() {
    'use strict';

    /**
     * Wait for DOM to be ready
     */
    function domReady(fn) {
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', fn);
        } else {
            fn();
        }
    }

    /**
     * Initialize application
     */
    function initApp() {
        console.log('PhisDetect — Initializing...');
        console.log('Current page:', window.location.pathname);

        // Check if managers exist before initializing
        const managers = {
            Theme: typeof ThemeManager !== 'undefined',
            Notification: typeof NotificationManager !== 'undefined',
            Profile: typeof ProfileManager !== 'undefined',
            Navigation: typeof NavigationManager !== 'undefined',
            Scanner: typeof ScannerManager !== 'undefined',
            Dashboard: typeof DashboardManager !== 'undefined',
            Minigame: typeof MinigamesManager !== 'undefined',
            LinkDismantler: typeof LinkDismantlerManager !== 'undefined',
            ThreatHunt: typeof ThreatHuntManager !== 'undefined',
            MinigameModal: typeof MinigameModalManager !== 'undefined',
            Faq: typeof FaqManager !== 'undefined'
        };

        console.log('Managers loaded:', managers);

        if (managers.Theme) {
            try {
                ThemeManager.init();
                console.log('ThemeManager initialized');
            } catch (e) {
                console.error('ThemeManager init failed:', e);
            }
        } else {
            console.warn('ThemeManager not found');
        }
        // Initialize core managers (always needed)
        if (managers.Notification) {
            try {
                NotificationManager.init();
                console.log('NotificationManager initialized');
            } catch (e) {
                console.error('NotificationManager init failed:', e);
            }
        } else {
            console.warn('NotificationManager not found');
        }

        if (managers.Profile) {
            try {
                ProfileManager.init();
                console.log('ProfileManager initialized');
            } catch (e) {
                console.error('ProfileManager init failed:', e);
            }
        } else {
            console.warn('ProfileManager not found');
        }

        if (managers.Navigation) {
            try {
                NavigationManager.init();
                console.log('NavigationManager initialized');
            } catch (e) {
                console.error('NavigationManager init failed:', e);
            }
        } else {
            console.warn('NavigationManager not found');
        }

        // Page-specific initialization
        const path = window.location.pathname;
        
        if (path.includes('dashboard.html')) {
            console.log('Dashboard page detected');
            if (managers.Dashboard) {
                try {
                    DashboardManager.init();
                    console.log('DashboardManager initialized');
                } catch (e) {
                    console.error('DashboardManager init failed:', e);
                }
            } else {
                console.warn('DashboardManager not found');
            }
        } else if (path.includes('minigames.html')) {
            console.log('Minigames page detected');
            if (managers.Minigame) {
                try {
                    MinigamesManager.init();
                    console.log('MinigamesManager initialized');
                } catch (e) {
                    console.error('MinigamesManager init failed:', e);
                }
            } else {
                console.warn('MinigamesManager not found');
            }
            if (managers.LinkDismantler) {
                try {
                    LinkDismantlerManager.init();
                    console.log('LinkDismantlerManager initialized');
                } catch (e) {
                    console.error('LinkDismantlerManager init failed:', e);
                }
            } else {
                console.warn('LinkDismantlerManager not found');
            }
            if (managers.ThreatHunt) {
                try {
                    ThreatHuntManager.init();
                    console.log('ThreatHuntManager initialized');
                } catch (e) {
                    console.error('ThreatHuntManager init failed:', e);
                }
            } else {
                console.warn('ThreatHuntManager not found');
            }
            if (typeof LeaderboardManager !== 'undefined') {
                try {
                    LeaderboardManager.init();
                    console.log('LeaderboardManager initialized');
                } catch (e) {
                    console.error('LeaderboardManager init failed:', e);
                }
            }
            if (managers.MinigameModal) {
                try {
                    MinigameModalManager.init();
                    console.log('MinigameModalManager initialized');
                } catch (e) {
                    console.error('MinigameModalManager init failed:', e);
                }
            }
        } else if (path.includes('help.html')) {
            console.log('Help page detected');
            if (managers.Faq) {
                try {
                    FaqManager.init();
                    console.log('FaqManager initialized');
                } catch (e) {
                    console.error('FaqManager init failed:', e);
                }
            } else {
                console.warn('FaqManager not found');
            }
        } else {
            console.log('Scanner page detected');
            if (managers.Scanner) {
                try {
                    ScannerManager.init();
                    console.log('ScannerManager initialized');
                } catch (e) {
                    console.error('ScannerManager init failed:', e);
                }
            } else {
                console.warn('ScannerManager not found');
            }
        }

        console.log('PhisDetect — Ready');
    }

    // Initialize when DOM is ready
    domReady(initApp);

})();
