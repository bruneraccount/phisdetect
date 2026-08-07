/**
 * navigation.js — Sidebar Navigation Manager
 * PhisDetect — Terminal Dashboard
 */

const NavigationManager = {
    /**
     * Initialize navigation
     */
    init() {
        this.setupSidebarToggle();
        this.setupNavigationLinks();
        this.setupLogout();
        this.highlightCurrentPage();
    },

    /**
     * Setup mobile sidebar toggle
     */
    setupSidebarToggle() {
        const toggleBtn = document.getElementById('menuToggle');
        const sidebar = document.getElementById('sidebar');
        const overlay = document.getElementById('sidebarOverlay');

        if (toggleBtn && sidebar && overlay && !toggleBtn.dataset.navInit) {
            toggleBtn.dataset.navInit = 'true';
            toggleBtn.addEventListener('click', (e) => {
                e.stopPropagation();
                sidebar.classList.toggle('open');
                overlay.classList.toggle('visible');
                document.body.style.overflow = sidebar.classList.contains('open') ? 'hidden' : '';
            });

            overlay.addEventListener('click', () => {
                sidebar.classList.remove('open');
                overlay.classList.remove('visible');
                document.body.style.overflow = '';
            });

            // Close sidebar on escape key
            document.addEventListener('keydown', (e) => {
                if (e.key === 'Escape' && sidebar.classList.contains('open')) {
                    sidebar.classList.remove('open');
                    overlay.classList.remove('visible');
                    document.body.style.overflow = '';
                }
            });
        }
    },

    /**
     * Setup navigation link clicks
     */
    setupNavigationLinks() {
        const links = document.querySelectorAll('.sidebar-item[data-page]');
        links.forEach(link => {
            link.addEventListener('click', (e) => {
                const page = link.dataset.page;
                const href = link.getAttribute('href');

                // If href exists, let browser handle it
                if (href && href !== '#') {
                    return;
                }

                e.preventDefault();
                this.navigate(page);
            });
        });
    },

    /**
     * Navigate to a page
     */
    navigate(page) {
        // Remove active state from all links
        document.querySelectorAll('.sidebar-item').forEach(item => {
            item.classList.remove('active');
            item.removeAttribute('aria-current');
        });

        // Find and activate the corresponding link
        const targetLink = document.querySelector(`.sidebar-item[data-page="${page}"]`);
        if (targetLink) {
            targetLink.classList.add('active');
            targetLink.setAttribute('aria-current', 'page');
        }

        // Close mobile sidebar
        const sidebar = document.getElementById('sidebar');
        const overlay = document.getElementById('sidebarOverlay');
        if (sidebar) sidebar.classList.remove('open');
        if (overlay) overlay.classList.remove('visible');
        document.body.style.overflow = '';

        // Navigate based on page
        switch (page) {
            case 'dashboard':
                window.location.href = themeHref('dashboard.html');
                break;
            case 'scanner':
                window.location.href = themeHref('index.html');
                break;
            case 'minigames':
                window.location.href = themeHref('minigames.html');
                break;
            case 'help':
                window.location.href = themeHref('help.html');
                break;
            default:
                console.warn('Unknown page:', page);
        }
    },

    /**
     * Highlight current page in sidebar
     */
    highlightCurrentPage() {
        const currentPath = window.location.pathname.split('/').pop() || 'index.html';
        
        let currentPage = '';
        if (currentPath === 'index.html' || currentPath === '') {
            currentPage = 'scanner';
        } else if (currentPath === 'dashboard.html') {
            currentPage = 'dashboard';
        } else if (currentPath === 'help.html') {
            currentPage = 'help';
        } else if (currentPath === 'minigames.html') {
            currentPage = 'minigames';
        }

        if (currentPage) {
            const link = document.querySelector(`.sidebar-item[data-page="${currentPage}"]`);
            if (link) {
                link.classList.add('active');
                link.setAttribute('aria-current', 'page');
            }
        }
    },

    /**
     * Setup logout button
     */
    setupLogout() {
        const logoutBtns = document.querySelectorAll('#logoutBtn, #logoutBtnDropdown');
        logoutBtns.forEach(btn => {
            if (btn) {
                btn.addEventListener('click', () => {
                    Utils.confirmDialog('Are you sure you want to logout?', {
                        title: 'Logout',
                        confirmText: 'Logout'
                    }).then(confirmed => {
                        if (!confirmed) return;
                        // Clear any user data
                        localStorage.removeItem('phisdetect-user');
                        // Redirect to home
                        window.location.href = themeHref('index.html');
                    });
                });
            }
        });
    },

    /**
     * Get current page name
     */
    getCurrentPage() {
        const currentPath = window.location.pathname.split('/').pop() || 'index.html';
        if (currentPath === 'index.html' || currentPath === '') return 'scanner';
        if (currentPath === 'dashboard.html') return 'dashboard';
        if (currentPath === 'help.html') return 'help';
        if (currentPath === 'minigames.html') return 'minigames';
        return 'scanner';
    }
};

// Export for use in other modules
window.NavigationManager = NavigationManager;