/**
 * profile.js — Profile Manager
 * PhisDetect — Terminal Dashboard
 */

const ProfileManager = {
    /**
     * User data
     */
    user: {
        username: 'Guest User',
        points: 0,
        reports: 0,
        rank: '--'
    },

    /**
     * Initialize profile manager
     */
    init() {
        this.loadFromStorage();
        this.setupToggle();
        this.setupSettings();
        this.setupLogout();
        this.render();
    },

    /**
     * Load user data from localStorage
     */
    loadFromStorage() {
        try {
            const saved = localStorage.getItem('phisdetect-user');
            if (saved) {
                const parsed = JSON.parse(saved);
                this.user = { ...this.user, ...parsed };
            }
        } catch (e) {
            console.warn('Failed to load user data:', e);
        }
    },

    /**
     * Save user data to localStorage
     */
    saveToStorage() {
        try {
            localStorage.setItem('phisdetect-user', JSON.stringify(this.user));
        } catch (e) {
            console.warn('Failed to save user data:', e);
        }
    },

    /**
     * Render profile in dropdown
     */
    render() {
        const panel = document.getElementById('profilePanel');
        if (!panel) return;

        const nameEl = panel.querySelector('.profile-name');
        const pointsEl = panel.querySelector('.profile-points');
        const stats = panel.querySelectorAll('.stat-value');
        
        if (nameEl) nameEl.textContent = this.user.username;
        if (pointsEl) pointsEl.innerHTML = `<i class="fa-regular fa-star" style="color: #f59e0b;"></i> ${this.user.points} points`;
        if (stats.length >= 2) {
            stats[0].textContent = this.user.reports;
            stats[1].textContent = `#${this.user.rank}`;
        }
    },

    /**
     * Update user data
     */
    updateUser(data) {
        this.user = { ...this.user, ...data };
        this.saveToStorage();
        this.render();
    },

    /**
     * Toggle profile panel
     */
    toggle() {
        const panel = document.getElementById('profilePanel');
        const notifPanel = document.getElementById('notificationPanel');
        
        if (!panel) return;

        // Close notification panel if open
        if (notifPanel) {
            notifPanel.classList.remove('show');
            notifPanel.style.display = 'none';
            notifPanel.setAttribute('aria-hidden', 'true');
        }
        
        // Toggle profile panel
        const isOpen = panel.classList.contains('show');
        
        if (isOpen) {
            panel.classList.remove('show');
            panel.style.display = 'none';
            panel.setAttribute('aria-hidden', 'true');
            document.getElementById('profileButton')?.focus();
        } else {
            panel.classList.add('show');
            panel.style.display = 'block';
            panel.setAttribute('aria-hidden', 'false');
        }
    },

    /**
     * Setup profile toggle button
     */
    setupToggle() {
        const btn = document.getElementById('profileButton');
        if (btn && !btn.dataset.profileInit) {
            btn.dataset.profileInit = 'true';
            btn.addEventListener('click', (e) => {
                e.stopPropagation();
                this.toggle();
            });
        }
    },

    /**
     * Setup settings button
     */
    setupSettings() {
        const btn = document.getElementById('settingsBtn');
        if (btn) {
            btn.addEventListener('click', () => {
                Utils.toast('Settings page coming soon!', 'info');
                this.closePanel();
            });
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
                        localStorage.removeItem('phisdetect-user');
                        this.user = { username: 'Guest User', points: 0, reports: 0, rank: '--' };
                        this.render();
                        this.closePanel();
                        Utils.toast('Logged out!', 'success');
                    });
                });
            }
        });
    },

    /**
     * Close profile panel
     */
    closePanel() {
        const panel = document.getElementById('profilePanel');
        if (panel) {
            panel.classList.remove('show');
            panel.style.display = 'none';
        }
    },

    /**
     * Auto-dismiss panel on outside click
     */
    setupAutoDismiss() {
        if (this._autoDismissInit) return;
        this._autoDismissInit = true;

        document.addEventListener('click', (e) => {
            const panel = document.getElementById('profilePanel');
            const btn = document.getElementById('profileButton');
            
            if (panel && btn) {
                const isPanelClick = panel.contains(e.target);
                const isBtnClick = btn.contains(e.target);
                
                if (!isPanelClick && !isBtnClick) {
                    panel.classList.remove('show');
                    panel.style.display = 'none';
                    panel.setAttribute('aria-hidden', 'true');
                }
            }
        });

        // Escape key
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') {
                const panel = document.getElementById('profilePanel');
                if (panel && panel.classList.contains('show')) {
                    panel.classList.remove('show');
                    panel.style.display = 'none';
                    panel.setAttribute('aria-hidden', 'true');
                    document.getElementById('profileButton')?.focus();
                }
            }
        });
    }
};

// Export for use in other modules
window.ProfileManager = ProfileManager;
