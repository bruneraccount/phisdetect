/**
 * notifications.js — Notification Manager
 * PhisDetect — Terminal Dashboard
 */

const NotificationManager = {
    /**
     * Notification data
     */
    notifications: [],

    /**
     * Initialize notification manager
     */
    init() {
        this.loadFromStorage();
        this.setupToggle();
        this.setupMarkAllRead();
        this.render();
        this.setupAutoDismiss();
    },

    /**
     * Load notifications from localStorage
     */
    loadFromStorage() {
        try {
            const saved = localStorage.getItem('phisdetect-notifications');
            if (saved) {
                const parsed = JSON.parse(saved);
                if (Array.isArray(parsed) && parsed.length > 0) {
                    this.notifications = parsed;
                }
            }
        } catch (e) {
            console.warn('Failed to load notifications:', e);
        }
    },

    /**
     * Save notifications to localStorage
     */
    saveToStorage() {
        try {
            localStorage.setItem('phisdetect-notifications', JSON.stringify(this.notifications));
        } catch (e) {
            console.warn('Failed to save notifications:', e);
        }
    },

    /**
     * Get unread count
     */
    unreadCount() {
        return this.notifications.filter(n => !n.read).length;
    },

    /**
     * Render notifications in dropdown
     */
    render() {
        const list = document.getElementById('notificationList');
        if (!list) {
            console.warn('Notification list element not found');
            return;
        }

        if (this.notifications.length === 0) {
            list.innerHTML = `
                <div class="no-notifs">
                    <i class="fa-regular fa-bell-slash" style="font-size: 20px; display: block; margin-bottom: 8px; opacity: 0.4;"></i>
                    No notifications
                </div>
            `;
        } else {
            list.innerHTML = this.notifications.map(n => `
                <div class="notification-item ${n.read ? 'read' : 'unread'}" data-id="${n.id}">
                    <div class="notif-icon" style="color: ${n.color}">
                        <i class="fas ${n.icon}"></i>
                    </div>
                    <div class="notif-content">
                        <p>${this.escapeHtml(n.message)}</p>
                        <small>${n.time}</small>
                    </div>
                    <button class="notif-dismiss" data-id="${n.id}" aria-label="Dismiss notification">
                        <i class="fas fa-times"></i>
                    </button>
                </div>
            `).join('');
        }

        // Attach dismiss events
        list.querySelectorAll('.notif-dismiss').forEach(btn => {
            btn.addEventListener('click', (e) => {
                e.stopPropagation();
                const id = parseInt(btn.dataset.id);
                this.dismiss(id);
            });
        });

        // Mark as read on click
        list.querySelectorAll('.notification-item').forEach(item => {
            item.addEventListener('click', (e) => {
                // Don't trigger if clicking dismiss button
                if (e.target.closest('.notif-dismiss')) return;
                
                const id = parseInt(item.dataset.id);
                this.markAsRead(id);
            });
        });

        this.updateBadge();
        this.saveToStorage();
    },

    /**
     * Escape HTML to prevent XSS
     */
    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    },

    /**
     * Update notification badge
     */
    updateBadge() {
        const badge = document.getElementById('notifBadge');
        const count = this.unreadCount();
        if (badge) {
            badge.textContent = count;
            badge.style.display = count > 0 ? 'flex' : 'none';
        }
    },

    /**
     * Dismiss a notification
     */
    dismiss(id) {
        this.notifications = this.notifications.filter(n => n.id !== id);
        this.render();
    },

    /**
     * Mark a notification as read
     */
    markAsRead(id) {
        const notification = this.notifications.find(n => n.id === id);
        if (notification && !notification.read) {
            notification.read = true;
            this.render();
        }
    },

    /**
     * Mark all notifications as read
     */
    markAllRead() {
        this.notifications.forEach(n => n.read = true);
        this.render();
    },

    /**
     * Add a new notification
     */
    add(notification) {
        const newNotif = {
            id: Date.now(),
            read: false,
            time: 'Just now',
            ...notification
        };
        
        this.notifications.unshift(newNotif);
        
        // Keep at most 50 notifications
        if (this.notifications.length > 50) {
            this.notifications = this.notifications.slice(0, 50);
        }
        
        this.render();
        
        // Auto-close panel after 5 seconds if open
        setTimeout(() => {
            const panel = document.getElementById('notificationPanel');
            if (panel && panel.classList.contains('show')) {
                // Don't auto-close if user is interacting
            }
        }, 5000);
    },

    /**
     * Toggle notification panel
     */
    toggle() {
        const panel = document.getElementById('notificationPanel');
        const profilePanel = document.getElementById('profilePanel');
        
        if (!panel) {
            console.warn('Notification panel not found');
            return;
        }

        // Close profile panel if open
        if (profilePanel) {
            profilePanel.classList.remove('show');
            profilePanel.style.display = 'none';
            profilePanel.setAttribute('aria-hidden', 'true');
        }
        
        // Toggle notification panel
        const isOpen = panel.classList.contains('show');
        
        if (isOpen) {
            panel.classList.remove('show');
            panel.style.display = 'none';
            panel.setAttribute('aria-hidden', 'true');
            document.getElementById('notifButton')?.focus();
        } else {
            panel.classList.add('show');
            panel.style.display = 'block';
            panel.setAttribute('aria-hidden', 'false');
        }
    },

    /**
     * Setup toggle button
     */
    setupToggle() {
        const btn = document.getElementById('notifButton');
        if (btn && !btn.dataset.notifInit) {
            btn.dataset.notifInit = 'true';
            btn.addEventListener('click', (e) => {
                e.stopPropagation();
                this.toggle();
            });
        } else if (!btn) {
            console.warn('Notification button not found');
        }
    },

    /**
     * Setup mark all read button
     */
    setupMarkAllRead() {
        const btn = document.querySelector('.mark-all-read');
        if (btn) {
            btn.addEventListener('click', (e) => {
                e.stopPropagation();
                this.markAllRead();
            });
        }
    },

    /**
     * Auto-dismiss panel on outside click
     */
    setupAutoDismiss() {
        if (this._autoDismissInit) return;
        this._autoDismissInit = true;

        document.addEventListener('click', (e) => {
            const panel = document.getElementById('notificationPanel');
            const btn = document.getElementById('notifButton');
            
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
                const panel = document.getElementById('notificationPanel');
                if (panel && panel.classList.contains('show')) {
                    panel.classList.remove('show');
                    panel.style.display = 'none';
                    panel.setAttribute('aria-hidden', 'true');
                    document.getElementById('notifButton')?.focus();
                }
            }
        });
    }
};

// Export for use in other modules
window.NotificationManager = NotificationManager;