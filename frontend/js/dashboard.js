/**
 * dashboard.js — Dashboard Statistics Manager
 * PhisDetect — Terminal Dashboard
 */

const DashboardManager = {
    /**
     * Dashboard state
     */
    state: {
        totalScans: 0,
        threatsDetected: 0,
        reportsSubmitted: 0,
        pointsEarned: 0,
        activityLog: []
    },

    /**
     * Initialize dashboard
     */
    init() {
        this.loadState();
        this.renderStats();
        this.renderActivityLog();
        this.setupRefreshButton();
    },

    /**
     * Load state from localStorage
     */
    loadState() {
        const saved = localStorage.getItem('phisdetect-dashboard');
        if (saved) {
            try {
                const parsed = JSON.parse(saved);
                this.state = { ...this.state, ...parsed };
            } catch (e) {
                console.warn('Failed to load dashboard state:', e);
            }
        }
    },

    /**
     * Save state to localStorage
     */
    saveState() {
        try {
            localStorage.setItem('phisdetect-dashboard', JSON.stringify(this.state));
        } catch (e) {
            console.warn('Failed to save dashboard state:', e);
        }
    },

    /**
     * Animate a stat number toward its target value
     */
    animateValue(el, target) {
        if (!el) return;
        const current = parseInt(el.dataset.value || '0', 10);
        if (current === target) return;
        el.dataset.value = target;

        const reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
        const delta = Math.abs(target - current);

        if (reduceMotion || delta === 1) {
            el.textContent = target;
            return;
        }

        const duration = 600;
        const start = performance.now();
        const step = now => {
            const p = Math.min(1, (now - start) / duration);
            const eased = 1 - Math.pow(1 - p, 3);
            el.textContent = Math.round(current + (target - current) * eased);
            if (p < 1) requestAnimationFrame(step);
        };
        requestAnimationFrame(step);
    },

    /**
     * Render statistics cards
     */
    renderStats() {
        const elements = {
            totalScans: document.getElementById('totalScans'),
            threatsDetected: document.getElementById('threatsDetected'),
            reportsSubmitted: document.getElementById('reportsSubmitted'),
            pointsEarned: document.getElementById('pointsEarned')
        };

        this.animateValue(elements.totalScans, this.state.totalScans);
        this.animateValue(elements.threatsDetected, this.state.threatsDetected);
        this.animateValue(elements.reportsSubmitted, this.state.reportsSubmitted);
        this.animateValue(elements.pointsEarned, this.state.pointsEarned);
    },

    /**
     * Render activity log
     */
    renderActivityLog() {
        const logContainer = document.getElementById('activityLog');
        if (!logContainer) return;

        if (this.state.activityLog.length === 0) {
            logContainer.innerHTML = `
                <div class="log-line">
                    <span class="log-time">--:--:--</span>
                    <span class="log-gray">System ready. Waiting for activity...</span>
                </div>
            `;
            return;
        }

        // Get last 10 activities (most recent first)
        const recent = this.state.activityLog.slice(-10).reverse();

        logContainer.innerHTML = recent.map(entry => {
            const time = entry.timestamp || '--:--:--';
            const icon = this.getActivityIcon(entry.type);
            const colorClass = this.getActivityColor(entry.type);
            
            return `
                <div class="log-line">
                    <span class="log-time">${time}</span>
                    <span class="${colorClass}">${icon} ${entry.message}</span>
                </div>
            `;
        }).join('');
    },

    /**
     * Get icon for activity type
     */
    getActivityIcon(type) {
        const icons = {
            scan: '[S]',
            threat: '[T]',
            report: '[R]',
            points: '[P]',
            system: '[Sys]'
        };
        return icons[type] || '[•]';
    },

    /**
     * Get color class for activity type
     */
    getActivityColor(type) {
        const colors = {
            scan: 'log-green',
            threat: 'log-red',
            report: 'log-amber',
            points: 'log-green',
            system: 'log-gray'
        };
        return colors[type] || 'log-gray';
    },

    /**
     * Add activity to log
     */
    addActivity(type, message) {
        const now = new Date();
        const timestamp = now.toTimeString().slice(0, 8);
        
        this.state.activityLog.push({
            type,
            message,
            timestamp,
            date: now.toISOString()
        });

        // Keep log manageable (max 100 entries)
        if (this.state.activityLog.length > 100) {
            this.state.activityLog = this.state.activityLog.slice(-100);
        }

        this.saveState();
        this.renderActivityLog();
    },

    /**
     * Update statistics
     */
    updateStats(data) {
        if (data.totalScans !== undefined) {
            this.state.totalScans = data.totalScans;
        }
        if (data.threatsDetected !== undefined) {
            this.state.threatsDetected = data.threatsDetected;
        }
        if (data.reportsSubmitted !== undefined) {
            this.state.reportsSubmitted = data.reportsSubmitted;
        }
        if (data.pointsEarned !== undefined) {
            this.state.pointsEarned = data.pointsEarned;
        }

        this.saveState();
        this.renderStats();
    },

    /**
     * Increment scans counter
     */
    incrementScans(count = 1) {
        this.state.totalScans += count;
        this.saveState();
        this.renderStats();
        this.addActivity('scan', `Scan completed (${count})`);
    },

    /**
     * Increment threats counter
     */
    incrementThreats(count = 1) {
        this.state.threatsDetected += count;
        this.saveState();
        this.renderStats();
        this.addActivity('threat', `Threat detected (${count})`);
    },

    /**
     * Increment reports counter
     */
    incrementReports(count = 1) {
        this.state.reportsSubmitted += count;
        this.saveState();
        this.renderStats();
        this.addActivity('report', `Report submitted (${count})`);
    },

    /**
     * Increment points counter
     */
    incrementPoints(count = 1) {
        this.state.pointsEarned += count;
        this.saveState();
        this.renderStats();
        this.addActivity('points', `+${count} points earned`);
    },

    /**
     * Setup refresh button
     */
    setupRefreshButton() {
        const refreshBtn = document.querySelector('button[onclick*="location.reload()"]');
        if (refreshBtn) {
            refreshBtn.addEventListener('click', (e) => {
                e.preventDefault();
                this.refresh();
            });
        }

        // Also check for any button with refresh icon
        document.querySelectorAll('.btn .fa-rotate').forEach(icon => {
            const btn = icon.closest('.btn');
            if (btn) {
                btn.addEventListener('click', (e) => {
                    e.preventDefault();
                    this.refresh();
                });
            }
        });
    },

    /**
     * Refresh dashboard data
     */
    refresh() {
        // Simulate loading
        const stats = document.querySelectorAll('.card .stat-value');
        stats.forEach(el => {
            el.textContent = '...';
        });

        setTimeout(() => {
            // Reload from localStorage
            this.loadState();
            this.renderStats();
            this.renderActivityLog();
            this.addActivity('system', 'Dashboard refreshed');
            
            // Visual feedback
            const refreshBtn = document.querySelector('.btn .fa-rotate')?.closest('.btn');
            if (refreshBtn) {
                refreshBtn.style.opacity = '0.6';
                setTimeout(() => {
                    refreshBtn.style.opacity = '1';
                }, 300);
            }
        }, 500);
    },

    /**
     * Reset all stats (for testing)
     */
    reset() {
        Utils.confirmDialog('Reset all dashboard statistics?', {
            title: 'Reset Statistics',
            confirmText: 'Reset'
        }).then(confirmed => {
            if (!confirmed) return;

            this.state = {
                totalScans: 0,
                threatsDetected: 0,
                reportsSubmitted: 0,
                pointsEarned: 0,
                activityLog: []
            };
            this.saveState();
            this.renderStats();
            this.renderActivityLog();
            this.addActivity('system', 'Statistics reset');
            Utils.toast('Dashboard statistics reset.', 'info');
        });
    }
};

// Export for use in other modules
window.DashboardManager = DashboardManager;