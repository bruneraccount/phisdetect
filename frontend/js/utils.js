/**
 * utils.js — Utility Functions
 * PhisDetect — Terminal Dashboard
 */

const Utils = {
    /**
     * Validate URL format
     */
    isValidUrl(string) {
        try {
            const url = new URL(string);
            return url.protocol === 'http:' || url.protocol === 'https:';
        } catch (_) {
            return false;
        }
    },

    /**
     * Validate email format
     */
    isValidEmail(string) {
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        return emailRegex.test(string);
    },

    /**
     * Sanitize input (prevent XSS)
     */
    sanitize(string) {
        const element = document.createElement('div');
        element.textContent = string;
        return element.innerHTML;
    },

    /**
     * Truncate string with ellipsis
     */
    truncate(string, length = 50) {
        if (string.length <= length) return string;
        return string.slice(0, length) + '...';
    },

    /**
     * Get current timestamp
     */
    getTimestamp() {
        return new Date().toTimeString().slice(0, 8);
    },

    /**
     * Get current date
     */
    getDate() {
        return new Date().toLocaleDateString('en-US', {
            year: 'numeric',
            month: 'short',
            day: 'numeric'
        });
    },

    /**
     * Get relative time (e.g., "2 min ago")
     */
    getRelativeTime(date) {
        const now = new Date();
        const diff = Math.floor((now - date) / 1000);

        const intervals = {
            year: 31536000,
            month: 2592000,
            week: 604800,
            day: 86400,
            hour: 3600,
            minute: 60
        };

        for (const [unit, seconds] of Object.entries(intervals)) {
            const count = Math.floor(diff / seconds);
            if (count >= 1) {
                return `${count} ${unit}${count > 1 ? 's' : ''} ago`;
            }
        }

        return 'Just now';
    },

    /**
     * Generate random ID
     */
    generateId() {
        return Date.now().toString(36) + Math.random().toString(36).slice(2, 7);
    },

    /**
     * Debounce function
     */
    debounce(func, wait = 300) {
        let timeout;
        return function executedFunction(...args) {
            const later = () => {
                clearTimeout(timeout);
                func(...args);
            };
            clearTimeout(timeout);
            timeout = setTimeout(later, wait);
        };
    },

    /**
     * Throttle function
     */
    throttle(func, limit = 300) {
        let inThrottle;
        return function executedFunction(...args) {
            if (!inThrottle) {
                func(...args);
                inThrottle = true;
                setTimeout(() => {
                    inThrottle = false;
                }, limit);
            }
        };
    },

    /**
     * Get URL parameters
     */
    getUrlParams() {
        const params = new URLSearchParams(window.location.search);
        const result = {};
        for (const [key, value] of params) {
            result[key] = value;
        }
        return result;
    },

    /**
     * Get domain from URL
     */
    getDomain(url) {
        try {
            const parsed = new URL(url);
            return parsed.hostname;
        } catch (_) {
            return url;
        }
    },

    /**
     * Check if string contains suspicious patterns
     */
    containsSuspiciousPattern(string) {
        const patterns = [
            /(free|win|prize|claim|urgent|verify|account|update|confirm)/i,
            /https?:\/\/[^\s]+\.[^\s]{2,}/i,
            /\.(xyz|top|loan|work|date|click|gq|ml|tk|cf|ga|men|pro|com\.)/i,
            /[0-9]{10,}/,
            /(login|signin|secure|bank|paypal|apple|microsoft|google)/i
        ];
        return patterns.some(pattern => pattern.test(string));
    },

    /**
     * Class name utility (conditional classes)
     */
    classNames(...args) {
        return args.filter(Boolean).join(' ');
    },

    /**
     * Deep clone object
     */
    deepClone(obj) {
        return JSON.parse(JSON.stringify(obj));
    },

    /**
     * Check if running on mobile device
     */
    isMobile() {
        return window.innerWidth <= 768;
    },

    /**
     * Check if running on tablet
     */
    isTablet() {
        return window.innerWidth > 768 && window.innerWidth <= 1024;
    },

    /**
     * Check if running on desktop
     */
    isDesktop() {
        return window.innerWidth > 1024;
    },

    /**
     * Copy text to clipboard
     */
    copyToClipboard(text) {
        if (navigator.clipboard && navigator.clipboard.writeText) {
            return navigator.clipboard.writeText(text);
        }
        // Fallback
        const textarea = document.createElement('textarea');
        textarea.value = text;
        document.body.appendChild(textarea);
        textarea.select();
        document.execCommand('copy');
        document.body.removeChild(textarea);
        return Promise.resolve();
    },

    /**
     * Download data as file
     */
    downloadFile(data, filename, type = 'text/plain') {
        const blob = new Blob([data], { type });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    },

    /**
     * Format file size
     */
    formatFileSize(bytes) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    },

    /**
     * Color utilities
     */
    color: {
        /**
         * Get status color by risk level
         */
        getRiskColor(risk) {
            const colors = {
                safe: 'var(--status-safe)',
                medium: 'var(--status-suspicious)',
                high: 'var(--status-danger)',
                critical: 'var(--status-critical)',
                waiting: 'var(--text-muted)'
            };
            return colors[risk] || colors.waiting;
        },

        /**
         * Get status icon by risk level
         */
        getRiskIcon(risk) {
            const icons = {
                safe: 'fa-check-circle',
                medium: 'fa-exclamation-triangle',
                high: 'fa-circle-exclamation',
                critical: 'fa-skull',
                waiting: 'fa-hourglass-half'
            };
            return icons[risk] || icons.waiting;
        },

        /**
         * Get status badge class by risk level
         */
        getRiskBadgeClass(risk) {
            const classes = {
                safe: 'badge-green',
                medium: 'badge-amber',
                high: 'badge-red',
                critical: 'badge-red'
            };
            return classes[risk] || 'badge-gray';
        },

        /**
         * Get status label by risk level
         */
        getRiskLabel(risk) {
            const labels = {
                safe: 'Safe',
                medium: 'Suspicious',
                high: 'Threat',
                critical: 'Critical',
                waiting: 'Waiting'
            };
            return labels[risk] || labels.waiting;
        }
    },

    /**
     * Show a terminal-styled toast notification.
     * Types: info | success | warning | error
     */
    toast(message, type = 'info') {
        let container = document.getElementById('toastContainer');
        if (!container) {
            container = document.createElement('div');
            container.id = 'toastContainer';
            container.className = 'toast-container';
            container.setAttribute('aria-live', 'polite');
            document.body.appendChild(container);
        }

        const icons = {
            info: 'fa-circle-info',
            success: 'fa-circle-check',
            warning: 'fa-triangle-exclamation',
            error: 'fa-circle-xmark'
        };

        const toast = document.createElement('div');
        toast.className = `toast toast-${type}`;
        toast.setAttribute('role', 'status');

        const icon = document.createElement('i');
        icon.className = `fa-solid ${icons[type] || icons.info}`;
        const msg = document.createElement('span');
        msg.textContent = message;

        toast.appendChild(icon);
        toast.appendChild(msg);
        container.appendChild(toast);

        requestAnimationFrame(() => toast.classList.add('show'));

        const dismiss = () => {
            toast.classList.remove('show');
            setTimeout(() => toast.remove(), 300);
        };

        setTimeout(dismiss, 3800);
        toast.addEventListener('click', dismiss);
    },

    /**
     * Terminal-styled confirm dialog. Resolves with a boolean.
     */
    confirmDialog(message, options = {}) {
        const title = options.title || 'Confirm';
        const confirmText = options.confirmText || 'Confirm';
        const cancelText = options.cancelText || 'Cancel';

        return new Promise(resolve => {
            const overlay = document.createElement('div');
            overlay.className = 'modal-overlay';
            overlay.innerHTML = `
                <div class="terminal-modal" role="dialog" aria-modal="true" aria-label="${this.sanitize(title)}">
                    <div class="terminal-bar">
                        <span class="dot dot-red"></span>
                        <span class="dot dot-amber"></span>
                        <span class="dot dot-green"></span>
                        <span class="terminal-title">${this.sanitize(title)}</span>
                    </div>
                    <div class="modal-body"></div>
                    <div class="modal-actions">
                        <button class="btn btn-secondary" data-act="cancel">${this.sanitize(cancelText)}</button>
                        <button class="btn btn-primary" data-act="confirm">${this.sanitize(confirmText)}</button>
                    </div>
                </div>`;
            overlay.querySelector('.modal-body').textContent = message;
            document.body.appendChild(overlay);

            requestAnimationFrame(() => overlay.classList.add('show'));

            const confirmBtn = overlay.querySelector('[data-act="confirm"]');
            const cancelBtn = overlay.querySelector('[data-act="cancel"]');

            const cleanup = () => {
                document.removeEventListener('keydown', onKey);
                document.removeEventListener('click', onOverlay);
                overlay.remove();
            };

            const close = result => {
                overlay.classList.remove('show');
                setTimeout(() => {
                    cleanup();
                    resolve(result);
                }, 200);
            };

            const onKey = e => {
                if (e.key === 'Escape') close(false);
                if (e.key === 'Enter') close(true);
            };
            const onOverlay = e => {
                if (e.target === overlay) close(false);
            };

            confirmBtn.addEventListener('click', () => close(true));
            cancelBtn.addEventListener('click', () => close(false));
            document.addEventListener('keydown', onKey);
            document.addEventListener('click', onOverlay);

            confirmBtn.focus();
        });
    }
};

// Export for use in other modules
window.Utils = Utils;