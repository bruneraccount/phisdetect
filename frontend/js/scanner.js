/**
 * scanner.js — Scanner Manager (URL, Email, QR)
 * PhisDetect — Terminal Dashboard
 */

const BACKEND_URL = 'http://localhost:3000';

const ScannerManager = {
    currentTab: 'url',

    init() {
        this.setupTabs();
        this.setupUrlScanner();
        this.setupEmailScanner();
        this.setupQrScanner();
        this.resetAnalysis('url');
        this.resetAnalysis('email');
        this.resetAnalysis('qr');
        this.showTab('url');
    },

    // ============================================
    // TABS
    // ============================================
    setupTabs() {
        const tabs = document.querySelectorAll('.tab');
        tabs.forEach(tab => {
            tab.addEventListener('click', () => {
                const tabName = tab.dataset.tab;
                this.showTab(tabName);
                tab.focus();
            });

            // Arrow-key navigation between tabs
            tab.addEventListener('keydown', (e) => {
                if (e.key !== 'ArrowLeft' && e.key !== 'ArrowRight' && e.key !== 'Home' && e.key !== 'End') return;
                e.preventDefault();
                const index = Array.from(tabs).indexOf(tab);
                let next;
                if (e.key === 'ArrowRight') next = tabs[(index + 1) % tabs.length];
                else if (e.key === 'ArrowLeft') next = tabs[(index - 1 + tabs.length) % tabs.length];
                else if (e.key === 'Home') next = tabs[0];
                else next = tabs[tabs.length - 1];
                this.showTab(next.dataset.tab);
                next.focus();
            });
        });
    },

    showTab(tabName) {
        this.currentTab = tabName;

        // Update tab buttons
        document.querySelectorAll('.tab').forEach(tab => {
            const isActive = tab.dataset.tab === tabName;
            tab.classList.toggle('active', isActive);
            tab.setAttribute('aria-selected', isActive);
        });

        // Update panels
        document.querySelectorAll('.tab-panel').forEach(panel => {
            const panelId = panel.id;
            if (panelId === `panel-${tabName}`) {
                panel.style.display = 'block';
                panel.classList.add('active');
                panel.setAttribute('role', 'tabpanel');
            } else {
                panel.style.display = 'none';
                panel.classList.remove('active');
            }
        });
    },

    // ============================================
    // URL SCANNER
    // ============================================
    setupUrlScanner() {
        const analyzeBtn = document.getElementById('analyzeUrlBtn');
        const clearBtn = document.getElementById('clearUrlBtn');
        const input = document.getElementById('urlInput');

        if (analyzeBtn) {
            analyzeBtn.addEventListener('click', () => this.scanUrl());
        }
        if (clearBtn) {
            clearBtn.addEventListener('click', () => {
                if (input) input.value = '';
                this.resetAnalysis('url');
            });
        }
        if (input) {
            input.addEventListener('keydown', (e) => {
                if (e.key === 'Enter') {
                    e.preventDefault();
                    this.scanUrl();
                }
            });
        }
    },

    scanUrl() {
        const input = document.getElementById('urlInput');
        const url = input?.value.trim();

        if (!url) {
            this.showAlert('Please enter a URL to scan.', 'warning');
            return;
        }

        if (!this.isValidUrl(url)) {
            this.showAlert('Please enter a valid URL (e.g., https://example.com)', 'warning');
            return;
        }

        this.runScanWithOverlay('url', () => this.callBackend('/api/scan/url', { url }))
            .then(result => this.updateAnalysis('url', result))
            .catch(err => this.showAlert(`Backend error: ${err.message}`, 'error'));
    },

    // ============================================
    // EMAIL SCANNER
    // ============================================
    setupEmailScanner() {
        const analyzeBtn = document.getElementById('analyzeEmailBtn');
        const clearBtn = document.getElementById('clearEmailBtn');
        const input = document.getElementById('emailInput');

        if (analyzeBtn) {
            analyzeBtn.addEventListener('click', () => this.scanEmail());
        }
        if (clearBtn) {
            clearBtn.addEventListener('click', () => {
                if (input) input.value = '';
                this.resetAnalysis('email');
            });
        }
    },

    scanEmail() {
        const input = document.getElementById('emailInput');
        const email = input?.value.trim();

        if (!email) {
            this.showAlert('Please paste an email to analyze.', 'warning');
            return;
        }

        this.runScanWithOverlay('email', () => this.callBackend('/api/scan/email', { content: email }))
            .then(result => this.updateAnalysis('email', result))
            .catch(err => this.showAlert(`Backend error: ${err.message}`, 'error'));
    },

    // ============================================
    // QR SCANNER
    // ============================================
    setupQrScanner() {
        const uploadBtn = document.getElementById('qrUploadBtn');
        const fileInput = document.getElementById('qrFileInput');
        const uploadArea = document.getElementById('qrUploadArea');
        const analyzeBtn = document.getElementById('analyzeQrBtn');
        const clearBtn = document.getElementById('clearQrBtn');

        if (uploadBtn) {
            uploadBtn.addEventListener('click', (e) => {
                e.stopPropagation();
                if (fileInput) fileInput.click();
            });
        }

        if (uploadArea) {
            uploadArea.addEventListener('click', () => {
                if (fileInput) fileInput.click();
            });
            uploadArea.addEventListener('dragover', (e) => {
                e.preventDefault();
                uploadArea.classList.add('dragover');
            });
            uploadArea.addEventListener('dragleave', () => {
                uploadArea.classList.remove('dragover');
            });
            uploadArea.addEventListener('drop', (e) => {
                e.preventDefault();
                uploadArea.classList.remove('dragover');
                const files = e.dataTransfer.files;
                if (files.length > 0) {
                    this.processQrImage(files[0]);
                }
            });
        }

        if (fileInput) {
            fileInput.addEventListener('change', (e) => {
                if (e.target.files.length > 0) {
                    this.processQrImage(e.target.files[0]);
                }
            });
        }

        if (analyzeBtn) {
            analyzeBtn.addEventListener('click', () => {
                const extractedUrl = document.getElementById('extractedUrl')?.textContent;
                if (extractedUrl && extractedUrl !== 'No URL found in QR code') {
                    this.scanQrUrl(extractedUrl);
                } else {
                    this.showAlert('No valid URL found in QR code to analyze.', 'warning');
                }
            });
        }

        if (clearBtn) {
            clearBtn.addEventListener('click', () => {
                this.resetQrScanner();
            });
        }
    },

    processQrImage(file) {
        if (!file.type.startsWith('image/')) {
            this.showAlert('Please upload an image file.', 'warning');
            return;
        }

        const reader = new FileReader();
        reader.onload = (e) => {
            const image = new Image();
            image.onload = () => {
                const canvas = document.createElement('canvas');
                const ctx = canvas.getContext('2d');
                canvas.width = image.width;
                canvas.height = image.height;
                ctx.drawImage(image, 0, 0, image.width, image.height);
                const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
                const code = jsQR(imageData.data, imageData.width, imageData.height);

                const extractedUrl = code?.data || 'No URL found in QR code';
                document.getElementById('extractedUrl').textContent = extractedUrl;

                if (code && this.isValidUrl(extractedUrl)) {
                    document.getElementById('qrUploadArea').style.display = 'none';
                    document.getElementById('qrResult').style.display = 'block';
                    document.getElementById('qrActions').style.display = 'flex';
                    this.showAlert('QR code decoded successfully!', 'success');
                } else {
                    document.getElementById('qrResult').style.display = 'block';
                    document.getElementById('qrActions').style.display = 'flex';
                    this.showAlert('Could not extract a valid URL from this QR code.', 'warning');
                }
            };
            image.src = e.target.result;
        };
        reader.readAsDataURL(file);
    },

    scanQrUrl(url) {
        this.runScanWithOverlay('qr', () => this.callBackend('/api/scan/url', { url }))
            .then(result => this.updateAnalysis('qr', result))
            .catch(err => this.showAlert(`Backend error: ${err.message}`, 'error'));
    },

    resetQrScanner() {
        document.getElementById('qrUploadArea').style.display = 'block';
        document.getElementById('qrResult').style.display = 'none';
        document.getElementById('qrActions').style.display = 'none';
        document.getElementById('qrFileInput').value = '';
        document.getElementById('extractedUrl').textContent = '';
        this.resetAnalysis('qr');
    },

    // ============================================
    // UTILITY FUNCTIONS
    // ============================================
    isValidUrl(string) {
        try {
            const url = new URL(string);
            return url.protocol === 'http:' || url.protocol === 'https:';
        } catch (_) {
            return false;
        }
    },

    showAlert(message, type = 'info') {
        if (window.Utils && Utils.toast) {
            Utils.toast(message, type);
        }
    },

    setButtonBusy(type, busy) {
        const btnId = `analyze${type.charAt(0).toUpperCase() + type.slice(1)}Btn`;
        const btn = document.getElementById(btnId);
        if (!btn) return;

        if (busy) {
            if (btn.dataset.originalHtml) return;
            btn.dataset.originalHtml = btn.innerHTML;
            btn.disabled = true;
            btn.classList.add('busy');
            btn.innerHTML = `<i class="fa-solid fa-circle-notch fa-spin"></i> Scanning...`;
        } else {
            if (!btn.dataset.originalHtml) return;
            btn.innerHTML = btn.dataset.originalHtml;
            delete btn.dataset.originalHtml;
            btn.disabled = false;
            btn.classList.remove('busy');
        }
    },

    resetResultCards(type) {
        const prefix = type;
        const results = document.getElementById(`${prefix}Results`);
        const reportBtn = document.getElementById(`report${type.charAt(0).toUpperCase() + type.slice(1)}Btn`);

        if (results) results.classList.remove('scan-complete');

        const ids = [`${prefix}Confidence`, ...this.getDetailConfig(type).map(c => c.id)];
        ids.forEach(id => {
            const el = document.getElementById(id);
            if (el) {
                el.textContent = '--';
                el.className = 'stat-value neutral';
            }
        });

        if (reportBtn) reportBtn.style.display = 'none';

        const indicatorsEl = document.getElementById(`${prefix}Indicators`);
        if (indicatorsEl) indicatorsEl.innerHTML = '';
    },

    setAnalysisLoading(type) {
        const prefix = type;
        this.resetResultCards(type);

        const badge = document.getElementById(`${prefix}StatusBadge`);
        if (badge) {
            badge.className = 'status-badge amber';
            badge.innerHTML = `<span class="badge-dot"></span> Scanning`;
        }
    },

    resetAnalysis(type) {
        const prefix = type;
        const riskLabel = document.getElementById(`${prefix}RiskLabel`);
        this.resetResultCards(type);

        if (riskLabel) {
            riskLabel.className = 'risk-label waiting hidden';
            riskLabel.innerHTML = '';
        }

        const badge = document.getElementById(`${prefix}StatusBadge`);
        if (badge) {
            badge.className = 'status-badge gray';
            badge.innerHTML = `<span class="badge-dot"></span> Ready`;
        }
    },

    // ============================================
    // UPDATE UI FUNCTIONS
    // ============================================
    getDetailConfig(type) {
        if (type === 'email') {
            return [
                { id: 'emailLinks', value: r => r.suspiciousLinks, cls: r => r.suspiciousLinks !== '0' ? 'danger' : 'safe' },
                { id: 'emailAttachments', value: r => r.suspiciousAttachments, cls: r => r.suspiciousAttachments !== '0' ? 'danger' : 'safe' },
                { id: 'emailGrammar', value: r => r.grammarManipulation, cls: r => r.grammarManipulation === 'None' || r.grammarManipulation === 'Minor' ? 'safe' : 'danger' },
                { id: 'emailSpoofing', value: r => r.spoofingDetected, cls: r => r.spoofingDetected === 'Yes' ? 'danger' : 'safe' }
            ];
        }
        return [
            { id: `${type}DomainAge`, value: r => r.domainAge, cls: r => r.domainAge.includes('hour') || r.domainAge.includes('day') ? 'danger' : r.domainAge === 'Unknown' ? 'warning' : 'safe' },
            { id: `${type}SslStatus`, value: r => r.sslStatus, cls: r => r.sslStatus === 'Valid' ? 'safe' : 'danger' },
            { id: `${type}Redirection`, value: r => r.redirection, cls: r => r.redirection === 'Detected' ? 'danger' : 'safe' },
            { id: `${type}Blacklist`, value: r => r.blacklist, cls: r => r.blacklist === 'Flagged' ? 'danger' : 'safe' }
        ];
    },

    updateAnalysis(type, result) {
        const prefix = type;
        const riskLabel = document.getElementById(`${prefix}RiskLabel`);
        const reportBtn = document.getElementById(`report${prefix.charAt(0).toUpperCase() + prefix.slice(1)}Btn`);
        const results = document.getElementById(`${prefix}Results`);

        if (results) results.classList.add('scan-complete');

        // The scan terminal transforms into the verdict banner
        if (riskLabel) {
            riskLabel.className = `risk-label ${result.risk}`;
            riskLabel.innerHTML = `<span class="risk-icon"><i class="fa-solid fa-${result.risk === 'safe' ? 'check' : result.risk === 'medium' ? 'exclamation' : 'triangle-exclamation'}"></i></span> ${result.verdict.label}`;
        }

        const gaugeClass = result.risk === 'safe' ? 'safe' : result.risk === 'medium' ? 'warning' : result.risk === 'critical' ? 'critical' : 'danger';

        // AI CONFIDENCE stat
        const score = document.getElementById(`${prefix}Confidence`);
        if (score) {
            score.textContent = `${result.confidence}%`;
            score.className = `stat-value ${gaugeClass}`;
        }

        // Detail stats
        this.getDetailConfig(type).forEach(({ id, value, cls }) => {
            const el = document.getElementById(id);
            if (el) {
                el.textContent = value(result);
                el.className = `stat-value ${cls(result)}`;
            }
        });

        this.renderIndicators(type, result);

        // Show report button if threat detected
        if (result.risk !== 'safe') {
            reportBtn.style.display = 'flex';
            reportBtn.onclick = () => this.submitReport(type, result);
        } else {
            reportBtn.style.display = 'none';
        }

        // Update status badge
        const badge = document.getElementById(`${prefix}StatusBadge`);
        if (badge) {
            const statusClass = result.risk === 'safe' ? 'green' : result.risk === 'medium' ? 'amber' : 'red';
            const statusLabel = result.risk === 'safe' ? 'Safe' : result.risk === 'medium' ? 'Suspicious' : 'Threat';
            badge.className = `status-badge ${statusClass}`;
            badge.innerHTML = `<span class="badge-dot"></span> ${statusLabel}`;
        }

        // Award points for detection
        if (result.risk !== 'safe') {
            this.addPoints(5);
        }
    },

    escapeHtml(value) {
        return String(value).replace(/[&<>"']/g, (c) => ({
            '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
        }[c]));
    },

    renderIndicators(type, result) {
        const container = document.getElementById(`${type}Indicators`);
        if (!container) return;

        const items = [];
        if (type === 'url') {
            if (Array.isArray(result.indicators)) {
                result.indicators.forEach((ind) => items.push({ icon: 'fa-circle-exclamation', html: this.escapeHtml(ind) }));
            }
        } else {
            if (Array.isArray(result.indicators)) {
                result.indicators.forEach((ind) => items.push({ icon: 'fa-circle-exclamation', html: this.escapeHtml(ind) }));
            }
            if (Array.isArray(result.links)) {
                result.links.forEach((link) => {
                    const verdictCls = link.risk === 'safe' ? 'green' : link.risk === 'medium' ? 'amber' : 'red';
                    const hint = link.indicators && link.indicators.length ? this.escapeHtml(link.indicators[0]) : '';
                    items.push({
                        icon: 'fa-link',
                        html: `
                            <span class="status-badge ${verdictCls}">${this.escapeHtml(link.verdict)}</span>
                            <span class="indicator-host">${this.escapeHtml(link.host)}</span>${hint ? `<span class="indicator-hint">${hint}</span>` : ''}
                        `,
                    });
                });
            }
        }

        if (!items.length) {
            container.innerHTML = '';
            return;
        }

        container.innerHTML = `
            <div class="indicator-block">
                <div class="indicator-block-label">Indicators</div>
                ${items.slice(0, 12).map((it) => `
                    <div class="indicator-item">
                        <i class="fa-solid ${it.icon} indicator-icon"></i>
                        <span class="indicator-detail">${it.html}</span>
                    </div>
                `).join('')}
            </div>`;
    },

    // ============================================
    // REPORT SYSTEM
    // ============================================
    submitReport(type, result) {
        Utils.confirmDialog(
            'Submit this threat report to cybersecurity authorities?',
            { title: 'Report Threat', confirmText: 'Submit' }
        ).then(confirmed => {
            if (!confirmed) return;

            // Add notification
            if (window.NotificationManager) {
                window.NotificationManager.add({
                    icon: 'fa-flag',
                    color: '#ff3b3b',
                    message: 'Threat reported! +10 points earned.'
                });
            }

            this.addPoints(10);

            // Update dashboard if available
            if (window.DashboardManager) {
                window.DashboardManager.incrementReports(1);
            }

            this.showAlert('Threat reported successfully! +10 points awarded!', 'success');

            const reportBtn = document.getElementById(`report${type.charAt(0).toUpperCase() + type.slice(1)}Btn`);
            if (reportBtn) reportBtn.style.display = 'none';
        });
    },

    // ============================================
    // POINTS SYSTEM
    // ============================================
    addPoints(points) {
        // Update profile if available
        if (window.ProfileManager) {
            const user = window.ProfileManager.user;
            user.points += points;
            if (points === 10) user.reports += 1;
            window.ProfileManager.render();
        }

        // Update dashboard if available
        if (window.DashboardManager) {
            window.DashboardManager.incrementPoints(points);
            if (points === 10) {
                window.DashboardManager.incrementReports(1);
            }
        }

        // Update any UI elements showing points
        if (document.getElementById('userPoints')) {
            document.getElementById('userPoints').textContent = 
                window.ProfileManager ? window.ProfileManager.user.points : '0';
        }
    },

    callBackend(endpoint, data) {
        return fetch(`${BACKEND_URL}${endpoint}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(data)
        })
        .then(res => {
            if (!res.ok) throw new Error(`Server returned ${res.status}`);
            return res.json();
        })
        .then(result => {
            if (result.error) throw new Error(result.error);
            return result;
        });
    },

    // ============================================
    // INLINE SCAN PROGRESS — Terminal Log
    // ============================================
    appendProgressLine(container, message, awaiting) {
        if (!container) return null;
        const line = document.createElement('div');
        line.className = 'scan-progress-line' + (awaiting ? ' awaiting' : '');
        line.innerHTML = `<span class="sp"><i class="fa-solid fa-spinner fa-spin"></i></span><span class="msg">&gt; ${message}</span>`;
        container.appendChild(line);
        return line;
    },

    getScanSteps(type) {
        if (type === 'email') {
            return [
                'Extracting embedded links',
                'Scanning links with threat model',
                'Checking for urgency signals',
                'Analyzing attachments',
                'Checking sender spoofing',
                'Computing heuristic risk'
            ];
        }
        return [
            'Extracting URL features',
            'Querying DNS records',
            'Running machine learning model',
            'Checking domain registration age',
            'Verifying SSL certificate',
            'Tracing redirect chain',
            'Checking blocklists',
            'Computing risk verdict'
        ];
    },

    runScanWithOverlay(type, requestFn) {
        const steps = this.getScanSteps(type);
        const startedAt = Date.now();
        const prefix = type;
        const riskLabel = document.getElementById(`${prefix}RiskLabel`);
        const lines = [];
        let played = 0;
        let backendDone = false;
        let terminalDone = false;
        let result = null;

        this.setButtonBusy(type, true);
        this.setAnalysisLoading(type);

        // Transform the risk label into an inline terminal log
        if (riskLabel) {
            riskLabel.className = 'risk-label waiting scan-progress';
            riskLabel.innerHTML = '';
        }

        return new Promise((resolve, reject) => {
            const attemptResolve = () => {
                if (!backendDone || !terminalDone) return;
                const wait = Math.max(0, 1400 - (Date.now() - startedAt));
                setTimeout(() => {
                    if (result.ok) resolve(result.payload);
                    else reject(result.payload);
                }, wait);
            };

            const markLine = (line, ok) => {
                line.classList.remove('awaiting');
                line.classList.add(ok ? 'done' : 'failed');
                const sp = line.querySelector('.sp');
                if (sp) sp.innerHTML = `<i class="fa-solid ${ok ? 'fa-check' : 'fa-xmark'}"></i>`;
            };

            const playNext = () => {
                if (!riskLabel) {
                    terminalDone = true;
                    attemptResolve();
                    return;
                }
                if (played < steps.length) {
                    const line = this.appendProgressLine(riskLabel, steps[played]);
                    if (backendDone) markLine(line, result.ok);
                    played++;
                    setTimeout(playNext, 420);
                    return;
                }
                if (!lines.some(l => l.classList.contains('awaiting'))) {
                    lines.push(this.appendProgressLine(riskLabel, 'Awaiting analysis results', true));
                }
                terminalDone = true;
                attemptResolve();
            };
            playNext();

            const finish = (ok, payload) => {
                backendDone = true;
                result = { ok, payload };
                this.setButtonBusy(type, false);
                lines.forEach(line => markLine(line, ok));
                attemptResolve();
            };

            requestFn()
                .then(result => finish(true, result))
                .catch(err => finish(false, err));
        });
    },
};

// Export for use in other modules
window.ScannerManager = ScannerManager;