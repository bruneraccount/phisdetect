/**
 * minigames.js — Security Minigames Manager
 * PhisDetect — Terminal Dashboard
 *
 * Three training games:
 *   1. Phish or Legit    — quick-fire email/URL classification
 *   2. Link Dismantler   — pick the real registrable domain of a URL
 *   3. Threat Hunt       — click every red flag before the clock runs out
 *
 * Each game supports Easy / Normal / Hard difficulty. Correct answers award
 * points scaled by difficulty (x1 / x2 / x3) into the same pool as threat
 * reports, and round results are synced to the backend leaderboard.
 */

const MINIGAME_BACKEND = 'http://localhost:3000';

const DIFFICULTIES = {
    easy:   { label: 'Easy',   multiplier: 1, timer: 25 },
    normal: { label: 'Normal', multiplier: 2, timer: 20 },
    hard:   { label: 'Hard',   multiplier: 3, timer: 15 }
};

const MG_EMPTY_BEST = { easy: { score: 0, streak: 0 }, normal: { score: 0, streak: 0 }, hard: { score: 0, streak: 0 } };

/**
 * Build the question pool for a given difficulty tier.
 * Easy = easy only; Normal = normal + easy; Hard = hard + normal.
 */
function mgSelectPool(bank, difficulty) {
    const byDiff = { easy: [], normal: [], hard: [] };
    bank.forEach(q => {
        const d = q.difficulty === 'hard' || q.difficulty === 'easy' ? q.difficulty : 'normal';
        byDiff[d].push(q);
    });
    if (difficulty === 'easy') return byDiff.easy;
    if (difficulty === 'hard') return byDiff.hard.concat(byDiff.normal);
    return byDiff.normal.concat(byDiff.easy);
}

function mgLoadBest(key) {
    try {
        const saved = JSON.parse(localStorage.getItem(key) || '{}');
        if (saved && saved.easy && typeof saved.easy.score === 'number') {
            return {
                easy:   { score: Number(saved.easy.score) || 0,   streak: Number(saved.easy.streak) || 0 },
                normal: { score: Number(saved.normal.score) || 0, streak: Number(saved.normal.streak) || 0 },
                hard:   { score: Number(saved.hard.score) || 0,   streak: Number(saved.hard.streak) || 0 }
            };
        }
        // Migrate legacy flat {score, streak} storage -> Normal tier.
        return {
            easy:   { score: 0, streak: 0 },
            normal: { score: Number(saved && saved.score) || 0, streak: Number(saved && saved.streak) || 0 },
            hard:   { score: 0, streak: 0 }
        };
    } catch (e) {
        return JSON.parse(JSON.stringify(MG_EMPTY_BEST));
    }
}

function mgSaveBest(key, best) {
    try {
        localStorage.setItem(key, JSON.stringify(best));
    } catch (e) {
        console.warn('Failed to save minigame bests:', e);
    }
}

function mgPlayerName() {
    try {
        if (window.ProfileManager && window.ProfileManager.user && window.ProfileManager.user.username) {
            return String(window.ProfileManager.user.username);
        }
    } catch (e) { /* no profile */ }
    return 'Guest';
}

/**
 * POST a finished round to the backend leaderboard (fire-and-forget).
 */
function mgSubmitResult(game, difficulty, score, total, bestStreak, name) {
    try {
        fetch(`${MINIGAME_BACKEND}/api/minigame/result`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ game, difficulty, score, total, bestStreak, name })
        }).then(r => r.json()).then(res => {
            if (res && res.ok && window.LeaderboardManager) {
                window.LeaderboardManager.onSubmitted(res);
            }
        }).catch(() => {});
    } catch (e) { /* backend unavailable — ignore */ }
}

/**
 * LeaderboardManager — renders the global leaderboard card.
 */
const LeaderboardManager = {
    gameNames: {
        'phish-or-legit': 'Phish or Legit',
        'link-dismantler': 'Link Dismantler',
        'threat-hunt': 'Threat Hunt'
    },
    diffLabels: { easy: 'Easy', normal: 'Normal', hard: 'Hard' },
    el: null,

    init() {
        this.el = document.getElementById('leaderboardBody');
        if (this.el) {
            const btn = document.getElementById('lbRefresh');
            if (btn) btn.addEventListener('click', () => this.load());
            this.load();
        }
    },

    load() {
        if (!this.el) return;
        this.el.innerHTML = '<p class="lb-empty">Loading&hellip;</p>';
        fetch(`${MINIGAME_BACKEND}/api/minigame/leaderboard`)
            .then(r => r.json())
            .then(d => this.render((d && d.leaderboard) || {}))
            .catch(() => {
                this.el.innerHTML = '<p class="lb-error">Leaderboard unavailable &mdash; is the backend running on :3000?</p>';
            });
    },

    render(board) {
        const html = Object.keys(this.gameNames).map(game => {
            const diffs = ['easy', 'normal', 'hard'].map(diff => {
                const entries = (board[game] && board[game][diff]) || [];
                const list = entries.length
                    ? '<ul class="lb-list">' + entries.map((e, i) =>
                        `<li><span class="lb-rank">${i + 1}</span>` +
                        `<span class="lb-name">${this.esc(e.name)}</span>` +
                        `<span class="lb-score">${e.score}</span></li>`).join('') + '</ul>'
                    : '<p class="lb-empty">No scores yet</p>';
                return `<div class="lb-difficulty"><div class="diff-label">${this.diffLabels[diff]}</div>${list}</div>`;
            }).join('');
            return `<div class="lb-game"><h3><i class="fa-solid fa-gamepad"></i>${this.gameNames[game]}</h3>${diffs}</div>`;
        }).join('');
        this.el.innerHTML = html || '<p class="lb-empty">No scores yet &mdash; finish a round to join the board!</p>';
    },

    onSubmitted(res) {
        if (typeof Utils !== 'undefined' && Utils.toast) {
            Utils.toast(`Round saved &mdash; rank #${res.rank} on the ${this.diffLabels[res.difficulty] || res.difficulty} board.`, 'success');
        }
        this.load();
    },

    esc(s) {
        return String(s == null ? '' : s).replace(/[&<>"']/g,
            c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
    }
};

/**
 * MinigamesManager — "Phish or Legit" minigame.
 */
const MinigamesManager = {
    ROUND_SIZE: 10,
    POINTS_PER_ANSWER: 10,
    GAME_ID: 'phish-or-legit',
    gameKey: 'mg',

    bank: [
        // ==================== EASY ====================
        {
            kind: 'email', difficulty: 'easy', answer: 'phish',
            content: 'Subject: You are a Winner!!!\n\nCongratulations! Your email address has been randomly selected to receive USD 1,000,000 in the International Email Lottery. Contact our agent to claim your prize.\n\nBest regards,\nMr. John Williams',
            explain: 'Unexpected lottery winnings from a stranger are a textbook scam. Nobody gives away money via email.'
        },
        {
            kind: 'email', difficulty: 'easy', answer: 'phish',
            content: 'Subject: Overdue Invoice #9841\n\nDear Sir/Madam,\n\nPlease find attached the invoice for services rendered. Kindly settle the amount of $1,240.50 before the due date.\n\nAccounts Department\n\n[attachment: invoice_9841.zip]',
            explain: 'Unsolicited invoices with zip attachments are a common malware delivery method.'
        },
        {
            kind: 'email', difficulty: 'easy', answer: 'legit',
            content: 'Subject: Your weekly security digest\n\nHi Alex,\n\nHere are this week\'s top articles on staying safe online:\n- Avoid credential reuse\n- Enable two-factor authentication\n\nYou are receiving this because you subscribed. Unsubscribe here.',
            explain: 'A newsletter you subscribed to, personalized greeting, no attachments and no link pressure. Legit.'
        },
        {
            kind: 'email', difficulty: 'easy', answer: 'legit',
            content: 'Subject: Sprint planning — tomorrow 10:00 AM\n\nHi team,\n\nReminder that our sprint planning call is tomorrow at 10:00 AM. Agenda is on our shared drive as always.\n\nThanks,\nPriya',
            explain: 'A colleague reminder with no links, no attachments and no sense of emergency. Legit.'
        },
        {
            kind: 'email', difficulty: 'easy', answer: 'legit',
            content: 'Subject: PyCon 2026 — Registration now open\n\nHi,\n\nEarly-bird registration for PyCon 2026 is open until end of month. Tickets start at $250. Visit our official website to register.\n\nOrganizers, pycon.org',
            explain: 'Points to the real pycon.org and comes from a known organizer. No attachments, no urgency. Legit.'
        },
        {
            kind: 'url', difficulty: 'easy', answer: 'phish',
            content: 'http://faceb00k-login.com/verify/account',
            explain: '"faceb00k" uses letter substitution to mimic Facebook — a homograph trick.'
        },
        {
            kind: 'url', difficulty: 'easy', answer: 'phish',
            content: 'http://185.220.101.4/emails/update.html',
            explain: 'Credential-phishing page hosted on a raw IP address — no legitimate service does that.'
        },
        {
            kind: 'url', difficulty: 'easy', answer: 'legit',
            content: 'https://www.google.com/search?q=phishing+awareness',
            explain: 'Real Google domain with a normal search query.'
        },
        {
            kind: 'url', difficulty: 'easy', answer: 'legit',
            content: 'https://github.com/bruneraccount',
            explain: 'Real github.com profile URL.'
        },
        {
            kind: 'url', difficulty: 'easy', answer: 'legit',
            content: 'https://www.netflix.com/browse',
            explain: 'Real netflix.com domain.'
        },
        {
            kind: 'url', difficulty: 'easy', answer: 'legit',
            content: 'https://mail.google.com/mail/u/0/#inbox',
            explain: 'Real Google mail subdomain on google.com.'
        },

        // ==================== NORMAL ====================
        {
            kind: 'email', difficulty: 'normal', answer: 'phish',
            content: 'Subject: Account Suspension Warning\n\nDear customer,\n\nYour online banking account has been temporarily suspended due to suspicious activity. Please verify your identity immediately to avoid permanent closure.\n\nVerify Now: http://secure-bank-verify.com/account/login\n\nRegards,\nSecurity Team',
            explain: 'Generic greeting, manufactured urgency, and a link to an unknown "verify" domain — classic phishing pressure tactics.'
        },
        {
            kind: 'email', difficulty: 'normal', answer: 'phish',
            content: 'Subject: Your package could not be delivered\n\nDear customer,\n\nYour parcel was returned to the depot. To reschedule delivery, confirm your details here: http://dhl-tracking.update-info.com\n\nShipping Team',
            explain: 'The "delivery problem" hook uses a domain that only resembles a courier. Check the real tracking site directly.'
        },
        {
            kind: 'email', difficulty: 'normal', answer: 'phish',
            content: 'Subject: Your password expires in 24 hours\n\nHi user,\n\nYour account password will expire today. Sign in to keep your account active.\n\nKeep My Account: http://paypa1-security-login.com/update\n\nDo not reply to this email.',
            explain: '"paypa1" is a homograph of a famous brand, and real services never email an expiring-password login link.'
        },
        {
            kind: 'email', difficulty: 'normal', answer: 'phish',
            content: 'Subject: Tax refund approved\n\nDear taxpayer,\n\nYour 2025 tax refund of $850.00 is approved but could not be processed. Enter your bank details to receive the amount.\n\nClaim Refund: http://refund-claim-center.net/enter\n\nIRS Support',
            explain: 'Goverment agencies never ask for bank details by email. The domain is not an official government site.'
        },
        {
            kind: 'email', difficulty: 'normal', answer: 'legit',
            content: 'Subject: Your September statement is ready\n\nDear Alex Smith,\n\nYour credit card statement for September is now available to view in the app.\n\nSummary:\n- Previous balance: $1,230.00\n- Payment received: -$1,230.00\n\nWe are happy to help if you have questions.\n\nCustomer Care, Chase',
            explain: 'Generic but low-pressure account statement, no embedded links asking you to act now. Normal banking email.'
        },
        {
            kind: 'email', difficulty: 'normal', answer: 'legit',
            content: 'Subject: Password change confirmation\n\nHi Alex,\n\nYour password for the account "alex" was just changed. If this was you, no further action is needed. If not, contact support immediately.\n\nGitHub Support',
            explain: 'A security notification confirming an action — informative, not requesting anything. Legit.'
        },
        {
            kind: 'email', difficulty: 'normal', answer: 'phish',
            content: 'Subject: Your Microsoft 365 mailbox is almost full\n\nDear employee,\n\nYour mailbox is at 98% capacity. Confirm your credentials to avoid email interruption.\n\nManage Mailbox: http://microsoft-mailbox-verify.com/signin\n\nIT Helpdesk',
            explain: 'IT would never ask for credentials by email, and "microsoft-mailbox-verify.com" is not a Microsoft domain.'
        },
        {
            kind: 'url', difficulty: 'normal', answer: 'legit',
            content: 'https://www.dropbox.com/s/abc123/notes.docx',
            explain: 'Real dropbox.com shared-file link.'
        },
        {
            kind: 'url', difficulty: 'normal', answer: 'phish',
            content: 'http://secure-login-verify.tk/account/confirm.php',
            explain: 'Free ".tk" domain stuffed with trust words like "secure-login-verify".'
        },
        {
            kind: 'url', difficulty: 'normal', answer: 'phish',
            content: 'http://bankofamerica-accounts-verify.net/update',
            explain: 'Brand name chained to unrelated words in the domain itself. Official sites use the real brand domain.'
        },
        {
            kind: 'url', difficulty: 'normal', answer: 'phish',
            content: 'https://amazon-order-tracking.info/confirm-order',
            explain: '"amazon" is embedded in a much longer unknown domain — the registrable domain is "amazon-order-tracking.info".'
        },

        // ==================== HARD ====================
        {
            kind: 'email', difficulty: 'hard', answer: 'phish',
            content: 'Subject: Wells Fargo — Account Restricted\n\nDear valued customer,\n\nYour Wells Fargo Online account has been temporarily restricted due to unusual activity. Restore full access now:\n\nhttps://wellsfargo.com.wellsfargo-verify-support.info/restore\n\nWells Fargo Fraud Prevention',
            explain: 'The real domain is "wellsfargo-verify-support.info"; "wellsfargo.com" is only a subdomain decoy in front of it.'
        },
        {
            kind: 'email', difficulty: 'hard', answer: 'phish',
            content: 'Subject: Google Account — Unusual sign-in detected\n\nHi,\n\nWe detected unusual sign-in activity on your Google Account. If this was not you, review the activity immediately.\n\nReview Activity: https://accounts.google.com.verify-google-security.net/review\n\nGoogle Security Team',
            explain: '"accounts.google.com" is just a subdomain prefix; the attacker owns "verify-google-security.net".'
        },
        {
            kind: 'email', difficulty: 'hard', answer: 'legit',
            content: 'Subject: Reset your GitHub password\n\nHello Alex,\n\nWe received a request to reset the password for your GitHub account. If this was you, use the link below within 24 hours.\n\nReset password: https://github.com/password_reset\n\nIf you did not request this, you can safely ignore this email.\n\nGitHub Security',
            explain: 'Real github.com domain plus the "ignore if not you" fallback — a legit password reset. Even legit resets say "if this was you".'
        },
        {
            kind: 'url', difficulty: 'hard', answer: 'phish',
            content: 'https://paypal.com@185.220.101.4/login',
            explain: 'Everything after the "@" is the real host (a raw IP). "paypal.com" is just credential text in the URL.'
        },
        {
            kind: 'url', difficulty: 'hard', answer: 'phish',
            content: 'http://bit.ly/3xkQ2jF',
            explain: 'URL shorteners hide the true destination — always expand a short link before clicking.'
        },
        {
            kind: 'url', difficulty: 'hard', answer: 'phish',
            content: 'https://www-paypal.com.securereset.xyz/verify',
            explain: 'The registrable domain is "securereset.xyz" — "www-paypal.com" is only a subdomain prefix.'
        },
        {
            kind: 'url', difficulty: 'hard', answer: 'phish',
            content: 'https://bank-login.account-verify.workers.dev/authenticate',
            explain: 'Hosted on a free Cloudflare Workers subdomain ("workers.dev") — attackers use these throwaway domains for credential pages.'
        },
        {
            kind: 'url', difficulty: 'hard', answer: 'legit',
            content: 'https://zoom.us/j/98823456712',
            explain: 'Real zoom.us meeting link — short ID, no login or payment pressure.'
        },
        {
            kind: 'url', difficulty: 'hard', answer: 'phish',
            content: 'https://paypal.com.secure-login.tk/account/update',
            explain: 'The real domain is "secure-login.tk"; "paypal.com" is a subdomain decoy.'
        },
        {
            kind: 'url', difficulty: 'hard', answer: 'legit',
            content: 'https://en.wikipedia.org/wiki/Phishing',
            explain: 'Real wikipedia.org — the registrable domain is wikipedia.org, "en" is just a subdomain.'
        }
    ],

    state: {
        questions: [],
        index: 0,
        score: 0,
        streak: 0,
        bestStreak: 0,
        locked: false
    },

    best: JSON.parse(JSON.stringify(MG_EMPTY_BEST)),
    difficulty: 'easy',
    el: {},

    init() {
        this.el = {
            start: document.getElementById('mgStart'),
            game: document.getElementById('mgGame'),
            results: document.getElementById('mgResults'),
            startBtn: document.getElementById('mgStartBtn'),
            playAgainBtn: document.getElementById('mgPlayAgainBtn'),
            phishBtn: document.getElementById('mgPhishBtn'),
            legitBtn: document.getElementById('mgLegitBtn'),
            nextBtn: document.getElementById('mgNextBtn'),
            progress: document.getElementById('mgProgress'),
            kind: document.getElementById('mgKind'),
            diff: document.getElementById('mgDiff'),
            score: document.getElementById('mgScore'),
            streak: document.getElementById('mgStreak'),
            best: document.getElementById('mgBest'),
            question: document.getElementById('mgQuestion'),
            feedback: document.getElementById('mgFeedback'),
            feedbackLabel: document.getElementById('mgFeedbackLabel'),
            explain: document.getElementById('mgExplain'),
            resultIcon: document.getElementById('mgResultIcon'),
            resultTitle: document.getElementById('mgResultTitle'),
            resultScore: document.getElementById('mgResultScore'),
            resultDetail: document.getElementById('mgResultDetail'),
            resultStats: document.getElementById('mgResultStats')
        };

        this.best = mgLoadBest('phisdetect-minigames');
        this.setupDifficulty(this.gameKey);

        if (this.el.startBtn) {
            this.el.startBtn.addEventListener('click', () => this.start());
        }
        if (this.el.playAgainBtn) {
            this.el.playAgainBtn.addEventListener('click', () => this.start());
        }
        if (this.el.phishBtn) {
            this.el.phishBtn.addEventListener('click', () => this.answer('phish'));
        }
        if (this.el.legitBtn) {
            this.el.legitBtn.addEventListener('click', () => this.answer('legit'));
        }
        if (this.el.nextBtn) {
            this.el.nextBtn.addEventListener('click', () => this.next());
        }

        document.addEventListener('keydown', (e) => this.onKeydown(e));

        this.renderBest();
        this.renderDiff();
    },

    setupDifficulty(gameKey) {
        const containers = document.querySelectorAll(`.minigame-difficulty[data-game="${gameKey}"]`);
        containers.forEach(container => {
            container.querySelectorAll('.diff-btn').forEach(btn => {
                btn.addEventListener('click', () => {
                    this.difficulty = btn.dataset.diff;
                    this.syncDifficultyUI();
                    this.renderBest();
                    this.renderDiff();
                });
            });
        });
    },

    syncDifficultyUI() {
        document.querySelectorAll(`.minigame-difficulty[data-game="${this.gameKey}"]`).forEach(c => {
            c.querySelectorAll('.diff-btn').forEach(b => b.classList.toggle('active', b.dataset.diff === this.difficulty));
        });
    },

    onKeydown(e) {
        if (e.repeat || !this.el.game) return;
        if (this.el.game.style.display === 'none') return;
        if (this.el.results.style.display !== 'none') return;
        if (this.state.locked) return;
        const k = e.key.toLowerCase();
        if (k === 'p' || k === '1') { e.preventDefault(); this.answer('phish'); }
        else if (k === 'l' || k === '2') { e.preventDefault(); this.answer('legit'); }
    },

    /**
     * Start a new round
     */
    start() {
        const pool = mgSelectPool(this.bank, this.difficulty);
        const shuffled = pool.slice().sort(() => Math.random() - 0.5);
        this.state = {
            questions: shuffled.slice(0, this.ROUND_SIZE),
            index: 0,
            score: 0,
            streak: 0,
            bestStreak: 0,
            locked: false
        };
        this.resetButtons();
        this.hide(this.el.results);
        this.hide(this.el.feedback);
        this.hide(this.el.start);
        this.show(this.el.game);
        this.renderQuestion();
    },

    /**
     * Handle a player's choice
     */
    answer(choice) {
        if (this.state.locked) return;
        this.state.locked = true;

        const q = this.state.questions[this.state.index];
        const correct = q.answer === choice;

        if (correct) {
            this.state.score += 1;
            this.state.streak += 1;
            this.state.bestStreak = Math.max(this.state.bestStreak, this.state.streak);
            this.awardPoints();
            this.setFeedback('Correct', 'mg-correct',
                q.explain, `${choice === 'phish' ? 'Phish' : 'Legit'}! You earned +${this.pointsFor(1)} points.`);
        } else {
            this.state.streak = 0;
            const correctLabel = q.answer === 'phish' ? 'Phish' : 'Legit';
            this.setFeedback('Incorrect', 'mg-wrong',
                q.explain, `The answer was ${correctLabel}. Better luck next time.`);
        }

        this.highlightAnswer(q, choice);
        this.disableButtons();
        this.renderHud();
    },

    pointsFor(correctCount) {
        return correctCount * this.POINTS_PER_ANSWER * DIFFICULTIES[this.difficulty].multiplier;
    },

    /**
     * Advance to the next question or finish the round
     */
    next() {
        this.state.index += 1;
        if (this.state.index >= this.state.questions.length) {
            this.finish();
            return;
        }
        this.state.locked = false;
        this.resetButtons();
        this.hide(this.el.feedback);
        this.renderQuestion();
    },

    /**
     * Show round results
     */
    finish() {
        const total = this.state.questions.length;
        const accuracy = Math.round((this.state.score / total) * 100);
        const earned = this.pointsFor(this.state.score);
        const best = this.best[this.difficulty];

        if (this.state.score > best.score) {
            best.score = this.state.score;
            mgSaveBest('phisdetect-minigames', this.best);
        }
        if (this.state.bestStreak > best.streak) {
            best.streak = this.state.bestStreak;
            mgSaveBest('phisdetect-minigames', this.best);
        }
        this.renderBest();

        this.hide(this.el.game);
        this.show(this.el.results);
        this.el.resultIcon.innerHTML = accuracy >= 70
            ? '<i class="fa-solid fa-trophy" style="color: var(--green);"></i>'
            : '<i class="fa-solid fa-arrow-rotate-right" style="color: var(--text-muted);"></i>';
        this.el.resultTitle.textContent = accuracy >= 70
            ? 'Round Complete'
            : 'Keep Training';
        this.el.resultScore.textContent = `${this.state.score} / ${total}`;
        this.el.resultDetail.textContent =
            `${DIFFICULTIES[this.difficulty].label} difficulty. You earned +${earned} points ` +
            `(${this.POINTS_PER_ANSWER} x${DIFFICULTIES[this.difficulty].multiplier} per correct answer).`;
        this.el.resultStats.innerHTML =
            `<div><span>Accuracy</span><strong>${accuracy}%</strong></div>` +
            `<div><span>Best streak</span><strong>${this.state.bestStreak}</strong></div>` +
            `<div><span>Points earned</span><strong>+${earned}</strong></div>`;

        mgSubmitResult(this.GAME_ID, this.difficulty, earned, total, this.state.bestStreak, mgPlayerName());
    },

    /**
     * Render the current question
     */
    renderQuestion() {
        const q = this.state.questions[this.state.index];
        this.el.question.textContent = q.content;
        this.el.question.classList.toggle('mg-url', q.kind === 'url');
        this.el.kind.textContent = q.kind === 'url' ? 'URL' : 'Email';
        this.el.kind.className = 'minigame-badge ' + q.kind;
        this.renderDiff();
        this.renderHud();
    },

    /**
     * Update the scoreboard
     */
    renderHud() {
        const s = this.state;
        this.el.progress.textContent = `Question ${Math.min(s.index + 1, s.questions.length)} / ${s.questions.length}`;
        this.el.score.innerHTML = `Score: <strong>${s.score}</strong>`;
        this.el.streak.innerHTML = `Streak: <strong>${s.streak}</strong>`;
    },

    renderBest() {
        if (this.el.best && this.best[this.difficulty]) {
            const b = this.best[this.difficulty];
            this.el.best.textContent = `Best: ${b.score} / ${b.streak}`;
        }
    },

    renderDiff() {
        const d = DIFFICULTIES[this.difficulty];
        if (this.el.diff) {
            this.el.diff.textContent = d.label;
            this.el.diff.className = 'diff-badge ' + this.difficulty;
        }
        this.syncDifficultyUI();
    },

    /**
     * Show correct/incorrect feedback
     */
    setFeedback(label, cls, explain, detail) {
        this.el.feedbackLabel.textContent = label;
        this.el.feedbackLabel.className = 'mg-feedback-label ' + cls;
        this.el.explain.textContent = `${detail} ${explain}`;
        this.show(this.el.feedback);
    },

    /**
     * Highlight the picked button
     */
    highlightAnswer(q, choice) {
        const picked = choice === 'phish' ? this.el.phishBtn : this.el.legitBtn;
        const correct = q.answer === 'phish' ? this.el.phishBtn : this.el.legitBtn;
        picked.classList.add('picked');
        if (picked !== correct) correct.classList.add('correct');
    },

    disableButtons() {
        [this.el.phishBtn, this.el.legitBtn].forEach(btn => { btn.disabled = true; });
    },

    resetButtons() {
        [this.el.phishBtn, this.el.legitBtn].forEach(btn => {
            btn.classList.remove('picked', 'correct');
            btn.disabled = false;
        });
    },

    /**
     * Award points to the user's profile (same pool as threat reports)
     */
    awardPoints() {
        const pts = this.POINTS_PER_ANSWER * DIFFICULTIES[this.difficulty].multiplier;
        if (window.ProfileManager) {
            const user = window.ProfileManager.user;
            window.ProfileManager.updateUser({ points: user.points + pts });
        }
        if (window.DashboardManager) {
            window.DashboardManager.incrementPoints(pts);
        }
        if (typeof Utils !== 'undefined' && Utils.toast) {
            Utils.toast(`Correct! +${pts} points`, 'success');
        }
    },

    show(el) { if (el) el.style.display = 'block'; },
    hide(el) { if (el) el.style.display = 'none'; }
};

/**
 * LinkDismantlerManager — "Link Dismantler" minigame.
 * Deconstruct a URL and pick the real registrable domain (the site the
 * attacker actually controls). Points scale with difficulty.
 */
const LinkDismantlerManager = {
    ROUND_SIZE: 10,
    POINTS_PER_ANSWER: 10,
    GAME_ID: 'link-dismantler',
    gameKey: 'ld',

    bank: [
        // ==================== EASY ====================
        {
            difficulty: 'easy',
            url: 'http://faceb00k-login.com/verify/account',
            correct: 'faceb00k-login.com',
            distractors: ['faceb00k.com', 'login.com', 'facebook.com'],
            explain: 'Here the attacker owns "faceb00k-login.com" itself — a letter-swapped lookalike of Facebook.'
        },
        {
            difficulty: 'easy',
            url: 'https://www.paypal.com/signin',
            correct: 'paypal.com',
            distractors: ['paypa1.com', 'paypal-security.com', 'www.paypal.com/signin'],
            explain: 'Real PayPal. The registrable domain is "paypal.com"; "www.paypal.com/signin" is a path, not a domain.'
        },
        {
            difficulty: 'easy',
            url: 'http://185.220.101.4/emails/update.html',
            correct: '185.220.101.4',
            distractors: ['emails/update.html', '185.220.101', 'update.html'],
            explain: 'The destination is a raw IP address — legitimate services never host login pages on bare IPs.'
        },
        {
            difficulty: 'easy',
            url: 'https://www.microsoft.com/en-us/software-download',
            correct: 'microsoft.com',
            distractors: ['software-download.com', 'www.microsoft.com', 'microsoft-download.com'],
            explain: 'Real Microsoft — the registrable domain is "microsoft.com".'
        },
        {
            difficulty: 'easy',
            url: 'https://github.com/bruneraccount',
            correct: 'github.com',
            distractors: ['github.com/bruneraccount', 'bruneraccount.com', 'github.login'],
            explain: 'Real GitHub — "github.com/bruneraccount" is a path, not a domain.'
        },
        {
            difficulty: 'easy',
            url: 'https://www.netflix.com/browse',
            correct: 'netflix.com',
            distractors: ['netflix.com/browse', 'browse.com', 'www.netflix.com'],
            explain: 'Real Netflix — "netflix.com/browse" is a path, not a separate domain.'
        },
        {
            difficulty: 'easy',
            url: 'https://www.google.com/search?q=phishing+awareness',
            correct: 'google.com',
            distractors: ['google.com/search', 'search.com', 'www.google.com'],
            explain: 'Real Google — "google.com/search" is a path on the real domain.'
        },
        {
            difficulty: 'easy',
            url: 'https://mail.google.com/mail/u/0/',
            correct: 'google.com',
            distractors: ['mail.google.com', 'gmail.com', 'mail.com'],
            explain: '"mail.google.com" is a subdomain of google.com, so the registrable domain is google.com.'
        },
        {
            difficulty: 'easy',
            url: 'https://en.wikipedia.org/wiki/Phishing',
            correct: 'wikipedia.org',
            distractors: ['wikipedia.org/wiki', 'phishing.org', 'en.wikipedia.org'],
            explain: 'The registrable domain is "wikipedia.org"; "en" is just a subdomain.'
        },
        {
            difficulty: 'easy',
            url: 'https://www.amazon.com/dp/B0BXYZ',
            correct: 'amazon.com',
            distractors: ['amazon.com/dp/B0BXYZ', 'dp.com', 'B0BXYZ.com'],
            explain: 'Real Amazon — "/dp/B0BXYZ" is a product path, not a domain.'
        },

        // ==================== NORMAL ====================
        {
            difficulty: 'normal',
            url: 'https://amazon-order-tracking.info/confirm-order',
            correct: 'amazon-order-tracking.info',
            distractors: ['amazon.com', 'order-tracking.info', 'amazon.info'],
            explain: 'The real registrable domain is "amazon-order-tracking.info" — a brand name wrapped into an unrelated domain.'
        },
        {
            difficulty: 'normal',
            url: 'http://secure-login-verify.tk/account/confirm.php',
            correct: 'secure-login-verify.tk',
            distractors: ['confirm.php', 'secure-login.com', 'login-verify.tk'],
            explain: 'A free .tk domain stuffed with trust words — that is the attacker\'s real property.'
        },
        {
            difficulty: 'normal',
            url: 'https://secure-bankofamerica-verify.com/online/login',
            correct: 'secure-bankofamerica-verify.com',
            distractors: ['bankofamerica.com', 'secure-bankofamerica.com', 'online.login'],
            explain: 'The whole "secure-bankofamerica-verify.com" is one registrable domain impersonating Bank of America.'
        },
        {
            difficulty: 'normal',
            url: 'http://dhl-tracking.update-info.com/reschedule',
            correct: 'update-info.com',
            distractors: ['dhl.com', 'dhl-tracking.com', 'reschedule.com'],
            explain: 'The real domain is "update-info.com"; "dhl-tracking" is a subdomain decoy.'
        },
        {
            difficulty: 'normal',
            url: 'https://login.chase.com/',
            correct: 'chase.com',
            distractors: ['login.chase.com', 'chase-login.com', 'login.com'],
            explain: '"login.chase.com" is a subdomain of chase.com — still owned by Chase. The registrable domain is "chase.com".'
        },
        {
            difficulty: 'normal',
            url: 'https://support.microsoft.com/en-us/office',
            correct: 'microsoft.com',
            distractors: ['microsoft.com/en-us/office', 'support.com', 'office.com'],
            explain: '"support.microsoft.com" is a subdomain of microsoft.com.'
        },
        {
            difficulty: 'normal',
            url: 'http://login.yahoo.com/',
            correct: 'yahoo.com',
            distractors: ['login.yahoo.com', 'login.com', 'yahoo-login.com'],
            explain: '"login" is a subdomain of the real yahoo.com.'
        },
        {
            difficulty: 'normal',
            url: 'https://myaccount.google.com/',
            correct: 'google.com',
            distractors: ['myaccount.com', 'google.myaccount.com', 'my.google.com'],
            explain: '"myaccount.google.com" is a subdomain owned by Google; the registrable domain is google.com.'
        },
        {
            difficulty: 'normal',
            url: 'https://accounts.spotify.com/en/login',
            correct: 'spotify.com',
            distractors: ['accounts.spotify.com', 'spotify-login.com', 'accounts.com'],
            explain: '"accounts" is a subdomain of the real spotify.com.'
        },
        {
            difficulty: 'normal',
            url: 'https://web.telegram.org/k/',
            correct: 'telegram.org',
            distractors: ['web.telegram.org', 'telegram.org/k', 'telegram.com'],
            explain: '"web" is a subdomain of telegram.org; the ".com" lookalike would be the spoof.'
        },

        // ==================== HARD ====================
        {
            difficulty: 'hard',
            url: 'https://www.paypa1.com.secure-login.tk/account/update',
            correct: 'secure-login.tk',
            distractors: ['paypa1.com', 'www.paypa1.com', 'login.tk'],
            explain: 'The attacker controls the registrable domain "secure-login.tk". "paypa1.com" is only a subdomain decoy in front of it.'
        },
        {
            difficulty: 'hard',
            url: 'https://google.com.verify-account-support.org/login',
            correct: 'verify-account-support.org',
            distractors: ['google.com', 'verify-account-support.com', 'google.login'],
            explain: '"google.com" is just a subdomain. The attacker controls "verify-account-support.org".'
        },
        {
            difficulty: 'hard',
            url: 'https://netflix.com.accounts-update.net/login',
            correct: 'accounts-update.net',
            distractors: ['netflix.com', 'netflix.net', 'accounts.net'],
            explain: 'The attacker owns "accounts-update.net"; "netflix.com" is a decoy subdomain in front of it.'
        },
        {
            difficulty: 'hard',
            url: 'https://amazon.com.extra-shipping-fee.com/update',
            correct: 'extra-shipping-fee.com',
            distractors: ['amazon.com', 'shipping-fee.com', 'extra.com'],
            explain: 'The owner controls "extra-shipping-fee.com"; "amazon.com" is just a subdomain prefix.'
        },
        {
            difficulty: 'hard',
            url: 'https://login.microsoftonline.com/@attacker.evil.com/oauth2/authorize',
            correct: 'microsoftonline.com',
            distractors: ['attacker.evil.com', 'microsoft.com', 'microsoftonline.com/@attacker.evil.com'],
            explain: 'The registrable domain is "microsoftonline.com"; "@attacker.evil.com" is just userinfo text the scammer hopes you misread.'
        },
        {
            difficulty: 'hard',
            url: 'http://www.bankofamerica.com.secure-verify.xyz/update',
            correct: 'secure-verify.xyz',
            distractors: ['bankofamerica.com', 'secure-verify.com', 'www.bankofamerica.com'],
            explain: 'The attacker owns "secure-verify.xyz"; "bankofamerica.com" is a decoy subdomain prefix.'
        },
        {
            difficulty: 'hard',
            url: 'https://paypal.com@185.220.101.4/capture',
            correct: '185.220.101.4',
            distractors: ['paypal.com', 'capture.com', 'paypal.com@185.220.101.4'],
            explain: 'Everything after the "@" is the real host — a raw IP. "paypal.com" is only userinfo text.'
        },
        {
            difficulty: 'hard',
            url: 'https://bit.ly/3xkQ2jF',
            correct: 'bit.ly',
            distractors: ['3xkQ2jF.com', 'bitly.com', 'bit.ly/3xkQ2jF'],
            explain: 'The registrable domain of a short link is the shortener itself — "bit.ly". You cannot see past it.'
        },
        {
            difficulty: 'hard',
            url: 'https://chase.com.security-check-now.info/verify',
            correct: 'security-check-now.info',
            distractors: ['chase.com', 'security-check.com', 'chase.security.com'],
            explain: 'The attacker owns "security-check-now.info"; "chase.com" is a subdomain prefix decoy.'
        },
        {
            difficulty: 'hard',
            url: 'http://update-itunes.xyz/install',
            correct: 'update-itunes.xyz',
            distractors: ['itunes.com', 'update-itunes.com', 'apple.com'],
            explain: 'The whole "update-itunes.xyz" is one attacker-owned domain resembling an Apple update page.'
        }
    ],

    state: {
        questions: [],
        index: 0,
        score: 0,
        streak: 0,
        bestStreak: 0,
        locked: false
    },

    best: JSON.parse(JSON.stringify(MG_EMPTY_BEST)),
    difficulty: 'easy',
    el: {},

    init() {
        this.el = {
            start: document.getElementById('ldStart'),
            game: document.getElementById('ldGame'),
            results: document.getElementById('ldResults'),
            startBtn: document.getElementById('ldStartBtn'),
            playAgainBtn: document.getElementById('ldPlayAgainBtn'),
            nextBtn: document.getElementById('ldNextBtn'),
            progress: document.getElementById('ldProgress'),
            diff: document.getElementById('ldDiff'),
            score: document.getElementById('ldScore'),
            streak: document.getElementById('ldStreak'),
            best: document.getElementById('ldBest'),
            question: document.getElementById('ldQuestion'),
            options: document.getElementById('ldOptions'),
            feedback: document.getElementById('ldFeedback'),
            feedbackLabel: document.getElementById('ldFeedbackLabel'),
            explain: document.getElementById('ldExplain'),
            resultIcon: document.getElementById('ldResultIcon'),
            resultTitle: document.getElementById('ldResultTitle'),
            resultScore: document.getElementById('ldResultScore'),
            resultDetail: document.getElementById('ldResultDetail'),
            resultStats: document.getElementById('ldResultStats')
        };

        this.best = mgLoadBest('phisdetect-linkdismantler');
        this.setupDifficulty(this.gameKey);

        if (this.el.startBtn) {
            this.el.startBtn.addEventListener('click', () => this.start());
        }
        if (this.el.playAgainBtn) {
            this.el.playAgainBtn.addEventListener('click', () => this.start());
        }
        if (this.el.nextBtn) {
            this.el.nextBtn.addEventListener('click', () => this.next());
        }

        this.renderBest();
        this.renderDiff();
    },

    setupDifficulty(gameKey) {
        const containers = document.querySelectorAll(`.minigame-difficulty[data-game="${gameKey}"]`);
        containers.forEach(container => {
            container.querySelectorAll('.diff-btn').forEach(btn => {
                btn.addEventListener('click', () => {
                    this.difficulty = btn.dataset.diff;
                    this.syncDifficultyUI();
                    this.renderBest();
                    this.renderDiff();
                });
            });
        });
    },

    syncDifficultyUI() {
        document.querySelectorAll(`.minigame-difficulty[data-game="${this.gameKey}"]`).forEach(c => {
            c.querySelectorAll('.diff-btn').forEach(b => b.classList.toggle('active', b.dataset.diff === this.difficulty));
        });
    },

    pointsFor(correctCount) {
        return correctCount * this.POINTS_PER_ANSWER * DIFFICULTIES[this.difficulty].multiplier;
    },

    start() {
        const pool = mgSelectPool(this.bank, this.difficulty);
        const shuffled = pool.slice().sort(() => Math.random() - 0.5);
        this.state = {
            questions: shuffled.slice(0, this.ROUND_SIZE),
            index: 0,
            score: 0,
            streak: 0,
            bestStreak: 0,
            locked: false
        };
        this.hide(this.el.results);
        this.hide(this.el.feedback);
        this.hide(this.el.start);
        this.show(this.el.game);
        this.renderQuestion();
    },

    answer(opt, btn) {
        if (this.state.locked) return;
        this.state.locked = true;

        const q = this.state.questions[this.state.index];
        const correct = opt === q.correct;
        const btns = this.el.options.querySelectorAll('.mg-option');
        btns.forEach(b => { b.disabled = true; });

        if (correct) {
            btn.classList.add('correct');
            this.state.score += 1;
            this.state.streak += 1;
            this.state.bestStreak = Math.max(this.state.bestStreak, this.state.streak);
            this.awardPoints();
            this.setFeedback('Correct', 'mg-correct', q.explain,
                `You earned +${this.pointsFor(1)} points.`);
        } else {
            btn.classList.add('picked');
            btns.forEach(b => { if (b.textContent === q.correct) b.classList.add('correct'); });
            this.state.streak = 0;
            this.setFeedback('Incorrect', 'mg-wrong', q.explain,
                `The real destination is ${q.correct}.`);
        }

        this.renderHud();
    },

    next() {
        this.state.index += 1;
        if (this.state.index >= this.state.questions.length) {
            this.finish();
            return;
        }
        this.state.locked = false;
        this.hide(this.el.feedback);
        this.renderQuestion();
    },

    finish() {
        const total = this.state.questions.length;
        const accuracy = Math.round((this.state.score / total) * 100);
        const earned = this.pointsFor(this.state.score);
        const best = this.best[this.difficulty];

        if (this.state.score > best.score) {
            best.score = this.state.score;
            mgSaveBest('phisdetect-linkdismantler', this.best);
        }
        if (this.state.bestStreak > best.streak) {
            best.streak = this.state.bestStreak;
            mgSaveBest('phisdetect-linkdismantler', this.best);
        }
        this.renderBest();

        this.hide(this.el.game);
        this.show(this.el.results);
        this.el.resultIcon.innerHTML = accuracy >= 70
            ? '<i class="fa-solid fa-trophy" style="color: var(--green);"></i>'
            : '<i class="fa-solid fa-arrow-rotate-right" style="color: var(--text-muted);"></i>';
        this.el.resultTitle.textContent = accuracy >= 70 ? 'Round Complete' : 'Keep Training';
        this.el.resultScore.textContent = `${this.state.score} / ${total}`;
        this.el.resultDetail.textContent =
            `${DIFFICULTIES[this.difficulty].label} difficulty. You earned +${earned} points ` +
            `(${this.POINTS_PER_ANSWER} x${DIFFICULTIES[this.difficulty].multiplier} per correct answer).`;
        this.el.resultStats.innerHTML =
            `<div><span>Accuracy</span><strong>${accuracy}%</strong></div>` +
            `<div><span>Best streak</span><strong>${this.state.bestStreak}</strong></div>` +
            `<div><span>Points earned</span><strong>+${earned}</strong></div>`;

        mgSubmitResult(this.GAME_ID, this.difficulty, earned, total, this.state.bestStreak, mgPlayerName());
    },

    renderQuestion() {
        const q = this.state.questions[this.state.index];
        this.el.question.textContent = q.url;

        const opts = [q.correct, ...q.distractors].sort(() => Math.random() - 0.5);
        this.el.options.innerHTML = '';
        opts.forEach(opt => {
            const btn = document.createElement('button');
            btn.type = 'button';
            btn.className = 'btn btn-outline-primary mg-option';
            btn.textContent = opt;
            btn.addEventListener('click', () => this.answer(opt, btn));
            this.el.options.appendChild(btn);
        });

        this.renderDiff();
        this.renderHud();
    },

    renderHud() {
        const s = this.state;
        this.el.progress.textContent = `Question ${Math.min(s.index + 1, s.questions.length)} / ${s.questions.length}`;
        this.el.score.innerHTML = `Score: <strong>${s.score}</strong>`;
        this.el.streak.innerHTML = `Streak: <strong>${s.streak}</strong>`;
    },

    renderBest() {
        if (this.el.best && this.best[this.difficulty]) {
            const b = this.best[this.difficulty];
            this.el.best.textContent = `Best: ${b.score} / ${b.streak}`;
        }
    },

    renderDiff() {
        const d = DIFFICULTIES[this.difficulty];
        if (this.el.diff) {
            this.el.diff.textContent = d.label;
            this.el.diff.className = 'diff-badge ' + this.difficulty;
        }
        this.syncDifficultyUI();
    },

    setFeedback(label, cls, explain, detail) {
        this.el.feedbackLabel.textContent = label;
        this.el.feedbackLabel.className = 'mg-feedback-label ' + cls;
        this.el.explain.textContent = `${detail} ${explain}`;
        this.show(this.el.feedback);
    },

    awardPoints() {
        const pts = this.POINTS_PER_ANSWER * DIFFICULTIES[this.difficulty].multiplier;
        if (window.ProfileManager) {
            const user = window.ProfileManager.user;
            window.ProfileManager.updateUser({ points: user.points + pts });
        }
        if (window.DashboardManager) {
            window.DashboardManager.incrementPoints(pts);
        }
        if (typeof Utils !== 'undefined' && Utils.toast) {
            Utils.toast(`Correct! +${pts} points`, 'success');
        }
    },

    show(el) { if (el) el.style.display = 'block'; },
    hide(el) { if (el) el.style.display = 'none'; }
};

/**
 * ThreatHuntManager — "Threat Hunt" minigame.
 * Race against the clock: click every red flag (phishing token) in an email
 * or a dismantled URL before the timer runs out. A false positive or a missed
 * flag ends the question. Points scale with difficulty; harder difficulties
 * shrink the timer (25s / 20s / 15s).
 */
const ThreatHuntManager = {
    ROUND_SIZE: 10,
    POINTS_PER_ANSWER: 10,
    GAME_ID: 'threat-hunt',
    gameKey: 'th',

    bank: [
        // ==================== EASY ====================
        {
            kind: 'email', difficulty: 'easy',
            content: 'Subject: You are a Winner!!!\n\nCongratulations! Your email address has been randomly selected to receive USD 1,000,000 in the International Email Lottery. Contact our agent to claim your prize.\n\nBest regards,\nMr. John Williams',
            flags: ['Winner', 'Lottery', '1,000,000'],
            explain: 'Unexpected lottery winnings and an unknown "agent" to contact — a classic advance-fee scam.'
        },
        {
            kind: 'email', difficulty: 'easy',
            content: 'Subject: Overdue Invoice #9841\n\nDear Sir/Madam,\n\nPlease find attached the invoice for services rendered. Kindly settle the amount of $1,240.50 before the due date.\n\nAccounts Department\n\n[attachment: invoice_9841.zip]',
            flags: ['Overdue', 'invoice_9841.zip'],
            explain: 'An unsolicited invoice carrying a zip attachment is a common malware delivery tactic.'
        },
        {
            kind: 'email', difficulty: 'easy',
            content: 'Subject: Your weekly security digest\n\nHi Alex,\n\nHere are this week\'s top articles on staying safe online:\n- Avoid credential reuse\n- Enable two-factor authentication\n\nYou are receiving this because you subscribed. Unsubscribe here.',
            flags: [],
            explain: 'A newsletter you subscribed to — no urgency, no links, no attachments. Safe.'
        },
        {
            kind: 'email', difficulty: 'easy',
            content: 'Subject: Sprint planning — tomorrow 10:00 AM\n\nHi team,\n\nReminder that our sprint planning call is tomorrow at 10:00 AM. Agenda is on our shared drive as always.\n\nThanks,\nPriya',
            flags: [],
            explain: 'A colleague reminder with no links, no attachments and no sense of emergency. Safe.'
        },
        {
            kind: 'url', difficulty: 'easy',
            chunks: [{ t: 'http://', f: false }, { t: '185.220.101.4', f: true }, { t: '/emails/', f: false }, { t: 'update.html', f: false }],
            flags: ['185.220.101.4'],
            explain: 'A raw IP address as the destination — legitimate services never host login pages on bare IPs.'
        },
        {
            kind: 'url', difficulty: 'easy',
            chunks: [{ t: 'https://', f: false }, { t: 'www.', f: false }, { t: 'netflix.com', f: false }, { t: '/browse', f: false }],
            flags: [],
            explain: 'Real Netflix — no red flags here. Click "Done" to confirm.'
        },
        {
            kind: 'url', difficulty: 'easy',
            chunks: [{ t: 'https://', f: false }, { t: 'login.', f: false }, { t: 'chase.com', f: false }, { t: '/', f: false }],
            flags: [],
            explain: 'login.chase.com is a real subdomain of chase.com — safe.'
        },
        {
            kind: 'url', difficulty: 'easy',
            chunks: [{ t: 'https://', f: false }, { t: 'github.com', f: false }, { t: '/', f: false }, { t: 'bruneraccount', f: false }],
            flags: [],
            explain: 'Real GitHub domain — safe.'
        },
        {
            kind: 'url', difficulty: 'easy',
            chunks: [{ t: 'https://', f: false }, { t: 'www.', f: false }, { t: 'spotify.com', f: false }, { t: '/', f: false }],
            flags: [],
            explain: 'Real Spotify domain — safe.'
        },
        {
            kind: 'url', difficulty: 'easy',
            chunks: [{ t: 'https://', f: false }, { t: 'www.', f: false }, { t: 'microsoft.com', f: false }, { t: '/', f: false }],
            flags: [],
            explain: 'Real Microsoft domain — safe.'
        },

        // ==================== NORMAL ====================
        {
            kind: 'email', difficulty: 'normal',
            content: 'Subject: Account Suspension Warning\n\nDear customer,\n\nYour online banking account has been temporarily suspended due to suspicious activity. Please verify your identity immediately to avoid permanent closure.\n\nVerify Now: http://secure-bank-verify.com/account/login\n\nRegards,\nSecurity Team',
            flags: ['customer', 'immediately', 'http://secure-bank-verify.com/account/login'],
            explain: 'Generic greeting ("Dear customer"), pressure word "immediately", and a link to an unknown "verify" domain.'
        },
        {
            kind: 'email', difficulty: 'normal',
            content: 'Subject: Your password expires in 24 hours\n\nHi user,\n\nYour account password will expire today. Sign in to keep your account active.\n\nKeep My Account: http://paypa1-security-login.com/update\n\nDo not reply to this email.',
            flags: ['expire', 'http://paypa1-security-login.com/update'],
            explain: '"paypa1" is a PayPal homograph and the email pressures you about password expiry — real services never email login links.'
        },
        {
            kind: 'email', difficulty: 'normal',
            content: 'Subject: Tax refund approved\n\nDear taxpayer,\n\nYour 2025 tax refund of $850.00 is approved but could not be processed. Enter your bank details to receive the amount.\n\nClaim Refund: http://refund-claim-center.net/enter\n\nIRS Support',
            flags: ['bank', 'http://refund-claim-center.net/enter'],
            explain: 'Government agencies never request bank details by email, and the link is not an official site.'
        },
        {
            kind: 'email', difficulty: 'normal',
            content: 'Subject: Your package could not be delivered\n\nDear customer,\n\nYour parcel was returned to the depot. To reschedule delivery, confirm your details here: http://dhl-tracking.update-info.com/reschedule\n\nShipping Team',
            flags: ['confirm', 'http://dhl-tracking.update-info.com/reschedule'],
            explain: 'The courier hook steers you to a lookalike domain that only resembles the real service.'
        },
        {
            kind: 'email', difficulty: 'normal',
            content: 'Subject: Your Netflix account has been suspended\n\nDear customer,\n\nWe could not process your latest payment. Your Netflix account has been suspended. Update your billing to restore service.\n\nhttp://netflix-account-restore.com/login\n\nNetflix Billing',
            flags: ['suspended', 'http://netflix-account-restore.com/login'],
            explain: '"netflix-account-restore.com" is not a Netflix domain — billing hooks are a favorite phishing lure.'
        },
        {
            kind: 'email', difficulty: 'normal',
            content: 'Subject: Your Microsoft 365 mailbox is almost full\n\nDear employee,\n\nYour mailbox is at 98% capacity. Confirm your credentials to avoid email interruption.\n\nManage Mailbox: http://microsoft-mailbox-verify.com/signin\n\nIT Helpdesk',
            flags: ['Microsoft', 'http://microsoft-mailbox-verify.com/signin'],
            explain: 'IT never asks for credentials by email, and "microsoft-mailbox-verify.com" is not a Microsoft domain.'
        },
        {
            kind: 'url', difficulty: 'normal',
            chunks: [{ t: 'http://', f: false }, { t: 'secure-login-verify.tk', f: true }, { t: '/account/', f: false }, { t: 'confirm.php', f: false }],
            flags: ['secure-login-verify.tk'],
            explain: 'A free ".tk" domain stuffed with trust words — that is the attacker\'s real property.'
        },
        {
            kind: 'url', difficulty: 'normal',
            chunks: [{ t: 'https://', f: false }, { t: 'www.', f: false }, { t: 'paypal.com', f: false }, { t: '/signin', f: false }],
            flags: [],
            explain: 'Real PayPal sign-in page — safe.'
        },
        {
            kind: 'url', difficulty: 'normal',
            chunks: [{ t: 'http://', f: false }, { t: 'faceb00k-login.com', f: true }, { t: '/verify/', f: false }, { t: 'account', f: false }],
            flags: ['faceb00k-login.com'],
            explain: 'A letter-swapped homograph of Facebook — the whole registrable domain is the attacker\'s.'
        },
        {
            kind: 'email', difficulty: 'normal',
            content: 'Subject: Priya shared a folder with you on Dropbox\n\nHi Alex,\n\nPriya has shared the folder "Q3 Planning" with you.\n\nOpen: https://www.dropbox.com/sh/abc123/q3\n\nYou can manage your sharing settings anytime.',
            flags: [],
            explain: 'A real dropbox.com link from a colleague — no urgency, no credential request. Safe.'
        },

        // ==================== HARD ====================
        {
            kind: 'email', difficulty: 'hard',
            content: 'Subject: Wells Fargo — Account Restricted\n\nDear valued customer,\n\nYour Wells Fargo Online account has been temporarily restricted due to unusual activity. Restore full access now:\n\nhttps://wellsfargo.com.wellsfargo-verify-support.info/restore\n\nWells Fargo Fraud Prevention',
            flags: ['restricted', 'https://wellsfargo.com.wellsfargo-verify-support.info/restore'],
            explain: 'The real domain is "wellsfargo-verify-support.info"; "wellsfargo.com" is only a subdomain decoy.'
        },
        {
            kind: 'url', difficulty: 'hard',
            chunks: [{ t: 'https://', f: false }, { t: 'paypal.com@', f: true }, { t: '185.220.101.4', f: true }, { t: '/capture', f: false }],
            flags: ['paypal.com@', '185.220.101.4'],
            explain: 'Everything after the "@" is the real host — a raw IP. "paypal.com" is just userinfo text.'
        },
        {
            kind: 'url', difficulty: 'hard',
            chunks: [{ t: 'http://', f: false }, { t: 'bit.ly', f: true }, { t: '/', f: false }, { t: '3xkQ2jF', f: false }],
            flags: ['bit.ly'],
            explain: 'A URL shortener hides the true destination — a common obfuscation trick.'
        },
        {
            kind: 'email', difficulty: 'hard',
            content: 'Subject: Re-authenticate your Microsoft account\n\nDear user,\n\nYour Microsoft account will be deactivated in 48 hours. Re-authenticate to keep it active.\n\nhttp://www.micrоsоft.com-verify.net/signin\n\nMicrosoft Security',
            flags: ['deactivated', 'micrоsоft.com-verify.net'],
            explain: 'Cyrillic "о" characters replace Latin "o" in "microsoft" — a homograph domain. Real Microsoft never emails auth links.'
        },
        {
            kind: 'email', difficulty: 'hard',
            content: 'Subject: Your PayPal account is limited\n\nDear user,\n\nYour PayPal account has been limited until you verify your information.\n\nVerify: http://paypal-account-resolution.com/confirm\n\nPayPal Service',
            flags: ['limited', 'http://paypal-account-resolution.com/confirm'],
            explain: '"paypal-account-resolution.com" is not PayPal — account-limits are a favorite high-urgency lure.'
        },
        {
            kind: 'url', difficulty: 'hard',
            chunks: [{ t: 'https://', f: false }, { t: 'netflix.com.', f: true }, { t: 'accounts-update.net', f: true }, { t: '/login', f: false }],
            flags: ['netflix.com.', 'accounts-update.net'],
            explain: 'The attacker owns "accounts-update.net"; "netflix.com" is a decoy subdomain in front of it.'
        },
        {
            kind: 'url', difficulty: 'hard',
            chunks: [{ t: 'https://', f: false }, { t: 'google.com.', f: true }, { t: 'verify-account-support.org', f: true }, { t: '/login', f: false }],
            flags: ['google.com.', 'verify-account-support.org'],
            explain: 'The attacker owns verify-account-support.org; google.com is only a subdomain decoy.'
        },
        {
            kind: 'url', difficulty: 'hard',
            chunks: [{ t: 'https://', f: false }, { t: 'www.paypa1.com.', f: true }, { t: 'secure-login.tk', f: true }, { t: '/account/update', f: false }],
            flags: ['paypa1', 'secure-login.tk'],
            explain: '"paypa1" is a homograph, and the real domain is the free ".tk" one.'
        },
        {
            kind: 'url', difficulty: 'hard',
            chunks: [{ t: 'https://', f: false }, { t: 'amazon.com.', f: true }, { t: 'extra-shipping-fee.com', f: true }, { t: '/update', f: false }],
            flags: ['amazon.com.', 'extra-shipping-fee.com'],
            explain: 'The real domain is extra-shipping-fee.com; amazon.com is a decoy subdomain.'
        },
        {
            kind: 'url', difficulty: 'hard',
            chunks: [{ t: 'https://', f: false }, { t: 'www.', f: false }, { t: 'bing.com', f: false }, { t: '/', f: false }],
            flags: [],
            explain: 'Real Bing domain — this one is safe, but staying calm under the clock is the real test.'
        }
    ],

    state: {
        questions: [],
        index: 0,
        score: 0,
        streak: 0,
        bestStreak: 0,
        status: 'idle'
    },

    best: JSON.parse(JSON.stringify(MG_EMPTY_BEST)),
    difficulty: 'easy',
    el: {},
    tokens: [],
    tokenBtns: [],
    remaining: 0,
    timerId: null,

    init() {
        this.el = {
            start: document.getElementById('thStart'),
            game: document.getElementById('thGame'),
            results: document.getElementById('thResults'),
            startBtn: document.getElementById('thStartBtn'),
            playAgainBtn: document.getElementById('thPlayAgainBtn'),
            nextBtn: document.getElementById('thNextBtn'),
            doneBtn: document.getElementById('thDoneBtn'),
            progress: document.getElementById('thProgress'),
            diff: document.getElementById('thDiff'),
            score: document.getElementById('thScore'),
            streak: document.getElementById('thStreak'),
            best: document.getElementById('thBest'),
            timerText: document.getElementById('thTimerText'),
            timerBar: document.getElementById('thTimerFill'),
            hint: document.getElementById('thHint'),
            content: document.getElementById('thContent'),
            feedback: document.getElementById('thFeedback'),
            feedbackLabel: document.getElementById('thFeedbackLabel'),
            explain: document.getElementById('thExplain'),
            resultIcon: document.getElementById('thResultIcon'),
            resultTitle: document.getElementById('thResultTitle'),
            resultScore: document.getElementById('thResultScore'),
            resultDetail: document.getElementById('thResultDetail'),
            resultStats: document.getElementById('thResultStats')
        };

        this.best = mgLoadBest('phisdetect-threathunt');
        this.setupDifficulty(this.gameKey);

        if (this.el.startBtn) {
            this.el.startBtn.addEventListener('click', () => this.start());
        }
        if (this.el.playAgainBtn) {
            this.el.playAgainBtn.addEventListener('click', () => this.start());
        }
        if (this.el.nextBtn) {
            this.el.nextBtn.addEventListener('click', () => this.next());
        }
        if (this.el.doneBtn) {
            this.el.doneBtn.addEventListener('click', () => this.submitDone());
        }

        this.renderBest();
        this.renderDiff();
    },

    setupDifficulty(gameKey) {
        const containers = document.querySelectorAll(`.minigame-difficulty[data-game="${gameKey}"]`);
        containers.forEach(container => {
            container.querySelectorAll('.diff-btn').forEach(btn => {
                btn.addEventListener('click', () => {
                    this.difficulty = btn.dataset.diff;
                    this.syncDifficultyUI();
                    this.renderBest();
                    this.renderDiff();
                });
            });
        });
    },

    syncDifficultyUI() {
        document.querySelectorAll(`.minigame-difficulty[data-game="${this.gameKey}"]`).forEach(c => {
            c.querySelectorAll('.diff-btn').forEach(b => b.classList.toggle('active', b.dataset.diff === this.difficulty));
        });
    },

    get timerSeconds() {
        return DIFFICULTIES[this.difficulty].timer;
    },

    pointsFor(correctCount) {
        return correctCount * this.POINTS_PER_ANSWER * DIFFICULTIES[this.difficulty].multiplier;
    },

    start() {
        const pool = mgSelectPool(this.bank, this.difficulty);
        const shuffled = pool.slice().sort(() => Math.random() - 0.5);
        this.state = {
            questions: shuffled.slice(0, this.ROUND_SIZE),
            index: 0,
            score: 0,
            streak: 0,
            bestStreak: 0,
            status: 'idle'
        };
        this.hide(this.el.results);
        this.hide(this.el.feedback);
        this.hide(this.el.start);
        this.show(this.el.game);
        this.renderQuestion();
    },

    renderQuestion() {
        const q = this.state.questions[this.state.index];

        this.tokens = [];
        this.tokenBtns = [];
        if (q.kind === 'url') {
            this.tokens = q.chunks.map(c => ({ text: c.t, isFlag: c.f }));
        } else {
            const lines = q.content.split('\n');
            lines.forEach((line, li) => {
                const parts = line.split(/\s+/).filter(Boolean);
                parts.forEach(p => {
                    this.tokens.push({ text: p, isFlag: q.flags.some(f => p.toLowerCase().includes(f.toLowerCase())) });
                });
                if (li < lines.length - 1) this.tokens.push({ text: '\n', isFlag: false, lineBreak: true });
            });
        }

        this.el.content.innerHTML = '';
        this.tokens.forEach((tok, idx) => {
            if (tok.lineBreak) {
                this.el.content.appendChild(document.createElement('br'));
                this.tokenBtns.push(null);
                return;
            }
            const btn = document.createElement('button');
            btn.type = 'button';
            btn.className = 'th-token' + (tok.isFlag ? ' is-flag' : '');
            btn.textContent = tok.text;
            btn.addEventListener('click', () => this.clickToken(idx));
            this.el.content.appendChild(btn);
            this.tokenBtns.push(btn);
        });

        this.state.status = 'active';
        this.el.doneBtn.disabled = false;
        this.hide(this.el.feedback);
        this.updateHint();
        this.startTimer();
        this.renderDiff();
        this.renderHud();
    },

    clickToken(idx) {
        if (this.state.status !== 'active') return;
        const tok = this.tokens[idx];
        const btn = this.tokenBtns[idx];
        if (!btn || btn.disabled) return;
        btn.disabled = true;

        if (tok.isFlag) {
            btn.classList.add('found');
            tok.found = true;
            this.updateHint();
            const allFound = this.tokens.filter(t => t.isFlag).every(t => t.found);
            if (allFound) this.complete(true, 'all');
        } else {
            btn.classList.add('miss');
            this.complete(false, 'fp');
        }
    },

    submitDone() {
        if (this.state.status !== 'active') return;
        const allFound = this.tokens.filter(t => t.isFlag).every(t => t.found);
        this.complete(allFound, allFound ? 'done' : 'missed');
    },

    complete(correct, reason) {
        if (this.state.status === 'done') return;
        this.state.status = 'done';
        this.stopTimer();
        this.el.doneBtn.disabled = true;

        const q = this.state.questions[this.state.index];
        this.revealFlags();

        if (correct) {
            this.state.score += 1;
            this.state.streak += 1;
            this.state.bestStreak = Math.max(this.state.bestStreak, this.state.streak);
            this.awardPoints();
            this.setFeedback('Correct', 'mg-correct', q.explain,
                `You earned +${this.pointsFor(1)} points.`);
        } else {
            this.state.streak = 0;
            let label = 'Incorrect';
            if (reason === 'time') label = 'Time\'s up!';
            if (reason === 'fp') label = 'False alarm!';
            this.setFeedback(label, 'mg-wrong', q.explain,
                reason === 'time'
                    ? 'You ran out of time before flagging every threat. '
                    : reason === 'fp'
                        ? 'You flagged something that is not a threat. '
                        : 'You missed at least one red flag. ');
        }

        this.renderHud();
    },

    revealFlags() {
        this.tokenBtns.forEach((btn, idx) => {
            if (btn && this.tokens[idx].isFlag) {
                btn.classList.add('reveal');
                btn.disabled = true;
            }
        });
    },

    updateHint() {
        if (!this.el.hint) return;
        const total = this.tokens.filter(t => t.isFlag).length;
        const left = this.tokens.filter(t => t.isFlag && !t.found).length;
        if (total === 0) {
            this.el.hint.textContent = 'No red flags here. Press "Done" to confirm this is safe.';
        } else if (left === 0) {
            this.el.hint.textContent = 'All threats flagged — confirming.';
        } else {
            this.el.hint.textContent = `Click the red flags below (${left} left). Press "Done" when nothing is left.`;
        }
    },

    next() {
        this.state.index += 1;
        if (this.state.index >= this.state.questions.length) {
            this.finish();
            return;
        }
        this.renderQuestion();
    },

    finish() {
        const total = this.state.questions.length;
        const accuracy = Math.round((this.state.score / total) * 100);
        const earned = this.pointsFor(this.state.score);
        const best = this.best[this.difficulty];

        if (this.state.score > best.score) {
            best.score = this.state.score;
            mgSaveBest('phisdetect-threathunt', this.best);
        }
        if (this.state.bestStreak > best.streak) {
            best.streak = this.state.bestStreak;
            mgSaveBest('phisdetect-threathunt', this.best);
        }
        this.renderBest();

        this.hide(this.el.game);
        this.show(this.el.results);
        this.el.resultIcon.innerHTML = accuracy >= 70
            ? '<i class="fa-solid fa-trophy" style="color: var(--green);"></i>'
            : '<i class="fa-solid fa-arrow-rotate-right" style="color: var(--text-muted);"></i>';
        this.el.resultTitle.textContent = accuracy >= 70 ? 'Round Complete' : 'Keep Training';
        this.el.resultScore.textContent = `${this.state.score} / ${total}`;
        this.el.resultDetail.textContent =
            `${DIFFICULTIES[this.difficulty].label} difficulty. You earned +${earned} points ` +
            `(${this.POINTS_PER_ANSWER} x${DIFFICULTIES[this.difficulty].multiplier} per correct answer).`;
        this.el.resultStats.innerHTML =
            `<div><span>Accuracy</span><strong>${accuracy}%</strong></div>` +
            `<div><span>Best streak</span><strong>${this.state.bestStreak}</strong></div>` +
            `<div><span>Points earned</span><strong>+${earned}</strong></div>`;

        mgSubmitResult(this.GAME_ID, this.difficulty, earned, total, this.state.bestStreak, mgPlayerName());
    },

    renderHud() {
        const s = this.state;
        this.el.progress.textContent = `Question ${Math.min(s.index + 1, s.questions.length)} / ${s.questions.length}`;
        this.el.score.innerHTML = `Score: <strong>${s.score}</strong>`;
        this.el.streak.innerHTML = `Streak: <strong>${s.streak}</strong>`;
    },

    renderBest() {
        if (this.el.best && this.best[this.difficulty]) {
            const b = this.best[this.difficulty];
            this.el.best.textContent = `Best: ${b.score} / ${b.streak}`;
        }
    },

    renderDiff() {
        const d = DIFFICULTIES[this.difficulty];
        if (this.el.diff) {
            this.el.diff.textContent = d.label;
            this.el.diff.className = 'diff-badge ' + this.difficulty;
        }
        this.syncDifficultyUI();
    },

    startTimer() {
        this.stopTimer();
        this.remaining = this.timerSeconds;
        const endTime = Date.now() + this.remaining * 1000;
        const tick = () => {
            this.remaining = Math.max(0, (endTime - Date.now()) / 1000);
            this.updateTimer();
            if (this.remaining <= 0) {
                this.complete(false, 'time');
                return;
            }
            this.timerId = setTimeout(tick, 100);
        };
        tick();
    },

    stopTimer() {
        if (this.timerId) {
            clearTimeout(this.timerId);
            this.timerId = null;
        }
    },

    updateTimer() {
        if (!this.el.timerText) return;
        const secs = Math.max(0, Math.ceil(this.remaining));
        this.el.timerText.textContent = `${secs}s`;
        const pct = (this.remaining / this.timerSeconds) * 100;
        if (this.el.timerBar) {
            this.el.timerBar.style.width = pct + '%';
        }
    },

    setFeedback(label, cls, explain, detail) {
        this.el.feedbackLabel.textContent = label;
        this.el.feedbackLabel.className = 'mg-feedback-label ' + cls;
        this.el.explain.textContent = `${detail} ${explain}`;
        this.show(this.el.feedback);
    },

    awardPoints() {
        const pts = this.POINTS_PER_ANSWER * DIFFICULTIES[this.difficulty].multiplier;
        if (window.ProfileManager) {
            const user = window.ProfileManager.user;
            window.ProfileManager.updateUser({ points: user.points + pts });
        }
        if (window.DashboardManager) {
            window.DashboardManager.incrementPoints(pts);
        }
        if (typeof Utils !== 'undefined' && Utils.toast) {
            Utils.toast(`Correct! +${pts} points`, 'success');
        }
    },

    show(el) { if (el) el.style.display = 'block'; },
    hide(el) { if (el) el.style.display = 'none'; }
};

/**
 * MinigameModalManager — opens and closes the full-screen game overlays.
 * Also resets each game back to its start screen whenever a modal opens,
 * and stops the Threat Hunt clock if a round is abandoned mid-way.
 */
const MinigameModalManager = {
    games: ['mg', 'ld', 'th'],
    managers: {},
    hideTimers: {},

    init() {
        this.managers = {
            mg: typeof MinigamesManager !== 'undefined' ? MinigamesManager : null,
            ld: typeof LinkDismantlerManager !== 'undefined' ? LinkDismantlerManager : null,
            th: typeof ThreatHuntManager !== 'undefined' ? ThreatHuntManager : null
        };

        this.games.forEach(key => {
            const overlay = document.getElementById(key + 'Overlay');
            if (!overlay) return;

            document.querySelectorAll('[data-open="' + key + '"]').forEach(btn => {
                btn.addEventListener('click', () => this.open(key));
            });

            const closeBtn = document.getElementById(key + 'Close');
            if (closeBtn) closeBtn.addEventListener('click', () => this.close(key));

            overlay.addEventListener('click', e => {
                if (e.target === overlay) this.close(key);
            });
        });

        document.addEventListener('keydown', e => {
            if (e.key === 'Escape') this.closeAll();
        });
    },

    open(key) {
        this.closeAll();
        const overlay = document.getElementById(key + 'Overlay');
        if (!overlay) return;
        if (this.hideTimers[key]) {
            clearTimeout(this.hideTimers[key]);
            this.hideTimers[key] = null;
        }
        this.reset(key);
        overlay.style.display = 'flex';
        requestAnimationFrame(() => overlay.classList.add('show'));
        document.body.classList.add('modal-open');
    },

    close(key) {
        const overlay = document.getElementById(key + 'Overlay');
        if (!overlay) return;
        overlay.classList.remove('show');
        if (this.hideTimers[key]) {
            clearTimeout(this.hideTimers[key]);
        }
        this.hideTimers[key] = setTimeout(() => {
            overlay.style.display = 'none';
            this.hideTimers[key] = null;
        }, 200);
        const mgr = this.managers[key];
        if (mgr && typeof mgr.stopTimer === 'function') mgr.stopTimer();
        document.body.classList.remove('modal-open');
    },

    closeAll() {
        this.games.forEach(key => this.close(key));
    },

    reset(key) {
        const mgr = this.managers[key];
        if (!mgr || !mgr.el) return;
        if (typeof mgr.stopTimer === 'function') mgr.stopTimer();
        mgr.hide(mgr.el.game);
        mgr.hide(mgr.el.results);
        mgr.hide(mgr.el.feedback);
        mgr.show(mgr.el.start);
    }
};
