/**
 * minigames.js — Security Minigames Manager
 * PhisDetect — Terminal Dashboard
 *
 * Implements the "Phish or Legit" quick-fire training game.
 * Correct answers award +10 points (same pool as threat reports).
 */

const MinigamesManager = {
    ROUND_SIZE: 10,
    POINTS_PER_ANSWER: 10,

    bank: [
        // --- Phishing emails ---
        {
            kind: 'email',
            answer: 'phish',
            content: 'Subject: Account Suspension Warning\n\nDear customer,\n\nYour online banking account has been temporarily suspended due to suspicious activity. Please verify your identity immediately to avoid permanent closure.\n\nVerify Now: http://secure-bank-verify.com/account/login\n\nRegards,\nSecurity Team',
            explain: 'Generic greeting, manufactured urgency, and a link to an unknown "verify" domain — classic phishing pressure tactics.'
        },
        {
            kind: 'email',
            answer: 'phish',
            content: 'Subject: You are a Winner!!!\n\nCongratulations! Your email address has been randomly selected to receive USD 1,000,000 in the International Email Lottery. Contact our agent to claim your prize.\n\nBest regards,\nMr. John Williams',
            explain: 'Unexpected lottery winnings from a stranger are a textbook scam. Nobody gives away money via email.'
        },
        {
            kind: 'email',
            answer: 'phish',
            content: 'Subject: Your package could not be delivered\n\nDear customer,\n\nYour parcel was returned to the depot. To reschedule delivery, confirm your details here: http://dhl-tracking.update-info.com\n\nShipping Team',
            explain: 'The "delivery problem" hook uses a domain that only resembles a courier. Check the real tracking site directly.'
        },
        {
            kind: 'email',
            answer: 'phish',
            content: 'Subject: Your password expires in 24 hours\n\nHi user,\n\nYour account password will expire today. Sign in to keep your account active.\n\nKeep My Account: http://paypa1-security-login.com/update\n\nDo not reply to this email.',
            explain: '"paypa1" is a homograph of a famous brand, and real services never email an expiring-password login link.'
        },
        {
            kind: 'email',
            answer: 'phish',
            content: 'Subject: Overdue Invoice #9841\n\nDear Sir/Madam,\n\nPlease find attached the invoice for services rendered. Kindly settle the amount of $1,240.50 before the due date.\n\nAccounts Department\n\n[attachment: invoice_9841.zip]',
            explain: 'Unsolicited invoices with zip attachments are a common malware delivery method.'
        },
        {
            kind: 'email',
            answer: 'phish',
            content: 'Subject: Tax refund approved\n\nDear taxpayer,\n\nYour 2025 tax refund of $850.00 is approved but could not be processed. Enter your bank details to receive the amount.\n\nClaim Refund: http://refund-claim-center.net/enter\n\nIRS Support',
            explain: 'Goverment agencies never ask for bank details by email. The domain is not an official government site.'
        },

        // --- Legitimate emails ---
        {
            kind: 'email',
            answer: 'legit',
            content: 'Subject: Your weekly security digest\n\nHi Alex,\n\nHere are this week\'s top articles on staying safe online:\n- Avoid credential reuse\n- Enable two-factor authentication\n\nYou are receiving this because you subscribed. Unsubscribe here.',
            explain: 'A newsletter you subscribed to, personalized greeting, no attachments and no link pressure. Legit.'
        },
        {
            kind: 'email',
            answer: 'legit',
            content: 'Subject: Your September statement is ready\n\nDear Alex Smith,\n\nYour credit card statement for September is now available to view in the app.\n\nSummary:\n- Previous balance: $1,230.00\n- Payment received: -$1,230.00\n\nWe are happy to help if you have questions.\n\nCustomer Care, Chase',
            explain: 'Generic but low-pressure account statement, no embedded links asking you to act now. Normal banking email.'
        },
        {
            kind: 'email',
            answer: 'legit',
            content: 'Subject: Sprint planning — tomorrow 10:00 AM\n\nHi team,\n\nReminder that our sprint planning call is tomorrow at 10:00 AM. Agenda is on our shared drive as always.\n\nThanks,\nPriya',
            explain: 'A colleague reminder with no links, no attachments and no sense of emergency. Legit.'
        },
        {
            kind: 'email',
            answer: 'legit',
            content: 'Subject: Password change confirmation\n\nHi Alex,\n\nYour password for the account "alex" was just changed. If this was you, no further action is needed. If not, contact support immediately.\n\nGitHub Support',
            explain: 'A security notification confirming an action — informative, not requesting anything. Legit.'
        },
        {
            kind: 'email',
            answer: 'legit',
            content: 'Subject: PyCon 2026 — Registration now open\n\nHi,\n\nEarly-bird registration for PyCon 2026 is open until end of month. Tickets start at $250. Visit our official website to register.\n\nOrganizers, pycon.org',
            explain: 'Points to the real pycon.org and comes from a known organizer. No attachments, no urgency. Legit.'
        },

        // --- Phishing URLs ---
        {
            kind: 'url',
            answer: 'phish',
            content: 'http://faceb00k-login.com/verify/account',
            explain: '"faceb00k" uses letter substitution to mimic Facebook — a homograph trick.'
        },
        {
            kind: 'url',
            answer: 'phish',
            content: 'http://secure-login-verify.tk/account/confirm.php',
            explain: 'Free ".tk" domain stuffed with trust words like "secure-login-verify".'
        },
        {
            kind: 'url',
            answer: 'phish',
            content: 'https://www.paypa1.com.secure-login.tk/account/update',
            explain: 'The real domain is "secure-login.tk"; "paypa1" is just a subdomain decoy.'
        },
        {
            kind: 'url',
            answer: 'phish',
            content: 'http://bankofamerica-accounts-verify.net/update',
            explain: 'Brand name chained to unrelated words in the domain itself. Official sites use the real brand domain.'
        },
        {
            kind: 'url',
            answer: 'phish',
            content: 'https://amazon-order-tracking.info/confirm-order',
            explain: '"amazon" is embedded in a much longer unknown domain — the registrable domain is "amazon-order-tracking.info".'
        },
        {
            kind: 'url',
            answer: 'phish',
            content: 'http://185.220.101.4/emails/update.html',
            explain: 'Credential-phishing page hosted on a raw IP address — no legitimate service does that.'
        },
        {
            kind: 'url',
            answer: 'phish',
            content: 'https://google.com.verify-account-support.org/login',
            explain: 'The domain that matters is "verify-account-support.org"; google.com is only a subdomain prefix.'
        },

        // --- Legitimate URLs ---
        {
            kind: 'url',
            answer: 'legit',
            content: 'https://www.google.com/search?q=phishing+awareness',
            explain: 'Real Google domain with a normal search query.'
        },
        {
            kind: 'url',
            answer: 'legit',
            content: 'https://github.com/bruneraccount',
            explain: 'Real github.com profile URL.'
        },
        {
            kind: 'url',
            answer: 'legit',
            content: 'https://www.netflix.com/browse',
            explain: 'Real netflix.com domain.'
        },
        {
            kind: 'url',
            answer: 'legit',
            content: 'https://mail.google.com/mail/u/0/#inbox',
            explain: 'Real Google mail subdomain on google.com.'
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

    best: {
        score: 0,
        streak: 0
    },

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

        this.loadBest();

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

        this.renderBest();
    },

    /**
     * Load best score/streak from localStorage
     */
    loadBest() {
        try {
            const saved = JSON.parse(localStorage.getItem('phisdetect-minigames') || '{}');
            this.best = {
                score: Number(saved.score) || 0,
                streak: Number(saved.streak) || 0
            };
        } catch (e) {
            this.best = { score: 0, streak: 0 };
        }
    },

    /**
     * Persist best score/streak to localStorage
     */
    saveBest() {
        try {
            localStorage.setItem('phisdetect-minigames', JSON.stringify(this.best));
        } catch (e) {
            console.warn('Failed to save minigame bests:', e);
        }
    },

    /**
     * Start a new round
     */
    start() {
        const shuffled = this.bank.slice().sort(() => Math.random() - 0.5);
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
                q.explain, `${choice === 'phish' ? 'Phish' : 'Legit'}! You earned +${this.POINTS_PER_ANSWER} points.`);
        } else {
            this.state.streak = 0;
            const correctLabel = q.answer === 'phish' ? 'Phish' : 'Legit';
            this.setFeedback('Incorrect', 'mg-wrong',
                q.explain, `The answer was ${correctLabel}. Better luck next time.`);
        }

        this.highlightAnswer(q, choice);
        this.renderHud();
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
        const earned = this.state.score * this.POINTS_PER_ANSWER;

        if (this.state.score > this.best.score) {
            this.best.score = this.state.score;
            this.saveBest();
        }
        if (this.state.bestStreak > this.best.streak) {
            this.best.streak = this.state.bestStreak;
            this.saveBest();
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
            `You earned +${earned} points (${this.POINTS_PER_ANSWER} per correct answer).`;
        this.el.resultStats.innerHTML =
            `<div><span>Accuracy</span><strong>${accuracy}%</strong></div>` +
            `<div><span>Best streak</span><strong>${this.state.bestStreak}</strong></div>` +
            `<div><span>Points earned</span><strong>+${earned}</strong></div>`;
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
        if (this.el.best) {
            this.el.best.textContent = `Best: ${this.best.score} / ${this.best.streak}`;
        }
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
        if (window.ProfileManager) {
            const user = window.ProfileManager.user;
            window.ProfileManager.updateUser({ points: user.points + this.POINTS_PER_ANSWER });
        }
        if (window.DashboardManager) {
            window.DashboardManager.incrementPoints(this.POINTS_PER_ANSWER);
        }
        if (typeof Utils !== 'undefined' && Utils.toast) {
            Utils.toast(`Correct! +${this.POINTS_PER_ANSWER} points`, 'success');
        }
    },

    show(el) { if (el) el.style.display = 'block'; },
    hide(el) { if (el) el.style.display = 'none'; }
};

/**
 * LinkDismantlerManager — "Link Dismantler" minigame.
 * Deconstruct a URL and pick the real registrable domain (the site the
 * attacker actually controls). Correct answers award +10 points.
 */
const LinkDismantlerManager = {
    ROUND_SIZE: 10,
    POINTS_PER_ANSWER: 10,

    bank: [
        {
            url: 'https://www.paypa1.com.secure-login.tk/account/update',
            correct: 'secure-login.tk',
            distractors: ['paypa1.com', 'www.paypa1.com', 'login.tk'],
            explain: 'The attacker controls the registrable domain "secure-login.tk". "paypa1.com" is only a subdomain decoy in front of it.'
        },
        {
            url: 'http://faceb00k-login.com/verify/account',
            correct: 'faceb00k-login.com',
            distractors: ['faceb00k.com', 'login.com', 'facebook.com'],
            explain: 'Here the attacker owns "faceb00k-login.com" itself — a letter-swapped lookalike of Facebook.'
        },
        {
            url: 'https://amazon-order-tracking.info/confirm-order',
            correct: 'amazon-order-tracking.info',
            distractors: ['amazon.com', 'order-tracking.info', 'amazon.info'],
            explain: 'The real registrable domain is "amazon-order-tracking.info" — a brand name wrapped into an unrelated domain.'
        },
        {
            url: 'https://google.com.verify-account-support.org/login',
            correct: 'verify-account-support.org',
            distractors: ['google.com', 'verify-account-support.com', 'google.login'],
            explain: '"google.com" is just a subdomain. The attacker controls "verify-account-support.org".'
        },
        {
            url: 'http://secure-login-verify.tk/account/confirm.php',
            correct: 'secure-login-verify.tk',
            distractors: ['confirm.php', 'secure-login.com', 'login-verify.tk'],
            explain: 'A free .tk domain stuffed with trust words — that is the attacker\'s real property.'
        },
        {
            url: 'https://www.paypal.com/signin',
            correct: 'paypal.com',
            distractors: ['paypa1.com', 'paypal-security.com', 'www.paypal.com/signin'],
            explain: 'Real PayPal. The registrable domain is "paypal.com"; "www.paypal.com/signin" is a path, not a domain.'
        },
        {
            url: 'http://185.220.101.4/emails/update.html',
            correct: '185.220.101.4',
            distractors: ['emails/update.html', '185.220.101', 'update.html'],
            explain: 'The destination is a raw IP address — legitimate services never host login pages on bare IPs.'
        },
        {
            url: 'https://secure-bankofamerica-verify.com/online/login',
            correct: 'secure-bankofamerica-verify.com',
            distractors: ['bankofamerica.com', 'secure-bankofamerica.com', 'online.login'],
            explain: 'The whole "secure-bankofamerica-verify.com" is one registrable domain impersonating Bank of America.'
        },
        {
            url: 'https://www.microsoft.com/en-us/software-download',
            correct: 'microsoft.com',
            distractors: ['software-download.com', 'www.microsoft.com', 'microsoft-download.com'],
            explain: 'Real Microsoft — the registrable domain is "microsoft.com".'
        },
        {
            url: 'https://netflix.com.accounts-update.net/login',
            correct: 'accounts-update.net',
            distractors: ['netflix.com', 'netflix.net', 'accounts.net'],
            explain: 'The attacker owns "accounts-update.net"; "netflix.com" is a decoy subdomain in front of it.'
        },
        {
            url: 'https://github.com/bruneraccount',
            correct: 'github.com',
            distractors: ['github.com/bruneraccount', 'bruneraccount.com', 'github.login'],
            explain: 'Real GitHub — "github.com/bruneraccount" is a path, not a domain.'
        },
        {
            url: 'http://dhl-tracking.update-info.com/reschedule',
            correct: 'update-info.com',
            distractors: ['dhl.com', 'dhl-tracking.com', 'reschedule.com'],
            explain: 'The real domain is "update-info.com"; "dhl-tracking" is a subdomain decoy.'
        },
        {
            url: 'https://login.chase.com/',
            correct: 'chase.com',
            distractors: ['login.chase.com', 'chase-login.com', 'login.com'],
            explain: '"login.chase.com" is a subdomain of chase.com — still owned by Chase. The registrable domain is "chase.com".'
        },
        {
            url: 'https://amazon.com.extra-shipping-fee.com/update',
            correct: 'extra-shipping-fee.com',
            distractors: ['amazon.com', 'shipping-fee.com', 'extra.com'],
            explain: 'The owner controls "extra-shipping-fee.com"; "amazon.com" is just a subdomain prefix.'
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

    best: {
        score: 0,
        streak: 0
    },

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

        this.loadBest();

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
    },

    loadBest() {
        try {
            const saved = JSON.parse(localStorage.getItem('phisdetect-linkdismantler') || '{}');
            this.best = {
                score: Number(saved.score) || 0,
                streak: Number(saved.streak) || 0
            };
        } catch (e) {
            this.best = { score: 0, streak: 0 };
        }
    },

    saveBest() {
        try {
            localStorage.setItem('phisdetect-linkdismantler', JSON.stringify(this.best));
        } catch (e) {
            console.warn('Failed to save minigame bests:', e);
        }
    },

    start() {
        const shuffled = this.bank.slice().sort(() => Math.random() - 0.5);
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
                `You earned +${this.POINTS_PER_ANSWER} points.`);
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
        const earned = this.state.score * this.POINTS_PER_ANSWER;

        if (this.state.score > this.best.score) {
            this.best.score = this.state.score;
            this.saveBest();
        }
        if (this.state.bestStreak > this.best.streak) {
            this.best.streak = this.state.bestStreak;
            this.saveBest();
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
            `You earned +${earned} points (${this.POINTS_PER_ANSWER} per correct answer).`;
        this.el.resultStats.innerHTML =
            `<div><span>Accuracy</span><strong>${accuracy}%</strong></div>` +
            `<div><span>Best streak</span><strong>${this.state.bestStreak}</strong></div>` +
            `<div><span>Points earned</span><strong>+${earned}</strong></div>`;
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

        this.renderHud();
    },

    renderHud() {
        const s = this.state;
        this.el.progress.textContent = `Question ${Math.min(s.index + 1, s.questions.length)} / ${s.questions.length}`;
        this.el.score.innerHTML = `Score: <strong>${s.score}</strong>`;
        this.el.streak.innerHTML = `Streak: <strong>${s.streak}</strong>`;
    },

    renderBest() {
        if (this.el.best) {
            this.el.best.textContent = `Best: ${this.best.score} / ${this.best.streak}`;
        }
    },

    setFeedback(label, cls, explain, detail) {
        this.el.feedbackLabel.textContent = label;
        this.el.feedbackLabel.className = 'mg-feedback-label ' + cls;
        this.el.explain.textContent = `${detail} ${explain}`;
        this.show(this.el.feedback);
    },

    awardPoints() {
        if (window.ProfileManager) {
            const user = window.ProfileManager.user;
            window.ProfileManager.updateUser({ points: user.points + this.POINTS_PER_ANSWER });
        }
        if (window.DashboardManager) {
            window.DashboardManager.incrementPoints(this.POINTS_PER_ANSWER);
        }
        if (typeof Utils !== 'undefined' && Utils.toast) {
            Utils.toast(`Correct! +${this.POINTS_PER_ANSWER} points`, 'success');
        }
    },

    show(el) { if (el) el.style.display = 'block'; },
    hide(el) { if (el) el.style.display = 'none'; }
};

/**
 * ThreatHuntManager — "Threat Hunt" minigame.
 * Race against the clock: click every red flag (phishing token) in an email
 * or a dismantled URL before the timer runs out. A false positive or a missed
 * flag ends the question. Correct answers award +10 points.
 */
const ThreatHuntManager = {
    ROUND_SIZE: 10,
    POINTS_PER_ANSWER: 10,
    TIMER_SECONDS: 20,

    bank: [
        // --- Emails ---
        {
            kind: 'email',
            content: 'Subject: Account Suspension Warning\n\nDear customer,\n\nYour online banking account has been temporarily suspended due to suspicious activity. Please verify your identity immediately to avoid permanent closure.\n\nVerify Now: http://secure-bank-verify.com/account/login\n\nRegards,\nSecurity Team',
            flags: ['customer', 'immediately', 'http://secure-bank-verify.com/account/login'],
            explain: 'Generic greeting ("Dear customer"), pressure word "immediately", and a link to an unknown "verify" domain.'
        },
        {
            kind: 'email',
            content: 'Subject: Your password expires in 24 hours\n\nHi user,\n\nYour account password will expire today. Sign in to keep your account active.\n\nKeep My Account: http://paypa1-security-login.com/update\n\nDo not reply to this email.',
            flags: ['expire', 'http://paypa1-security-login.com/update'],
            explain: '"paypa1" is a PayPal homograph and the email pressures you about password expiry — real services never email login links.'
        },
        {
            kind: 'email',
            content: 'Subject: You are a Winner!!!\n\nCongratulations! Your email address has been randomly selected to receive USD 1,000,000 in the International Email Lottery. Contact our agent to claim your prize.\n\nBest regards,\nMr. John Williams',
            flags: ['Winner', 'Lottery', '1,000,000'],
            explain: 'Unexpected lottery winnings and an unknown "agent" to contact — a classic advance-fee scam.'
        },
        {
            kind: 'email',
            content: 'Subject: Overdue Invoice #9841\n\nDear Sir/Madam,\n\nPlease find attached the invoice for services rendered. Kindly settle the amount of $1,240.50 before the due date.\n\nAccounts Department\n\n[attachment: invoice_9841.zip]',
            flags: ['Overdue', 'invoice_9841.zip'],
            explain: 'An unsolicited invoice carrying a zip attachment is a common malware delivery tactic.'
        },
        {
            kind: 'email',
            content: 'Subject: Tax refund approved\n\nDear taxpayer,\n\nYour 2025 tax refund of $850.00 is approved but could not be processed. Enter your bank details to receive the amount.\n\nClaim Refund: http://refund-claim-center.net/enter\n\nIRS Support',
            flags: ['bank', 'http://refund-claim-center.net/enter'],
            explain: 'Government agencies never request bank details by email, and the link is not an official site.'
        },
        {
            kind: 'email',
            content: 'Subject: Your package could not be delivered\n\nDear customer,\n\nYour parcel was returned to the depot. To reschedule delivery, confirm your details here: http://dhl-tracking.update-info.com/reschedule\n\nShipping Team',
            flags: ['confirm', 'http://dhl-tracking.update-info.com/reschedule'],
            explain: 'The courier hook steers you to a lookalike domain that only resembles the real service.'
        },

        // --- URLs (pre-dismantled into chunks) ---
        {
            kind: 'url',
            chunks: [{ t: 'https://', f: false }, { t: 'www.paypa1.com.', f: true }, { t: 'secure-login.tk', f: true }, { t: '/account/update', f: false }],
            flags: ['paypa1', 'secure-login.tk'],
            explain: '"paypa1" is a homograph, and the real domain is the free ".tk" one.'
        },
        {
            kind: 'url',
            chunks: [{ t: 'http://', f: false }, { t: '185.220.101.4', f: true }, { t: '/emails/', f: false }, { t: 'update.html', f: false }],
            flags: ['185.220.101.4'],
            explain: 'A raw IP address as the destination — legitimate services never host login pages on bare IPs.'
        },
        {
            kind: 'url',
            chunks: [{ t: 'https://', f: false }, { t: 'google.com.', f: true }, { t: 'verify-account-support.org', f: true }, { t: '/login', f: false }],
            flags: ['google.com.', 'verify-account-support.org'],
            explain: 'The attacker owns verify-account-support.org; google.com is only a subdomain decoy.'
        },
        {
            kind: 'url',
            chunks: [{ t: 'https://', f: false }, { t: 'www.', f: false }, { t: 'netflix.com', f: false }, { t: '/browse', f: false }],
            flags: [],
            explain: 'Real Netflix — no red flags here. Click "Done" to confirm.'
        },
        {
            kind: 'url',
            chunks: [{ t: 'https://', f: false }, { t: 'login.', f: false }, { t: 'chase.com', f: false }, { t: '/', f: false }],
            flags: [],
            explain: 'login.chase.com is a real subdomain of chase.com — safe.'
        },
        {
            kind: 'url',
            chunks: [{ t: 'http://', f: false }, { t: 'faceb00k-login.com', f: true }, { t: '/verify/', f: false }, { t: 'account', f: false }],
            flags: ['faceb00k-login.com'],
            explain: 'A letter-swapped homograph of Facebook — the whole registrable domain is the attacker\'s.'
        },
        {
            kind: 'url',
            chunks: [{ t: 'https://', f: false }, { t: 'github.com', f: false }, { t: '/', f: false }, { t: 'bruneraccount', f: false }],
            flags: [],
            explain: 'Real GitHub domain — safe.'
        },
        {
            kind: 'url',
            chunks: [{ t: 'https://', f: false }, { t: 'amazon.com.', f: true }, { t: 'extra-shipping-fee.com', f: true }, { t: '/update', f: false }],
            flags: ['amazon.com.', 'extra-shipping-fee.com'],
            explain: 'The real domain is extra-shipping-fee.com; amazon.com is a decoy subdomain.'
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

    best: {
        score: 0,
        streak: 0
    },

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
            score: document.getElementById('thScore'),
            streak: document.getElementById('thStreak'),
            best: document.getElementById('thBest'),
            timerText: document.getElementById('thTimerText'),
            timerBar: document.getElementById('thTimerFill'),
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

        this.loadBest();

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
    },

    loadBest() {
        try {
            const saved = JSON.parse(localStorage.getItem('phisdetect-threathunt') || '{}');
            this.best = {
                score: Number(saved.score) || 0,
                streak: Number(saved.streak) || 0
            };
        } catch (e) {
            this.best = { score: 0, streak: 0 };
        }
    },

    saveBest() {
        try {
            localStorage.setItem('phisdetect-threathunt', JSON.stringify(this.best));
        } catch (e) {
            console.warn('Failed to save minigame bests:', e);
        }
    },

    start() {
        const shuffled = this.bank.slice().sort(() => Math.random() - 0.5);
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
        this.hide(this.el.feedback);
        this.startTimer();
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

        const q = this.state.questions[this.state.index];
        this.revealFlags();

        if (correct) {
            this.state.score += 1;
            this.state.streak += 1;
            this.state.bestStreak = Math.max(this.state.bestStreak, this.state.streak);
            this.awardPoints();
            this.setFeedback('Correct', 'mg-correct', q.explain,
                `You earned +${this.POINTS_PER_ANSWER} points.`);
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
        const earned = this.state.score * this.POINTS_PER_ANSWER;

        if (this.state.score > this.best.score) {
            this.best.score = this.state.score;
            this.saveBest();
        }
        if (this.state.bestStreak > this.best.streak) {
            this.best.streak = this.state.bestStreak;
            this.saveBest();
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
            `You earned +${earned} points (${this.POINTS_PER_ANSWER} per correct answer).`;
        this.el.resultStats.innerHTML =
            `<div><span>Accuracy</span><strong>${accuracy}%</strong></div>` +
            `<div><span>Best streak</span><strong>${this.state.bestStreak}</strong></div>` +
            `<div><span>Points earned</span><strong>+${earned}</strong></div>`;
    },

    renderHud() {
        const s = this.state;
        this.el.progress.textContent = `Question ${Math.min(s.index + 1, s.questions.length)} / ${s.questions.length}`;
        this.el.score.innerHTML = `Score: <strong>${s.score}</strong>`;
        this.el.streak.innerHTML = `Streak: <strong>${s.streak}</strong>`;
    },

    renderBest() {
        if (this.el.best) {
            this.el.best.textContent = `Best: ${this.best.score} / ${this.best.streak}`;
        }
    },

    startTimer() {
        this.remaining = this.TIMER_SECONDS;
        this.updateTimer();
        this.stopTimer();
        this.timerId = setInterval(() => {
            this.remaining -= 0.1;
            if (this.remaining <= 0) {
                this.remaining = 0;
                this.updateTimer();
                this.complete(false, 'time');
            } else {
                this.updateTimer();
            }
        }, 100);
    },

    stopTimer() {
        if (this.timerId) {
            clearInterval(this.timerId);
            this.timerId = null;
        }
    },

    updateTimer() {
        if (!this.el.timerText) return;
        const secs = Math.max(0, Math.ceil(this.remaining));
        this.el.timerText.textContent = `${secs}s`;
        const pct = (this.remaining / this.TIMER_SECONDS) * 100;
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
        if (window.ProfileManager) {
            const user = window.ProfileManager.user;
            window.ProfileManager.updateUser({ points: user.points + this.POINTS_PER_ANSWER });
        }
        if (window.DashboardManager) {
            window.DashboardManager.incrementPoints(this.POINTS_PER_ANSWER);
        }
        if (typeof Utils !== 'undefined' && Utils.toast) {
            Utils.toast(`Correct! +${this.POINTS_PER_ANSWER} points`, 'success');
        }
    },

    show(el) { if (el) el.style.display = 'block'; },
    hide(el) { if (el) el.style.display = 'none'; }
};
