# Project Structure

```
phish-detect/
├── .gitignore                      # Files git should NOT track (venv, models, caches, logs)
├── structure.md                    # This file — the folder/file map
│
├── backend/                        # The server side (a Flask Python API)
│   ├── server.py                   # Main backend program: all the API endpoints live here
│   └── data/
│       └── minigame_scores.json    # Saved game scores (created at runtime; not committed)
│
├── frontend/                       # The web pages users actually see and click
│   ├── index.html                  # The Scanner page — paste a URL/email to check it
│   ├── dashboard.html              # The Dashboard page — your activity/points overview
│   ├── minigames.html              # The Minigames page — three training games
│   ├── help.html                   # The Help / FAQ page
│   ├── css/                        # All the styling that makes the pages look "terminal"
│   │   ├── main.css                # Base look: colors, fonts, buttons, cards
│   │   ├── layout.css              # Page layout: sidebar, header, main area
│   │   ├── components.css          # Reusable pieces: modals, dropdowns, badges, leaderboard
│   │   ├── terminal.css            # The terminal-window style (title bars, dots, borders)
│   │   ├── status.css              # Status colors/glow (safe / suspicious / malicious)
│   │   ├── results.css             # Styles for the scan results panel
│   │   └── responsive.css          # Makes everything fit on phones and tablets
│   └── js/                         # All the browser-side logic
│       ├── app.js                  # Boots up the right page module when each page loads
│       ├── utils.js                # Shared helpers: toasts, confirm popups, clipboard, etc.
│       ├── theme.js                # Dark/light theme switching (saved in your browser)
│       ├── navigation.js           # Sidebar/menu + logout behavior
│       ├── notifications.js        # The notification bell and its dropdown
│       ├── profile.js              # Your fake "user" profile stored in the browser
│       ├── scanner.js              # Sends URLs/emails to the backend and shows results
│       ├── dashboard.js            # Builds the dashboard stats and history
│       ├── minigames.js            # All three games + the global leaderboard logic
│       └── faq.js                  # Expands/collapses the FAQ answers
│
├── model/                          # The machine-learning part (the "brain")
│   ├── requirements.txt            # Python packages needed to train/run the model
│   ├── data/                       # Raw email datasets used to teach the model
│   │   ├── easy_ham.tar.bz2        # Archive of real, normal (non-scam) emails
│   │   ├── email_text_dataset.jsonl# Cleaned email samples, ready for training
│   │   └── phishing0-3.mbox        # Real phishing/scam emails, used as "bad" examples
│   ├── lists/                      # Big lists of real/known websites
│   │   ├── openphish_hosts.txt     # Known phishing website domains
│   │   ├── tranco_top100k.txt      # Top 100K most popular real domains
│   │   └── tranco_top1m.txt        # Top 1M most popular real domains
│   ├── lookup/                     # Small reference lists
│   │   ├── shorteners.txt          # Known URL shortener domains (bit.ly, etc.)
│   │   └── tlds.txt                # All top-level domains (.com, .org, .uk…)
│   ├── src/                        # The training scripts (developer tools)
│   │   ├── extract_features.py     # Turns a URL into numbers the model understands
│   │   ├── email_text_features.py  # Turns an email into numbers the model understands
│   │   ├── url_text_features.py    # Extra "word" analysis for URLs
│   │   ├── augment_dataset.py      # Makes more training examples from the ones we have
│   │   ├── train.py                # Trains the main phishing model from the CSV data
│   │   ├── train_email_text_model.py# Trains the email-text model from JSON data
│   │   ├── train_url_text_model.py # Trains the URL-text model from the lists
│   │   ├── update_email_data.py    # Rebuilds the email training dataset
│   │   └── update_lists.py         # Downloads fresh copies of the website lists
│   └── trained/                    # The finished model files (output of training)
│       ├── dataset_small.csv       # Small training table (URL features + labels)
│       ├── dataset_augmented.csv   # Bigger training table with extra fake examples
│       ├── features.txt            # Names of the features the model uses
│       ├── phishing_model.joblib   # The main trained model (385 MB, generated — not in git)
│       ├── url_text_model.joblib   # Trained URL-word model (generated — not in git)
│       └── email_text_model.joblib # Trained email-word model (generated — not in git)
```

## What each file does

### `backend/`

- **`server.py`** — The heart of the app. It listens for requests from the web page and answers them: checking a URL or email for phishing, saving game scores, and returning the leaderboard.
- **`data/minigame_scores.json`** — Where game scores are saved between restarts. It is created on the first game and is not stored in git.

### `frontend/`

- **`index.html`** — The Scanner page: you paste a suspicious link or email, hit scan, and get a verdict.
- **`dashboard.html`** — Your overview page: shows your points, reports, and history.
- **`minigames.html`** — The arcade: Phish or Legit, Link Dismantler, and Threat Hunt, plus the global leaderboard.
- **`help.html`** — The FAQ page where users learn about phishing and how the tool works.
- **`css/main.css`** — The base design system: fonts, colors, buttons, cards.
- **`css/layout.css`** — Arranges the page skeleton: sidebar, top bar, and content area.
- **`css/components.css`** — Styling for reusable parts: popups, dropdowns, badges, leaderboard, and all the game screens.
- **`css/terminal.css`** — Makes panels look like a hacker terminal: the traffic-light dots, title bars, and borders.
- **`css/status.css`** — The green/yellow/red verdict colors and glows.
- **`css/results.css`** — Styling for the scan report that appears after a check.
- **`css/responsive.css`** — Fixes the layout so it still looks good on small screens.
- **`js/app.js`** — The starter: decides which module to load based on the page you opened.
- **`js/utils.js`** — Shared little helpers used everywhere (popup messages, confirm dialogs, copy buttons).
- **`js/theme.js`** — Switches between dark and light mode and remembers your choice.
- **`js/navigation.js`** — Makes the sidebar links work and handles logout.
- **`js/notifications.js`** — Powers the bell icon and the list of alerts in the top bar.
- **`js/profile.js`** — Stores a local guest profile (name and points) in the browser.
- **`js/scanner.js`** — The brains in the browser for the scanner: calls the backend and draws the results.
- **`js/dashboard.js`** — Fills the dashboard with your stats and past scans.
- **`js/minigames.js`** — All three games and the leaderboard: questions, difficulty, scoring, and timer.
- **`js/faq.js`** — Opens and closes the FAQ answers when you click them.

### `model/`

- **`requirements.txt`** — The list of Python libraries you must install to train or run the model.
- **`data/easy_ham.tar.bz2`** — A zip of everyday, innocent emails used as "safe" examples.
- **`data/email_text_dataset.jsonl`** — Cleaned email samples (both safe and scam) used to train the email model.
- **`data/phishing0-3.mbox`** — Real scam emails used as the "dangerous" examples.
- **`lists/openphish_hosts.txt`** — Domains known to host phishing pages.
- **`lists/tranco_top100k.txt`** — The 100,000 most-visited real websites.
- **`lists/tranco_top1m.txt`** — The 1,000,000 most-visited real websites.
- **`lookup/shorteners.txt`** — Known URL shortener services.
- **`lookup/tlds.txt`** — Every top-level domain ending (.com, .org, .io…).
- **`src/extract_features.py`** — Translates a URL into the numbers/features the model scores.
- **`src/email_text_features.py`** — Translates an email's text into features.
- **`src/url_text_features.py`** — Extra text checks on the words in a URL.
- **`src/augment_dataset.py`** — Creates extra training examples by tweaking existing ones, so the model learns better.
- **`src/train.py`** — Trains the main model from the CSV training tables.
- **`src/train_email_text_model.py`** — Trains the model that reads email wording.
- **`src/train_url_text_model.py`** — Trains the model that reads URL wording.
- **`src/update_email_data.py`** — Rebuilds the email training dataset from the raw mailboxes.
- **`src/update_lists.py`** — Downloads fresh copies of the popular-site and phishing lists.
- **`trained/dataset_small.csv`** — A training table of URL examples and their labels.
- **`trained/dataset_augmented.csv`** — The same training table, expanded with extra examples.
- **`trained/features.txt`** — The names of the inputs the main model uses.
- **`trained/phishing_model.joblib`** — The finished main model (large; generated by training, not uploaded to GitHub).
- **`trained/url_text_model.joblib`** — The finished URL-word model (generated, not uploaded).
- **`trained/email_text_model.joblib`** — The finished email-word model (generated, not uploaded).
