# Installing PhisDetect on Your Own Computer

**PhisDetect** is a phishing detector: you give it a web address (URL) or the text
of a suspicious email, and it tells you how likely it is to be a phishing attack
(fake login pages, scam emails, malicious links, etc.).

This guide walks a beginner through the whole process, from downloading the code
to running your own copy. At the end you will have:

1. The PhisDetect files on your computer.
2. The "brain" of the tool (the trained AI models) built on your machine.
3. The scanner running on your computer and open in your web browser.

> **Time needed:** about 10–30 minutes, depending on your internet speed and how
> fast your computer is. The slowest part is the one-time model training.

---

## 0. What you need before you start

| You need | Why | How to check |
|----------|-----|--------------|
| A computer | Runs the code locally | Any Windows, macOS or Linux PC |
| Internet | To download the files, install packages, and (later) let the scanner query live services | — |
| **Python** (version **3.14**) | Runs the server and training | See below |
| Git (only for method 1B below) | To "clone" the repository | Optional — you can download a ZIP instead |

### Checking if Python is installed

Open a terminal / command prompt and type:

```
python --version
```

(or `python3 --version` on macOS/Linux). PhisDetect is developed and tested with
**Python 3.14.x**, so you should see something like `Python 3.14.6`. If the
command is not found, or shows a different version, install Python 3.14 from
<https://www.python.org/downloads/> and **make sure you tick "Add Python to
PATH"** during installation on Windows.

> Other Python versions are not officially supported — install the newest
> **3.14** release.

---

## 1. Get the files from GitHub

The code lives at **<https://github.com/bruneraccount/phisdetect>**. There are
two ways to get it onto your computer — choose the one you are comfortable with.

### Option A — Download a ZIP (easiest, no extra software)

1. Open <https://github.com/bruneraccount/phisdetect> in your browser.
2. Click the green **"Code"** button, then click **"Download ZIP"**.
3. The download is fairly large because it includes the training data, so it
   may take a little while.
4. Unzip the downloaded file. On Windows, right-click → *Extract All*. You now
   have a folder called `phisdetect-main` (the unzipper renames it).

   > If you like, rename it to just `phisdetect` so the instructions below match
   > exactly. On Windows that is fine; on macOS/Linux run
   > `mv phisdetect-main phisdetect`.

### Option B — Clone with Git (best if you want easy updates)

If you have Git installed, open a terminal and run:

```
git clone https://github.com/bruneraccount/phisdetect.git
```

This creates a folder called `phisdetect` with the latest code.

### Know where your project folder is

From now on, all the commands in this guide assume you are **inside the
`phisdetect` folder**:

- **Windows:** open the folder in File Explorer, click into the address bar,
  type `cmd`, and press Enter. That opens a command prompt inside the folder.
- **macOS / Linux:** in the terminal, run `cd phisdetect` (from wherever you
  downloaded it). If unsure where you are, run `pwd` to print the current folder.

> **Important:** a full clone/ZIP contains the training data, the lists and the
> source code — but **not** the three big model files. Those are too large for
> GitHub (the main one is ~385 MB, GitHub allows 100 MB max), so you will build
> them yourself in Step 3. This is normal and expected.

---

## 2. Create a clean Python "virtual environment"

A *virtual environment* is a private folder where the required Python packages
get installed, so they do not mix with anything else on your system. Every
project should have its own.

Run this command **inside the `phisdetect` folder**:

```
python -m venv venv
```

(If that gives an error, try `python3 -m venv venv` or `python3.14 -m venv venv`.)

This creates a new folder called `venv`. Now you must **activate** it in every
terminal you use:

- **Windows (Command Prompt):**
  ```
  venv\Scripts\activate
  ```
- **Windows (PowerShell):** first run
  `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`, then
  `venv\Scripts\activate`
- **macOS / Linux:**
  ```
  source venv/bin/activate
  ```

When it works, you will see `(venv)` appear at the start of your command prompt.

Quickly verify that the environment is set up correctly:

```
python --version
python -m pip --version
```

Both commands should respond (e.g. `Python 3.14.x` and a `pip ...` line). Keep
this terminal open for the next steps.

---

## 3. Install the required Python packages

While the `(venv)` environment is active, run:

```
python -m pip install -r model/requirements.txt
```

This downloads and installs the 9 packages PhisDetect needs (Flask, pandas,
scikit-learn, and friends — the full list is explained in
[`requirements.md`](requirements.md)). It usually takes 2–5 minutes.

When it finishes you should see something like
`Successfully installed Flask-3.1.3 pandas-3.0.5 scikit-learn-1.9.0 ...`.

> If you see a `python`/`pip` "not found" or "is not recognized" error, the
> virtual environment is not active — check the `(venv)` prefix.

---

## 4. Build the models (one-time, the slow step)

The three AI models are not shipped on GitHub because they are too big. You now
rebuild them from the training data that *is* included in the download. The
main one takes a few minutes on a normal laptop.

Still inside the `phisdetect` folder, with `(venv)` active, run these three
commands one by one:

```
python model/src/train.py
python model/src/train_url_text_model.py
python model/src/train_email_text_model.py
```

What each one does:

| Command | What it builds | Internet needed? | Approx. size |
|---------|----------------|------------------|--------------|
| `python model/src/train.py` | The **main** model from 103 hand-crafted URL features (Random Forest) | No (data is included) | ~385 MB |
| `python model/src/train_url_text_model.py` | The "URL wording" model (TF-IDF + Logistic Regression) | **Yes** — it downloads live phishing feeds first | ~6 MB |
| `python model/src/train_email_text_model.py` | The "email wording" model | No (data is included) | ~4.5 MB |

You will know each one finished because it prints a line like
`Saved phishing_model.joblib + features.txt`.

The new files appear in the `model/trained/` folder. They are automatically
ignored by Git, so they will never be accidentally uploaded.

### Optional: refresh the website lists

The scanner uses two lists: a top-1-million legitimate domains list and a list
of known phishing sites. The included copies work fine, but you can refresh them
any time (requires internet):

```
python model/src/update_lists.py
```

### What if the URL-text model can't download (no internet)?

Don't worry — the server still starts. When `url_text_model.joblib` is missing,
that one signal is skipped silently and the rest of the scanner keeps working.
If the **main** model (`phishing_model.joblib`) is missing, the server will not
start, so make sure `train.py` completed.

---

## 5. Start the backend server

With `(venv)` active, run:

```
python backend/server.py
```

After a few seconds (the model takes a moment to load into memory) you should
see Flask's startup message ending in:

```
 * Running on http://127.0.0.1:3000 (Press CTRL+C to quit)
```

**Do not close this terminal window** — the server must keep running while you
use the app. (To stop it later, press **Ctrl+C** in that window.)

To double-check the server is alive, open a web browser and visit:

```
http://localhost:3000/api/minigame/leaderboard
```

You should see a small JSON page like `{"leaderboard": {...}}`. If that page
loads, the backend is healthy.

> **Why localhost:3000?** The server deliberately listens only on
> `127.0.0.1` (your own computer), so no one else on the network can reach it.
> The web app talks to this address.

---

## 6. Open the web app in your browser

The app itself is a normal web page. The easiest way to view it is to serve it
with Python's built-in web server. Open a **second** terminal window, go into
the frontend folder, and start it:

```
cd phisdetect/frontend
python -m http.server 8000
```

Now open your browser and go to:

```
http://localhost:8000
```

You should see the PhisDetect home page. Keep both terminals running (one for
the backend on port 3000, one for the frontend on port 8000).

> **Why two servers?** The Python code (the "backend") does the scanning. The
> web page (the "frontend") is the interface. The frontend calls the backend at
> `http://localhost:3000` automatically — that address is written into the
> frontend's code, so keep both on the same computer.

---

## 7. How to use it

### Scanning a URL

1. On the home page, find the **URL scanner** box.
2. Paste or type a web address you are allowed to test. A safe first try is
   `https://example.com` — the reserved test domain — which should come back
   **Safe**.
3. To see a suspicious-looking result without ever contacting a real phishing
   site, test something like `http://paypal-account.verify-now.invalid/login` —
   `.invalid` is a reserved test suffix, so no real site exists behind it.
4. Click **Scan**.
5. Wait a few seconds (the scanner checks the domain, blacklists, and the page
   content — first scan is always slowest). You get a verdict:

   | Verdict | Meaning |
   |---------|---------|
   | **Safe** | Looks legitimate |
   | **Suspicious** | Some warning signs, worth double-checking |
   | **Threat** | Strong signs of phishing — do **not** enter any details |
   | **Critical** | Nearly certain phishing — treat as dangerous |

   Below the verdict you'll see the reasons (e.g. a suspicious keyword in the
   domain name, a look-alike domain, an IP address instead of a name, the
   domain being very new, etc.).

### Scanning a QR code (camera)

1. Open the **QR Scanner** page.
2. Your browser asks for camera permission — allow it.
3. Point the camera at a QR code. PhisDetect decodes it and scans the URL inside
   automatically.

> No camera? Just copy the URL out of the QR code and use the URL scanner.

### Scanning an email

1. Open the **Email Scanner** page.
2. Paste the email's subject and body text into the box (the text of the
   message, not the file itself).
3. Click **Scan**. The tool analyses the wording, embedded links, sender-auth
   hints and grammar to rate the email.

### Other pages

- **Dashboard** — a summary of your recent scans.
- **Profile** — your settings and history.
- **Minigames** — fun training games (Spot the Phish, Link Dismantler, Threat
  Hunt) with a leaderboard. Scores are saved by the backend on your computer in
  `backend/data/minigame_scores.json`.

### A note about internet access

For the most accurate results the scanner talks to live services at scan time:
DNS lookups, DNS blacklists, WHOIS (domain age), and the LanguageTool grammar
service. If your computer is offline, those signals are skipped and the tool
falls back to weaker heuristic-only detection — it still works, just less
precisely.

> **Responsible use:** this is a security tool. Scan only addresses and emails
> you are allowed to inspect.

---

## 8. Troubleshooting

| Problem | Likely cause | Fix |
|---------|--------------|-----|
| `'python' is not recognized` / `command not found` | Python not installed or not in PATH | Install Python 3.14 and re-open the terminal |
| `(venv)` is missing from the prompt | Environment not activated | Run the activation command from Step 2 |
| `python -m pip install` fails | Package or Python version problem | Make sure you have Python 3.14, then retry `python -m pip install -r model/requirements.txt` |
| Server crashes with `No such file or directory` mentioning `phishing_model.joblib` | You skipped or aborted `train.py` | Run `python model/src/train.py` and wait for the "Saved" message |
| `url_text_model.joblib` was not created | That training script needs internet | Re-run `python model/src/train_url_text_model.py` with internet, or continue without it (feature is skipped) |
| `http://localhost:3000/...` page won't load | Backend not running | Go to the backend terminal and confirm the `Running on http://127.0.0.1:3000` line |
| Scan says the backend is unreachable | Backend stopped, or frontend not on the same machine | Restart `python backend/server.py`; both servers must run on the same computer |
| Port 3000 / 8000 already in use | Another program is using the port | Close the other program, or use a different port for the frontend (`python -m http.server 9000` and open `http://localhost:9000`) |
| Camera doesn't start for QR | Permission blocked or no camera | Click the camera icon in the address bar and allow it; or paste the URL instead |
| First scan feels very slow | DNS/WHOIS lookups take a few seconds | Be patient; later scans are faster |
| Something says "X is missing" | You deleted a required file | Do not delete `model/requirements.txt`, `model/trained/features.txt`, or anything under `model/trained/` after training |

---

## 9. Updating to a newer version

- If you **cloned** with Git: run `git pull` inside the `phisdetect` folder.
- If you used the **ZIP**: download the new ZIP and unzip it over the old files.

Your trained models and `venv` are not stored in Git, so an update will not
overwrite them — you normally do **not** need to retrain. You may need to
re-run `python -m pip install -r model/requirements.txt` if new packages were added.

---

## 10. Quick reference (all commands)

```
# One-time setup
python -m venv venv
source venv/bin/activate            # Windows: venv\Scripts\activate
python -m pip install -r model/requirements.txt
python model/src/train.py
python model/src/train_url_text_model.py
python model/src/train_email_text_model.py

# Every time you want to use it (two terminals)
source venv/bin/activate            # Windows: venv\Scripts\activate
python backend/server.py            # terminal 1 — keep running

cd frontend
python -m http.server 8000          # terminal 2 — keep running

# Then open http://localhost:8000 in your browser
```
