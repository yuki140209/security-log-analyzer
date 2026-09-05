# 🪷 LotusGuard — Security Log Analyzer

**Live demo:** https://lotusguard.onrender.com
**Repo:** https://github.com/yuki140209/security-log-analyzer

LotusGuard is a full-stack security log analysis tool that detects brute-force attacks, compromised accounts, and unusual login activity from log files — with an AI-generated plain-English summary of the findings. Built as a hands-on portfolio project to demonstrate core cybersecurity analyst concepts: log parsing, indicator-of-compromise detection, severity triage, and secure application design.

> ⚠️ **This is a demonstration/learning project, not a production security product.** Only test/synthetic data or files you own should be uploaded — never real production credentials or sensitive company logs. See [Limitations](#limitations--future-improvements) below.

---

## 🔍 What it does

- Parses login/activity logs in `.txt`, `.log`, `.json`, `.csv`, or `.zip` format
- Detects:
  - **Brute-force patterns** — repeated failed logins from the same IP
  - **Account compromise** — a successful login from an IP that was previously flagged for brute-force
  - **Unusual-time activity** — logins outside typical business hours
  - **Dormant sessions** — successful logins with no follow-up activity
- Assigns a **severity score** (INFO / LOW / MEDIUM / HIGH) per IP based on combined signals
- Generates a **plain-English AI summary** of findings (via Groq's LLM API) for non-technical stakeholders
- Lets logged-in users **upload their own files**, view results, and revisit or delete past analyses
- Includes a **Live Login Monitor** that analyzes the app's own real authentication log on demand
- Validated against a **real-world Kaggle brute-force dataset** (651 unique attacking IPs, 497 flagged suspicious) in addition to synthetic test data

## 🏗️ Architecture

- **Backend:** Python (Flask)
- **Detection engine:** rule-based, pure Python (`log_analyzer.py`) — no external ML/security library, so every detection is fully explainable
- **AI layer:** Groq API (`openai/gpt-oss-120b`) turns structured findings into a short plain-English summary
- **Database:** SQLite (`database.py`) — stores user accounts (hashed passwords) and per-user analysis history; migrated from an earlier flat-file (JSON) prototype
- **Auth:** Flask-Login with password hashing (Werkzeug), login rate-limiting/lockout, and email-based password reset (Gmail SMTP with a time-limited 6-digit code)
- **Large-file handling:** files are streamed line-by-line / parsed incrementally (`ijson` for JSON) rather than loaded fully into memory, so multi-hundred-MB files don't crash the app
- **Frontend:** server-rendered HTML/CSS/JS (no framework) — a deliberate choice to keep the whole stack simple and inspectable
- **Deployment:** Render (free tier), served via Gunicorn

## 🧠 Why rule-based detection (not ML)?

Real SOC/SIEM tools (Splunk, Microsoft Sentinel) rely heavily on rule-based detection for exactly the patterns this tool implements — it's predictable, auditable, and doesn't require training data. This project deliberately does **not** claim to do machine-learning-based anomaly detection or "detect novel/unknown attacks" — that's a distinct, much larger problem (behavioral baselining, ML models) that would need substantially more data and complexity than a demo project like this can honestly support. A more sophisticated version of this tool would layer statistical anomaly detection on top of these rules — noted below as a future improvement.

## 📊 Real-world validation

In addition to hand-built synthetic test logs, the brute-force detector was run against a public Kaggle dataset of intercepted Windows RDP brute-force attempts (651 unique attacking IPs), correctly flagging 497 of them (~76%) as suspicious under the 3-attempt threshold — a sanity check that the detection logic generalizes beyond hand-picked examples.

## 🔐 Security design choices

- Passwords are hashed (never stored in plaintext) using Werkzeug's `generate_password_hash`
- Login attempts are rate-limited (5 attempts → 60-second lockout per email) — a small full-circle touch, since the tool itself detects this exact brute-force pattern
- Secrets (API keys, Gmail credentials, Flask secret key) are stored in environment variables, never committed to source control
- A sensitive file (an early flat-file user store) that had been accidentally committed was later scrubbed from the entire git history using `git-filter-repo`, and exposed API keys were rotated

## ⚠️ Limitations & future improvements

Being upfront about these is part of understanding the tool, not a weakness:

- **Free-tier hosting constraints:** deployed on Render's free tier (shared CPU, 512MB RAM, spins down when idle). Large file uploads (50–100MB+) or concurrent users could be slow or hit memory limits — a production deployment would need a paid tier and background job processing for large files.
- **"Live monitor" is refresh-based, not real-time push:** it re-reads the login activity log on demand when you click refresh, not via WebSockets/live streaming. A true real-time version would use something like Server-Sent Events or WebSockets.
- **Rule-based only:** thresholds (e.g., "3 failed attempts," "outside 6am–10pm") are simplified and static. Real systems tune these per-environment and often add statistical/ML-based anomaly detection on top — a natural next step for this project.
- **Single-server SQLite:** fine for a personal/demo deployment; a multi-instance production deployment would need a networked database (e.g., PostgreSQL).
- **Not intended for real sensitive data:** as a portfolio/demo project, it hasn't been through a security audit and shouldn't be used with real production credentials or logs.

## 🛠️ Tech stack

Python · Flask · Flask-Login · SQLite · Groq API (LLM) · ijson · Gunicorn · Render · HTML/CSS/JS

## 🚀 Running it locally

```bash
pip install -r requirements.txt
python migrate.py   # one-time: sets up the SQLite database
python app.py
```

Requires a `.env` file with `GROQ_API_KEY`, `GMAIL_ADDRESS`, `GMAIL_APP_PASSWORD`, and `FLASK_SECRET_KEY`.

## 📄 License

All rights reserved — see [LICENSE](./LICENSE). Viewing this repository does not grant permission to reuse, copy, or redistribute any part of it.
