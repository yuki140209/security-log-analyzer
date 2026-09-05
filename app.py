import os
import re
import time
import csv
import json
import zipfile
import ijson
import smtplib
import random
from email.mime.text import MIMEText
from datetime import datetime
from dotenv import load_dotenv
from flask import Flask, render_template, jsonify, request, redirect, url_for
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash

from log_analyzer import (
    detect_bruteforce,
    detect_compromise,
    detect_unusual_time,
    calculate_severity,
    get_username_for_ip,
    generate_ai_summary,
)
from database import (
    init_db,
    create_user,
    get_user,
    update_user_password,
    add_history_entry,
    get_recent_history,
    get_history_entry_by_position,
    delete_history_entry_by_position,
)

load_dotenv()
init_db()

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "fallback_dev_secret_change_me")
app.config["MAX_CONTENT_LENGTH"] = 200 * 1024 * 1024

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

LIVE_LOG_FILE = "login_activity.log"
IP_PATTERN = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_SECONDS = 60
MAX_RESULT_ROWS = 500
CODE_EXPIRY_SECONDS = 600

GMAIL_ADDRESS = os.getenv("GMAIL_ADDRESS")
GMAIL_APP_PASSWORD = os.getenv("GMAIL_APP_PASSWORD")

login_attempts = {}
reset_codes = {}


def log_login_activity(email, ip, success):
    if not os.path.exists(LIVE_LOG_FILE):
        open(LIVE_LOG_FILE, "w").close()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    status = "SUCCESS" if success else "FAILED"
    line = timestamp + " LOGIN " + status + " user=" + email + " ip=" + ip + "\n"
    with open(LIVE_LOG_FILE, "a") as f:
        f.write(line)


def send_reset_email(to_email, code):
    subject = "Your LotusGuard password reset code"
    body = "Your password reset code is: " + code + "\n\nThis code expires in 10 minutes."
    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = GMAIL_ADDRESS
    msg["To"] = to_email
    with smtplib.SMTP("smtp.gmail.com", 587) as server:
        server.starttls()
        server.login(GMAIL_ADDRESS, GMAIL_APP_PASSWORD)
        server.sendmail(GMAIL_ADDRESS, to_email, msg.as_string())


class User(UserMixin):
    def __init__(self, email):
        self.id = email


@login_manager.user_loader
def load_user(email):
    row = get_user(email)
    if row is not None:
        return User(email)
    return None


def is_locked_out(email):
    record = login_attempts.get(email)
    if record is None:
        return False
    count, last_attempt_time = record
    if count >= MAX_LOGIN_ATTEMPTS and (time.time() - last_attempt_time) < LOCKOUT_SECONDS:
        return True
    return False


def record_failed_attempt(email):
    count, _ = login_attempts.get(email, (0, 0))
    login_attempts[email] = (count + 1, time.time())


def clear_attempts(email):
    if email in login_attempts:
        del login_attempts[email]


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        if not EMAIL_PATTERN.match(email):
            return render_template("signup.html", error="Please enter a valid email address.")
        if len(password) < 8:
            return render_template("signup.html", error="Password must be at least 8 characters long.")
        if get_user(email) is not None:
            return render_template("signup.html", error="An account with this email already exists.")
        create_user(email, generate_password_hash(password))
        user = User(email)
        login_user(user)
        return redirect(url_for("home"))
    return render_template("signup.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        visitor_ip = request.remote_addr or "0.0.0.0"

        if is_locked_out(email):
            log_login_activity(email, visitor_ip, success=False)
            return render_template("login.html", error="Too many failed attempts. Please wait a minute and try again.")

        row = get_user(email)
        if row is None or not check_password_hash(row["password_hash"], password):
            record_failed_attempt(email)
            log_login_activity(email, visitor_ip, success=False)
            return render_template("login.html", error="Invalid email or password.")

        clear_attempts(email)
        log_login_activity(email, visitor_ip, success=True)
        user = User(email)
        login_user(user)
        return redirect(url_for("home"))

    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form.get("email", "").strip()

        if get_user(email) is None:
            return render_template("forgot_password.html", stage="request", error="No account found with that email.")

        code = str(random.randint(100000, 999999))
        reset_codes[email] = (code, time.time())

        try:
            send_reset_email(email, code)
        except Exception as e:
            return render_template("forgot_password.html", stage="request", error="Could not send email: " + str(e))

        return render_template("forgot_password.html", stage="reset", email=email)

    return render_template("forgot_password.html", stage="request")


@app.route("/reset-password", methods=["POST"])
def reset_password():
    email = request.form.get("email", "").strip()
    code = request.form.get("code", "").strip()
    new_password = request.form.get("new_password", "")

    record = reset_codes.get(email)
    if record is None:
        return render_template("forgot_password.html", stage="request", error="Reset session expired. Please request a new code.")

    correct_code, sent_time = record
    if time.time() - sent_time > CODE_EXPIRY_SECONDS:
        del reset_codes[email]
        return render_template("forgot_password.html", stage="request", error="Code expired. Please request a new one.")

    if code != correct_code:
        return render_template("forgot_password.html", stage="reset", email=email, error="Incorrect code.")

    if len(new_password) < 8:
        return render_template("forgot_password.html", stage="reset", email=email, error="Password must be at least 8 characters.")

    update_user_password(email, generate_password_hash(new_password))
    del reset_codes[email]

    return redirect(url_for("login"))


def stream_txt_lines(filepath):
    with open(filepath, "r", errors="ignore") as f:
        for line in f:
            yield line.strip()


def analyze_txt_file(filepath):
    failed_attempts = {}
    compromise_alerts = []
    unusual_time_entries = []
    all_lines_sample = []
    suspicious_ips = set()

    for line in stream_txt_lines(filepath):
        if len(all_lines_sample) < 20000:
            all_lines_sample.append(line)
        if "LOGIN FAILED" in line:
            parts = line.split()
            ip = parts[-1].replace("ip=", "")
            failed_attempts[ip] = failed_attempts.get(ip, 0) + 1
            if failed_attempts[ip] >= 3:
                suspicious_ips.add(ip)

    for line in stream_txt_lines(filepath):
        if "LOGIN SUCCESS" in line:
            parts = line.split()
            ip = parts[-1].replace("ip=", "")
            if ip in suspicious_ips:
                compromise_alerts.append(line)

    for line in stream_txt_lines(filepath):
        parts = line.split()
        if len(parts) >= 2:
            try:
                timestamp = datetime.strptime(parts[0] + " " + parts[1], "%Y-%m-%d %H:%M:%S")
                if timestamp.hour < 6 or timestamp.hour >= 22:
                    unusual_time_entries.append(line)
            except ValueError:
                pass

    results = []
    for ip, count in failed_attempts.items():
        username = get_username_for_ip(all_lines_sample, ip)
        is_suspicious = ip in suspicious_ips
        has_compromise = any(ip in alert for alert in compromise_alerts)
        has_unusual = any(ip in entry for entry in unusual_time_entries)
        score = (1 if is_suspicious else 0) + (2 if has_compromise else 0) + (1 if has_unusual else 0)
        severity = "HIGH" if score >= 3 else "MEDIUM" if score == 2 else "LOW" if score == 1 else "INFO"
        results.append({"ip": ip, "username": username, "count": count, "severity": severity})

    return results


def analyze_json_stream(filepath):
    attempts_by_ip = {}
    usernames = {}
    with open(filepath, "rb") as f:
        for entry in ijson.items(f, "item"):
            ip = entry.get("ip_address", "unknown")
            attempts_by_ip[ip] = attempts_by_ip.get(ip, 0) + 1
            if ip not in usernames:
                usernames[ip] = entry.get("username", "unknown")

    results = []
    for ip, count in attempts_by_ip.items():
        results.append({
            "ip": ip,
            "username": usernames.get(ip, "unknown"),
            "count": count,
            "severity": "HIGH" if count >= 3 else "INFO"
        })
    return results


def analyze_csv_stream(filepath):
    ip_column = None
    user_column = None
    attempts_by_ip = {}
    usernames = {}

    with open(filepath, "r", newline="", errors="ignore") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if ip_column is None:
                for h in row.keys():
                    h_lower = h.lower()
                    if "ip" in h_lower:
                        ip_column = h
                    if "user" in h_lower or "name" in h_lower:
                        user_column = h
            ip = row.get(ip_column, "unknown") if ip_column else "unknown"
            attempts_by_ip[ip] = attempts_by_ip.get(ip, 0) + 1
            if user_column and ip not in usernames:
                usernames[ip] = row.get(user_column, "unknown")

    results = []
    for ip, count in attempts_by_ip.items():
        results.append({
            "ip": ip,
            "username": usernames.get(ip, "unknown"),
            "count": count,
            "severity": "HIGH" if count >= 3 else "INFO"
        })
    return results


def analyze_generic_stream(filepath):
    attempts_by_ip = {}
    with open(filepath, "r", errors="ignore") as f:
        for line in f:
            for ip in IP_PATTERN.findall(line):
                attempts_by_ip[ip] = attempts_by_ip.get(ip, 0) + 1

    results = []
    for ip, count in attempts_by_ip.items():
        results.append({
            "ip": ip,
            "username": "unknown",
            "count": count,
            "severity": "HIGH" if count >= 3 else "INFO"
        })
    return results


def peek_file_looks_like_logs(filepath):
    with open(filepath, "r", errors="ignore") as f:
        for _ in range(50):
            line = f.readline()
            if not line:
                break
            if "LOGIN FAILED" in line or "LOGIN SUCCESS" in line:
                return True
    return False


def analyze_single_file(filepath, filename):
    if filename.endswith(".json"):
        return analyze_json_stream(filepath)
    elif filename.endswith(".csv"):
        return analyze_csv_stream(filepath)
    elif filename.endswith(".txt") or filename.endswith(".log"):
        if peek_file_looks_like_logs(filepath):
            return analyze_txt_file(filepath)
        else:
            return analyze_generic_stream(filepath)
    else:
        return analyze_generic_stream(filepath)


@app.errorhandler(413)
def file_too_large(e):
    return jsonify({"error": "File is too large. Please upload a file under 200MB."}), 413


@app.route("/")
@login_required
def home():
    rows = get_recent_history(current_user.id, limit=5)
    history = []
    for row in rows:
        history.append({
            "filename": row["filename"],
            "total_ips": row["total_ips"],
            "high_severity_count": row["high_severity_count"],
            "timestamp": row["timestamp"]
        })
    return render_template("index.html", user_email=current_user.id, history=history)


@app.route("/upload-analysis", methods=["POST"])
@login_required
def upload_analysis():
    uploaded_file = request.files.get("logfile")
    if uploaded_file is None or uploaded_file.filename == "":
        return jsonify({"error": "No file selected"}), 400

    filename = uploaded_file.filename
    save_path = os.path.join(UPLOAD_FOLDER, filename)
    uploaded_file.save(save_path)

    results = []
    try:
        if filename.endswith(".zip"):
            extract_folder = os.path.join(UPLOAD_FOLDER, "extracted_" + filename.replace(".zip", ""))
            os.makedirs(extract_folder, exist_ok=True)
            with zipfile.ZipFile(save_path, "r") as zip_ref:
                zip_ref.extractall(extract_folder)
            for inner_filename in os.listdir(extract_folder):
                inner_path = os.path.join(extract_folder, inner_filename)
                if os.path.isfile(inner_path):
                    results.extend(analyze_single_file(inner_path, inner_filename))
        else:
            results = analyze_single_file(save_path, filename)
    except Exception as e:
        return jsonify({"error": "Could not process this file: " + str(e)}), 400

    merged = {}
    for item in results:
        ip = item["ip"]
        if ip in merged:
            merged[ip]["count"] += item["count"]
            if item["severity"] == "HIGH":
                merged[ip]["severity"] = "HIGH"
        else:
            merged[ip] = item

    final_results = list(merged.values())
    final_results.sort(key=lambda x: x["count"], reverse=True)

    summary_lines = []
    summary_lines.append("Total unique IPs: " + str(len(final_results)))
    high_ips = [r for r in final_results if r["severity"] == "HIGH"]
    summary_lines.append("High severity IPs: " + str(len(high_ips)))
    for r in final_results[:20]:
        summary_lines.append("IP " + r["ip"] + " (" + r["username"] + "): " + str(r["count"]) + " attempts, " + r["severity"] + " severity")
    findings_text = "\n".join(summary_lines)

    try:
        ai_summary = generate_ai_summary(findings_text)
    except Exception as e:
        ai_summary = "AI summary unavailable: " + str(e)

    high_count = len(high_ips)
    limited_results = final_results[:MAX_RESULT_ROWS]

    add_history_entry(
        user_email=current_user.id,
        filename=filename,
        total_ips=len(final_results),
        high_severity_count=high_count,
        timestamp=time.strftime("%Y-%m-%d %H:%M:%S"),
        results=limited_results,
        ai_summary=ai_summary
    )

    return jsonify({
        "results": limited_results,
        "total_entries": len(final_results),
        "truncated": len(final_results) > MAX_RESULT_ROWS,
        "ai_summary": ai_summary
    })


@app.route("/view-history/<int:index>")
@login_required
def view_history(index):
    row = get_history_entry_by_position(current_user.id, index)
    if row is None:
        return jsonify({"error": "History entry not found"}), 404
    return jsonify({
        "results": json.loads(row["results_json"]),
        "total_entries": row["total_ips"],
        "ai_summary": row["ai_summary"]
    })


@app.route("/delete-history/<int:index>", methods=["POST"])
@login_required
def delete_history(index):
    success = delete_history_entry_by_position(current_user.id, index)
    if not success:
        return jsonify({"error": "History entry not found"}), 404
    return jsonify({"success": True})


@app.route("/live-monitor")
@login_required
def live_monitor():
    if not os.path.exists(LIVE_LOG_FILE) or os.path.getsize(LIVE_LOG_FILE) == 0:
        return jsonify({"results": [], "total_entries": 0, "message": "No login activity recorded yet."})
    results = analyze_txt_file(LIVE_LOG_FILE)
    results.sort(key=lambda x: x["count"], reverse=True)
    return jsonify({"results": results, "total_entries": len(results)})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)