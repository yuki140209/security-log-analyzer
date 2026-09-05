from datetime import datetime


def load_logs(filename):
    with open(filename, "r") as file:
        lines = file.readlines()
    return [line.strip() for line in lines]


def detect_bruteforce(lines, threshold=3):
    failed_attempts = {}
    for line in lines:
        if "LOGIN FAILED" in line:
            parts = line.split()
            ip = parts[-1].replace("ip=", "")
            failed_attempts[ip] = failed_attempts.get(ip, 0) + 1
    suspicious_ips = {ip: count for ip, count in failed_attempts.items() if count >= threshold}
    return failed_attempts, suspicious_ips


def detect_compromise(lines, suspicious_ips):
    alerts = []
    for line in lines:
        if "LOGIN SUCCESS" in line:
            parts = line.split()
            ip = parts[-1].replace("ip=", "")
            if ip in suspicious_ips:
                alerts.append(line)
    return alerts


def detect_unusual_time(lines, start_hour=6, end_hour=22):
    unusual = []
    for line in lines:
        parts = line.split()
        date_str, time_str = parts[0], parts[1]
        timestamp = datetime.strptime(date_str + " " + time_str, "%Y-%m-%d %H:%M:%S")
        if timestamp.hour < start_hour or timestamp.hour >= end_hour:
            unusual.append(line)
    return unusual


def detect_dormant_sessions(lines):
    dormant = []
    for i, line in enumerate(lines):
        if "LOGIN SUCCESS" in line:
            parts = line.split()
            user = None
            for part in parts:
                if part.startswith("user="):
                    user = part.replace("user=", "")

            followed_up = False
            for later_line in lines[i + 1:]:
                if user is not None and "user=" + user in later_line:
                    followed_up = True
                    break

            if not followed_up:
                dormant.append(line)

    return dormant


def calculate_severity(ip, suspicious_ips, compromise_alerts, unusual_time_entries):
    score = 0
    if ip in suspicious_ips:
        score = score + 1
    if any(ip in alert for alert in compromise_alerts):
        score = score + 2
    if any(ip in entry for entry in unusual_time_entries):
        score = score + 1
    if score >= 3:
        return "HIGH"
    elif score == 2:
        return "MEDIUM"
    elif score == 1:
        return "LOW"
    else:
        return "INFO"


def get_username_for_ip(lines, ip):
    for line in lines:
        if ip in line:
            parts = line.split()
            for part in parts:
                if part.startswith("user="):
                    return part.replace("user=", "")
    return "unknown"


def generate_ai_summary(findings_text):
    from dotenv import load_dotenv
    import os
    from groq import Groq

    load_dotenv()
    client = Groq(api_key=os.getenv("GROQ_API_KEY"))

    system_msg = "You are a cybersecurity analyst assistant. Explain security log findings clearly and briefly for a report, in plain English, for a non-technical manager."
    user_msg = "Here are the security findings:" + "\n\n" + findings_text + "\n\n" + "Write a short 3-5 sentence plain-English summary of what happened and what should be done next."

    response = client.chat.completions.create(
        model="openai/gpt-oss-120b",
        messages=[
            {"role": "system", "content": system_msg},
            {"role": "user", "content": user_msg}
        ]
    )
    return response.choices[0].message.content


def build_findings_text(lines, failed_attempts, suspicious_ips, compromise_alerts, unusual_time_entries, dormant_sessions):
    findings_lines = []
    findings_lines.append("Total log entries analyzed: " + str(len(lines)))

    findings_lines.append("Failed Login Summary:")
    for ip, count in failed_attempts.items():
        findings_lines.append("IP " + ip + ": " + str(count) + " failed attempt(s)")

    findings_lines.append("Suspicious IPs (Possible Brute-Force):")
    for ip, count in suspicious_ips.items():
        findings_lines.append(ip + " had " + str(count) + " failed login attempts")

    findings_lines.append("Compromise Alerts:")
    for alert in compromise_alerts:
        findings_lines.append(alert)

    findings_lines.append("Unusual Time Activity:")
    for entry in unusual_time_entries:
        findings_lines.append(entry)

    findings_lines.append("Dormant Sessions (Login With No Follow-Up Activity):")
    for entry in dormant_sessions:
        findings_lines.append(entry)

    all_ips = set(failed_attempts.keys())
    findings_lines.append("Overall Severity by IP:")
    for ip in all_ips:
        severity = calculate_severity(ip, suspicious_ips, compromise_alerts, unusual_time_entries)
        findings_lines.append("IP " + ip + ": " + severity + " severity")

    return "\n".join(findings_lines)


def generate_report(lines, failed_attempts, suspicious_ips, compromise_alerts, unusual_time_entries, dormant_sessions, filename="report.txt"):
    findings_text = build_findings_text(lines, failed_attempts, suspicious_ips, compromise_alerts, unusual_time_entries, dormant_sessions)

    print("Generating AI summary...")
    ai_summary = generate_ai_summary(findings_text)

    with open(filename, "w") as report:
        report.write("SECURITY LOG ANALYSIS REPORT\n")
        report.write("========================================\n\n")
        report.write(findings_text + "\n\n")
        report.write("=== AI-Generated Summary ===\n")
        report.write(ai_summary + "\n")

    print("Report saved to " + filename)
    print("=== AI Summary ===")
    print(ai_summary)


def main():
    print("Log analyzer starting...")
    lines = load_logs("sample_log.txt")
    print("Loaded " + str(len(lines)) + " log entries.")

    failed_attempts, suspicious_ips = detect_bruteforce(lines)
    compromise_alerts = detect_compromise(lines, suspicious_ips)
    unusual_time_entries = detect_unusual_time(lines)
    dormant_sessions = detect_dormant_sessions(lines)

    print("=== Failed Login Summary ===")
    for ip, count in failed_attempts.items():
        print("IP " + ip + ": " + str(count) + " failed attempt(s)")

    print("=== Suspicious IPs (Possible Brute-Force) ===")
    for ip, count in suspicious_ips.items():
        print(ip + " had " + str(count) + " failed login attempts - possible brute-force")

    print("=== Compromise Check (Success After Brute-Force) ===")
    for alert in compromise_alerts:
        print("ALERT: " + alert)

    print("=== Unusual Time Activity (Outside 6 AM - 10 PM) ===")
    for entry in unusual_time_entries:
        print("Unusual time login: " + entry)

    print("=== Dormant Sessions (Login With No Follow-Up Activity) ===")
    for entry in dormant_sessions:
        print("No follow-up activity after: " + entry)

    print("=== Overall Severity by IP ===")
    all_ips = set(failed_attempts.keys())
    for ip in all_ips:
        severity = calculate_severity(ip, suspicious_ips, compromise_alerts, unusual_time_entries)
        print("IP " + ip + ": " + severity + " severity")

    generate_report(lines, failed_attempts, suspicious_ips, compromise_alerts, unusual_time_entries, dormant_sessions)


if __name__ == "__main__":
    main()