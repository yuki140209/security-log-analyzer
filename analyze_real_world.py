import json
from datetime import datetime


def load_real_world_logs(filename):
    with open(filename, "r") as file:
        data = json.load(file)
    return data


def detect_bruteforce_real(data, threshold=3):
    attempts_by_ip = {}
    for entry in data:
        ip = entry["ip_address"]
        attempts_by_ip[ip] = attempts_by_ip.get(ip, 0) + 1

    suspicious_ips = {ip: count for ip, count in attempts_by_ip.items() if count >= threshold}
    return attempts_by_ip, suspicious_ips


def get_username_for_ip_real(data, ip):
    for entry in data:
        if entry.get("ip_address") == ip:
            return entry.get("username", "unknown")
    return "unknown"


def main():
    print("Loading real-world Kaggle dataset (Windows RDP brute-force logs)...")
    data = load_real_world_logs("real_world_log.json")
    print("Loaded " + str(len(data)) + " intercepted attempt records.")

    attempts_by_ip, suspicious_ips = detect_bruteforce_real(data)

    print("")
    print("=== Top Attacking IPs (Real-World Data) ===")
    sorted_ips = sorted(attempts_by_ip.items(), key=lambda x: x[1], reverse=True)
    for ip, count in sorted_ips[:10]:
        print("IP " + ip + ": " + str(count) + " attempts")

    print("")
    print("=== Suspicious IPs (3+ attempts) ===")
    for ip, count in suspicious_ips.items():
        print("IP " + ip + " flagged with " + str(count) + " brute-force attempts")

    print("")
    print("Total unique attacking IPs: " + str(len(attempts_by_ip)))
    print("Total flagged as suspicious: " + str(len(suspicious_ips)))


if __name__ == "__main__":
    main()