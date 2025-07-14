import re
from datetime import datetime

AUTH_LOG = "sample_auth.log"
THRESHOLD = 5
output = []
suspicious_ips = {}

def analyze_logs():
    with open(AUTH_LOG, "r") as f:
        lines = f.readlines()

    for line in lines:
        if "Failed password" in line:
            ip_match = re.search(r"from (\d+\.\d+\.\d+\.\d+)", line)
            if ip_match:
                ip = ip_match.group(1)
                suspicious_ips[ip] = suspicious_ips.get(ip, 0) + 1

        if "session opened for user root" in line:
            output.append(f"[ROOT LOGIN] {line.strip()}")

    # Check IPs with too many failures
    for ip, count in suspicious_ips.items():
        if count >= THRESHOLD:
            output.append(f"[SUSPICIOUS] {ip} had {count} failed attempts")

def save_report():
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open("output_report.txt", "w") as report:
        report.write(f"--- Intrusion Report ({now}) ---\n")
        for entry in output:
            report.write(entry + "\n")

    with open("suspicious_ips.txt", "w") as sfile:
        for ip in suspicious_ips:
            if suspicious_ips[ip] >= THRESHOLD:
                sfile.write(ip + "\n")

if __name__ == "__main__":
    analyze_logs()
    save_report()
    print("[+] Analysis complete. Check output_report.txt")
