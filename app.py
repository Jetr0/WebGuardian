
from flask import Flask, request, jsonify, render_template, redirect
import os, subprocess, re
from datetime import datetime

app = Flask(__name__)

log_dir = "logs"
log_file = os.path.join(log_dir, "api_logs.txt")
blocked_ips_file = os.path.join(log_dir, "blocked_ips.txt")
whitelist_file = os.path.join(log_dir, "whitelist.txt")

SQLI_PAYLOADS = ["'", "--", ";", "' OR '1'='1", "UNION SELECT", "DROP TABLE", "admin'--"]

DEFAULT_WHITELIST = ['127.0.0.1', '0.0.0.0', 'localhost']

stats = {
    'total_requests': 0,
    'blocked_requests': 0,
    'blocked_ips': 0,
    'last_request': None
}

def write_log(message, is_blocked=False):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_type = "BLOQUEADO" if is_blocked else "INFO"
    with open(log_file, "a") as f:
        f.write(f"{timestamp} - {log_type} - {message}\n")

def detect_sqli(text):
    for payload in SQLI_PAYLOADS:
        if payload.lower() in text.lower():
            return True
    return False

def block_ip_permanently(ip):
    if is_ip_whitelisted(ip):
        return False
    cmd = f"sudo iptables -A INPUT -s {ip} -j DROP"
    subprocess.run(cmd, shell=True)
    with open(blocked_ips_file, "a") as f:
        f.write(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - {ip}\n")
    stats['blocked_ips'] += 1
    write_log(f"IP {ip} bloqueada", True)
    return True

def is_ip_whitelisted(ip):
    return ip in load_whitelist()

def load_whitelist():
    wl = DEFAULT_WHITELIST.copy()
    if os.path.exists(whitelist_file):
        with open(whitelist_file, 'r') as f:
            for line in f:
                ip = line.strip()
                if ip not in wl:
                    wl.append(ip)
    return wl

def get_blocked_ips():
    if os.path.exists(blocked_ips_file):
        with open(blocked_ips_file, 'r') as f:
            return f.readlines()
    return []

@app.before_request
def global_filter():
    if request.path.startswith(("/logs", "/whitelist", "/api")) and request.remote_addr != "127.0.0.1":
        return jsonify({"error": "Acceso denegado"}), 403

@app.route("/")
def index():
    stats['total_requests'] += 1
    stats['last_request'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return render_template("index.html", stats=stats, SQLI_PAYLOADS=SQLI_PAYLOADS)

@app.route("/logs")
def view_logs():
    logs = []
    if os.path.exists(log_file):
        with open(log_file) as f:
            logs = f.readlines()[-50:]
    return render_template("logs.html", logs=logs, stats=stats, whitelist=load_whitelist(), blocked_ips=get_blocked_ips(), default_whitelist=DEFAULT_WHITELIST)

@app.route("/whitelist")
def whitelist_view():
    return render_template("whitelist.html", whitelist=load_whitelist(), default_whitelist=DEFAULT_WHITELIST)

@app.route("/api/blocked_ips")
def api_blocked_ips():
    blocked_ips = get_blocked_ips()
    ip_list = []
    for line in blocked_ips:
        match = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", line)
        if match:
            ip_list.append(match.group(1))
    return jsonify(ip_list)

@app.route("/check")
def apache_check():
    uri = request.args.get("uri", "")
    ip = request.args.get("ip", request.remote_addr)
    if detect_sqli(uri):
        block_ip_permanently(ip)
        return jsonify({"error": "Bloqueado"}), 403
    return jsonify({"status": "OK"}), 200

if __name__ == "__main__":
    os.makedirs("logs", exist_ok=True)
    open(log_file, 'a').close()
    open(blocked_ips_file, 'a').close()
    open(whitelist_file, 'a').close()
    app.run(host="127.0.0.1", port=5000, debug=True)
