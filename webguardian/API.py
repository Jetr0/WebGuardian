from __future__ import annotations

import json
import os
import re
import subprocess
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Set

from flask import Flask, jsonify, request, abort
from flask_cors import CORS

###############################################################################
# Configuración                                                                 
###############################################################################
APP_PORT             = 5000
LOG_FILE             = "/var/log/apache2/access.log"   # ajustar si es otro
WHITELIST_FILE       = "/etc/webguardian/whitelist.json"
BLOCKED_FILE         = "/etc/webguardian/blocked_ips.json"  # persistencia opcional
TAIL_LINES_LOGS      = 400

IPTABLES_CMD         = "/sbin/iptables"  # ruta absoluta por seguridad

attack_regexps = [
    re.compile(p, re.I) for p in [
        r"(?:\b(?:UNION|SELECT|INSERT|UPDATE|DELETE)[^\n]{1,200})",  # SQLi basico
        r"<script[^>]*>.*?</script>",                                 # XSS
        r"\b/etc/passwd\b",                                         # LFI hints
        r"\b(\.{2}/)+\b",                                          # directory traversal
    ]
]

###############################################################################
# Utilidades de sistema                                                        
###############################################################################

def _run(cmd: List[str]) -> subprocess.CompletedProcess:
    """Ejecuta un comando y devuelve el CompletedProcess, lanza excepción si falla."""
    return subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)


def _iptables_op(action: str, ip: str) -> None:
    """Inserta (-I) o elimina (-D) una regla DROP para la IP."""
    assert action in ("-I", "-D"), "acción iptables desconocida"
    try:
        _run([IPTABLES_CMD, action, "INPUT", "-s", ip, "-j", "DROP"])
    except subprocess.CalledProcessError as ex:
        # La regla ya existe o no existe; lo ignoramos
        pass

###############################################################################
# Estado global / persistencia                                                 
###############################################################################

def _load_json(path: str, default):
    try:
        with open(path) as f:
            return json.load(f)
    except FileNotFoundError:
        return default

def _save_json(path: str, data) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    tmp = f"{path}.tmp"
    with open(tmp, "w") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp, path)

whitelist: Set[str] = set(_load_json(WHITELIST_FILE, []))
blocked_ips: Set[str] = set(_load_json(BLOCKED_FILE, []))

stats: Dict[str, int | Dict[str, int] | str] = {
    "total_requests": 0,
    "blocked_requests": 0,
    "blocked_ips": len(blocked_ips),
    "last_request": "",
    "attacks_by_type": {
        "SQLi": 0,
        "XSS": 0,
        "LFI": 0,
        "Traversal": 0,
    },
}

attack_labels = ["SQLi", "XSS", "LFI", "Traversal"]

###############################################################################
# Flask                                                                        
###############################################################################

app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "*"}})

###############################################################################
# Funciones núcleo                                                             
###############################################################################

def _detect_attack(payload: str) -> str | None:
    for label, regex in zip(attack_labels, attack_regexps):
        if regex.search(payload):
            return label
    return None


def _block_ip(ip: str):
    if ip in whitelist:
        return  # nunca bloquear whitelisted
    if ip not in blocked_ips:
        _iptables_op("-I", ip)
        blocked_ips.add(ip)
        stats["blocked_ips"] = len(blocked_ips)
        _save_json(BLOCKED_FILE, list(blocked_ips))


def _unblock_ip(ip: str):
    if ip in blocked_ips:
        _iptables_op("-D", ip)
        blocked_ips.discard(ip)
        stats["blocked_ips"] = len(blocked_ips)
        _save_json(BLOCKED_FILE, list(blocked_ips))


def _add_whitelist(ip: str):
    whitelist.add(ip)
    _save_json(WHITELIST_FILE, list(whitelist))
    # por si acaso estaba bloqueada, la quitamos
    _unblock_ip(ip)


def _remove_whitelist(ip: str):
    whitelist.discard(ip)
    _save_json(WHITELIST_FILE, list(whitelist))

###############################################################################
# Middleware                                                                   
###############################################################################

@app.before_request
def analyse_request():
    ip = request.remote_addr or "0.0.0.0"
    now = datetime.utcnow().isoformat(" ", timespec="seconds")
    stats["total_requests"] += 1
    stats["last_request"] = f"{now} – {ip} – {request.path}"

    # Si IP en blacklist ⇒ 403
    if ip in blocked_ips:
        stats["blocked_requests"] += 1
        abort(403)

    # Payload a inspeccionar
    payload_str = " ".join([
        " ".join([f"{k}={v}" for k, v in request.args.items()]),
        request.get_data(as_text=True) or "",
        " ".join([f"{k}={v}" for k, v in request.form.items()]),
    ])
    if payload_str:
        attack = _detect_attack(payload_str)
        if attack:
            stats["blocked_requests"] += 1
            stats["attacks_by_type"][attack] += 1
            _block_ip(ip)
            abort(403)

###############################################################################
# Rutas API JSON                                                               
###############################################################################

@app.route("/api/stats")
def api_stats():
    return jsonify(stats)


@app.route("/api/logs")
def api_logs():
    if not os.path.exists(LOG_FILE):
        return jsonify([])
    with open(LOG_FILE, "r", encoding="utf-8", errors="ignore") as f:
        lines = f.readlines()[-TAIL_LINES_LOGS:]
    return jsonify(lines)


@app.route("/api/blocked_ips")
def api_blocked_ips():
    return jsonify(sorted(blocked_ips))


@app.route("/api/block/<ip>", methods=["POST", "GET"])
def api_block_ip(ip):
    _block_ip(ip)
    return jsonify({"status": "blocked"})


@app.route("/api/unblock/<ip>", methods=["POST", "GET"])
def api_unblock_ip(ip):
    _unblock_ip(ip)
    return jsonify({"status": "unblocked"})


@app.route("/api/whitelist")
def api_whitelist():
    return jsonify(sorted(whitelist))


@app.route("/api/whitelist/add", methods=["POST"])
def api_whitelist_add():
    ip = request.json.get("ip") if request.is_json else request.form.get("ip")
    if not ip:
        abort(400, "ip required")
    _add_whitelist(ip)
    return jsonify({"status": "added", "ip": ip}), 201

@app.route("/api/whitelist/remove/<ip>", methods=["POST", "GET"])
def api_whitelist_remove(ip):
    _remove_whitelist(ip)
    return jsonify({"status": "removed", "ip": ip})

###############################################################################
# Hilo de monitorización de logs Apache                                        
###############################################################################

def _tail_log():
    """Hilo que monitoriza el log de acceso para detección pasiva de patrones."""
    if not os.path.exists(LOG_FILE):
        return
    with open(LOG_FILE, "r", encoding="utf-8", errors="ignore") as f:
        # Saltar a final del fichero
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue
            # Ejemplo simple: si 403 entonces añadir a stats
            if " 403 " in line:
                stats["blocked_requests"] += 1


def start_background_tasks():
    threading.Thread(target=_tail_log, daemon=True).start()

###############################################################################
# Main                                                                         
###############################################################################

if __name__ == "__main__":
    start_background_tasks()
    app.run(host="0.0.0.0", port=APP_PORT, threaded=True)