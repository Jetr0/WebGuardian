from flask import Flask, request, jsonify, render_template, redirect
import os
import subprocess
import re
from datetime import datetime

app = Flask(__name__)

# Crear directorio para logs
log_dir = "logs"
if not os.path.exists(log_dir):
    os.makedirs(log_dir)

# Archivos de configuracion
log_file = os.path.join(log_dir, "api_logs.txt")
blocked_ips_file = os.path.join(log_dir, "blocked_ips.txt")
whitelist_file = os.path.join(log_dir, "whitelist.txt")

# Lista ampliada de payloads SQLi de PayloadsAllTheThings
SQLI_PAYLOADS = [
    # Payloads originales
    "'", "--", ";", "/*", "*/", "OR 1=1", "' OR '1'='1", "\" OR \"1\"=\"1",
    "OR 1=1--", "' OR 'x'='x", "UNION SELECT", "DROP TABLE", "INSERT INTO",
    "DELETE FROM", "UPDATE ", "EXEC ", "SLEEP(", "WAITFOR DELAY", "SELECT *",
    "admin'--", "' OR 1 -- -", "LIKE '%",

    # Payloads adicionales
    "convert(", "cast(", "benchmark(", "substring(", "group_concat",
    "load_file", "outfile", "dumpfile", "mid(", "=1", "1=1", "<>", "><",
    "ORDER BY", "GROUP BY", "HAVING", "LIMIT", "PROCEDURE", "UNION ALL",
    "extractvalue", "updatexml", "version(", "user()", "database()",
    "concat(", "char(", "hex(", "unhex(", "ascii(", "@@version", "@@datadir",
    "information_schema", "sysobjects", "sysusers", "sys.", "msf.", "dbo.",
    "xp_cmdshell", "#", "-- ", "'--", "VARCHAR", "CONCAT", "CHAR(",
    "+AND+", "+OR+", "AND 1=1", "AND 1=2", "AND 1=0", "IF(", "CASE WHEN",
    "UNION ALL SELECT", "pg_sleep", "WAITFOR DELAY", "BENCHMARK",
    "UTL_HTTP", "UTL_INADDR", "INTO OUTFILE", "INTO DUMPFILE"
]

# IPs en whitelist (siempre permitidas)
DEFAULT_WHITELIST = ['127.0.0.1', '0.0.0.0', 'localhost']

# Estad  sticas
stats = {
    'total_requests': 0,
    'blocked_requests': 0,
    'blocked_ips': 0,
    'last_request': None
}

def write_log(message, is_blocked=False):
    """Escribe un mensaje en el archivo de log"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_type = "BLOQUEADO" if is_blocked else "INFO"
    log_entry = f"{timestamp} - {log_type} - {message}\n"

    with open(log_file, "a") as f:
        f.write(log_entry)

def detect_sqli(text):
    """Detecta posibles inyecciones SQL con patrones ampliados"""
    if not text or not isinstance(text, str):
        return False

    # Comprobar coincidencias exactas
    for payload in SQLI_PAYLOADS:
        if payload.lower() in text.lower():
            return True

    # Patrones regulares para detecci  n m  s sofisticada
    patterns = [
        r"(\%27)|(\')|(--)|(\%23)|(#)",
        r"((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))",
        r"(union)[^\n]*(select)",
        r"(exec)[^\n]*(xp_cmdshell)",
        r"(load_file|benchmark|sleep)",
    ]

    for pattern in patterns:
        if re.search(pattern, text, re.IGNORECASE):
            return True

    return False

def load_whitelist():
    """Carga la lista de IPs permitidas desde el archivo whitelist.txt"""
    whitelist = DEFAULT_WHITELIST.copy()
    if os.path.exists(whitelist_file):
        with open(whitelist_file, 'r') as f:
            for line in f:
                ip = line.strip()
                if ip and ip not in whitelist:
                    whitelist.append(ip)
    return whitelist

def add_to_whitelist(ip):
    """A  ade una IP a la whitelist"""
    whitelist = load_whitelist()
    if ip not in whitelist:
        with open(whitelist_file, 'a') as f:
            f.write(f"{ip}\n")
        write_log(f"IP {ip} a  adida a la whitelist")
        return True
    return False

def remove_from_whitelist(ip):
    """Elimina una IP de la whitelist"""
    if ip in DEFAULT_WHITELIST:
        return False

    whitelist = load_whitelist()
    if ip in whitelist and ip not in DEFAULT_WHITELIST:
        whitelist.remove(ip)
        with open(whitelist_file, 'w') as f:
            for whitelisted_ip in whitelist:
                if whitelisted_ip not in DEFAULT_WHITELIST:
                    f.write(f"{whitelisted_ip}\n")
        write_log(f"IP {ip} eliminada de la whitelist")
        return True
    return False

def is_ip_whitelisted(ip):
    """Verifica si una IP est   en la whitelist"""
    whitelist = load_whitelist()
    return ip in whitelist

def block_ip_permanently(ip):
    """Bloquea una IP permanentemente usando iptables"""
    try:
        # No bloquear IPs en whitelist
        if is_ip_whitelisted(ip):
            write_log(f"Intento de bloqueo ignorado: IP {ip} est   en whitelist")
            return False

        # Verificar si la IP ya est   bloqueada
        check_cmd = f"sudo iptables -L INPUT -v -n | grep {ip}"
        result = subprocess.run(check_cmd, shell=True, capture_output=True, text=True)

        if ip in result.stdout:
            write_log(f"IP {ip} ya est   bloqueada permanentemente")
            return True

        # Bloquear la IP de forma permanente
        block_cmd = f"sudo iptables -A INPUT -s {ip} -j DROP"
        subprocess.run(block_cmd, shell=True, check=True)

        # Guardar reglas para que persistan tras reinicios (puede requerir configuraci  n adicional en Kali)
        try:
            save_cmd = "sudo iptables-save > /etc/iptables/rules.v4"
            subprocess.run(save_cmd, shell=True, check=True)
        except Exception as e:
            write_log(f"Aviso: No se pudieron guardar las reglas iptables permanentemente: {str(e)}")

        # Registrar la IP bloqueada
        with open(blocked_ips_file, "a") as f:
            f.write(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - {ip}\n")

        stats['blocked_ips'] += 1
        write_log(f"IP {ip} bloqueada permanentemente con iptables")
        return True
    except Exception as e:
        write_log(f"Error al bloquear IP {ip}: {str(e)}")
        return False

def get_blocked_ips():
    """Obtiene la lista de IPs bloqueadas"""
    if os.path.exists(blocked_ips_file):
        with open(blocked_ips_file, "r") as f:
            return f.readlines()
    return []

def is_ip_blocked(ip):
    """Verifica si una IP est   bloqueada en iptables"""
    try:
        check_cmd = f"sudo iptables -L INPUT -v -n | grep {ip}"
        result = subprocess.run(check_cmd, shell=True, capture_output=True, text=True)
        return ip in result.stdout
    except Exception:
        # En caso de error, verificar en el archivo de IPs bloqueadas
        blocked_ips = get_blocked_ips()
        for line in blocked_ips:
            if ip in line:
                return True
        return False
    
# Middleware para filtrar todas las solicitudes
@app.before_request
def check_all_requests():
    """Filtro global para todas las solicitudes"""
    # Ignorar solicitudes a /logs y /whitelist para evitar bloqueos accidentales
    if request.path in ['/logs', '/whitelist', '/unblock']:
        return None

    client_ip = request.remote_addr

    # Verificar si la IP est   en whitelist
    if is_ip_whitelisted(client_ip):
        return None  # Permitir la solicitud

    # Verificar si la IP ya est   bloqueada
    if is_ip_blocked(client_ip):
        stats['blocked_requests'] += 1
        write_log(f"Acceso bloqueado: IP {client_ip} en lista negra")
        return jsonify({"error": "Acceso denegado - IP bloqueada"}), 403

    # Verificar todos los par  metros de URL
    for key, value in request.args.items():
        if detect_sqli(value):
            stats['blocked_requests'] += 1
            write_log(f"SQLi detectado en par  metro URL '{key}': {value} desde {client_ip}", True)
            block_ip_permanently(client_ip)
            return jsonify({"error": "Acceso bloqueado por posible intento de SQL injection"}), 403

    # Verificar formularios o datos JSON
    if request.is_json:
        try:
            data = request.get_json(silent=True)
            if data:
                # Verificar recursivamente todos los valores en el JSON
                if check_json_for_sqli(data, client_ip):
                    return jsonify({"error": "Acceso bloqueado por posible intento de SQL injection"}), 403
        except Exception as e:
            write_log(f"Error al procesar JSON: {str(e)}")

    # Verificar datos de formulario
    if request.form:
        for key, value in request.form.items():
            if detect_sqli(value):
                stats['blocked_requests'] += 1
                write_log(f"SQLi detectado en formulario '{key}': {value} desde {client_ip}", True)
                block_ip_permanently(client_ip)
                return jsonify({"error": "Acceso bloqueado por posible intento de SQL injection"}), 403

    # Si pasa todas las verificaciones, permitir la solicitud
    return None

def check_json_for_sqli(data, client_ip):
    """Verifica recursivamente valores en datos JSON"""
    if isinstance(data, dict):
        for key, value in data.items():
            if isinstance(value, (dict, list)):
                if check_json_for_sqli(value, client_ip):
                    return True
            elif isinstance(value, str) and detect_sqli(value):
                stats['blocked_requests'] += 1
                write_log(f"SQLi detectado en JSON '{key}': {value} desde {client_ip}", True)
                block_ip_permanently(client_ip)
                return True
    elif isinstance(data, list):
        for item in data:
            if check_json_for_sqli(item, client_ip):
                return True
    return False

    def sync_blocked_ips():
        logging.info("Inicializando sincronizaci  n de IPs bloqueadas")

    api_blocked_ips = get_blocked_ips()
    if api_blocked_ips is None:
        logging.error("No se pudieron obtener las IPs bloqueadas de la API")
        return False

    logging.info(f"IPs desde la API: {api_blocked_ips}")

@app.route("/")
def root():
    # Actualizar estad  sticas
    stats['total_requests'] += 1
    stats['last_request'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Registrar solicitud
    write_log(f"Acceso a ruta ra  z desde {request.remote_addr}")

    return render_template("index.html",
        stats=stats,
        SQLI_PAYLOADS=SQLI_PAYLOADS)
    
@app.route("/test/<param>")
def test(param):
    # Actualizar estad  sticas
    stats['total_requests'] += 1
    stats['last_request'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Comprobar inyecci  n en param (aunque el middleware global ya lo comprueba)
    if detect_sqli(param):
        stats['blocked_requests'] += 1
        client_ip = request.remote_addr
        write_log(f"Intento de SQLi bloqueado en param: '{param}' desde {client_ip}", True)

        # Bloquear IP si no est   en whitelist
        if not is_ip_whitelisted(client_ip):
            block_ip_permanently(client_ip)

        return jsonify({"error": "Acceso bloqueado por posible intento de SQL injection"}), 403

    # Si no hay inyecci  n, procesar normalmente
    write_log(f"Par  metro test: '{param}' desde {request.remote_addr}")
    return jsonify({"param": param}), 200

@app.route("/query")
def query_test():
    # Las verificaciones de SQLi se realizan en el middleware global
    # Esta funci  n solo procesa solicitudes leg  timas

    # Actualizar estad  sticas
    stats['total_requests'] += 1
    stats['last_request'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Procesar par  metros
    result = {key: value for key, value in request.args.items()}
    write_log(f"Consulta con par  metros: {result} desde {request.remote_addr}")
    return jsonify(result), 200

@app.route("/logs")
def view_logs():
    # Actualizar estad  sticas
    stats['total_requests'] += 1
    stats['last_request'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Leer logs existentes
    logs = []
    if os.path.exists(log_file):
        with open(log_file, 'r') as f:
            logs = f.readlines()
            logs = logs[-50:] if len(logs) > 50 else logs  # Mostrar   ltimos 50 logs

    # Obtener IPs bloqueadas
    blocked_ips = get_blocked_ips()

    # Obtener whitelist
    whitelist = load_whitelist()

    write_log(f"Vista de logs accedida desde {request.remote_addr}")

    # Renderizar plantilla
    return render_template("logs.html",
                           stats=stats,
                           logs=logs,
                           blocked_ips=blocked_ips,
                           whitelist=whitelist,
                           default_whitelist=DEFAULT_WHITELIST)

@app.route("/unblock/<ip>")
def unblock_ip(ip):
    """Endpoint para desbloquear una IP bloqueada"""
    try:
        # Desbloquear la IP
        unblock_cmd = f"sudo iptables -D INPUT -s {ip} -j DROP"
        subprocess.run(unblock_cmd, shell=True, check=True)

        write_log(f"IP {ip} desbloqueada por {request.remote_addr}")

        # Actualizar archivo de IPs bloqueadas
        if os.path.exists(blocked_ips_file):
            with open(blocked_ips_file, "r") as f:
                lines = f.readlines()

            with open(blocked_ips_file, "w") as f:
                for line in lines:
                    if ip not in line:
                        f.write(line)

        stats['blocked_ips'] -= 1

        # Redirigir a la p  gina de logs
        return redirect('/logs')
    except Exception as e:
        return jsonify({"error": f"Error al desbloquear IP: {str(e)}"}), 500

@app.route("/whitelist")
def whitelist_management():
    """P  gina de gesti  n de la whitelist"""
    # Actualizar estad  sticas
    stats['total_requests'] += 1
    stats['last_request'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Obtener whitelist
    whitelist = load_whitelist()

    write_log(f"Vista de gesti  n de whitelist accedida desde {request.remote_addr}")

    # Renderizar plantilla
    return render_template("whitelist.html",
                          whitelist=whitelist,
                          default_whitelist=DEFAULT_WHITELIST)

@app.route("/whitelist/add", methods=["POST"])
def add_ip_to_whitelist():
    """A  ade una IP a la whitelist"""
    ip = request.form.get("ip", "").strip()

    if not ip:
        return jsonify({"error": "IP no proporcionada"}), 400

    # Validar formato de IP b  sico
    ip_pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
    if not re.match(ip_pattern, ip):
        return jsonify({"error": "Formato de IP inv  lido"}), 400

    result = add_to_whitelist(ip)

    if result:
        write_log(f"IP {ip} a  adida a whitelist por {request.remote_addr}")
        # Desbloquear la IP si estaba bloqueada
        if is_ip_blocked(ip):
            try:
                unblock_cmd = f"sudo iptables -D INPUT -s {ip} -j DROP"
                subprocess.run(unblock_cmd, shell=True, check=True)
                write_log(f"IP {ip} desbloqueada autom  ticamente al a  adirla a whitelist")
            except Exception as e:
                write_log(f"Error al desbloquear IP {ip}: {str(e)}")

    # Redirigir a la p  gina de whitelist
    return redirect('/whitelist')

@app.route("/whitelist/remove/<ip>")
def remove_ip_from_whitelist(ip):
    """Elimina una IP de la whitelist"""
    result = remove_from_whitelist(ip)

    if result:
        write_log(f"IP {ip} eliminada de whitelist por {request.remote_addr}")
    else:
        write_log(f"No se pudo eliminar IP {ip} de whitelist (IP predeterminada o no encontrada)")

    # Redirigir a la p  gina de whitelist
    return redirect('/whitelist')

@app.route("/api/blocked_ips")
def api_blocked_ips():

    blocked_ips = get_blocked_ips()
    ip_list = []

    for line in blocked_ips:
        match = re.search(r'(\d{1,3}(?:\.\d{1,3}){3})', line)
        if match:
            ip_list.append(match.group(0))
    return jsonify(ip_list)

    # Crear directorio de logs si no existe
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)

    # Crear archivos necesarios si no existen
    if not os.path.exists(log_file):
        with open(log_file, 'w') as f:
            f.write(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - INFO - API iniciada\n")

    if not os.path.exists(blocked_ips_file):
        with open(blocked_ips_file, 'w') as f:
            pass

    if not os.path.exists(whitelist_file):
        with open(whitelist_file, 'w') as f:
            for ip in DEFAULT_WHITELIST:
                if ip not in ['127.0.0.1', '0.0.0.0', 'localhost']:
                    f.write(f"{ip}\n")

@app.route("/proxy")
def proxy_pass():
    return redirect("http://localhost/", code=302)



@app.route("/check")
def apache_check():
    uri = request.args.get("uri", "")
    ip = request.args.get("ip", request.remote_addr)
    print(f"[DEBUG] Verificando URI: {uri}")
    if detect_sqli(uri):
        write_log(f"SQLi detectado en Apache URI '{uri}' desde {ip}", True)
        block_ip_permanently(ip)
        return jsonify({"error": "Bloqueado"}), 403

    return jsonify({"status": "OK"}), 200

    # Inicializar estadisticas de IPs bloqueadas
    blocked_ips = get_blocked_ips()
    stats['blocked_ips'] = len(blocked_ips)

    print("=================================================")
    print("  WebGuardian: Proteccion contra SQL Injection   ")
    print("=================================================")
    print(f"- API iniciada en http://0.0.0.0:5000/")
    print(f"- Panel de control: http://0.0.0.0:5000/logs")
    print(f"- Gestion de whitelist: http://0.0.0.0:5000/whitelist")
    print(f"- Deteccion de {len(SQLI_PAYLOADS)} patrones de SQLi")
    print(f"- {len(load_whitelist())} IPs en whitelist")
    print("=================================================")

    # Crear carpeta de templates si no existe
    if not os.path.exists("templates"):
        os.makedirs("templates")

    # Crear carpeta de static si no existe
    if not os.path.exists("static"):
        os.makedirs("static")

    # Iniciar aplicacion
if __name__ == "__main__":
    app.run(host='127.0.0.1', port=5000)

