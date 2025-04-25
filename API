from flask import Flask, request, jsonify, render_template, redirect
import os
import subprocess
import re
import time
import threading
import glob
from datetime import datetime, timedelta

app = Flask(__name__)

# Crear directorio para logs
log_dir = "logs"
if not os.path.exists(log_dir):
    os.makedirs(log_dir)

# Archivos de configuración
log_file = os.path.join(log_dir, "api_logs.txt")
blocked_ips_file = os.path.join(log_dir, "blocked_ips.txt")
whitelist_file = os.path.join(log_dir, "whitelist.txt")

# Configuración de los logs de Apache
APACHE_LOG_DIR = "/var/log/apache2"
APACHE_ACCESS_LOG = os.path.join(APACHE_LOG_DIR, "access.log")
APACHE_ERROR_LOG = os.path.join(APACHE_LOG_DIR, "error.log")

# Patrón para parsear logs de Apache
# Formato común: LogFormat "%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\"" combined
APACHE_LOG_PATTERN = r'^(\S+) \S+ \S+ \[([^:]+):(\d+:\d+:\d+) ([^\]]+)\] "(\S+) (.+?) (\S+)" (\d+) (\S+) "([^"]*)" "([^"]*)"'

# Contador de intentos de ataque por IP
attack_attempts = {}
# Umbral de intentos antes de bloqueo permanente
ATTACK_THRESHOLD = 3
# Tiempo de reset del contador (minutos)
RESET_TIME_MINUTES = 60

# Lista ampliada de payloads para múltiples vectores de ataque
ATTACK_PAYLOADS = {
    # Payloads SQLi originales (mantenidos)
    "sqli": [
        "'", "--", ";", "/*", "*/", "OR 1=1", "' OR '1'='1", "\" OR \"1\"=\"1",
        "OR 1=1--", "' OR 'x'='x", "UNION SELECT", "DROP TABLE", "INSERT INTO",
        "DELETE FROM", "UPDATE ", "EXEC ", "SLEEP(", "WAITFOR DELAY", "SELECT *",
        "admin'--", "' OR 1 -- -", "LIKE '%",
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
    ],
    
    # NUEVOS PAYLOADS - XSS (Cross-Site Scripting)
    "xss": [
        "<script>", "</script>", "<img src=x onerror=", "javascript:", "onload=", 
        "onclick=", "onerror=", "onmouseover=", "onfocus=", "onblur=", 
        "alert(", "String.fromCharCode(", "eval(", "document.cookie", 
        "<svg onload=", "<iframe src=", "<img src=\"javascript:", 
        "\"/><script>", "';alert(", "\"><script>", "\"autofocus onfocus=", 
        "<body onload=", "<details open ontoggle=", "<A HREF=\"javascript:", 
        "&#x", "%3C", "%3E", "<noscript><p title=\"", "><script>"
    ],
    
    # NUEVOS PAYLOADS - Path Traversal y LFI
    "path_traversal": [
        "../", "..\\", "/../", "/..\\", "\\..\\",
        "/etc/passwd", "C:\\Windows\\system.ini", "/proc/self/environ",
        "file:///", "php://filter/", "php://input", "data://",
        "/var/www/", "C:\\inetpub\\", "/WEB-INF/web.xml",
        "....//", "..../\\", "%2e%2e%2f", "%252e%252e%252f",
        "/windows/win.ini", "../../../../", "\\..\\..\\..\\",
        "file://", "expect://", "zip://", "phar://"
    ],
    
    # NUEVOS PAYLOADS - Command Injection
    "cmd_injection": [
        "| ", "& ", "; ", "&&", "||", "`", "$(",
        "$(sleep", "& sleep", "; sleep", "| sleep",
        "ping -c", "ping -n", "whoami", "net user",
        "cat /etc/", "type C:\\", "wget", "curl",
        "nc -e", "bash -i", "cmd.exe", "powershell",
        "> /tmp/", "> C:\\temp\\", "2>&1", "/dev/tcp/",
        "{{\"\".getClass().forName()", "Runtime.getRuntime().exec",
        "Process", "python -c", "perl -e", "ruby -e"
    ],
    
    # NUEVOS PAYLOADS - SSRF (Server-Side Request Forgery)
    "ssrf": [
        "http://localhost", "http://127.0.0.1", "http://[::1]",
        "http://internal-service", "https://169.254.169.254/",
        "http://metadata.google.internal/", "http://169.254.169.254/latest/meta-data/",
        "file:///", "dict://", "gopher://", "ldap://", "tftp://",
        "ftp://", "http://0177.0.0.1", "http://0x7f.0.0.1",
        "http://127.1", "http://127.000.000.001", "http://2130706433"
    ],
    
    # NUEVOS PAYLOADS - Inyección de Cabeceras HTTP
    "header_injection": [
        "Host:", "Content-Length:", "Transfer-Encoding: chunked",
        "Content-Type: application/x-www-form-urlencoded",
        "X-Forwarded-For:", "X-Remote-IP:", "X-Remote-Addr:",
        "X-Originating-IP:", "X-Client-IP:", "CF-Connecting-IP:",
        "True-Client-IP:", "Referer:", "User-Agent:", "Cookie:"
    ],
    
    # NUEVOS PAYLOADS - Inyección NoSQL
    "nosql_injection": [
        "$where:", "$ne:", "$gt:", "$lt:", "$regex:", "$in:",
        "{\"$gt\":", "{\"$ne\":", "{\"$regex\":", "{\"$where\":",
        "true, $where:", "1, $where:", "$or:", "$and:",
        "db.collection.find", "db.getCollectionNames",
        "password", "username", "$exists", "$regex",
        "$where", "sleep(1000)", "1 == 1"
    ]
}

# Para compatibilidad con el código existente
SQLI_PAYLOADS = ATTACK_PAYLOADS["sqli"]

# IPs en whitelist (siempre permitidas)
DEFAULT_WHITELIST = ['127.0.0.1', '0.0.0.0', 'localhost', '10.1.101.52']

# Estadisticas
stats = {
    'total_requests': 0,
    'blocked_requests': 0,
    'blocked_ips': 0,
    'last_request': None,
    'attacks_by_type': {
        'sqli': 0,
        'xss': 0,
        'path_traversal': 0,
        'cmd_injection': 0,
        'ssrf': 0,
        'header_injection': 0,
        'nosql_injection': 0,
        'suspicious': 0
    }
}

def write_log(message, is_blocked=False):
    """Escribe un mensaje en el archivo de log"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_type = "BLOQUEADO" if is_blocked else "INFO"
    log_entry = f"{timestamp} - {log_type} - {message}\n"

    with open(log_file, "a") as f:
        f.write(log_entry)

def detect_attack(text, full_request=None):
    """Detecta posibles ataques con patrones ampliados"""
    if not text or not isinstance(text, str):
        return False, None
    
    # Convertir text a minusculas una vez
    text_lower = text.lower()
    
    attack_patterns = {
        # Ataques de red
        "network_scan": [
            "nmap", "masscan", "zmap", "ping sweep", 
            "port scanning", "network enumeration"
        ],
        
        # Ataques de credenciales
        "credential_attack": [
            "password cracking", "brute force", "hydra", 
            "medusa", "dictionary attack", "login bypass"
        ],
        
        # Ataques de exfiltración
        "data_exfiltration": [
            "data leak", "sensitive info", "exfiltrate", 
            "download sensitive", "extract database"
        ],
        
        # Malware y payloads maliciosos
        "malware_payload": [
            "reverse shell", "meterpreter", "shellcode", 
            "remote access tool", "persistence mechanism"
        ],
        
        # Ataques de escalada de privilegios
        "privilege_escalation": [
            "sudo exploit", "kernel exploit", "root access", 
            "elevation of privilege"
        ]
    }
    
    all_payloads = {**ATTACK_PAYLOADS, **attack_patterns}
    
    # Verificar cada tipo de ataque
    for attack_type, patterns in all_payloads.items():
        for pattern in patterns:
            if isinstance(pattern, str):
                if pattern.lower() in text_lower:
                    return True, attack_type
    
    # Patrones regulares para detección más sofisticada
    regex_patterns = {
        "sqli": [
            r"(\%27)|(\')|(--)|(\%23)|(#)",
            r"((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))",
            r"(union)[^\n]*(select)",
            r"(exec)[^\n]*(xp_cmdshell)",
            r"(load_file|benchmark|sleep)",
        ],
        "xss": [
            r"<[^>]*script.*?>",
            r"<[^>]*on\w+\s*=",
            r"javascript\s*:",
            r"(alert|confirm|prompt)\s*\(",
            r"document\.(cookie|location|write)",
        ],
        "path_traversal": [
            r"(\.\.\/){1,}",
            r"(\.\.\\){1,}",
            r"%2e%2e(%2f|%5c)",
            r"(file|php|data|expect|zip|phar)\s*:",
        ],
        "cmd_injection": [
            r";\s*\w+",
            r"\|\s*\w+",
            r"&&\s*\w+",
            r"\$\([^)]*\)",
            r"`[^`]*`",
        ],
        "ssrf": [
            r"(https?|ftp|dict|ldap|gopher|tftp)://",
            r"(localhost|127\.0\.0\.1|\[::1\])",
            r"169\.254\.169\.254",
        ],
        "nosql_injection": [
            r"\{\s*\$\w+\s*:",
            r"\$\w+\s*:",
            r"db\.\w+\.\w+\(",
        ]
    }
    
    for attack_type, patterns in regex_patterns.items():
        for pattern in patterns:
            if re.search(pattern, text, re.IGNORECASE):
                return True, attack_type
    
    return False, None

# Mantener la función detect_sqli para compatibilidad
def detect_sqli(text):
    """Detecta posibles inyecciones SQL con patrones ampliados (versión compatibilidad)"""
    is_attack, attack_type = detect_attack(text)
    return is_attack and attack_type == "sqli"

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
    """Añade una IP a la whitelist"""
    whitelist = load_whitelist()
    if ip not in whitelist:
        with open(whitelist_file, 'a') as f:
            f.write(f"{ip}\n")
        write_log(f"IP {ip} añadida a la whitelist")
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
    """Verifica si una IP está en la whitelist"""
    whitelist = load_whitelist()
    return ip in whitelist

def block_ip_permanently(ip):
    """Bloquea una IP permanentemente usando iptables"""
    try:
        # No bloquear IPs en whitelist
        if is_ip_whitelisted(ip):
            write_log(f"Intento de bloqueo ignorado: IP {ip} está en whitelist")
            return False

        # Verificar si la IP ya está bloqueada
        check_cmd = f"sudo iptables -L INPUT -v -n | grep {ip}"
        result = subprocess.run(check_cmd, shell=True, capture_output=True, text=True)

        if ip in result.stdout:
            write_log(f"IP {ip} ya está bloqueada permanentemente")
            return True

        # Bloquear la IP de forma permanente
        block_cmd = f"sudo iptables -A INPUT -s {ip} -j DROP"
        subprocess.run(block_cmd, shell=True, check=True)

        # Guardar reglas para que persistan tras reinicios (puede requerir configuración adicional en Kali)
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
    """Verifica si una IP está bloqueada en iptables"""
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

# Funciones para monitoreo de logs de Apache
def parse_apache_log_line(line):
    """Parsea una línea de log de Apache y extrae información relevante"""
    match = re.match(APACHE_LOG_PATTERN, line)
    if not match:
        return None
    
    ip = match.group(1)
    date = match.group(2)
    time = match.group(3)
    timezone = match.group(4)
    method = match.group(5)
    path = match.group(6)
    protocol = match.group(7)
    status = match.group(8)
    size = match.group(9)
    referer = match.group(10)
    user_agent = match.group(11)
    
    return {
        'ip': ip,
        'datetime': f"{date}:{time} {timezone}",
        'method': method,
        'path': path,
        'protocol': protocol,
        'status': status,
        'size': size,
        'referer': referer,
        'user_agent': user_agent
    }

def monitor_apache_logs():
    """Función que monitorea continuamente los logs de Apache"""
    write_log("Iniciando monitoreo de logs de Apache")
    
    # Posición inicial en el archivo de logs
    current_position = 0
    
    # Intentar abrir el archivo de logs principal de Apache
    if os.path.exists(APACHE_ACCESS_LOG):
        with open(APACHE_ACCESS_LOG, 'r') as f:
            # Ir al final del archivo
            f.seek(0, 2)
            current_position = f.tell()
    else:
        write_log(f"No se pudo encontrar el archivo de logs: {APACHE_ACCESS_LOG}", True)
        return
    
    # Bucle de monitoreo continuo
    while True:
        try:
            with open(APACHE_ACCESS_LOG, 'r') as f:
                # Ir a la última posición leída
                f.seek(current_position)
                
                # Leer nuevas líneas
                new_lines = f.readlines()
                
                # Actualizar posición
                current_position = f.tell()
                
                # Procesar nuevas líneas
                for line in new_lines:
                    process_apache_log_line(line)
            
            # Verificar también logs rotados
            check_rotated_logs()
            
            # Resetear contadores antiguos
            reset_old_counters()
            
            # Pausa para no consumir demasiados recursos
            time.sleep(1)
            
        except Exception as e:
            write_log(f"Error en monitoreo de logs de Apache: {str(e)}")
            time.sleep(5)  # Pausa más larga en caso de error

def check_rotated_logs():
    """Verifica logs rotados para asegurarse de capturar todos los eventos"""
    try:
        # Buscar logs rotados recientes (últimas 24 horas)
        yesterday = datetime.now() - timedelta(days=1)
        yesterday_str = yesterday.strftime("%Y%m%d")
        
        # Patrones comunes de rotación de logs
        patterns = [
            f"{APACHE_ACCESS_LOG}.1",
            f"{APACHE_ACCESS_LOG}.{yesterday_str}",
            f"{APACHE_ACCESS_LOG}.{yesterday_str}.gz"
        ]
        
        for pattern in patterns:
            if os.path.exists(pattern):
                # Si es archivo comprimido, usar zcat
                if pattern.endswith('.gz'):
                    cmd = f"zcat {pattern}"
                    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, text=True)
                    output, _ = p.communicate()
                    for line in output.splitlines():
                        process_apache_log_line(line)
                else:
                    # Leer archivo normal
                    with open(pattern, 'r') as f:
                        for line in f:
                            process_apache_log_line(line)
    except Exception as e:
        write_log(f"Error al verificar logs rotados: {str(e)}")

def process_apache_log_line(line):
    """Procesa una línea de log de Apache para detectar ataques"""
    log_data = parse_apache_log_line(line)
    if not log_data:
        return
    
    # Ignorar IPs en whitelist
    if is_ip_whitelisted(log_data['ip']):
        return
    
    # Verificar si la IP ya está bloqueada
    if is_ip_blocked(log_data['ip']):
        return
    
    # Comprobar si hay intento de ataque en el path o en parámetros GET
    path = log_data['path']
    
    # Detectar ataque en el path
    is_attack, attack_type = detect_attack(path)
    if is_attack:
        handle_attack_attempt(log_data['ip'], attack_type, path)
        return
    
    # Extraer parámetros de consulta GET
    if '?' in path:
        query_params = path.split('?', 1)[1]
        params = query_params.split('&')
        for param in params:
            if '=' in param:
                _, value = param.split('=', 1)
                is_attack, attack_type = detect_attack(value)
                if is_attack:
                    handle_attack_attempt(log_data['ip'], attack_type, value)
                    return
    
    # Verificar códigos de error HTTP sospechosos (40x, 50x)
    status_code = int(log_data['status'])
    if status_code >= 400:
        # Especialmente vigilar: 404 (not found), 403 (forbidden), 500 (internal error)
        if status_code in [400, 403, 404, 405, 500]:
            # Si hay intentos repetidos de URLs no existentes o prohibidas, puede ser un escaneo
            record_suspicious_activity(log_data['ip'], f"HTTP {status_code}", path)

def handle_attack_attempt(ip, attack_type, payload):
    """Maneja un intento de ataque detectado en los logs de Apache"""
    # Registrar el intento
    write_log(f"Ataque {attack_type} detectado en logs de Apache desde {ip}: {payload}", True)
    
    # Actualizar estadísticas
    stats['attacks_by_type'][attack_type] = stats['attacks_by_type'].get(attack_type, 0) + 1
    
    # Incrementar contador de intentos para esta IP
    if ip not in attack_attempts:
        attack_attempts[ip] = {
            'count': 1,
            'first_attempt': datetime.now(),
            'last_attempt': datetime.now(),
            'attacks': [{'type': attack_type, 'payload': payload}]
        }
    else:
        attack_attempts[ip]['count'] += 1
        attack_attempts[ip]['last_attempt'] = datetime.now()
        attack_attempts[ip]['attacks'].append({'type': attack_type, 'payload': payload})
    
    # Si supera el umbral, bloquear permanentemente
    if attack_attempts[ip]['count'] >= ATTACK_THRESHOLD:
        write_log(f"Umbral de ataques superado para IP {ip} ({attack_attempts[ip]['count']} intentos). Bloqueando...", True)
        block_ip_permanently(ip)
        # Limpiar contador después de bloquear
        del attack_attempts[ip]

def record_suspicious_activity(ip, reason, details):
    """Registra actividad sospechosa que no es claramente un ataque pero debe vigilarse"""
    # Similar a handle_attack_attempt pero con un umbral más alto
    if ip not in attack_attempts:
        attack_attempts[ip] = {
            'count': 0.5,  # Contador parcial para actividad sospechosa
            'first_attempt': datetime.now(),
            'last_attempt': datetime.now(),
            'attacks': [{'type': 'suspicious', 'payload': f"{reason}: {details}"}]
        }
    else:
        attack_attempts[ip]['count'] += 0.5
        attack_attempts[ip]['last_attempt'] = datetime.now()
        attack_attempts[ip]['attacks'].append({'type': 'suspicious', 'payload': f"{reason}: {details}"})
    
    # Log con nivel más bajo
    write_log(f"Actividad sospechosa desde {ip}: {reason} - {details}")
    
    # Si acumula suficientes actividades sospechosas, se trata como ataque
    if attack_attempts[ip]['count'] >= ATTACK_THRESHOLD:
        write_log(f"Umbral de actividad sospechosa superado para IP {ip} ({attack_attempts[ip]['count']} actividades). Bloqueando...", True)
        block_ip_permanently(ip)
        del attack_attempts[ip]

def reset_old_counters():
    """Resetea contadores de intentos que son antiguos"""
    now = datetime.now()
    ips_to_remove = []
    
    for ip, data in attack_attempts.items():
        # Si el último intento fue hace más del tiempo de reset, eliminarlo
        time_diff = now - data['last_attempt']
        if time_diff.total_seconds() / 60 > RESET_TIME_MINUTES:
            ips_to_remove.append(ip)
    
    for ip in ips_to_remove:
        del attack_attempts[ip]

def start_apache_monitor():
    """Inicia el hilo de monitoreo de logs de Apache"""
    monitor_thread = threading.Thread(target=monitor_apache_logs, daemon=True)
    monitor_thread.start()

# Middleware para filtrar todas las solicitudes
@app.before_request
def check_all_requests():
    """Filtro global para todas las solicitudes"""
    # Ignorar solicitudes a rutas administrativas para evitar bloqueos accidentales
    if request.path in ['/logs', '/whitelist', '/unblock']:
        return None

    client_ip = request.remote_addr

    # Verificar si la IP está en whitelist
    if is_ip_whitelisted(client_ip):
        return None  # Permitir la solicitud

    # Verificar si la IP ya está bloqueada
    if is_ip_blocked(client_ip):
        stats['blocked_requests'] += 1
        write_log(f"Acceso bloqueado: IP {client_ip} en lista negra")
        return jsonify({"error": "Acceso denegado - IP bloqueada"}), 403

    # Verificar ruta completa para detectar ataques
    path = request.path
    is_attack, attack_type = detect_attack(path)
    if is_attack:
        stats['blocked_requests'] += 1
        stats['attacks_by_type'][attack_type] += 1
        write_log(f"Ataque {attack_type} detectado en ruta: '{path}' desde {client_ip}", True)
        block_ip_permanently(client_ip)
        return jsonify({"error": f"Acceso bloqueado por posible ataque de tipo {attack_type}"}), 403
    
    # Verificar todos los parámetros de URL
    for key, value in request.args.items():
        is_attack, attack_type = detect_attack(value)
        if is_attack:
            stats['blocked_requests'] += 1
            stats['attacks_by_type'][attack_type] += 1
            write_log(f"Ataque {attack_type} detectado en parámetro URL '{key}': {value} desde {client_ip}", True)
            block_ip_permanently(client_ip)
            return jsonify({"error": f"Acceso bloqueado por posible ataque de tipo {attack_type}"}), 403

    # Verificar formularios o datos JSON
    if request.is_json:
        try:
            data = request.get_json(silent=True)
            if data:
                # Verificar recursivamente todos los valores en el JSON
                is_attack, attack_type, attack_value = check_json_for_attacks(data, client_ip)
                if is_attack:
                    stats['blocked_requests'] += 1
                    stats['attacks_by_type'][attack_type] += 1
                    write_log(f"Ataque {attack_type} detectado en JSON: {attack_value} desde {client_ip}", True)
                    block_ip_permanently(client_ip)
                    return jsonify({"error": f"Acceso bloqueado por posible ataque de tipo {attack_type}"}), 403
        except Exception as e:
            write_log(f"Error al procesar JSON: {str(e)}")

    # Verificar datos de formulario
    if request.form:
        for key, value in request.form.items():
            is_attack, attack_type = detect_attack(value)
            if is_attack:
                stats['blocked_requests'] += 1
                stats['attacks_by_type'][attack_type] += 1
                write_log(f"Ataque {attack_type} detectado en formulario '{key}': {value} desde {client_ip}", True)
                block_ip_permanently(client_ip)
                return jsonify({"error": f"Acceso bloqueado por posible ataque de tipo {attack_type}"}), 403

    # Si pasa todas las verificaciones, permitir la solicitud
    return None

def check_json_for_attacks(data, client_ip):
    """Verifica recursivamente valores en datos JSON para detectar ataques"""
    if isinstance(data, dict):
        for key, value in data.items():
            if isinstance(value, (dict, list)):
                is_attack, attack_type, attack_value = check_json_for_attacks(value, client_ip)
                if is_attack:
                    return True, attack_type, attack_value
            elif isinstance(value, str):
                is_attack, attack_type = detect_attack(value)
                if is_attack:
                    return True, attack_type, value
    elif isinstance(data, list):
        for item in data:
            is_attack, attack_type, attack_value = check_json_for_attacks(item, client_ip)
            if is_attack:
                return True, attack_type, attack_value
    return False, None, None

# Mantener la compatibilidad con la función original
def check_json_for_sqli(data, client_ip):
    """Verifica recursivamente valores en datos JSON para detectar SQLi (compatibilidad)"""
    is_attack, attack_type, _ = check_json_for_attacks(data, client_ip)
    return is_attack and attack_type == "sqli"

@app.route("/")
def root():
    # Actualizar estadísticas
    stats['total_requests'] += 1
    stats['last_request'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Registrar solicitud
    write_log(f"Acceso a ruta raíz desde {request.remote_addr}")

    # Ahora pasamos ATTACK_PAYLOADS en lugar de SQLI_PAYLOADS
    return render_template("index.html",
                        stats=stats,
                        ATTACK_PAYLOADS=ATTACK_PAYLOADS)

@app.route("/test/<param>")
def test(param):
    # Actualizar estadísticas
    stats['total_requests'] += 1
    stats['last_request'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Comprobar ataques en param (aunque el middleware global ya lo comprueba)
    is_attack, attack_type = detect_attack(param)
    if is_attack:
        stats['blocked_requests'] += 1
        stats['attacks_by_type'][attack_type] += 1
        client_ip = request.remote_addr
        write_log(f"Ataque {attack_type} bloqueado en param: '{param}' desde {client_ip}", True)

        # Bloquear IP si no está en whitelist
        if not is_ip_whitelisted(client_ip):
            block_ip_permanently(client_ip)

        return jsonify({"error": f"Acceso bloqueado por posible ataque de tipo {attack_type}"}), 403

    # Si no hay ataque, procesar normalmente
    write_log(f"Parámetro test: '{param}' desde {request.remote_addr}")
    return jsonify({"param": param}), 200

@app.route("/query")
def query_test():
    # Las verificaciones se realizan en el middleware global
    # Esta función solo procesa solicitudes legítimas

    # Actualizar estadísticas
    stats['total_requests'] += 1
    stats['last_request'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Procesar parámetros
    result = {key: value for key, value in request.args.items()}
    write_log(f"Consulta con parámetros: {result} desde {request.remote_addr}")
    return jsonify(result), 200

@app.route("/logs")
def view_logs():
    # Actualizar estadísticas
    stats['total_requests'] += 1
    stats['last_request'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Leer logs existentes
    logs = []
    if os.path.exists(log_file):
        with open(log_file, 'r') as f:
            logs = f.readlines()
            logs = logs[-50:] if len(logs) > 50 else logs  # Mostrar últimos 50 logs

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
                           default_whitelist=DEFAULT_WHITELIST,
                           attack_types=list(ATTACK_PAYLOADS.keys()))

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

        # Redirigir a la página de logs
        return redirect('/logs')
    except Exception as e:
        return jsonify({"error": f"Error al desbloquear IP: {str(e)}"}), 500

@app.route("/whitelist")
def whitelist_management():
    """Página de gestión de la whitelist"""
    # Actualizar estadísticas
    stats['total_requests'] += 1
    stats['last_request'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Obtener whitelist
    whitelist = load_whitelist()

    write_log(f"Vista de gestión de whitelist accedida desde {request.remote_addr}")

    # Renderizar plantilla
    return render_template("whitelist.html",
                          whitelist=whitelist,
                          default_whitelist=DEFAULT_WHITELIST)

@app.route("/whitelist/add", methods=["POST"])
def add_ip_to_whitelist():
    """Añade una IP a la whitelist"""
    ip = request.form.get("ip", "").strip()

    if not ip:
        return jsonify({"error": "IP no proporcionada"}), 400

    # Validar formato de IP básico
    ip_pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
    if not re.match(ip_pattern, ip):
        return jsonify({"error": "Formato de IP inválido"}), 400

    result = add_to_whitelist(ip)

    if result:
        write_log(f"IP {ip} añadida a whitelist por {request.remote_addr}")
        # Desbloquear la IP si estaba bloqueada
        if is_ip_blocked(ip):
            try:
                unblock_cmd = f"sudo iptables -D INPUT -s {ip} -j DROP"
                subprocess.run(unblock_cmd, shell=True, check=True)
                write_log(f"IP {ip} desbloqueada automáticamente al añadirla a whitelist")
            except Exception as e:
                write_log(f"Error al desbloquear IP {ip}: {str(e)}")

    # Redirigir a la página de whitelist
    return redirect('/whitelist')

@app.route("/whitelist/remove/<ip>")
def remove_ip_from_whitelist(ip):
    """Elimina una IP de la whitelist"""
    result = remove_from_whitelist(ip)

    if result:
        write_log(f"IP {ip} eliminada de whitelist por {request.remote_addr}")
    else:
        write_log(f"No se pudo eliminar IP {ip} de whitelist (IP predeterminada o no encontrada)")

    # Redirigir a la página de whitelist
    return redirect('/whitelist')

@app.route('/<path:undefined_path>')
def catch_all(undefined_path):
    """Captura todas las rutas no definidas y verifica ataques en ellas"""
    # La verificacion general ya debe haber ocurrido en el middleware,
    # pero podemos añadir una capa extra de verificacion
    is_attack, attack_type = detect_attack(undefined_path)
    if is_attack:
        stats['blocked_requests'] += 1
        stats['attacks_by_type'][attack_type] += 1
        client_ip = request.remote_addr
        write_log(f"Ataque {attack_type} detectado en ruta indefinida: '{undefined_path}' desde {client_ip}", True)

        #Bloquear IP si no esta en whitelist
        if not is_ip_whitelisted(client_ip):
            block_ip_permanently(client_ip)
        return jsonify({"error": f"Acceso bloqueado por posible ataque de tipo {attack_type}"}), 403

    # Si no hay ataque, pero la ruta no existe
    return jsonify({"error": "Ruta no encontrada"}), 404

if __name__ == "__main__":
    # Crear directorio de logs si no existe
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)

    # Crear archivos necesarios si no existen
    if not os.path.exists(log_file):
        with open(log_file, 'w') as f:
            f.write(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - INFO - WebGuardian iniciado\n")

    if not os.path.exists(blocked_ips_file):
        with open(blocked_ips_file, 'w') as f:
            pass

    if not os.path.exists(whitelist_file):
        with open(whitelist_file, 'w') as f:
            for ip in DEFAULT_WHITELIST:
                if ip not in ['127.0.0.1', '0.0.0.0', 'localhost']:
                    f.write(f"{ip}\n")

    # Inicializar estadísticas de IPs bloqueadas
    blocked_ips = get_blocked_ips()
    stats['blocked_ips'] = len(blocked_ips)

    # Iniciar el monitoreo de logs de Apache
    start_apache_monitor()

    print("=================================================")
    print("  WebGuardian: Sistema de Protección Web Avanzado  ")
    print("=================================================")
    print(f"- API iniciada en http://0.0.0.0:5000/")
    print(f"- Panel de control: http://0.0.0.0:5000/logs")
    print(f"- Gestión de whitelist: http://0.0.0.0:5000/whitelist")
    print(f"- Detección de {sum(len(payloads) for payloads in ATTACK_PAYLOADS.values())} patrones de ataque")
    print(f"- {len(load_whitelist())} IPs en whitelist")
    print(f"- Monitoreo de logs de Apache: ACTIVO")
    print("- Vectores de ataque protegidos:")
    for attack_type, payloads in ATTACK_PAYLOADS.items():
        print(f"  * {attack_type}: {len(payloads)} patrones")
    print("=================================================")

    # Iniciar aplicación
    app.run(host='0.0.0.0', debug=True)
                