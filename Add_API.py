#Añadir librerias al principio

import re
import time
import threading
import glob
from datetime import datetime, timedelta





#-----------------------------------------
#Añadir variables al principio antes de funciones
APACHE_LOG_DIR = "/var/log/apache2"
APACHE_ACCESS_LOG = os.path.join(APACHE_LOG_DIR, "access.log")
APACHE_ERROR_LOG = os.path.join(APACHE_LOG_DIR, "error.log")

APACHE_LOG_PATTERN = r'^(\S+) \S+ \S+ \[([^:]+):(\d+:\d+:\d+) ([^\]]+)\] "(\S+) (.+?) (\S+)" (\d+) (\S+) "([^"]*)" "([^"]*)"'

# Contador de intentos de ataque por IP
attack_attempts = {}
# Umbral de intentos antes de bloqueo permanente
ATTACK_THRESHOLD = 3
# Tiempo de reset del contador (minutos)
RESET_TIME_MINUTES = 60


#-----------------------------------------
#Añadir funciones al final:
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


# ---------------------------------------
#Añadir funciones al final
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

# ---------------------------------------
#Añadir funciones al final
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

# ---------------------------------------
#Añadir funciones al final

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
# ---------------------------------------
#Añadir funciones al final
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
# ---------------------------------------
#Añadir funciones al final
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
# ---------------------------------------
#Añadir funciones al final
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

# --- Iniciar el hilo de monitoreo de logs al arrancar la aplicación ---
def start_apache_monitor():
    """Inicia el hilo de monitoreo de logs de Apache"""
    monitor_thread = threading.Thread(target=monitor_apache_logs, daemon=True)
    monitor_thread.start()
