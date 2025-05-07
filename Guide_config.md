# WebGuardian: Guía Completa de Implementación y Configuración

## Índice

1. [Introducción](#introducción)
2. [Visión General del Sistema](#visión-general-del-sistema)
3. [Instalación y Configuración](#instalación-y-configuración)
   - [Preparación del Entorno](#preparación-del-entorno)
   - [Instalación y Configuración de Apache](#instalación-y-configuración-de-apache)
   - [Estructura de Directorios](#estructura-de-directorios)
   - [Dependencias](#dependencias)
4. [Componentes Principales de WebGuardian](#componentes-principales-de-webguardian)
   - [Detección de Ataques](#detección-de-ataques)
   - [Gestión de IPs](#gestión-de-ips)
   - [Monitoreo de Logs de Apache](#monitoreo-de-logs-de-apache)
   - [Interfaz Web](#interfaz-web)
5. [Configuración](#configuración)
   - [Configuración de Apache](#configuración-de-apache)
   - [Permisos del Sistema](#permisos-del-sistema)
   - [Configuración del Servicio](#configuración-del-servicio)
6. [Sincronización de IPs](#sincronización-de-ips)
   - [Implementación del Script de Sincronización](#implementación-del-script-de-sincronización)
   - [Ejecución Programada](#ejecución-programada)
7. [Solución de Problemas](#solución-de-problemas)
8. [Pruebas y Verificación](#pruebas-y-verificación)
9. [Configuración Avanzada](#configuración-avanzada)
10. [Mejores Prácticas de Seguridad](#mejores-prácticas-de-seguridad)

## Introducción

WebGuardian es un sistema avanzado de seguridad web diseñado para proteger servicios web contra diversas amenazas cibernéticas. Funciona como una aplicación Flask que se integra con Apache para proporcionar protección integral mediante filtrado inteligente de solicitudes, registro detallado y gestión robusta de IPs.

Esta guía proporciona un recorrido completo para implementar WebGuardian en un servidor Apache que ejecuta Kali Linux, desde la configuración inicial hasta la configuración avanzada y la solución de problemas.

## Visión General del Sistema

WebGuardian ofrece protección contra múltiples vectores de ataque:

- Inyección SQL (SQLi)
- Cross-Site Scripting (XSS)
- Path Traversal
- Inyección de Comandos
- Server-Side Request Forgery (SSRF)
- Inyección de Cabeceras HTTP
- Inyección NoSQL

Características principales:

- Detección y bloqueo en tiempo real de intentos de ataque
- Bloqueo permanente de IPs mediante iptables
- Gestión de whitelist para IPs confiables
- Sistema de registro completo
- Panel web para monitoreo y administración
- Integración con logs de Apache para detección mejorada
- Sincronización a nivel de sistema de IPs bloqueadas

## Instalación y Configuración

### Preparación del Entorno

Comienza con una instalación actualizada de Kali Linux:

```bash
sudo apt update
sudo apt upgrade -y
```

### Instalación y Configuración de Apache

Instala Apache y los módulos necesarios:

```bash
# Instalar Apache y módulos requeridos
sudo apt install apache2 libapache2-mod-wsgi-py3 python3-pip -y

# Iniciar y habilitar Apache
sudo systemctl start apache2
sudo systemctl enable apache2

# Verificar que Apache está funcionando
sudo systemctl status apache2
```

### Estructura de Directorios

Crea la estructura de directorios para la aplicación:

```bash
# Crear directorio de aplicación
sudo mkdir -p /var/www/webguardian
sudo chown -R $USER:$USER /var/www/webguardian

# Crear subdirectorios
mkdir -p /var/www/webguardian/logs
mkdir -p /var/www/webguardian/templates
mkdir -p /var/www/webguardian/static
```

### Dependencias

Crea un archivo de requisitos para las dependencias de Python:

```bash
cat > /var/www/webguardian/requirements.txt << EOF
flask==2.0.1
werkzeug==2.0.1
requests==2.28.1
EOF
```

Instala las dependencias usando uno de estos métodos:

#### Opción 1: Usando un Entorno Virtual (Recomendado)

```bash
# Instalar virtualenv si no está instalado
sudo apt-get install python3-venv

# Crear y activar entorno virtual
cd /var/www/webguardian
python3 -m venv venv
source venv/bin/activate

# Instalar dependencias
pip install -r requirements.txt
```

#### Opción 2: Instalación a Nivel de Sistema

```bash
sudo apt-get install python3-flask python3-werkzeug python3-requests
```

## Componentes Principales de WebGuardian

### Creación del Archivo WSGI

Crea un archivo WSGI para conectar Apache con la aplicación Flask:

```bash
cat > /var/www/webguardian/webguardian.wsgi << 'EOF'
#!/usr/bin/env python3

import sys
import site
import logging

# Configurar logging
logging.basicConfig(stream=sys.stderr)

# Ruta al entorno virtual (si usas la Opción 1)
virtual_env = '/var/www/webguardian/venv'
site.addsitedir(f'{virtual_env}/lib/python3.9/site-packages')  # Ajusta la versión de Python según sea necesario

# Activar entorno virtual
activate_env = f'{virtual_env}/bin/activate_this.py'
with open(activate_env) as file_:
    exec(file_.read(), dict(__file__=activate_env))

# Añadir ruta de la aplicación
sys.path.insert(0, '/var/www/webguardian/')

# Importar la aplicación
from app import app as application
EOF
```

Si no usas un entorno virtual, simplifica el archivo WSGI:

```bash
cat > /var/www/webguardian/webguardian.wsgi << 'EOF'
#!/usr/bin/env python3

import sys
import logging

# Configurar logging
logging.basicConfig(stream=sys.stderr)

# Añadir ruta de la aplicación
sys.path.insert(0, '/var/www/webguardian/')

# Importar la aplicación
from app import app as application
EOF
```

### Creación del Archivo de Aplicación Principal

El archivo de aplicación (`app.py`) contiene la funcionalidad principal de WebGuardian. Es un archivo grande que implementa la detección de ataques, la gestión de IPs, el monitoreo de logs de Apache y la interfaz web.

```bash
# Copiar el archivo app.py completo desde el repositorio
# Para esta guía, asumimos que el archivo ya está creado
```

### Creación de Plantillas HTML

Crea las plantillas HTML necesarias para la interfaz web. Se necesitan tres plantillas esenciales:

1. **index.html**: Panel principal que muestra estadísticas y navegación
2. **logs.html**: Vista para logs e IPs bloqueadas
3. **whitelist.html**: Interfaz para administrar entradas de whitelist

Estas plantillas deben colocarse en el directorio `/var/www/webguardian/templates/`.

## Configuración

### Configuración de Apache

Crea un archivo de configuración de Apache para WebGuardian:

```bash
sudo cat > /etc/apache2/sites-available/webguardian.conf << 'EOF'
<VirtualHost *:80>
    ServerName webguardian.local
    ServerAdmin webmaster@localhost
    
    WSGIDaemonProcess webguardian user=www-data group=www-data threads=5
    WSGIScriptAlias / /var/www/webguardian/webguardian.wsgi
    
    <Directory /var/www/webguardian>
        WSGIProcessGroup webguardian
        WSGIApplicationGroup %{GLOBAL}
        Require all granted
    </Directory>
    
    ErrorLog ${APACHE_LOG_DIR}/webguardian-error.log
    CustomLog ${APACHE_LOG_DIR}/webguardian-access.log combined
</VirtualHost>
EOF
```

Habilita el sitio y reinicia Apache:

```bash
sudo a2ensite webguardian.conf
sudo a2dissite 000-default.conf  # Opcional: deshabilitar sitio predeterminado
sudo systemctl restart apache2
```

### Permisos del Sistema

Configura los permisos apropiados para la aplicación:

```bash
# Establecer propiedad y permisos correctos
sudo chown -R www-data:www-data /var/www/webguardian
sudo chmod -R 755 /var/www/webguardian

# Otorgar permisos de escritura para el directorio de logs
sudo chmod -R 775 /var/www/webguardian/logs
```

Configura permisos sudo para iptables:

```bash
sudo bash -c 'echo "www-data ALL=(ALL) NOPASSWD: /sbin/iptables" >> /etc/sudoers.d/webguardian'
sudo chmod 440 /etc/sudoers.d/webguardian
```

### Configuración del Servicio

Crea un servicio systemd para WebGuardian:

```bash
sudo cat > /etc/systemd/system/apache2-webguardian.service << 'EOF'
[Unit]
Description=Servicio Apache WebGuardian
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/var/www/webguardian
ExecStart=/usr/sbin/apache2ctl -D FOREGROUND
Restart=always

[Install]
WantedBy=multi-user.target
EOF
```

Habilita e inicia el servicio:

```bash
sudo systemctl daemon-reload
sudo systemctl enable apache2-webguardian.service
sudo systemctl start apache2-webguardian.service
```

## Sincronización de IPs

### Implementación del Script de Sincronización

Crea un script para sincronizar IPs bloqueadas entre WebGuardian y el firewall del sistema:

```bash
sudo mkdir -p /usr/local/bin
sudo cat > /usr/local/bin/sync_blocked_ips.py << 'EOF'
#!/usr/bin/env python3
"""
Script para sincronizar IPs bloqueadas desde WebGuardian a las reglas de iptables locales.
"""

import os
import sys
import requests
import subprocess
import json
import re
import logging
from datetime import datetime

# Configuración
API_URL = "http://localhost/api/blocked_ips"  # URL de API que devuelve IPs bloqueadas
LOG_FILE = "/var/log/ip_sync.log"
BLOCKED_IPS_FILE = "/etc/webguardian/blocked_ips.txt"

# Configurar logging
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def ensure_directories():
    """Asegurar que existan los directorios requeridos"""
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    os.makedirs(os.path.dirname(BLOCKED_IPS_FILE), exist_ok=True)

def get_blocked_ips():
    """Obtener lista de IPs bloqueadas desde la API"""
    try:
        response = requests.get(API_URL)
        if response.status_code == 200:
            return response.json()
        else:
            logging.error(f"Error al obtener IPs bloqueadas. Código: {response.status_code}")
            return None
    except Exception as e:
        logging.error(f"Error de conexión a la API: {str(e)}")
        return None

def get_local_blocked_ips():
    """Obtener IPs actualmente bloqueadas en iptables"""
    try:
        cmd = "sudo iptables -L INPUT -n | grep DROP"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        ips = re.findall(ip_pattern, result.stdout)
        return ips
    except Exception as e:
        logging.error(f"Error al obtener IPs bloqueadas localmente: {str(e)}")
        return []

def save_blocked_ips(ips):
    """Guardar lista de IPs bloqueadas en archivo para referencia"""
    try:
        with open(BLOCKED_IPS_FILE, 'w') as f:
            for ip in ips:
                f.write(f"{ip}\n")
        return True
    except Exception as e:
        logging.error(f"Error al guardar IPs bloqueadas: {str(e)}")
        return False

def block_ip(ip):
    """Bloquear una IP usando iptables"""
    try:
        # Verificar si la IP ya está bloqueada
        check_cmd = f"sudo iptables -L INPUT -n | grep {ip}"
        result = subprocess.run(check_cmd, shell=True, capture_output=True, text=True)
        
        if ip in result.stdout:
            logging.info(f"IP {ip} ya está bloqueada.")
            return True
            
        # Bloquear la IP
        block_cmd = f"sudo iptables -A INPUT -s {ip} -j DROP"
        subprocess.run(block_cmd, shell=True, check=True)
        
        logging.info(f"IP {ip} bloqueada exitosamente.")
        return True
    except Exception as e:
        logging.error(f"Error al bloquear IP {ip}: {str(e)}")
        return False

def unblock_ip(ip):
    """Desbloquear una IP eliminando la regla de iptables"""
    try:
        unblock_cmd = f"sudo iptables -D INPUT -s {ip} -j DROP"
        subprocess.run(unblock_cmd, shell=True, check=True)
        
        logging.info(f"IP {ip} desbloqueada.")
        return True
    except Exception as e:
        logging.error(f"Error al desbloquear IP {ip}: {str(e)}")
        return False

def save_iptables():
    """Guardar reglas de iptables para que persistan después de reiniciar"""
    try:
        save_cmd = "sudo iptables-save > /etc/iptables/rules.v4"
        subprocess.run(save_cmd, shell=True, check=True)
        
        logging.info("Reglas de iptables guardadas correctamente.")
        return True
    except Exception as e:
        logging.error(f"Error al guardar reglas de iptables: {str(e)}")
        return False

def sync_blocked_ips():
    """Función principal para sincronizar IPs bloqueadas"""
    logging.info("Iniciando sincronización de IPs bloqueadas")
    
    # Obtener IPs bloqueadas de la API
    api_blocked_ips = get_blocked_ips()
    if api_blocked_ips is None:
        logging.error("No se pudieron obtener las IPs bloqueadas de la API")
        return False
        
    # Obtener IPs actualmente bloqueadas en el sistema
    local_blocked_ips = get_local_blocked_ips()
    
    # IPs a bloquear (están en la API pero no localmente)
    ips_to_block = [ip for ip in api_blocked_ips if ip not in local_blocked_ips]
    
    # IPs a desbloquear (están bloqueadas localmente pero no en la API)
    ips_to_unblock = [ip for ip in local_blocked_ips if ip not in api_blocked_ips]
    
    # Bloquear nuevas IPs
    for ip in ips_to_block:
        block_ip(ip)
    
    # Desbloquear IPs que ya no están en la lista
    for ip in ips_to_unblock:
        unblock_ip(ip)
    
    # Guardar cambios
    if ips_to_block or ips_to_unblock:
        save_iptables()
        save_blocked_ips(api_blocked_ips)
        
    logging.info(f"Sincronización completada. {len(ips_to_block)} IPs bloqueadas, {len(ips_to_unblock)} IPs desbloqueadas.")
    return True

if __name__ == "__main__":
    ensure_directories()
    sync_blocked_ips()
EOF
```

Haz el script ejecutable:

```bash
sudo chmod +x /usr/local/bin/sync_blocked_ips.py
```

Instala dependencias para el script de sincronización:

```bash
sudo apt update
sudo apt install python3-requests -y
```

### Ejecución Programada

Configura la ejecución periódica usando cron:

```bash
# Añadir a crontab para ejecutar cada 5 minutos
(crontab -l 2>/dev/null; echo "*/5 * * * * /usr/bin/python3 /usr/local/bin/sync_blocked_ips.py") | crontab -
```

Alternativamente, crea un servicio systemd:

```bash
sudo cat > /etc/systemd/system/sync-blocked-ips.service << 'EOF'
[Unit]
Description=Sincronizar IPs bloqueadas desde WebGuardian
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /usr/local/bin/sync_blocked_ips.py
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
EOF
```

Habilita e inicia el servicio:

```bash
sudo systemctl daemon-reload
sudo systemctl enable sync-blocked-ips.service
sudo systemctl start sync-blocked-ips.service
```

## Solución de Problemas

### Error: "externally-managed-environment"

Este error ocurre al intentar instalar dependencias con pip en un entorno Python gestionado por el sistema.

**Solución**: Utilizar un entorno virtual como se detalla en la sección Dependencias, Opción 1.

### Permisos Insuficientes para iptables

Si encuentras errores de permisos al ejecutar comandos iptables:

**Solución**: Verificar que el usuario www-data tenga los permisos sudo necesarios:

```bash
sudo grep www-data /etc/sudoers /etc/sudoers.d/*
```

Si falta la configuración, agrégala:

```bash
sudo bash -c 'echo "www-data ALL=(ALL) NOPASSWD: /sbin/iptables" >> /etc/sudoers.d/webguardian'
sudo chmod 440 /etc/sudoers.d/webguardian
```

### Problemas de Acceso a Logs de Apache

Si el script no puede acceder a los logs de Apache:

**Solución**: Verificar ubicaciones de logs y otorgar permisos apropiados:

```bash
sudo ls -la /var/log/apache2/
sudo usermod -a -G adm www-data  # Añadir www-data al grupo que puede leer logs
sudo systemctl restart apache2
```

## Pruebas y Verificación

### Verificar Estado de la Aplicación

Comprobar si la aplicación está funcionando correctamente:

```bash
sudo systemctl status apache2-webguardian.service
```

### Revisar Logs de la Aplicación

Monitorear los logs de la aplicación:

```bash
tail -f /var/www/webguardian/logs/api_logs.txt
```

### Verificar Sincronización de IPs

Revisar los logs de sincronización de IPs:

```bash
tail -f /var/log/ip_sync.log
```

### Revisar Reglas de iptables

Revisar las reglas actuales de iptables:

```bash
sudo iptables -L INPUT -n | grep DROP
```

### Acceder a la Interfaz Web

Abrir un navegador y navegar a:

```
http://localhost/
```

La interfaz web proporciona:
- Estadísticas generales
- Gestión de whitelist
- Logs de acceso y ataques
- Gestión de IPs bloqueadas

## Configuración Avanzada

### Personalización de Patrones de Detección de Ataques

Los patrones de detección de ataques están definidos en el diccionario `ATTACK_PAYLOADS` en `app.py`. Puedes personalizar estos patrones para adaptarlos mejor a tu entorno:

```python
# Ejemplo de añadir patrones personalizados
ATTACK_PAYLOADS["ataques_personalizados"] = [
    "patron_especifico1",
    "patron_especifico2",
    r"patron_regex\d+"
]
```

### Integración con Herramientas de Seguridad Externas

WebGuardian puede integrarse con otras herramientas de seguridad a través de sus endpoints API. Por ejemplo:

1. **Integración con Sistemas de Gestión de Información y Eventos de Seguridad (SIEM)**:
   Utiliza los archivos de log o crea endpoints API personalizados para alimentar datos en tu sistema SIEM.

2. **Herramientas de monitoreo de red**:
   Configura alertas cuando WebGuardian bloquee una IP o detecte patrones de ataque.

## Mejores Prácticas de Seguridad

Al implementar WebGuardian, sigue estas mejores prácticas de seguridad:

1. **Actualizaciones regulares**:
   - Mantén los patrones de detección de ataques actualizados
   - Actualiza regularmente el sistema operativo y Apache

2. **Gestión de whitelist**:
   - Ten precaución al añadir IPs a la whitelist
   - Revisa y valida regularmente las entradas en la whitelist

3. **Monitoreo de logs**:
   - Configura agregación y monitoreo externo de logs
   - Crea alertas para patrones de ataque específicos o umbrales

4. **Capas de seguridad adicionales**:
   - Implementa un Firewall de Aplicaciones Web (WAF) como capa adicional
   - Usa HTTPS con configuración de certificados adecuada
   - Implementa segmentación de red cuando sea posible

5. **Copia de seguridad y recuperación**:
   - Respalda regularmente la configuración y logs de WebGuardian
   - Documenta procedimientos de recuperación para restauración rápida

Siguiendo esta guía integral, deberías tener una instalación de WebGuardian completamente funcional protegiendo tu servidor web Apache contra varias amenazas cibernéticas. La combinación de detección de ataques en tiempo real, bloqueo de IP y registro detallado proporciona una solución de seguridad robusta para aplicaciones web.
