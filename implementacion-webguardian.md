# Guía de Implementación de WebGuardian en Apache

Esta guía detalla el proceso completo para implementar WebGuardian, un sistema avanzado de protección web, en un servidor Apache en Kali Linux. Incluye la configuración del servidor, la integración con el sistema de logs de Apache y la sincronización de IPs bloqueadas a nivel de sistema.

## Índice
1. [Preparación del entorno](#1-preparación-del-entorno)
2. [Instalación de Apache y configuración inicial](#2-instalación-de-apache-y-configuración-inicial)
3. [Estructura de la aplicación](#3-estructura-de-la-aplicación)
4. [Código de la aplicación](#4-código-de-la-aplicación)
5. [Configuración de plantillas HTML](#5-configuración-de-plantillas-html)
6. [Configuración de Apache](#6-configuración-de-apache)
7. [Instalación de dependencias](#7-instalación-de-dependencias)
8. [Configuración de permisos](#8-configuración-de-permisos)
9. [Configuración del servicio](#9-configuración-del-servicio)
10. [Script de sincronización de IPs bloqueadas](#10-script-de-sincronización-de-ips-bloqueadas)
11. [Solución de problemas comunes](#11-solución-de-problemas-comunes)
12. [Pruebas y verificación](#12-pruebas-y-verificación)

## 1. Preparación del entorno

Antes de comenzar, asegúrate de tener una instalación actualizada de Kali Linux:

```bash
sudo apt update
sudo apt upgrade -y
```

## 2. Instalación de Apache y configuración inicial

Instala Apache y los módulos necesarios:

```bash
# Instalar Apache y módulos necesarios
sudo apt install apache2 libapache2-mod-wsgi-py3 python3-pip -y

# Iniciar y habilitar Apache
sudo systemctl start apache2
sudo systemctl enable apache2

# Verificar que Apache está funcionando
sudo systemctl status apache2
```

## 3. Estructura de la aplicación

Crea la estructura de directorios para la aplicación:

```bash
# Crear directorio para la aplicación dentro de /var/www
sudo mkdir -p /var/www/webguardian
sudo chown -R $USER:$USER /var/www/webguardian

# Crear estructura de directorios
mkdir -p /var/www/webguardian/logs
mkdir -p /var/www/webguardian/templates
mkdir -p /var/www/webguardian/static
```

## 4. Código de la aplicación

### Archivo WSGI para Apache

Crea un archivo WSGI para conectar Apache con la aplicación Flask:

```bash
nano /var/www/webguardian/webguardian.wsgi
```

Contenido:

```python
#!/usr/bin/env python3

import sys
import logging

# Configurar logging
logging.basicConfig(stream=sys.stderr)

# Añadir la ruta de la aplicación
sys.path.insert(0, '/var/www/webguardian/')

# Importar la aplicación
from app import app as application
```

### Archivo principal de la aplicación (app.py)

Crea el archivo principal de la aplicación:

```bash
nano /var/www/webguardian/app.py
```

El contenido del archivo `app.py` es extenso y contiene la lógica principal de WebGuardian. El código completo se encuentra en [este repositorio](https://github.com/tu-usuario/WebGuardian). Los componentes principales incluyen:

1. Detección de múltiples vectores de ataque (SQLi, XSS, Path Traversal, etc.)
2. Sistema de bloqueo de IPs con iptables
3. Monitoreo de logs de Apache
4. API para gestión de IPs bloqueadas y whitelist
5. Interfaz web para administración

> ⚠️ **Importante**: Necesitarás clonar el repositorio o copiar el código completo del archivo app.py desde el repositorio.

También, asegúrate de añadir el endpoint API para las IPs bloqueadas:

```python
@app.route("/api/blocked_ips")
def api_blocked_ips():
    """API endpoint para obtener IPs bloqueadas en formato JSON"""
    blocked_ips_list = []
    
    # Obtener IPs desde el archivo
    if os.path.exists(blocked_ips_file):
        with open(blocked_ips_file, "r") as f:
            for line in f:
                # Extraer solo la IP de cada línea
                ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
                if ip_match:
                    blocked_ips_list.append(ip_match.group(1))
    
    # También obtener IPs directamente de iptables para estar seguros
    try:
        check_cmd = "sudo iptables -L INPUT -n | grep DROP"
        result = subprocess.run(check_cmd, shell=True, capture_output=True, text=True)
        
        # Extraer IPs con expresión regular
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        iptables_ips = re.findall(ip_pattern, result.stdout)
        
        # Añadir IPs que no estén ya en la lista
        for ip in iptables_ips:
            if ip not in blocked_ips_list:
                blocked_ips_list.append(ip)
    except Exception as e:
        write_log(f"Error al obtener IPs bloqueadas de iptables: {str(e)}")
    
    return jsonify(blocked_ips_list)
```

## 5. Configuración de plantillas HTML

Las plantillas HTML proporcionan la interfaz web para WebGuardian. Crea los siguientes archivos:

### index.html

```bash
nano /var/www/webguardian/templates/index.html
```

### logs.html

```bash
nano /var/www/webguardian/templates/logs.html
```

### whitelist.html

```bash
nano /var/www/webguardian/templates/whitelist.html
```

### connections.html (opcional)

```bash
nano /var/www/webguardian/templates/connections.html
```

> 📝 **Nota**: Los contenidos HTML completos están disponibles en el repositorio de GitHub.

## 6. Configuración de Apache

Crea un archivo de configuración de Apache para la aplicación:

```bash
sudo nano /etc/apache2/sites-available/webguardian.conf
```

Contenido:

```apache
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
```

Activa el sitio y reinicia Apache:

```bash
sudo a2ensite webguardian.conf
sudo a2dissite 000-default.conf  # Opcional: deshabilitar el sitio predeterminado
sudo systemctl restart apache2
```

## 7. Instalación de dependencias

Crea un archivo de requisitos para la aplicación:

```bash
nano /var/www/webguardian/requirements.txt
```

Contenido:

```
flask==2.0.1
werkzeug==2.0.1
requests==2.28.1
```

En versiones recientes de Python, la instalación directa con pip está restringida en entornos gestionados por el sistema. Hay varias opciones para manejar esto:

### Opción 1: Crear y usar un entorno virtual (recomendado)

```bash
# Instalar virtualenv si no lo tienes
sudo apt-get install python3-venv

# Crear un entorno virtual en el directorio de la aplicación
cd /var/www/webguardian
python3 -m venv venv

# Activar el entorno virtual
source venv/bin/activate

# Instalar las dependencias
pip install -r requirements.txt

# Modificar el archivo WSGI para usar el entorno virtual
```

Actualiza el archivo WSGI para usar el entorno virtual:

```python
#!/usr/bin/env python3

import sys
import site
import logging

# Configurar logging
logging.basicConfig(stream=sys.stderr)

# Ruta al entorno virtual
virtual_env = '/var/www/webguardian/venv'
site.addsitedir(f'{virtual_env}/lib/python3.x/site-packages')  # Reemplaza x con tu versión de Python

# Activar entorno virtual
activate_env = f'{virtual_env}/bin/activate_this.py'
with open(activate_env) as file_:
    exec(file_.read(), dict(__file__=activate_env))

# Añadir la ruta de la aplicación
sys.path.insert(0, '/var/www/webguardian/')

# Importar la aplicación
from app import app as application
```

### Opción 2: Instalar paquetes a nivel del sistema

```bash
sudo apt-get install python3-flask python3-werkzeug python3-requests
```

### Opción 3: Usar el flag --break-system-packages (no recomendado para producción)

```bash
pip install --break-system-packages -r /var/www/webguardian/requirements.txt
```

## 8. Configuración de permisos

Configura los permisos adecuados:

```bash
# Asignar permisos correctos
sudo chown -R www-data:www-data /var/www/webguardian
sudo chmod -R 755 /var/www/webguardian

# Dar permisos de escritura en la carpeta logs
sudo chmod -R 775 /var/www/webguardian/logs
```

Configura permisos de sudo para iptables:

```bash
sudo visudo
```

Añade esta línea:

```
www-data ALL=(ALL) NOPASSWD: /sbin/iptables
```

## 9. Configuración del servicio

Crea un servicio systemd para asegurar que la aplicación se inicie automáticamente:

```bash
sudo nano /etc/systemd/system/apache2-webguardian.service
```

Contenido:

```
[Unit]
Description=WebGuardian Apache Service
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/var/www/webguardian
ExecStart=/usr/sbin/apache2ctl -D FOREGROUND
Restart=always

[Install]
WantedBy=multi-user.target
```

Habilita e inicia el servicio:

```bash
sudo systemctl daemon-reload
sudo systemctl enable apache2-webguardian.service
sudo systemctl start apache2-webguardian.service
```

## 10. Script de sincronización de IPs bloqueadas

Este script permite sincronizar las IPs bloqueadas por WebGuardian con el firewall del sistema local.

### Creación del script

Crea el directorio para el script:

```bash
sudo mkdir -p /usr/local/bin
```

Crea el archivo del script:

```bash
sudo nano /usr/local/bin/sync_blocked_ips.py
```

Contenido:

```python
#!/usr/bin/env python3
"""
Script para sincronizar IPs bloqueadas desde WebGuardian a las reglas de iptables locales.
Este script consulta la API de WebGuardian, obtiene las IPs bloqueadas y 
las aplica al firewall local.
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
API_URL = "http://localhost/api/blocked_ips"  # URL de la API que devuelve IPs bloqueadas
LOG_FILE = "/var/log/ip_sync.log"
BLOCKED_IPS_FILE = "/etc/webguardian/blocked_ips.txt"

# Configurar logging
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def ensure_directories():
    """Asegura que existan los directorios necesarios"""
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    os.makedirs(os.path.dirname(BLOCKED_IPS_FILE), exist_ok=True)

def get_blocked_ips():
    """Obtiene la lista de IPs bloqueadas desde la API"""
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
    """Obtiene las IPs actualmente bloqueadas en iptables"""
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
    """Guarda la lista de IPs bloqueadas en un archivo para referencia"""
    try:
        with open(BLOCKED_IPS_FILE, 'w') as f:
            for ip in ips:
                f.write(f"{ip}\n")
        return True
    except Exception as e:
        logging.error(f"Error al guardar IPs bloqueadas: {str(e)}")
        return False

def block_ip(ip):
    """Bloquea una IP usando iptables"""
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
    """Desbloquea una IP eliminando la regla de iptables"""
    try:
        unblock_cmd = f"sudo iptables -D INPUT -s {ip} -j DROP"
        subprocess.run(unblock_cmd, shell=True, check=True)
        
        logging.info(f"IP {ip} desbloqueada.")
        return True
    except Exception as e:
        logging.error(f"Error al desbloquear IP {ip}: {str(e)}")
        return False

def save_iptables():
    """Guarda las reglas de iptables para que persistan después de reiniciar"""
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
    
    # Guardar los cambios
    if ips_to_block or ips_to_unblock:
        save_iptables()
        save_blocked_ips(api_blocked_ips)
        
    logging.info(f"Sincronización completada. {len(ips_to_block)} IPs bloqueadas, {len(ips_to_unblock)} IPs desbloqueadas.")
    return True

if __name__ == "__main__":
    ensure_directories()
    sync_blocked_ips()
```

### Configuración del script

Haz el script ejecutable:

```bash
sudo chmod +x /usr/local/bin/sync_blocked_ips.py
```

Instala las dependencias necesarias:

```bash
sudo apt update
sudo apt install python3-requests
```

### Configuración de ejecución periódica

Configura cron para ejecutar el script periódicamente:

```bash
sudo crontab -e
```

Añade esta línea para ejecutar el script cada 5 minutos:

```
*/5 * * * * /usr/bin/python3 /usr/local/bin/sync_blocked_ips.py
```

También puedes crear un servicio systemd para este script:

```bash
sudo nano /etc/systemd/system/sync-blocked-ips.service
```

Contenido:

```
[Unit]
Description=Sincronización de IPs bloqueadas desde WebGuardian
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /usr/local/bin/sync_blocked_ips.py
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
```

Habilita e inicia el servicio:

```bash
sudo systemctl daemon-reload
sudo systemctl enable sync-blocked-ips.service
sudo systemctl start sync-blocked-ips.service
```

## 11. Solución de problemas comunes

### Error "externally-managed-environment"

Este error ocurre al intentar instalar dependencias con pip en un entorno Python gestionado por el sistema operativo:

```
error: externally-managed-environment
```

**Solución recomendada**: Usar un entorno virtual como se detalla en la sección 7, Opción 1.

### Permisos insuficientes para iptables

Si encuentras errores relacionados con permisos al ejecutar comandos iptables:

```
Permission denied: iptables
```

**Solución**: Verificar que el usuario www-data tenga los permisos sudo necesarios:

```bash
sudo grep www-data /etc/sudoers
```

Si no aparece la configuración, añádela:

```bash
sudo visudo
```

Y agrega:

```
www-data ALL=(ALL) NOPASSWD: /sbin/iptables
```

### Problemas de acceso a logs de Apache

Si el script no puede acceder a los logs de Apache:

```
No se pudo encontrar el archivo de logs
```

**Solución**: Verificar la ubicación de los logs y dar permisos:

```bash
sudo ls -la /var/log/apache2/
sudo usermod -a -G adm www-data  # Añadir www-data al grupo que puede leer logs
sudo systemctl restart apache2
```

## 12. Pruebas y verificación

### Verificar que la aplicación esté funcionando

```bash
sudo systemctl status apache2-webguardian.service
```

### Verificar logs de la aplicación

```bash
tail -f /var/www/webguardian/logs/api_logs.txt
```

### Verificar la sincronización de IPs bloqueadas

```bash
tail -f /var/log/ip_sync.log
```

### Verificar las reglas de iptables

```bash
sudo iptables -L INPUT -n | grep DROP
```

### Acceder a la interfaz web

Abre un navegador y accede a:

```
http://localhost/
```

Desde ahí podrás:
- Ver estadísticas generales
- Administrar la whitelist
- Ver logs de acceso y ataques
- Ver y gestionar IPs bloqueadas

---

## Resumen

Esta guía te ha mostrado cómo implementar WebGuardian en un servidor Apache en Kali Linux, incluyendo:

1. **Configuración básica** del servidor Apache
2. **Integración** con el monitoreo de logs de Apache
3. **Bloqueo de IPs** basado en detección de ataques
4. **Sincronización** de IPs bloqueadas con el firewall del sistema
5. **Interfaz web** para administración y monitoreo

WebGuardian proporciona una capa adicional de seguridad para tu servidor web, detectando y bloqueando automáticamente intentos de ataque como SQLi, XSS, Path Traversal y muchos otros.

```
[Visita el repositorio en GitHub](https://github.com/tu-usuario/WebGuardian) para obtener las últimas actualizaciones y más información.
```
