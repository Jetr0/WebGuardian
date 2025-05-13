# WebGuardian: Sistema de Protección Web Avanzado

![Estado](https://img.shields.io/badge/Status-Activo-green)
![Licencia](https://img.shields.io/badge/License-MIT-yellow)

## 🛡️ Descripción General

WebGuardian es un sistema avanzado de seguridad web desarrollado en Python con Flask, diseñado para actuar como un WAF (Web Application Firewall) que se instala directamente en un servidor con Apache y Kali Linux. Su función principal es detectar, registrar y bloquear ataques web en tiempo real utilizando `iptables` y proporcionando una interfaz de administración web.

Este repositorio contiene:

* Código fuente de la aplicación (`app.py`, `API.py`)
* Panel de administración web (`index.html`, `logs.html`, `whitelist.html`)
* Sistema de sincronización con firewall (`sync_blocked_ips.py`)
* Scripts de configuración (`setup_permissions.sh`)
* Archivos de configuración para Apache (`webguardian.conf`, `webguardian.wsgi`)

---

## 📚 Índice de Contenido

1. [Requisitos del Sistema](#requisitos-del-sistema)
2. [Instalación Completa Paso a Paso](#instalación-completa-paso-a-paso)
3. [Desinstalación](#desinstalación)
4. [Soporte](#soporte)

---

## Requisitos del Sistema

* Kali Linux (o Debian-based)
* Python 3.8+
* Apache 2.4+
* Privilegios sudo

---

## Instalación Completa Paso a Paso

### 1. Actualización del sistema

```bash
sudo apt update && sudo apt upgrade -y
```

### 2. Instalación de paquetes necesarios

```bash
sudo apt install apache2 libapache2-mod-wsgi-py3 python3-pip python3-venv git -y
```

### 3. Clonar el proyecto

```bash
cd /var/www/
sudo git clone https://github.com/Jetr0/WebGuardian.git webguardian
sudo chown -R $USER:$USER /var/www/webguardian
```

### 4. Crear entorno virtual e instalar dependencias

```bash
cd /var/www/webguardian
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 5. Crear estructura de carpetas adicional

```bash
mkdir -p logs static/css templates
cp assets/css/style.css static/css/
```

### 6. Crear archivo WSGI

```bash
nano /var/www/webguardian/webguardian.wsgi
```

Contenido:

```python
#!/usr/bin/env python3
import sys
import logging

logging.basicConfig(stream=sys.stderr)
sys.path.insert(0, '/var/www/webguardian/')

from app import app as application
```

### 7. Crear archivo de configuración de Apache

```bash
sudo nano /etc/apache2/sites-available/webguardian.conf
```

Contenido:

```apacheconf
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

    Alias /static /var/www/webguardian/static
    <Directory /var/www/webguardian/static>
        Require all granted
    </Directory>

    ErrorLog ${APACHE_LOG_DIR}/webguardian-error.log
    CustomLog ${APACHE_LOG_DIR}/webguardian-access.log combined
</VirtualHost>
```

### 8. Habilitar sitio en Apache

```bash
sudo a2ensite webguardian.conf
sudo a2dissite 000-default.conf
sudo systemctl reload apache2
```

### 9. Crear script de permisos y configuraciones automatizadas

```bash
nano /var/www/webguardian/scripts/setup_permissions.sh
```

(Pega contenido desde el script real del repositorio)

Dar permisos y ejecutarlo:

```bash
chmod +x scripts/setup_permissions.sh
sudo bash scripts/setup_permissions.sh
```

### 10. Crear servicio systemd para Apache con WebGuardian (opcional)

```bash
sudo nano /etc/systemd/system/webguardian.service
```

Contenido:

```ini
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
```

Activar e iniciar el servicio:

```bash
sudo systemctl daemon-reload
sudo systemctl enable webguardian.service
sudo systemctl start webguardian.service
```

### 11. Configurar sincronización de IPs bloqueadas

Asegúrate de tener el archivo `sync_blocked_ips.py` en:

```bash
/usr/local/bin/sync_blocked_ips.py
```

Si no existe:

```bash
sudo cp scripts/sync_blocked_ips.py /usr/local/bin/
sudo chmod +x /usr/local/bin/sync_blocked_ips.py
```

Programar ejecución con cron:

```bash
(crontab -l 2>/dev/null; echo "*/5 * * * * /usr/bin/python3 /usr/local/bin/sync_blocked_ips.py") | crontab -
```

---

## 
Si necesitas eliminar WebGuardian completamente de tu sistema, sigue estos pasos:


```bash
# Detener y deshabilitar el servicio
sudo systemctl stop webguardian.service
sudo systemctl disable webguardian.service

# Eliminar configuración de Apache
sudo a2dissite webguardian.conf
sudo systemctl reload apache2

# Borrar archivos del proyecto
sudo rm -rf /var/www/webguardian
sudo rm /etc/apache2/sites-available/webguardian.conf
sudo rm /etc/systemd/system/webguardian.service
sudo rm /etc/sudoers.d/webguardian
sudo rm /usr/local/bin/sync_blocked_ips.py

# (Opcional) Eliminar reglas iptables
# sudo iptables -F
```

---

## Soporte

Para sugerencias, contribuciones o problemas:

* Repositorio oficial: [https://github.com/Jetr0/WebGuardian](https://github.com/Jetr0/WebGuardian)
* Contacto directo: **Pau Rico** – [paurg06@gmail.com](mailto:paurg06@gmail.com)
* Licencia: MIT

> Regresa a la [introducción general](#webguardian-sistema-de-protección-web-avanzado)
