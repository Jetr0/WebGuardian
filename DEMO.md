WebGuardian: Instalación y Configuración
Instalación de Apache y dependencias
Instalamos Apache
bash# Como root, instalamos Apache2
apt install apache2
# Salida muestra paquetes que se instalarán:
# apache2, apache2-data, ldap-utils, apache2-bin, apache2-utils, liblbdap-common, libldap2
# Se instalarán 6 paquetes, se eliminarán 0, no se actualizarán 2114
# Tamaño de descarga: 0 B / 2370 kB
# Espacio necesario: 650 kB / 4531 MB disponible
Instalamos las dependencias
bash# Instalamos los módulos necesarios para Apache y Python
apt install libapache2-mod-wsgi-py3 python3-pip -y
# Se instalan automáticamente varios paquetes incluyendo:
# fonts-liberation2, libgfpc0, libpython3.11-dev
# libverbs-providers, libgfxdr0, librados2
# libarmadillo12, libglusterfs0, librdmacm1
# libblosc2-3, libhdf5-103-1.14, libsuperlu6
# libboost-iostreams1.83.0, libhdf5-hl-100hl64, python3-lib2to3
# libboost-thread1.83.0, libibverbs1, python3.11
# libcephfs2, liblbfgs0, python3.11-dev
# libgdal34164, libnetcdf19t64, python3.11-minimal
# libgfapi0, libopenmpi3, samba-vfs-modules
Habilitamos y arrancamos Apache2
bash# Verificamos el estado de Apache
systemctl status apache2
# Salida muestra:
# apache2.service - The Apache HTTP Server
#   Loaded: loaded (/usr/lib/systemd/system/apache2.service; enabled; preset: enabled)
#   Active: active (running) since Fri 2025-04-04 17:45:03 CEST; 10s ago
# ...múltiples líneas de información sobre el proceso...
# Apr 04 17:45:02 vbox systemd[1]: Starting apache2.service - The Apache HTTP Server...
# Apr 04 17:45:03 vbox systemd[1]: Started apache2.service - The Apache HTTP Server...
Configuración inicial de WebGuardian
Creamos la estructura de directorios
bash# Creamos el directorio principal
mkdir -p /var/www/webguardian

# Establecemos los permisos adecuados
chown -R $USER:$USER /var/www/webguardian

# Creamos las carpetas para logs, templates y archivos estáticos
mkdir -p /var/www/webguardian/logs
mkdir -p /var/www/webguardian/templates
mkdir -p /var/www/webguardian/static
Creamos el archivo principal app.py
bash# Creamos el archivo app.py
nano /var/www/webguardian/app.py
Añadimos el siguiente contenido inicial:
python#!/usr/bin/env python3
import sys
import logging

# Configurar logging
logging.basicConfig(stream=sys.stderr)

# Añadir la ruta de la aplicación
sys.path.insert(0, '/var/www/webguardian/')

# Importar la aplicación
from app import app as application
Configuramos los archivos de plantillas HTML
Archivo index.html
bash# Creamos el archivo de la plantilla principal
nano /var/www/webguardian/templates/index.html
Archivo logs.html
bash# Creamos la plantilla para visualizar logs
nano /var/www/webguardian/templates/logs.html
Archivo whitelist.html
bash# Creamos la plantilla para gestionar la whitelist
nano /var/www/webguardian/templates/whitelist.html
Configuración del archivo API
bash# Añadimos el código principal de la API
# El código completo está en el archivo API.py proporcionado
Configuración del archivo de Apache
bash# Creamos el archivo de configuración de Apache para WebGuardian
nano /etc/apache2/sites-available/webguardian.conf
Añadimos la siguiente configuración:
apache<VirtualHost *:80>
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
Creamos el archivo de requisitos
bash# Creamos el archivo de requisitos
nano /var/www/webguardian/requirements.txt
Añadimos las dependencias:
flask==2.0.1
werkzeug==2.0.1
Instalamos las dependencias de Python
bash# Activamos el entorno virtual (si se está usando) e instalamos los requisitos
pip install -r requirements.txt
# Salida muestra la instalación de:
# flask==2.0.1, werkzeug==2.0.1, jinja2>=3.0, itsdangerous>=2.0, click>=7.1.2, MarkupSafe>=2.0
Configuramos los permisos apropiados
bash# Establecemos los permisos correctos
chown -R www-data:www-data /var/www/webguardian
chmod -R 755 /var/www/webguardian
chmod -R 775 /var/www/webguardian/logs

# Configuramos sudo para permitir iptables sin contraseña
# Añadimos a visudo:
www-data ALL=(ALL) NOPASSWD: /sbin/iptables
Configuramos Apache
bash# Habilitamos el sitio y deshabilitamos el sitio por defecto
a2ensite webguardian.conf
# Salida: Site webguardian already enabled

a2dissite 000-default.conf
# Salida: Site 000-default already disabled

# Reiniciamos Apache para aplicar los cambios
systemctl restart apache2
Configuramos el servicio para inicio automático
bash# Creamos un archivo de servicio para systemd
nano /etc/systemd/system/apache2-webguardian.service
Añadimos la siguiente configuración:
ini[Unit]
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
Habilitamos el servicio
bash# Habilitamos el servicio para que se inicie automáticamente
systemctl enable apache2-webguardian.service
Terminamos la configuración
Con estos pasos, hemos completado la instalación básica de WebGuardian. El sistema está ahora configurado para proteger automáticamente contra varios tipos de ataques web, incluyendo:

Inyección SQL (SQLi)
Cross-Site Scripting (XSS)
Inyección de comandos
Path Traversal
Server-Side Request Forgery (SSRF)
Inyección de cabeceras HTTP
Inyección NoSQL

El panel de administración está disponible en:

http://localhost:5000/ (página principal)
http://localhost:5000/logs (visualización de logs)
http://localhost:5000/whitelist (gestión de IPs permitidas)

El sistema monitorizará automáticamente los logs de Apache y bloqueará IPs que muestren comportamiento malicioso.