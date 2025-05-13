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
2. [Instalación](#instalación)
3. [Estructura del Proyecto](#estructura-del-proyecto)
4. [Configuración de Apache](#configuración-de-apache)
5. [Permisos del Sistema](#permisos-del-sistema)
6. [Sincronización con iptables](#sincronización-con-iptables)
7. [Interfaz Web](#interfaz-web)
8. [Solución de Problemas](#solución-de-problemas)
9. [Prácticas Recomendadas de Seguridad](#prácticas-recomendadas-de-seguridad)
10. [Desinstalación](#desinstalación)
11. [Soporte](#soporte)

---

## Requisitos del Sistema

* Kali Linux (o Debian-based)
* Python 3.8+
* Apache 2.4+
* Privilegios sudo

---

## Instalación

### 1. Preparación del sistema

```bash
sudo apt update && sudo apt upgrade -y
```

### 2. Instalar dependencias necesarias

```bash
sudo apt install apache2 libapache2-mod-wsgi-py3 python3-pip python3-venv -y
```

### 3. Clonar el proyecto

```bash
sudo mkdir -p /var/www
cd /var/www
sudo git clone https://github.com/Jetr0/WebGuardian.git webguardian
sudo chown -R $USER:$USER /var/www/webguardian
```

### 4. Crear entorno virtual e instalar requisitos

```bash
cd /var/www/webguardian
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 5. Estructura de directorios y archivos estáticos

```bash
mkdir -p logs static/css
cp assets/css/style.css static/css/
```

### 6. Configurar permisos y servicios

```bash
sudo bash scripts/setup_permissions.sh
```

Esto:

* Asigna permisos correctos
* Configura sudoers para `www-data`
* Instala el script de sincronización
* Habilita persistencia de reglas iptables

### 7. Configurar Apache

```bash
sudo cp config/webguardian.conf /etc/apache2/sites-available/
sudo a2ensite webguardian.conf
sudo systemctl reload apache2
```

### 8. Configurar servicio systemd

```bash
sudo cp config/webguardian.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable webguardian.service
sudo systemctl start webguardian.service
```

---

## Estructura del Proyecto

```
webguardian/
├── app.py                # Aplicación principal
├── API.py                # API RESTful y monitoreo de Apache
├── templates/            # HTML de interfaz
├── static/css/           # Estilos
├── logs/                 # Registros de actividad
├── scripts/              # Scripts como sync_blocked_ips.py
├── config/               # Configuraciones de Apache y systemd
```

---

## Configuración de Apache

Archivo principal: `config/webguardian.conf`

Contiene la configuración de WSGI y alias para estáticos. Asegúrate de que:

* El archivo `webguardian.wsgi` esté en `/var/www/webguardian/`
* La aplicación Flask exporte `app as application`

---

## Permisos del Sistema

Configurados por `scripts/setup_permissions.sh`. Incluye:

* Propietario `www-data` en todo `/var/www/webguardian`
* Permisos 755/775 en carpetas necesarias
* Acceso a logs de Apache
* Permiso para usar iptables sin contraseña

---

## Sincronización con iptables

El script `sync_blocked_ips.py` sincroniza las IPs bloqueadas vía API con las reglas locales.

* Se instala automáticamente en `/usr/local/bin/`
* Ejecutado cada 5 minutos por `cron`
* Alternativamente puedes usar `systemd`

Ver detalles en el mismo script.

---

## Interfaz Web

Disponible en:

```
http://localhost/
```

Permite:

* Ver estadísticas en tiempo real
* Ver y filtrar logs
* Gestionar IPs bloqueadas
* Gestionar whitelist

---

## Solución de Problemas

### ❌ Error con iptables (permission denied)

Verifica sudoers:

```bash
sudo cat /etc/sudoers.d/webguardian
```

### ❌ No aparecen logs

Revisar:

```bash
tail -f /var/www/webguardian/logs/api_logs.txt
```

### ❌ Error al iniciar servicio

```bash
sudo journalctl -u webguardian.service
```

---

## Prácticas Recomendadas de Seguridad

* Actualiza regularmente dependencias y reglas de detección
* Monitorea logs de forma activa
* Usa WebGuardian como parte de una arquitectura defensiva más amplia (HTTPS, IDS, etc.)
* Limita el uso de whitelist solo a IPs necesarias

---

## Desinstalación

Si necesitas eliminar WebGuardian completamente de tu sistema, sigue estos pasos:

```bash
# Detener y deshabilitar el servicio
sudo systemctl stop webguardian.service
sudo systemctl disable webguardian.service

# Eliminar configuración de Apache
sudo a2dissite webguardian.conf
sudo systemctl reload apache2

# Borrar archivos
sudo rm -rf /var/www/webguardian
sudo rm /etc/apache2/sites-available/webguardian.conf
sudo rm /etc/systemd/system/webguardian.service
sudo rm /etc/sudoers.d/webguardian

# (Opcional) Limpiar reglas iptables si deseas
# sudo iptables -F
```

> Asegúrate de revisar cada comando antes de ejecutarlo en entornos de producción.

---

## Soporte

Para sugerencias, contribuciones o problemas:

* Repositorio oficial: [https://github.com/Jetr0/WebGuardian](https://github.com/Jetr0/WebGuardian)
* Contacto directo: **Pau Rico** – [paurg06@gmail.com](mailto:paurg06@gmail.com)
* Licencia: MIT

> Regresa a la [introducción general](#webguardian-sistema-de-protección-web-avanzado)
