# Guía de Instalación – WebGuardian 2025 (Arquitectura Static + API)

> **Objetivo**: desplegar WebGuardian en un servidor Linux con **Apache (80)** sirviendo únicamente contenido estático –principalmente un pequeño *index.html* con Javascript– y la **API Flask (5000)** ejecutándose de forma independiente. De este modo evitamos ejecutar una segunda instancia de la API dentro de Apache y simplificamos la pila.

---

## Índice

1. Requisitos previos
2. Estructura de la solución
3. Instalación paso a paso
      3.1 Actualizar el sistema
      3.2 Instalar dependencias
      3.3 Clonar el repositorio
      3.4 Preparar el front‑end estático (80)
      3.5 Desplegar la API Flask (5000)
      3.6 Permisos de iptables y sincronización
4. Pruebas rápidas
5. Desinstalación
6. FAQ & Solución de problemas

---

## 1 · Requisitos previos

* **Debian 12 / Kali 2024.x** (o derivado).
* **Python 3.10+**
* **Apache 2.4+** (solo módulo core; *no* se necesita `mod_wsgi`).
* Privilegios **sudo/root** para configurar iptables y systemd.

---

## 2 · Estructura de la solución

```text
┌──────── Browser ────────┐      ➊ HTTP 80 (estático)
│   http(s)://host/       │ ─────────────────────────▶ Apache
└─────────────────────────┘                               │
                                             index.html + JS ↻
                                             redirect / fetch
                                             │
                                             ▼
                                   ➋ HTTP 5000 (REST)
                                 Flask API ─ gunicorn
                                 iptables, logs, …
```

* **Apache** se limita a servir ficheros dentro de `/var/www/webguardian/static_site`.
* **index.html** incorpora un pequeño script (p.e. `window.location="http://"+location.hostname+":5000/"`) o botones que apunten a `:5000`.
* La **API** corre con *gunicorn* (o `python3 app.py`) y administra el firewall.

---

## 3 · Instalación paso a paso

### 3.1 Actualizar el sistema

```bash
sudo apt update && sudo apt upgrade -y
```

### 3.2 Instalar dependencias mínimas

```bash
# Servidor web y utilidades
sudo apt install apache2 python3-venv python3-pip iptables-persistent -y
```

*No instalamos* `libapache2-mod-wsgi-py3` porque ya no lo necesitamos.

### 3.3 Clonar el repositorio

```bash
sudo mkdir -p /opt && cd /opt
sudo git clone https://github.com/Jetr0/WebGuardian.git webguardian
sudo chown -R $USER:$USER webguardian
```

### 3.4 Preparar el front‑end estático (80)

1. Crear el directorio de destino:

   ```bash
   sudo mkdir -p /var/www/webguardian/static_site
   ```
2. Copiar **index.html**, `style.css` y cualquier recurso que quieras mostrar:

   ```bash
   sudo cp webguardian/templates/index.html /var/www/webguardian/static_site/index.html
   sudo cp -r webguardian/static/css /var/www/webguardian/static_site/
   ```
3. Edita `index.html` o añade un `main.js` con la lógica deseada. Ejemplo de redirección automática:

   ```html
   <script>
     // Redirige tras 3 segundos al panel API
     setTimeout(() => {
       window.location = "http://"+location.hostname+":5000/";
     }, 3000);
   </script>
   ```
4. Configurar un vhost *solo estático*:

   ```apache
   # /etc/apache2/sites-available/webguardian-static.conf
   <VirtualHost *:80>
       ServerName webguardian.local
       DocumentRoot /var/www/webguardian/static_site
       <Directory /var/www/webguardian/static_site>
           Options -Indexes +FollowSymLinks
           Require all granted
       </Directory>
       ErrorLog ${APACHE_LOG_DIR}/wg-static-error.log
       CustomLog ${APACHE_LOG_DIR}/wg-static-access.log combined
   </VirtualHost>
   ```

   ```bash
   sudo a2dissite 000-default.conf
   sudo a2ensite webguardian-static.conf
   sudo systemctl reload apache2
   ```

### 3.5 Desplegar la API Flask (5000)

```bash
# Crear entorno virtual y dependencias
cd /opt/webguardian
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt

# Comprobación rápida
python3 API\ \(1\).py --port 5000   # CTRL‑C para salir
```

#### Sistema `systemd`

```ini
[Unit]
Description=WebGuardian Flask API
After=network.target

[Service]
User=www-data
WorkingDirectory=/opt/webguardian
Environment="PATH=/opt/webguardian/venv/bin"
ExecStart=/opt/webguardian/venv/bin/gunicorn -b 0.0.0.0:5000 'API (1):app'
Restart=always

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now webguardian-api
```

> **Nota**: ya no existe ningún `webguardian.wsgi` ni líneas `from app import app as application`.

### 3.6 Permisos de iptables y sincronización

Ejecuta el script incluido:

```bash
sudo bash /opt/webguardian/setup_permisions.sh
```

Esto añadirá a `www-data` los permisos sudo para `iptables`, creará los directorios de logs y programará `sync_blocked_ips.py` cada 5 minutos.

---

## 4 · Pruebas rápidas

```bash
# 1) Visita http://TU-SERVIDOR/  (estático)
# 2) Haz clic o espera la redirección y verifica http://TU-SERVIDOR:5000/
# 3) Lanza una prueba XSS:
curl "http://TU-SERVIDOR:5000/test/<script>alert(1)</script>"
# 4) Comprueba iptables:
sudo iptables -L INPUT -n | grep DROP
```

---

## 5 · Desinstalación

```bash
# Detener servicios
a2dissite webguardian-static.conf && systemctl reload apache2
systemctl disable --now webguardian-api.service && rm /etc/systemd/system/webguardian-api.service

# Borrar archivos (opcional)
rm -rf /opt/webguardian /var/www/webguardian/static_site
rm /etc/apache2/sites-available/webguardian-static.conf
rm /etc/sudoers.d/webguardian
iptables -F  # revisa antes de ejecutar
```

---

## 6 · FAQ & Solución de problemas

**P: Apache sigue mostrando la página de Debian.**
R: Asegúrate de haber deshabilitado `000-default.conf` y habilitado tu vhost.

**P: No puedo acceder a `:5000` externamente.**
R: Verifica que el cortafuegos (ufw/iptables) permita el puerto o usa Nginx/Apache como *reverse‑proxy* si prefieres no exponerlo.

**P: `sync_blocked_ips.py` lanza *Permission denied*.**
R: Confirma que `www-data` tiene entrada en `/etc/sudoers.d/webguardian`.

---

© 2025 WebGuardian · Licencia MIT