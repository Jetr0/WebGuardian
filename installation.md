# WebGuardian 2025 — Guía de Instalación (Static + API)

> **Arquitectura final**  
> **Apache :80** ⇒ solo ficheros estáticos (HTML + CSS + JS)  
> **Flask API :5000** ⇒ lógica de WAF, bloqueo de IPs, estadísticas

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
sudo mkdir -p /opt/webguardian
sudo chown $USER /opt/webguardian
cd /opt/webguardian
git clone https://github.com/tu-usuario/webguardian.git .
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt     # incluye flask, flask-cors, psutil, etc.
```

### 3.2 Copia el front‑end estático a Apache
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
# /etc/systemd/system/webguardian-api.service
[Unit]
Description=WebGuardian Flask API (port 5000)
After=network.target

[Service]
User=www-data
Group=www-data
WorkingDirectory=/opt/webguardian
Environment="PATH=/opt/webguardian/venv/bin"
ExecStart=/opt/webguardian/venv/bin/python api.py
Restart=always

[Install]
WantedBy=multi-user.target
```
Habilita y arranca:
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now webguardian-api
```

### 3.5 Permisos y reglas iptables
Ejecuta el helper:
```bash
sudo bash setup_permissions.sh   # añade sudoers para iptables, persiste reglas, etc.
```

### 3.6 Sincronizador de IPs bloqueadas
Instálalo como **timer** systemd (recomendado):
`/etc/systemd/system/webguardian-sync.service`
```ini
[Unit]
Description=Sync blocked IPs with iptables
After=network.target

[Service]
Type=oneshot
WorkingDirectory=/opt/webguardian
ExecStart=/opt/webguardian/venv/bin/python sync_blocked_ips.py
```
`/etc/systemd/system/webguardian-sync.timer`
```ini
[Unit]
Description=Run WebGuardian sync every 5 min

[Timer]
OnBootSec=2min
OnUnitActiveSec=5min

[Install]
WantedBy=timers.target
```
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now webguardian-sync.timer
```
---

## 4. Comprobaciones rápidas

1. **Apache**: `curl -I http://localhost/` → `200 OK` (debe devolver `index.html`).
2. **API**: `curl http://localhost:5000/api/stats` → JSON con estadísticas.
3. **CORS**: abre el navegador en `http://<host>/` y comprueba consola JS (sin errores `CORS`/`net::ERR`).
4. **Bloqueo de prueba**:
   ```bash
   curl http://localhost:5000/api/block/1.2.3.4
   sudo iptables -L -n | grep 1.2.3.4   # debería aparecer en la cadena DROP
   ```
5. **sync_blocked_ips**: `sudo systemctl status webguardian-sync.timer` y `...sync.service`.

---
## 5. Actualización del sistema

```bash
cd /opt/webguardian
sudo systemctl stop webguardian-api
source venv/bin/activate
git pull
pip install -r requirements.txt
sudo systemctl start webguardian-api
```

---
## 6. Troubleshooting

| Síntoma | Pista |
|---------|-------|
| `502 Bad Gateway` en navegador | La API no escucha; revisa `systemctl status webguardian-api`. |
| Logs JS vacíos | Verifica ruta `/api/logs` en el navegador, confirma permisos de lectura sobre los ficheros de log. |
| IP no se bloquea | Comprueba que `www-data` tiene permisos sudo para `iptables` sin contraseña (`/etc/sudoers.d/webguardian`). |

---
## 7. Próximos pasos

* Habilita HTTPS con Let’s Encrypt (certbot) y redirige 80 → 443.
* Activa geo‑blocking o rate‑limiting en la API.
* Añade autenticación (token/JWT) para endpoints críticos como `block`/`unblock`.

¡Listo! WebGuardian está operativo en modo **Apache estático + Flask API**.