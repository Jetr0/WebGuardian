# 🛡️ WebGuardian

**WebGuardian** es un WAF (Web Application Firewall) casero diseñado para proteger un servidor Apache contra ataques por inyección SQL (SQLi). Se apoya en un hook Lua para interceptar peticiones HTTP y consultar una API Flask local que decide si se debe bloquear la IP mediante `iptables`.

---

## 📂 Estructura del proyecto

```
/var/www/html/webguardian/
├── apache_site/
│   ├── index.html
│   └── style.css
├── app.py                      # API Flask que detecta SQLi y gestiona logs, whitelist y bloqueo
├── check_sqli.lua              # Hook Lua que intercepta peticiones Apache
├── logs/
│   ├── api_logs.txt
│   ├── blocked_ips.txt
│   └── whitelist.txt
├── scripts/
│   ├── sync_blocked_ips.py     # Sincronizador opcional con iptables
│   └── restart_apache_loop.sh  # Bucle para reiniciar Apache cada 5 segundos (opcional)
├── static/
│   └── style.css
└── templates/
    ├── index.html
    ├── logs.html
    └── whitelist.html
```

---

## ⚙️ Requisitos

- Kali Linux o Debian
- Python 3.7+
- Apache2
- `iptables` y `iptables-persistent`
- `lua5.4`, `lua-socket`, `libapache2-mod-lua`

---

## 🔧 Instalación paso a paso

```bash
# 1. Instalar dependencias
sudo apt update
sudo apt install apache2 libapache2-mod-lua python3-pip iptables-persistent lua-socket -y
pip3 install flask requests

# 2. Crear estructura del proyecto (si no existe aún)
sudo mkdir -p /var/www/html/webguardian
cd /var/www/html/webguardian

# 3. Copiar o clonar los archivos del proyecto aquí

# 4. Configurar Apache
sudo tee /etc/apache2/sites-available/webguardian.conf > /dev/null <<EOF
<VirtualHost *:80>
    ServerName localhost
    DocumentRoot /var/www/html/webguardian/apache_site
    LuaHookAccessChecker /var/www/html/webguardian/check_sqli.lua access_check

    <Directory /var/www/html/webguardian/apache_site>
        Require all granted
    </Directory>

    ErrorLog \${APACHE_LOG_DIR}/webguardian_error.log
    CustomLog \${APACHE_LOG_DIR}/webguardian_access.log combined
</VirtualHost>
EOF

sudo a2enmod lua
sudo a2ensite webguardian
sudo systemctl reload apache2

# 5. Crear servicio systemd para la API Flask
sudo tee /etc/systemd/system/webguardian.service > /dev/null <<EOF
[Unit]
Description=WebGuardian WAF API
After=network.target

[Service]
ExecStart=/usr/bin/python3 /var/www/html/webguardian/app.py
WorkingDirectory=/var/www/html/webguardian
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable webguardian
sudo systemctl start webguardian
```

---

## 🔁 (Opcional) Reiniciar Apache cada 5 segundos

```bash
# Crear script de reinicio
sudo tee /usr/local/bin/restart_apache_loop.sh > /dev/null <<EOF
#!/bin/bash
while true; do
    systemctl restart apache2
    sleep 5
done
EOF

sudo chmod +x /usr/local/bin/restart_apache_loop.sh

# Añadir a cron con @reboot
(crontab -l 2>/dev/null; echo '@reboot /usr/local/bin/restart_apache_loop.sh &') | crontab -
```

---

## 🖥️ Interfaz web local (solo desde localhost)

- Panel principal: [http://localhost:5000/](http://localhost:5000/)
- Logs y estadísticas: [http://localhost:5000/logs](http://localhost:5000/logs)
- Gestión de whitelist: [http://localhost:5000/whitelist](http://localhost:5000/whitelist)

---

## 🧪 Pruebas

```bash
# 1. Prueba normal (debe devolver 200 OK)
curl "http://localhost/index.html"

# 2. Prueba con SQLi (debe devolver 403)
curl "http://localhost/index.html?id=1' OR '1'='1"
```

- ✔️ Apache devuelve 403 si hay patrón SQLi.
- ✔️ La IP es bloqueada vía iptables.
- ✔️ Aparece log en `/var/www/html/webguardian/logs/api_logs.txt`

---

## 🔐 Seguridad

- La API Flask solo escucha en `127.0.0.1`.
- Solo Apache puede consultarla internamente.
- El hook Lua valida cada petición antes de servir contenido.
- Las IPs bloqueadas son denegadas vía iptables.
- Las IPs en whitelist están protegidas contra bloqueo.

---

## 🧼 Desbloquear IP manualmente

```bash
# Desde el panel web: http://localhost:5000/logs
# O manualmente:
sudo iptables -D INPUT -s <IP> -j DROP
```

---

## 📎 Créditos

Desarrollado por **Pau Rico**  
© 2025 — WebGuardian Security Project