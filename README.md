
# 📘 Manual de Instalación: **WebGuardian**
> Sistema de protección contra SQL Injection para servidores web Apache

---

## 🔐 ¿Qué es WebGuardian?

WebGuardian es un **WAF (Web Application Firewall) casero** que:

- Protege **Apache** contra ataques SQLi.
- Analiza todas las peticiones **antes de servir contenido**.
- Usa **iptables** para bloquear IPs maliciosas.
- Ofrece una **interfaz de control local** (API Flask) para gestionar logs y whitelist.
- Utiliza un script **Lua** para interceptar peticiones y consultar la API.

---

## 📦 Requisitos

- Kali Linux o Debian con:
  - Apache2
  - Python 3.7+
  - `iptables`
  - `lua-socket`
- Acceso sudo/root

---

## 🗂️ Estructura del proyecto

```
/var/www/html/webguardian/
│
├── app.py                         # API WAF (solo accesible localmente)
├── templates/                     # HTML para logs, whitelist, index
├── static/style.css               # Estilo visual compartido
├── logs/                          # Logs, IPs bloqueadas, whitelist
├── scripts/sync_blocked_ips.py    # Sincronizador opcional con iptables
├── apache_site/index.html         # Página web servida por Apache
├── apache_site/style.css
└── check_sqli.lua                 # Hook Lua para validar peticiones
```

---

## ⚙️ Instalación paso a paso

### 1. 📥 Descargar y ubicar WebGuardian

```bash
sudo unzip WebGuardian.zip -d /var/www/html/
sudo mv /var/www/html/webguardian /var/www/html/webguardian
```

### 2. 🔧 Instalar dependencias

```bash
sudo apt update
sudo apt install apache2 libapache2-mod-lua python3-pip iptables-persistent lua-socket -y
pip3 install flask requests
```

### 3. 🧠 Activar módulos necesarios de Apache

```bash
sudo a2enmod lua
sudo systemctl restart apache2
```

### 4. 🛡️ Crear el hook Lua (`check_sqli.lua`)

Guarda en:
```
/var/www/html/webguardian/check_sqli.lua
```

```lua
function access_check(r)
    local uri = r.unparsed_uri
    local ip = r.useragent_ip

    local http = require("socket.http")
    local ltn12 = require("ltn12")

    local response_body = {}
    local api_url = "http://127.0.0.1:5000/check?uri=" .. uri .. "&ip=" .. ip

    local res, code = http.request{
        url = api_url,
        sink = ltn12.sink.table(response_body)
    }

    if code == 403 then
        r:err("Bloqueado por WebGuardian: " .. ip)
        return 403
    end

    return apache2.DECLINED
end
```

### 5. 🧩 Configurar Apache (`webguardian.conf`)

Crea o edita:

```
/etc/apache2/sites-available/webguardian.conf
```

```apache
<VirtualHost *:80>
    ServerName localhost

    DocumentRoot /var/www/html/webguardian/apache_site
    LuaHookAccessChecker /var/www/html/webguardian/check_sqli.lua access_check

    <Directory /var/www/html/webguardian/apache_site>
        Require all granted
    </Directory>

    ErrorLog ${APACHE_LOG_DIR}/webguardian_error.log
    CustomLog ${APACHE_LOG_DIR}/webguardian_access.log combined
</VirtualHost>
```

Luego:

```bash
sudo a2ensite webguardian.conf
sudo systemctl reload apache2
```

### 6. 🚦 Iniciar la API de WebGuardian

Edita `app.py`:

```python
app.run(host='127.0.0.1', port=5000)
```

Crea el servicio:

```bash
sudo nano /etc/systemd/system/webguardian.service
```

```ini
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
```

Activa y lanza el servicio:

```bash
sudo systemctl daemon-reload
sudo systemctl enable webguardian.service
sudo systemctl start webguardian.service
```

### 7. 🔁 Sincronización opcional de IPs bloqueadas

```bash
sudo crontab -e
```

Añadir:

```bash
*/2 * * * * /usr/bin/python3 /var/www/html/webguardian/scripts/sync_blocked_ips.py
```

---

## ✅ Pruebas

### ✔️ Acceso limpio

```bash
curl "http://localhost/index.html"
```

✔️ Apache responde.

### 🚫 Acceso con ataque SQLi

```bash
curl "http://localhost/index.html?id=1' OR '1'='1"
```

❌ Apache devuelve `403 Forbidden`  
✅ IP es bloqueada por WebGuardian  
✅ Log en `/var/www/html/webguardian/logs/api_logs.txt`

---

## 🔍 Interfaz local de administración (solo desde Kali)

```
http://localhost:5000/logs
http://localhost:5000/whitelist
```

---

## 🔐 Seguridad adicional

- Flask solo escucha en `127.0.0.1`
- Solo Apache accede a la API para validación
- IPs maliciosas son bloqueadas a nivel de red

---

## 🧼 Desbloquear IPs

Desde el panel: `http://localhost:5000/logs`  
O manualmente:

```bash
sudo iptables -D INPUT -s <IP> -j DROP
```
