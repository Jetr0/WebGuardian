# 🛡️ WebGuardian - Documentación Técnica de Herramientas

Esta documentación describe todas las herramientas que intervienen en el funcionamiento del proyecto **WebGuardian**, incluyendo la API, el servidor Apache, redirecciones, detección de ataques y el control mediante IPtables.

---

## 🔧 Herramientas y tecnologías utilizadas

### 1. **Flask (Python 3)**
- Framework web usado para construir la API.
- Proporciona rutas `/check`, `/logs`, `/whitelist`, `/api/blocked_ips`.
- Se encarga de detectar SQLi, bloquear IPs, gestionar la whitelist y mostrar logs.

**Ruta:** `/var/www/html/webguardian/app.py`

**Comando para ejecutar manualmente:**
```bash
python3 app.py
```

---

### 2. **iptables**
- Sistema de filtrado de paquetes del kernel de Linux.
- Se usa para aplicar bloqueos de red en tiempo real a IPs detectadas como maliciosas por la API.

**Ejemplo de bloqueo:**
```bash
sudo iptables -A INPUT -s <IP> -j DROP
```

**Visualizar reglas activas:**
```bash
sudo iptables -L INPUT -n --line-numbers
```

---

### 3. **Apache2**
- Servidor web que sirve una página estática (`apache_site`) al exterior (puerto 80).
- Usa `mod_lua` para interceptar peticiones y redirigirlas internamente a la API antes de decidir si servir o rechazar.

**Archivo de configuración:**
```
/etc/apache2/sites-available/webguardian.conf
```

**Activación del sitio:**
```bash
sudo a2ensite webguardian
sudo systemctl reload apache2
```

---

### 4. **mod_lua**
- Módulo de Apache que permite enganchar scripts en Lua en el flujo de procesamiento.
- Utilizado en conjunto con `LuaHookAccessChecker` para inspeccionar las peticiones mediante `check_sqli.lua`.

**Instalación:**
```bash
sudo apt install libapache2-mod-lua
sudo a2enmod lua
```

**Hook definido en webguardian.conf:**
```apache
LuaHookAccessChecker /var/www/html/webguardian/check_sqli.lua access_check
```

---

### 5. **Lua + LuaSocket**
- Lenguaje ligero embebido en Apache.
- Utilizado para escribir el hook `access_check()` que consulta la API antes de permitir la petición.
- `socket.http` y `ltn12` permiten enviar peticiones HTTP desde Lua.

**Instalación:**
```bash
sudo apt install lua5.4 lua-socket
```

**Script:**
```
/var/www/html/webguardian/check_sqli.lua
```

---

## 🧩 Estructura del proyecto

```
/var/www/html/webguardian/
├── app.py                     # API en Flask
├── check_sqli.lua             # Hook de Apache (mod_lua)
├── apache_site/               # Página HTML servida por Apache
│   ├── index.html
│   └── style.css
├── static/                    # CSS compartido
│   └── style.css
├── templates/                 # HTML renderizado desde Flask
│   ├── index.html
│   ├── logs.html
│   └── whitelist.html
├── logs/                      # Logs del sistema
│   ├── api_logs.txt
│   ├── blocked_ips.txt
│   └── whitelist.txt
└── scripts/
    └── sync_blocked_ips.py    # Script opcional para sincronizar IPs
```

---

## 🔁 Flujo de funcionamiento

1. Cliente hace una petición HTTP a Apache.
2. Apache ejecuta `access_check()` vía Lua.
3. Lua construye una llamada a `http://127.0.0.1:5000/check?...`
4. Flask evalúa si hay SQLi → si lo hay, bloquea la IP (iptables) y responde 403.
5. Lua devuelve ese 403 a Apache → el acceso se deniega.

---

## 🔒 Seguridad

- **Flask solo escucha en 127.0.0.1** → no accesible desde otras máquinas.
- Toda validación pasa por Apache + Lua → solo permite acceso si no hay SQLi.
- La whitelist impide bloquear IPs internas (como `127.0.0.1` o `0.0.0.0`).

---

## ✅ Verificación de estado

```bash
# Apache
sudo systemctl status apache2

# WebGuardian (si está como servicio systemd)
sudo systemctl status webguardian

# Estado del puerto Flask
ss -tuln | grep :5000

# Estado de los logs
cat /var/www/html/webguardian/logs/api_logs.txt
```

---

© 2025 - Proyecto WebGuardian
