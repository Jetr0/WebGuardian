# 📚 Documentación Técnica - WebGuardian

**WebGuardian** es un WAF (Web Application Firewall) casero que protege aplicaciones web Apache contra ataques por inyección SQL (SQLi). Utiliza una API local en Flask, un hook Lua con `mod_lua`, y reglas `iptables` para bloquear IPs maliciosas en tiempo real.

---

## 🧩 Componentes del sistema

### 🔹 Apache2
- Sirve contenido estático desde `apache_site/`.
- Utiliza `mod_lua` para enganchar un script Lua antes de servir cualquier petición.
- Este script consulta la API local y decide si permitir o bloquear.

### 🔹 Lua + mod_lua
- Script `check_sqli.lua` intercepta todas las peticiones web externas.
- Extrae URI + IP del cliente.
- Llama a la API: `http://127.0.0.1:5000/check?uri=...&ip=...`.
- Si la API responde 403 → Apache deniega el acceso.

### 🔹 Flask (API)
- Corre en `127.0.0.1:5000`.
- Rutas principales:
  - `/check`: analiza una URI y decide si bloquear.
  - `/logs`: interfaz web para ver actividad, bloquear/desbloquear IPs.
  - `/whitelist`: gestión de IPs exentas de bloqueo.
  - `/unblock/<ip>`: elimina una IP bloqueada.
  - `/block_ip_manual`: bloquea una IP desde formulario.
  - `/api/blocked_ips`: devuelve IPs bloqueadas en formato JSON.

### 🔹 iptables
- IPs maliciosas se bloquean mediante:
  ```bash
  sudo iptables -A INPUT -s <IP> -j DROP
  ```
- Whitelist protege IPs como `127.0.0.1`, `0.0.0.0`, `localhost`.
- Soporte para `iptables-persistent` para mantener reglas tras reinicio.

---

## 📁 Estructura del proyecto

```
webguardian/
├── app.py
├── check_sqli.lua
├── apache_site/
│   ├── index.html
│   └── style.css
├── templates/
│   ├── index.html
│   ├── logs.html
│   └── whitelist.html
├── static/
│   └── style.css
├── logs/
│   ├── api_logs.txt
│   ├── blocked_ips.txt
│   └── whitelist.txt
├── scripts/
│   ├── sync_blocked_ips.py
│   └── restart_apache_loop.sh
└── README.md
```

---

## 🔐 Flujo de funcionamiento

1. Cliente accede a Apache (`puerto 80`).
2. Apache ejecuta `check_sqli.lua`.
3. Lua llama a la API local (Flask) en `puerto 5000`.
4. La API analiza la URI y decide si bloquear:
   - Detecta patrones SQLi.
   - Aplica lógica de whitelist.
   - Escribe logs.
   - Bloquea IP con `iptables` si es necesario.
5. Apache sirve o deniega la petición según la respuesta.

---

## 🛡️ Funcionalidad WAF

### ✔️ Detección de SQLi
- Uso de payloads reales de *PayloadsAllTheThings*.
- Coincidencias exactas y expresiones regulares.

### ✔️ Whitelist
- IPs internas o confiables no se bloquean nunca.
- Gestión desde `/whitelist`.

### ✔️ Logs
- Logs detallados en `logs/api_logs.txt`.
- Últimos intentos se visualizan en `/logs`.

### ✔️ Bloqueo manual
- Desde `/logs` puedes añadir una IP manualmente a iptables.
- También desbloquearla con un clic.

---

## 🌐 Panel de administración (solo localhost)

- `/` — Panel de estado
- `/logs` — Ver intentos, IPs bloqueadas, y añadir/bloquear manualmente
- `/whitelist` — Gestionar IPs exentas de bloqueo

---

## 🛠️ Scripts adicionales

### 🔁 `sync_blocked_ips.py`
- Sincroniza reglas iptables con el archivo `blocked_ips.txt`.
- Útil si reinicias sin `iptables-persistent`.

### 🔁 `restart_apache_loop.sh`
- Reinicia Apache cada 5 segundos (modo debug/pruebas).
- Puede activarse en crontab con `@reboot`.

---

## 🧪 Comprobación del sistema

```bash
# Apache
sudo systemctl status apache2

# API
sudo systemctl status webguardian

# Ver si puerto 5000 está activo
ss -tuln | grep :5000

# Últimos 50 logs
tail -n 50 /var/www/html/webguardian/logs/api_logs.txt
```

---

## 🧼 Desbloquear IPs

```bash
# Desde la interfaz web: /logs
# O manualmente:
sudo iptables -D INPUT -s <IP> -j DROP
```

---

## ✏️ Notas adicionales

- El sistema está pensado para ser accesible **solo desde localhost** en el backend.
- Apache es el único intermediario entre el exterior y la validación Lua+Flask.
- Se pueden añadir mejoras como backoff exponencial, geo-blocking, etc.

---

## 📦 Autor

Desarrollado por **Pau Rico**  
© 2025 — Proyecto WebGuardian