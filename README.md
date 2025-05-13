# WebGuardian: Sistema de Protección Web Avanzado

![Estado](https://img.shields.io/badge/Status-Activo-green)
![Licencia](https://img.shields.io/badge/License-MIT-yellow)

## 🛡️ Descripción General

WebGuardian es un sistema avanzado de seguridad web desarrollado en Python con Flask, diseñado para actuar como un WAF (Web Application Firewall). Su objetivo es detectar, registrar y bloquear ataques web en tiempo real, integrándose directamente con servidores Apache en sistemas Debian (como Kali Linux).

### Características principales:
- **Detección de ataques en tiempo real**: SQLi, XSS, LFI, SSRF, entre otros.
- **Bloqueo automático de IPs maliciosas** mediante `iptables`.
- **Interfaz web intuitiva** para monitoreo y gestión de eventos de seguridad.
- **Gestión de whitelist** para IPs confiables.
- **Integración con Apache mediante WSGI**.
- **Sincronización automática** de IPs bloqueadas con el firewall del sistema.

---

## 📁 Estructura del Proyecto

```plaintext
webguardian/
├── app.py                # Aplicación principal (detección de ataques)
├── API.py                # API y monitoreo de logs
├── templates/            # HTML: index, logs, whitelist
├── static/css/           # Estilos visuales
├── logs/                 # Archivos de registro
├── scripts/              # sync_blocked_ips.py, setup_permissions.sh
├── config/               # Archivos .conf y .service
├── webguardian.wsgi      # Entrada WSGI para Apache
```

---

## 🚀 Instalación

### Requisitos del sistema:
- **Sistema operativo**: Debian-based (Kali Linux recomendado)
- **Python**: Versión 3.8 o superior
- **Apache**: Versión 2.4 o superior
- **Privilegios sudo**

### Pasos de instalación:

1. **Actualizar el sistema**:
   ```bash
   sudo apt update && sudo apt upgrade -y
   ```

2. **Instalar dependencias necesarias**:
   ```bash
   sudo apt install apache2 libapache2-mod-wsgi-py3 python3-pip python3-venv git -y
   ```

3. **Clonar el repositorio**:
   ```bash
   cd /var/www
   sudo git clone https://github.com/Jetr0/WebGuardian.git webguardian
   ```

4. **Crear entorno virtual e instalar dependencias**:
   ```bash
   cd webguardian
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```

5. **Configurar permisos**:
   ```bash
   sudo bash scripts/setup_permissions.sh
   ```

6. **Configurar Apache y WSGI**:
   ```bash
   sudo cp config/webguardian.conf /etc/apache2/sites-available/
   sudo a2ensite webguardian.conf
   sudo systemctl reload apache2
   ```

---

## 🌐 Acceso Web

Una vez instalado correctamente, accede a la aplicación desde tu navegador en la dirección configurada en `webguardian.conf` (por defecto: `http://webguardian.local`).

---

## 🛠️ Desinstalación

Para eliminar WebGuardian de tu sistema:
1. Deshabilitar el sitio en Apache:
   ```bash
   sudo a2dissite webguardian.conf
   sudo systemctl reload apache2
   ```

2. Eliminar archivos y directorios:
   ```bash
   sudo rm -rf /var/www/webguardian
   sudo rm /etc/apache2/sites-available/webguardian.conf
   ```

3. Eliminar reglas de iptables y configuraciones adicionales según sea necesario.

---

## 📄 Licencia

Este proyecto está licenciado bajo la licencia MIT. Consulta el archivo `LICENSE` para más detalles.

---

## 📧 Soporte

Para reportar problemas o sugerencias, abre un issue en el [repositorio oficial](https://github.com/Jetr0/WebGuardian/issues).