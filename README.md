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

## 📚 Índice de Documentación

| Archivo                | Descripción                                                                            |
| ---------------------- | -------------------------------------------------------------------------------------- |
| [`README.md`](#)       | Introducción general al proyecto y estructura del repositorio.                         |
| [`installation.md`](#) | Guía paso a paso para la instalación del sistema.                                      |
| [`Guide_config.md`](#) | Guía técnica de configuración, estructura del sistema, permisos, sincronización y más. |

---

## 🚀 Instalación Rápida (Resumen)

Para usuarios avanzados, aquí una visión general. Para detalles completos, consultar [`installation.md`](#):

```bash
# Clonar el repositorio y entrar en el directorio
sudo git clone https://github.com/Jetr0/WebGuardian.git /var/www/webguardian
cd /var/www/webguardian

# Crear entorno virtual e instalar dependencias
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Configurar permisos
sudo bash scripts/setup_permissions.sh

# Activar Apache y configurar servicio
sudo cp config/webguardian.conf /etc/apache2/sites-available/
sudo a2ensite webguardian.conf
sudo systemctl reload apache2
```

---

## 🌐 Acceso Web

Una vez instalado y en funcionamiento:

```
http://localhost/
```

Desde la interfaz podrás:

* Ver estadísticas de ataques
* Gestionar whitelist
* Desbloquear IPs bloqueadas
* Ver registros de eventos

---

## 🤝 Contribuciones

Las contribuciones están abiertas. Por favor, revisa las normas en `CONTRIBUTING.md` (próximamente).

## 📄 Licencia

Distribuido bajo la licencia MIT. Ver archivo `LICENSE` para más detalles.

## 📧 Contacto

**Autor:** Pau Rico
**Email:** [paurg06@gmail.com](mailto:paurg06@gmail.com)
**Repositorio oficial:** [https://github.com/Jetr0/WebGuardian](https://github.com/Jetr0/WebGuardian)

---

> Para continuar con la instalación detallada, consulta [`installation.md`](#)
> Para configuración técnica completa, ver [`Guide_config.md`](#)