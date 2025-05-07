# WebGuardian: Sistema Avanzado de Protección Web

![Escudo de Seguridad](https://img.shields.io/badge/Security-Advanced-blue)
![Estado](https://img.shields.io/badge/Status-Active-green)
![Licencia](https://img.shields.io/badge/License-MIT-yellow)

## 🛡️ Descripción

WebGuardian es un sistema avanzado de protección para aplicaciones web, desarrollado en Python con Flask, que proporciona una solución robusta y efectiva contra múltiples vectores de ataque. Diseñado para integrarse con servidores Apache, WebGuardian ofrece monitoreo en tiempo real, detección inteligente de ataques, y bloqueo automático de IPs maliciosas.

## ✨ Características Principales

### Protección Multi-Vector
- **Inyección SQL (SQLi)** - Bloqueo de intentos de manipulación de consultas a bases de datos
- **Cross-Site Scripting (XSS)** - Prevención de inyección de código malicioso en el navegador
- **Path Traversal** - Protección contra acceso a directorios no autorizados
- **Inyección de Comandos** - Detección de intentos de ejecución de comandos maliciosos
- **Server-Side Request Forgery (SSRF)** - Bloqueo de peticiones a servicios internos no autorizados
- **Inyección de Cabeceras HTTP** - Prevención de manipulación de cabeceras
- **Inyección NoSQL** - Protección para bases de datos NoSQL

### Gestión Avanzada de IPs
- Bloqueo permanente de IPs mediante iptables
- Sistema de whitelist configurable
- Sincronización automática con el firewall del sistema
- Interfaz de administración para gestionar IPs bloqueadas

### Monitoreo y Registro
- Registro detallado de todos los eventos y ataques
- Panel de control web con estadísticas en tiempo real
- Monitoreo automático de logs de Apache
- Clasificación de ataques por tipo y severidad

### Interfaz Web
- Panel de control intuitivo para visualizar estadísticas
- Gestión de whitelist desde la interfaz
- Visualización de logs y eventos de seguridad
- Administración de IPs bloqueadas

## 🚀 Instalación

### Requisitos Previos
- Python 3.8+
- Apache 2.4+
- Kali Linux (recomendado) o distribución similar
- Privilegios sudo para configuración de iptables

### Instalación Rápida

1. **Clonar el repositorio:**
   ```bash
   git clone https://github.com/Jetr0/WebGuardian.git
   cd WebGuardian
   ```

2. **Instalar dependencias:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Configurar Apache:**
   ```bash
   sudo cp config/webguardian.conf /etc/apache2/sites-available/
   sudo a2ensite webguardian.conf
   sudo systemctl restart apache2
   ```

4. **Configurar permisos:**
   ```bash
   sudo bash scripts/setup_permissions.sh
   ```

5. **Iniciar el servicio:**
   ```bash
   sudo systemctl enable webguardian.service
   sudo systemctl start webguardian.service
   ```

Para una instalación detallada, consulta nuestra [Guía de Implementación Completa](docs/guia-implementacion.md).

## 🔧 Configuración

### Estructura de Directorios
```
webguardian/
├── app.py                 # Aplicación principal
├── templates/             # Plantillas HTML para la interfaz
├── logs/                  # Directorio para logs
├── scripts/               # Scripts de utilidades
└── config/                # Archivos de configuración
```

### Configuración Básica
La configuración principal se encuentra en el archivo `config/settings.py`:

```python
# Ejemplo de configuración personalizada
ATTACK_THRESHOLD = 5       # Intentos antes de bloqueo
RESET_TIME_MINUTES = 120   # Tiempo para resetear contador
DEFAULT_WHITELIST = ['127.0.0.1', '10.0.0.1']  # IPs en whitelist por defecto
```

### Personalización de Patrones de Ataque
Puedes personalizar los patrones de detección de ataques en el archivo `config/attack_patterns.py`.

## 🌐 Uso

### Interfaz Web
Después de la instalación, accede a la interfaz web:
```
http://tu-servidor/
```

### Endpoints Principales
- **/** - Panel principal con estadísticas
- **/logs** - Visualización de logs y eventos
- **/whitelist** - Gestión de IPs en whitelist
- **/test/<param>** - Endpoint para pruebas de detección
- **/api/blocked_ips** - API para obtener IPs bloqueadas

### Línea de Comandos
También puedes gestionar WebGuardian desde la línea de comandos:

```bash
# Ver estado del servicio
sudo systemctl status webguardian

# Ver logs en tiempo real
tail -f /var/www/webguardian/logs/api_logs.txt

# Verificar IPs bloqueadas
sudo iptables -L INPUT -n | grep DROP
```

## 📊 Monitoreo y Estadísticas

WebGuardian proporciona estadísticas detalladas sobre:
- Total de solicitudes procesadas
- Solicitudes bloqueadas
- IPs bloqueadas actualmente
- Distribución de ataques por tipo
- Tiempo desde el último ataque detectado

## 🔒 Mejores Prácticas de Seguridad

Para maximizar la efectividad de WebGuardian:

1. **Actualizaciones regulares:**
   - Mantén los patrones de ataque actualizados
   - Actualiza regularmente el sistema

2. **Gestión responsable de whitelist:**
   - Limita las IPs en whitelist al mínimo necesario
   - Revisa periódicamente las IPs permitidas

3. **Monitoreo activo:**
   - Configura alertas para eventos críticos
   - Revisa los logs regularmente

4. **Implementación en capas:**
   - Usa WebGuardian como parte de una estrategia de seguridad más amplia
   - Combina con otras herramientas de seguridad

## 🤝 Contribuciones

¡Las contribuciones son bienvenidas! Si quieres mejorar WebGuardian:

1. Haz fork del repositorio
2. Crea una rama para tu función (`git checkout -b feature/AmazingFeature`)
3. Realiza tus cambios y haz commit (`git commit -m 'Add some AmazingFeature'`)
4. Haz push a la rama (`git push origin feature/AmazingFeature`)
5. Abre un Pull Request

## 📄 Licencia

Distribuido bajo la Licencia MIT. Ver `LICENSE` para más información.

## 📧 Contacto

Pau Rico - paurg06@gmail.com

Enlace del proyecto: [https://github.com/Jetr0/WebGuardian](https://github.com/Jetr0/WebGuardian)

---

## ⚠️ Aviso Legal

WebGuardian es una herramienta de seguridad y debe utilizarse de manera responsable. Asegúrate siempre de tener la autorización adecuada antes de implementar en cualquier sistema. Los autores no asumen responsabilidad por el uso indebido de esta herramienta.