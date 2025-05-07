# Guía de Instalación de WebGuardian

Esta guía detalla paso a paso el proceso para instalar y configurar WebGuardian en un servidor Kali Linux. El sistema está diseñado para integrarse con Apache y proporcionar protección avanzada contra múltiples vectores de ataque.

## Requisitos Previos

- Kali Linux (o distribución similar basada en Debian)
- Python 3.8+
- Apache 2.4+
- Privilegios de superusuario (sudo)

## Pasos de Instalación

### 1. Actualizar el Sistema

```bash
sudo apt update
sudo apt upgrade -y
```

### 2. Instalar Dependencias

```bash
# Instalar Apache y módulos necesarios
sudo apt install apache2 libapache2-mod-wsgi-py3 python3-pip python3-venv -y

# Iniciar y habilitar Apache
sudo systemctl start apache2
sudo systemctl enable apache2
```

### 3. Clonar el Repositorio

```bash
# Clonar el repositorio en /var/www
sudo mkdir -p /var/www
cd /var/www
sudo git clone https://github.com/Jetr0/WebGuardian.git webguardian
sudo chown -R $USER:$USER /var/www/webguardian
```

### 4. Configurar Entorno Virtual e Instalar Dependencias

```bash
# Crear y activar entorno virtual
cd /var/www/webguardian
python3 -m venv venv
source venv/bin/activate

# Instalar dependencias
pip install -r requirements.txt
```

### 5. Configurar Estructura de Directorios

```bash
# Crear directorios necesarios
mkdir -p logs
mkdir -p static/css

# Copiar archivos CSS
cp assets/css/style.css static/css/
```

### 6. Configurar Permisos

```bash
# Ejecutar script de configuración de permisos
sudo bash scripts/setup_permissions.sh
```

Este script:
- Asigna los permisos correctos a los directorios
- Configura sudo para que www-data pueda ejecutar iptables
- Configura el acceso a los logs de Apache
- Instala el script de sincronización de IPs bloqueadas
- Configura el servicio para que las reglas de iptables persistan tras reinicios

### 7. Configurar Apache

```bash
# Copiar archivo de configuración de Apache
sudo cp config/webguardian.conf /etc/apache2/sites-available/

# Habilitar el sitio
sudo a2ensite webguardian.conf

# Recargar Apache
sudo systemctl reload apache2
```

### 8. Configurar Sistema como Servicio

```bash
# Copiar archivo de servicio
sudo cp config/webguardian.service /etc/systemd/system/

# Recargar daemon y habilitar servicio
sudo systemctl daemon-reload
sudo systemctl enable webguardian.service
sudo systemctl start webguardian.service
```

## Verificación de la Instalación

### 1. Comprobar Estado del Servicio

```bash
sudo systemctl status webguardian.service
```

Deberías ver algo como:
```
● webguardian.service - WebGuardian Web Protection Service
   Loaded: loaded (/etc/systemd/system/webguardian.service; enabled; vendor preset: enabled)
   Active: active (running) since...
```

### 2. Verificar Acceso Web

Abre un navegador y accede a:
```
http://localhost/
```

Deberías ver el panel de control de WebGuardian.

### 3. Verificar Logs

```bash
# Ver logs de la aplicación
tail -f /var/www/webguardian/logs/api_logs.txt

# Ver logs de Apache para WebGuardian
tail -f /var/log/apache2/webguardian-access.log
tail -f /var/log/apache2/webguardian-error.log
```

## Configuración Personalizada

### Modificar Patrones de Detección

Para personalizar los patrones de detección de ataques, edita el diccionario `ATTACK_PAYLOADS` en el archivo `app.py`:

```bash
nano /var/www/webguardian/app.py
```

### Ajustar Configuración

Puedes modificar parámetros como:
- `ATTACK_THRESHOLD`: Número de intentos antes de bloquear una IP
- `RESET_TIME_MINUTES`: Tiempo antes de resetear contadores
- `DEFAULT_WHITELIST`: IPs que siempre estarán permitidas

## Solución de Problemas

### Error: "No se pudo encontrar el archivo de logs de Apache"

Si aparece este error en los logs:

```bash
# Verificar ubicación correcta de logs de Apache
sudo find /var/log -name "access.log"

# Modificar la configuración en app.py para apuntar a la ubicación correcta
nano /var/www/webguardian/app.py
```

### Error: "Permission denied" con iptables

Si observas errores de permisos con iptables:

```bash
# Verificar configuración de sudoers
sudo grep www-data /etc/sudoers.d/webguardian

# Reconfigurar si es necesario
echo "www-data ALL=(ALL) NOPASSWD: /sbin/iptables, /sbin/iptables-save" | sudo tee /etc/sudoers.d/webguardian
sudo chmod 440 /etc/sudoers.d/webguardian
```

### Error al iniciar el servicio

```bash
# Revisar los logs del sistema
sudo journalctl -u webguardian.service

# Verificar permisos y propiedad
sudo chown -R www-data:www-data /var/www/webguardian
sudo chmod -R 755 /var/www/webguardian
```

## Consideraciones de Seguridad

- **Evitar falsos positivos**: Añade a la whitelist las IPs de servicios legítimos.
- **Monitoreo regular**: Revisa los logs regularmente para detectar posibles problemas.
- **Actualizaciones**: Mantén actualizado WebGuardian y sus dependencias.
- **Protección en capas**: Usa WebGuardian como parte de una estrategia de seguridad más amplia.

## Desinstalación

Si necesitas desinstalar WebGuardian:

```bash
# Detener y deshabilitar servicios
sudo systemctl stop webguardian.service
sudo systemctl disable webguardian.service

# Deshabilitar configuración de Apache
sudo a2dissite webguardian.conf
sudo systemctl reload apache2

# Eliminar archivos
sudo rm -rf /var/www/webguardian
sudo rm /etc/apache2/sites-available/webguardian.conf
sudo rm /etc/systemd/system/webguardian.service
sudo rm /etc/sudoers.d/webguardian

# Eliminar reglas de iptables (opcional - revisa cuidadosamente)
# sudo iptables -F
```

## Soporte

Para reportar problemas o solicitar asistencia:
- Crea un issue en el repositorio: https://github.com/Jetr0/WebGuardian/issues
- Contacta con el desarrollador: paurg06@gmail.com
