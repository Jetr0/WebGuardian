#!/bin/bash
#
# Script para configurar permisos necesarios para WebGuardian
# Este script debe ejecutarse con sudo
#

# Comprobar si se ejecuta como root
if [ "$EUID" -ne 0 ]; then
  echo "Este script debe ejecutarse como root (con sudo)"
  exit 1
fi

echo "==================================================="
echo "  WebGuardian - Configuración de permisos"
echo "==================================================="

# Definir rutas
WEBGUARDIAN_DIR="/var/www/webguardian"
LOG_DIR="$WEBGUARDIAN_DIR/logs"
SUDOERS_FILE="/etc/sudoers.d/webguardian"
IPTABLES_RULES="/etc/iptables/rules.v4"
APACHE_LOG_DIR="/var/log/apache2"
SYNC_SCRIPT="/usr/local/bin/sync_blocked_ips.py"
SYSTEM_LOG_DIR="/var/log/webguardian"
SYSTEM_CONFIG_DIR="/etc/webguardian"

# Crear directorios necesarios
echo "Creando directorios necesarios..."
mkdir -p "$LOG_DIR"
mkdir -p "$SYSTEM_LOG_DIR"
mkdir -p "$SYSTEM_CONFIG_DIR"

# Configurar permisos de directorios
echo "Configurando permisos de directorios..."
chown -R www-data:www-data "$WEBGUARDIAN_DIR"
chmod -R 755 "$WEBGUARDIAN_DIR"
chmod -R 775 "$LOG_DIR"
chown -R www-data:www-data "$SYSTEM_LOG_DIR"
chmod -R 775 "$SYSTEM_LOG_DIR"
chown -R www-data:www-data "$SYSTEM_CONFIG_DIR"
chmod -R 775 "$SYSTEM_CONFIG_DIR"

# Configurar acceso a logs de Apache
echo "Configurando acceso a logs de Apache..."
usermod -a -G adm www-data

# Crear regla en sudoers para permitir a www-data ejecutar iptables sin contraseña
echo "Configurando permisos de sudo para iptables..."
echo "www-data ALL=(ALL) NOPASSWD: /sbin/iptables, /sbin/iptables-save" > "$SUDOERS_FILE"
chmod 440 "$SUDOERS_FILE"

# Copiar y configurar script de sincronización de IPs
if [ -f "scripts/sync_blocked_ips.py" ]; then
    echo "Instalando script de sincronización de IPs..."
    cp "scripts/sync_blocked_ips.py" "$SYNC_SCRIPT"
    chmod +x "$SYNC_SCRIPT"
    chown root:root "$SYNC_SCRIPT"
    
    # Crear una entrada en crontab para ejecutar el script cada 5 minutos
    echo "Configurando cron para sincronización de IPs..."
    CRON_JOB="*/5 * * * * python3 $SYNC_SCRIPT"
    (crontab -l 2>/dev/null | grep -v "$SYNC_SCRIPT"; echo "$CRON_JOB") | crontab -
fi

# Asegurar que el directorio para las reglas de iptables exista
if [ ! -d "/etc/iptables" ]; then
    echo "Creando directorio para reglas de iptables..."
    mkdir -p /etc/iptables
fi

# Guardar reglas actuales de iptables si no existe el archivo
if [ ! -f "$IPTABLES_RULES" ]; then
    echo "Guardando reglas actuales de iptables..."
    iptables-save > "$IPTABLES_RULES"
fi

# Crear servicio systemd para que las reglas de iptables persistan tras reinicios
echo "Configurando reglas persistentes de iptables..."
cat > /etc/systemd/system/iptables-restore.service << EOF
[Unit]
Description=Restore iptables rules
Before=network.target

[Service]
Type=oneshot
ExecStart=/sbin/iptables-restore < $IPTABLES_RULES
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

# Habilitar el servicio
systemctl daemon-reload
systemctl enable iptables-restore.service

echo "==================================================="
echo "  Permisos configurados correctamente"
echo "==================================================="
echo "- Permisos para www-data configurados"
echo "- Permiso sudo para iptables otorgado"
echo "- Permisos para logs configurados"
if [ -f "$SYNC_SCRIPT" ]; then
    echo "- Script de sincronización de IPs instalado"
    echo "- Cron para sincronización configurado"
fi
echo "- Reglas de iptables persistentes configuradas"
echo "==================================================="
echo "WebGuardian está listo para funcionar con los permisos adecuados."