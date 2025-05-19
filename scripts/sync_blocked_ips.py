#!/usr/bin/env python3
"""
Script para sincronizar IPs bloqueadas desde WebGuardian a las reglas de iptables locales.
Este script consulta la API de WebGuardian, obtiene las IPs bloqueadas y
las aplica al firewall local.
"""

import os
import sys
import requests
import subprocess
import json
import re
import logging
from datetime import datetime

# Configuraci  n
API_URL = "http://localhost:5000/api/blocked_ips"  # URL de la API que devuelve IPs bloqueadas
LOG_FILE = "/var/log/webguardian/ip_sync.log"
BLOCKED_IPS_FILE = "/etc/webguardian/blocked_ips.txt"

# Configurar logging
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def ensure_directories():
    """Asegura que existan los directorios necesarios"""
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    os.makedirs(os.path.dirname(BLOCKED_IPS_FILE), exist_ok=True)

def get_blocked_ips():
    """Obtiene la lista de IPs bloqueadas desde la API"""
    try:
        response = requests.get(API_URL)
        if response.status_code == 200:
            return response.json()
        else:
            logging.error(f"Error al obtener IPs bloqueadas. C  digo: {response.status_code}")
            return None
    except Exception as e:
        logging.error(f"Error de conexi  n a la API: {str(e)}")
        return None

def get_local_blocked_ips():
    """Obtiene las IPs actualmente bloqueadas en iptables"""
    try:
        cmd = "sudo iptables -L INPUT -n | grep DROP"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)

        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        ips = re.findall(ip_pattern, result.stdout)
        return ips
    except Exception as e:
        logging.error(f"Error al obtener IPs bloqueadas localmente: {str(e)}")
        return []

def save_blocked_ips(ips):
    """Guarda la lista de IPs bloqueadas en un archivo para referencia"""
    try:
        with open(BLOCKED_IPS_FILE, 'w') as f:
            for ip in ips:
                f.write(f"{ip}\n")
        return True
    except Exception as e:
        logging.error(f"Error al guardar IPs bloqueadas: {str(e)}")
        return False

def block_ip(ip):
    """Bloquea una IP usando iptables"""
    try:
        # Verificar si la IP ya est   bloqueada
        check_cmd = f"sudo iptables -L INPUT -n | grep {ip}"
        result = subprocess.run(check_cmd, shell=True, capture_output=True, text=True)

        if ip in result.stdout:
            logging.info(f"IP {ip} ya est   bloqueada.")
            return True

        # Bloquear la IP
        block_cmd = f"sudo iptables -A INPUT -s {ip} -j DROP"
        subprocess.run(block_cmd, shell=True, check=True)

        logging.info(f"IP {ip} bloqueada exitosamente.")
        return True
    except Exception as e:
        logging.error(f"Error al bloquear IP {ip}: {str(e)}")
        return False

def unblock_ip(ip):
    """Desbloquea una IP eliminando la regla de iptables"""
    try:
        unblock_cmd = f"sudo iptables -D INPUT -s {ip} -j DROP"
        subprocess.run(unblock_cmd, shell=True, check=True)

        logging.info(f"IP {ip} desbloqueada.")
        return True
    except Exception as e:
        logging.error(f"Error al desbloquear IP {ip}: {str(e)}")
        return False

def save_iptables():
    """Guarda las reglas de iptables para que persistan despu  s de reiniciar"""
    try:
        save_cmd = "sudo iptables-save > /etc/iptables/rules.v4"
        subprocess.run(save_cmd, shell=True, check=True)

        logging.info("Reglas de iptables guardadas correctamente.")
        return True
    except Exception as e:
        logging.error(f"Error al guardar reglas de iptables: {str(e)}")
        return False

def sync_blocked_ips():
    """Funci  n principal para sincronizar IPs bloqueadas"""
    logging.info("Iniciando sincronizaci  n de IPs bloqueadas")

    # Obtener IPs bloqueadas de la API
    api_blocked_ips = get_blocked_ips()
    if api_blocked_ips is None:
        logging.error("No se pudieron obtener las IPs bloqueadas de la API")
        return False

    local_blocked_ips = get_local_blocked_ips()

    ips_to_block = [ip for ip in api_blocked_ips if ip not in local_blocked_ips]

    ips_to_unblock = [ip for ip in local_blocked_ips if ip not in api_blocked_ips]

    for ip in ips_to_block:
        block_ip(ip)

    for ip in ips_to_unblock:
        unblock_ip(ip)

    if ips_to_block or ips_to_unblock:
        save_iptables()
        save_blocked_ips(api_blocked_ips)

    logging.info(f"Sincronizacion completada. {len(ips_to_block)} IPs bloqueadas, {len(ips_to_unblock)} IPs desbloqueadas.")
    return True

if __name__ == "__main__":
    ensure_directories()
    sync_blocked_ips()