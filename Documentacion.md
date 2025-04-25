# WebGuardian: Sistema Avanzado de Protección Web - Documentación

## Índice de Contenidos
1. [Introducción](#introducción)
2. [Arquitectura del Sistema](#arquitectura-del-sistema)
3. [Guía de Instalación](#guía-de-instalación)
4. [Configuración](#configuración)
5. [Características de Seguridad Principales](#características-de-seguridad-principales)
6. [Interfaz de Usuario](#interfaz-de-usuario)
7. [Administración](#administración)
8. [Monitorización de Logs de Apache](#monitorización-de-logs-de-apache)
9. [Buenas Prácticas](#buenas-prácticas)
10. [Resolución de Problemas](#resolución-de-problemas)
11. [Referencia de API](#referencia-de-api)

## Introducción

WebGuardian es una solución integral de seguridad web diseñada para proteger aplicaciones web frente a una amplia gama de amenazas cibernéticas. Desarrollado con Python y Flask, proporciona monitorización en tiempo real, detección de ataques y capacidades de gestión de IPs.

### Características Principales

- **Detección de Ataques Multi-Vector**: Protección contra inyección SQL, XSS, atravesamiento de directorios, inyección de comandos, SSRF, inyección de cabeceras e inyección NoSQL
- **Gestión Dinámica de IPs**: Bloqueo automático de IPs maliciosas mediante iptables
- **Monitorización de Logs de Apache**: Análisis en tiempo real de los logs de acceso y error de Apache
- **Panel de Control Web**: Interfaz amigable para monitorización y administración
- **Registro Exhaustivo**: Registros detallados de todos los eventos de seguridad

## Arquitectura del Sistema

WebGuardian está estructurado en torno a varios componentes principales:

1. **Aplicación Web Flask**: El motor principal que procesa las peticiones HTTP y sirve la interfaz web
2. **Filtro Middleware**: Comprueba todas las peticiones entrantes para detectar posibles ataques
3. **Motor de Detección de Ataques**: Detección basada en patrones para diversos vectores de ataque
4. **Sistema de Gestión de IPs**: Gestiona la lista blanca y el bloqueo de direcciones IP
5. **Monitor de Logs de Apache**: Hilo en segundo plano que monitoriza continuamente los logs de Apache
6. **Seguimiento de Estadísticas**: Registra y muestra métricas de seguridad

### Diagrama de Flujo

```
Petición → Filtro Middleware → Detección de Ataques → Gestión de IPs → Respuesta
                     ↓
           Procesos en Segundo Plano
                     ↓
   Monitor de Logs de Apache ← Archivos de Log
```

## Guía de Instalación

### Requisitos Previos

- Python 3.8 o superior
- Framework Flask
- Acceso sudo (para la gestión de iptables)
- Servidor Web Apache (para la monitorización de logs)
- Sistema basado en Linux (preferiblemente Kali Linux o similar)

### Pasos de Instalación

1. **Clonar el repositorio:**
   ```bash
   git clone https://github.com/Jetr0/WebGuardian.git
   cd WebGuardian
   ```

2. **Instalar dependencias:**
   ```bash
   pip install flask
   ```

3. **Configurar permisos de iptables:**
   ```bash
   sudo visudo
   ```
   Añade la siguiente línea para permitir la gestión de iptables sin contraseña:
   ```
   tuusuario ALL=(ALL) NOPASSWD: /sbin/iptables, /sbin/iptables-save
   ```

4. **Iniciar la aplicación:**
   ```bash
   python API.py
   ```

La aplicación se iniciará en http://0.0.0.0:5000/

## Configuración

### Estructura de Directorios

WebGuardian crea y utiliza los siguientes directorios y archivos:

- `logs/`: Contiene todos los archivos de registro
  - `api_logs.txt`: Logs principales de la aplicación
  - `blocked_ips.txt`: Registro de direcciones IP bloqueadas
  - `whitelist.txt`: Lista de direcciones IP en lista blanca

### Configuración Predeterminada

- **Rutas de Logs de Apache**:
  - Log de acceso: `/var/log/apache2/access.log`
  - Log de errores: `/var/log/apache2/error.log`

- **Umbral de Ataques**: 3 intentos (configurable mediante `ATTACK_THRESHOLD`)
- **Tiempo de Reinicio**: 60 minutos (configurable mediante `RESET_TIME_MINUTES`)
- **Lista Blanca Predeterminada**: 127.0.0.1, 0.0.0.0, localhost, 10.1.101.52

## Características de Seguridad Principales

### Detección de Ataques

WebGuardian detecta ataques utilizando reconocimiento basado en patrones para múltiples vectores de ataque:

#### Inyección SQL (SQLi)
Detecta intentos de manipular consultas SQL con patrones como:
- Comillas simples (`'`)
- Comentarios SQL (`--`, `/*`, `*/`)
- Comandos SQL (`UNION SELECT`, `DROP TABLE`)
- Ataques basados en lógica (`OR 1=1`)

#### Cross-Site Scripting (XSS)
Identifica intentos de inyectar JavaScript malicioso:
- Etiquetas de script (`<script>`, `</script>`)
- Manejadores de eventos (`onload=`, `onerror=`)
- Funciones JavaScript (`alert(`, `eval(`)
- Caracteres codificados (`&#x`, `%3C`)

#### Atravesamiento de Directorios (Path Traversal)
Detecta intentos de acceder a directorios no autorizados:
- Secuencias de atravesamiento de directorios (`../`, `..\\`)
- Acceso a archivos del sistema (`/etc/passwd`, `C:\\Windows\\system.ini`)
- Manejadores de protocolo (`file:///`, `php://filter/`)

#### Inyección de Comandos
Identifica intentos de ejecutar comandos del sistema:
- Separadores de comandos (`|`, `&`, `;`, `&&`, `||`)
- Ejecutores de comandos (`` ` ``, `$()`)
- Comandos del sistema (`ping`, `whoami`, `wget`)
- Acceso a shell (`bash -i`, `cmd.exe`)

#### Server-Side Request Forgery (SSRF)
Detecta intentos de realizar peticiones desde el servidor:
- URLs internas (`http://localhost`, `http://127.0.0.1`)
- Servicios de metadatos (`https://169.254.169.254/`)
- Protocolos alternativos (`dict://`, `gopher://`)

#### Inyección de Cabeceras HTTP
Identifica intentos de manipular cabeceras HTTP:
- Campos de cabecera (`Host:`, `Content-Length:`)
- Cabeceras de suplantación (`X-Forwarded-For:`, `X-Remote-IP:`)

#### Inyección NoSQL
Detecta intentos de manipular bases de datos NoSQL:
- Operadores de consulta (`$where:`, `$ne:`, `$gt:`)
- Intentos de manipulación (`true, $where:`, `{\"$regex\":`)

### Gestión de IPs

WebGuardian gestiona las direcciones IP a través de tres mecanismos:

#### Bloqueo Automático
- Las IPs que superan el umbral de ataques son bloqueadas automáticamente
- El bloqueo se implementa utilizando iptables
- Los bloqueos persisten tras reinicios del sistema

#### Gestión de Lista Blanca
- Las IPs en lista blanca nunca son bloqueadas
- La lista blanca predeterminada incluye localhost y IPs internas comunes
- Se pueden añadir entradas personalizadas a la lista blanca a través de la interfaz web

#### Control Manual
- Los administradores pueden desbloquear manualmente IPs a través de la interfaz web
- Las entradas de la lista blanca pueden añadirse o eliminarse según sea necesario

## Interfaz de Usuario

WebGuardian proporciona una interfaz web con varias páginas clave:

### Panel Principal
- URL: http://0.0.0.0:5000/
- Muestra estadísticas y métricas de ataques
- Enlaces a funciones administrativas

### Vista de Logs
- URL: http://0.0.0.0:5000/logs
- Muestra entradas de log recientes
- Lista las IPs bloqueadas con opciones para desbloquear

### Gestión de Lista Blanca
- URL: http://0.0.0.0:5000/whitelist
- Añadir o eliminar IPs de la lista blanca
- Ver entradas actuales de la lista blanca

## Administración

### Gestión de Logs

WebGuardian registra toda la actividad en `logs/api_logs.txt`. Cada entrada de log incluye:
- Marca de tiempo
- Tipo de log (INFO o BLOQUEADO)
- Mensaje detallado sobre el evento

Ejemplos de entradas de log:
```
2023-05-15 14:32:45 - INFO - WebGuardian iniciado
2023-05-15 14:35:12 - BLOQUEADO - Ataque sqli detectado en parámetro URL 'search': 1' OR '1'='1 desde 192.168.1.25
```

### Seguimiento de Estadísticas

WebGuardian realiza un seguimiento de las siguientes métricas:
- Total de peticiones procesadas
- Peticiones bloqueadas
- IPs actualmente bloqueadas
- Recuento de ataques por tipo
- Marca de tiempo de la petición más reciente

## Monitorización de Logs de Apache

WebGuardian incluye un robusto sistema de monitorización de logs de Apache que:

1. Lee continuamente nuevas entradas en los logs de acceso y error de Apache
2. Analiza las entradas de log para extraer información relevante
3. Analiza las peticiones en busca de patrones de ataque
4. Gestiona la rotación de logs para garantizar una monitorización continua
5. Hace seguimiento de actividades sospechosas (respuestas HTTP 400, 403, 404, 405, 500)

### Análisis de Logs

El sistema analiza los logs de Apache utilizando el siguiente patrón:
```
^(\S+) \S+ \S+ \[([^:]+):(\d+:\d+:\d+) ([^\]]+)\] "(\S+) (.+?) (\S+)" (\d+) (\S+) "([^"]*)" "([^"]*)"
```

Esto extrae:
- Dirección IP
- Fecha y hora
- Método HTTP
- Ruta de la petición
- Protocolo HTTP
- Código de estado
- Tamaño de la respuesta
- Referer
- Agente de usuario

## Buenas Prácticas

### Mejora de Seguridad

1. **Actualizaciones Regulares**: Mantén los patrones de ataque actualizados con la última inteligencia sobre amenazas
2. **Gestión de Lista Blanca**: Solo incluye en la lista blanca IPs confiables; revisa periódicamente
3. **Monitorización de Logs**: Revisa regularmente los logs en busca de patrones sospechosos
4. **Defensa en Profundidad**: Utiliza WebGuardian junto con otras medidas de seguridad
5. **Pruebas**: Realiza pruebas periódicas del sistema con simulaciones de ataque seguras

### Optimización del Rendimiento

1. **Limitación de Tasa**: Considera añadir limitación de tasa para escenarios de alto tráfico
2. **Gestión de Recursos**: Monitoriza el uso de CPU y memoria durante cargas altas
3. **Rotación de Logs**: Asegúrate de que los archivos de log no crezcan demasiado
4. **Caché**: Implementa caché para recursos estáticos

## Resolución de Problemas

### Problemas Comunes

#### Tráfico Legítimo Bloqueado
- Comprueba si la IP está en la lista de bloqueados
- Revisa los logs para detectar falsos positivos
- Añade IPs legítimas a la lista blanca

#### Problemas de Monitorización de Logs de Apache
- Verifica que las rutas de logs de Apache son correctas
- Asegúrate de que la aplicación tiene acceso de lectura a los archivos de log
- Comprueba que el formato de log coincide con el patrón esperado

#### Problemas de Permisos
- Verifica los permisos de sudo para iptables
- Comprueba los permisos de archivos para los directorios de log

### Pasos de Diagnóstico

1. Revisa los logs de la aplicación en `logs/api_logs.txt`
2. Verifica las reglas de iptables con `sudo iptables -L`
3. Comprueba que los logs de Apache son accesibles
4. Asegúrate de que todas las dependencias requeridas están instaladas

## Referencia de API

### Rutas de Flask

#### Rutas Principales
- **GET /** - Panel principal
- **GET /logs** - Ver entradas de log e IPs bloqueadas
- **GET /whitelist** - Gestionar entradas de la lista blanca

#### Rutas de Prueba
- **GET /test/<param>** - Probar filtrado de parámetros
- **GET /query** - Probar filtrado de parámetros de consulta

#### Rutas de Administración
- **GET /unblock/<ip>** - Desbloquear una IP específica
- **POST /whitelist/add** - Añadir una IP a la lista blanca
- **GET /whitelist/remove/<ip>** - Eliminar una IP de la lista blanca

### Funciones Principales

#### Detección de Ataques
- `detect_attack(text, full_request=None)` - Función principal de detección
- `detect_sqli(text)` - Función legada para detección de inyección SQL

#### Gestión de IPs
- `block_ip_permanently(ip)` - Bloquear una IP usando iptables
- `is_ip_blocked(ip)` - Comprobar si una IP está bloqueada
- `is_ip_whitelisted(ip)` - Comprobar si una IP está en la lista blanca

#### Funciones de Logs de Apache
- `monitor_apache_logs()` - Función principal de monitorización
- `parse_apache_log_line(line)` - Analizar una línea de log
- `process_apache_log_line(line)` - Procesar una entrada de log analizada
