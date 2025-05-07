#!/usr/bin/env python3

import sys
import site
import logging

# Configurar logging
logging.basicConfig(stream=sys.stderr)

# Ruta al entorno virtual (opcional, si usas virtualenv)
# Descomenta estas líneas si estás usando un entorno virtual
# virtual_env = '/var/www/webguardian/venv'
# site.addsitedir(f'{virtual_env}/lib/python3.9/site-packages')
# activate_env = f'{virtual_env}/bin/activate_this.py'
# with open(activate_env) as file_:
#     exec(file_.read(), dict(__file__=activate_env))

# Añadir ruta de la aplicación
sys.path.insert(0, '/var/www/webguardian/')

# Importar la aplicación
from app import app as application