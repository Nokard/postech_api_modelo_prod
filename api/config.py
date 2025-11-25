from sqlalchemy.orm import declarative_base, sessionmaker
from sqlalchemy import create_engine
import logging
import os


# Caminho absoluto para a pasta instance
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
INSTANCE_DIR = os.path.join(BASE_DIR, "instance")

# Garantir que a pasta instance exista
os.makedirs(INSTANCE_DIR, exist_ok=True)

# Criar o caminho correto do banco


SWAGGER = {
        'title':'PREVISÃO DO MODELO IRIS',
        'uiversion': 3
    }


# LOGGING
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("api_modelo")

# SQL ALCHEMY


