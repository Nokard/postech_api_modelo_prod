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


SECRET_KEY = 'sua_chave_secreta'
CACHE_TYPE = 'simples'
SWAGGER = {
        'title':'PREVISÃO DO MODELO IRIS',
        'uiversion': 3
    }

SQLALCHEMY_DATABASE_URI = "sqlite:///" + os.path.join(INSTANCE_DIR, "log_modelo.db")
SQLALCHEMY_TRACK_MODIFICATION   = False
JWT_SECRET                      = 'sua_chave_jwt_secreta'
JWT_ALGORITHM                   = "HS256"
JWT_EXP_DELTA_SECONDS           = 3600

# LOGGING
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("api_modelo")

# SQL ALCHEMY


