import os
import logging
import datetime
import jwt
from functools import wraps

from flask_jwt_extended import (
    JWTManager, create_access_token, 
    jwt_required, get_jwt_identity)

from flask import Flask, request, jsonify
import joblib
import numpy as np
from sqlalchemy import create_engine, Column, Integer, Float, String, DateTime
from sqlalchemy.orm import declarative_base, sessionmaker
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate



app = Flask(__name__, instance_relative_config=True)

app.config.from_object('api.config')

db = SQLAlchemy(app)
migrate = Migrate(app, db)
jwt = JWTManager(app)


# LOGGING
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("api_modelo")

# SQL ALCHEMY
engine                          = create_engine(app.config['SQLALCHEMY_DATABASE_URI'], echo=False)
Base                            = declarative_base()
SessionLocal                    = sessionmaker(bind=engine)



# Cria as tabelas no banco (em produção utilizar Alembic)

class Prediction(Base):
    __tablename__ = "predictions"

    id              = Column(Integer, primary_key=True, autoincrement=True)
    sepal_length    = Column(Float, nullable=False)
    sepal_width     = Column(Float, nullable=False)
    petal_length    = Column(Float, nullable=False)
    petal_width     = Column(Float, nullable=False)
    predicted_class = Column(Integer, nullable=False)
    created_at      = Column(DateTime, default=datetime.datetime.utcnow)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))  # api/
ROOT_DIR = os.path.dirname(BASE_DIR)                   # raiz do projeto

MODEL_PATH = os.path.join(ROOT_DIR, "modelo_iris.pkl")


Base.metadata.create_all(engine)

model   = joblib.load(MODEL_PATH)
logger.info("Modelo carregado com sucesso.")

def create_token(username):
    payload = {
        "username":username,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(seconds=app.config['JWT_EXP_DELTA_SECONDS'])
    }
    token = jwt.encode(payload, app.config['JWT_SECRET'], algorithm=pp.config['JWT_ALGORITHM'])
    return token

def token_required(f):
    @wraps(f)
    def decorated(*ards, **kwargs):
        # Pegar o token do header Authorization: Bearer <token>
        # decodificar e checar expiração
        return f(*ards, **kwargs)
    return decorated

TEST_USERNAME = 'hugo.dias'
TEST_PASSWORD = 'pass'

@app.route("/login", methods=["POST"])
def login():
    data     = request.get_json(force=True)
    username = data.get("username")
    password = data.get("password")
    if username == TEST_USERNAME and password == TEST_PASSWORD:

        token = create_token(username)
        return jsonify({"token": token})
    else:
        return jsonify({"error": "Credenciais inválidas"}), 401

  
@app.route("/", methods=['GET'])
def home():
    return jsonify({"msg":"Pagina inicial para ML"}), 200


predictions_cache = {}

@app.route("/predict", methods=['POST'])
#@token_required
def predict():
    """
    Endpoint protegido para token para obter predição
    Corp (JSON):
    {
        "sepal_length": 5.1,
        "sepal_width":  3.5,
        "petal_length": 1.4,
        "petal_width": 0.2    
    }
    """

    data = request.get_json(force=True)
    try:
        sepal_length  = float(data['sepal_length'])
        sepal_width   = float(data['sepal_width'])
        petal_length  = float(data['petal_length'])
        petal_width   = float(data['petal_width'])

    except (ValueError, KeyError) as e:
        logger.error("Dados de entrada inválidos: %s", e)
        return jsonify({"error":"Dados inválidos, verifique parâmetros"}), 400
    
   
    # Verificar se já está no cache
    features = (sepal_length,sepal_width, petal_length, petal_width)

    if features in predictions_cache:
        logger.info("Cache hit para %s", features)
        predicted_class = predictions_cache[features]
    
    else:
        # RODAR MODELO
        input_data = np.array([features])
        prediction = model.predict(input_data)
        predicted_class = int(prediction[0])

        # ARMAZENAR NO cache
        predictions_cache[features] = predicted_class
        logger.info("Cache updated para %s", features)

        #db.SessionLocal()

        # Essa é a classe PREDICITON do meu banco de dados
        new_pred = Prediction(
            sepal_length    = sepal_length,
            sepal_width     = sepal_width,
            petal_length    = petal_length,
            petal_width     = petal_width,
            predicted_class = predicted_class
        )

        db.session.add(new_pred)
        db.session.commit()
        #db.close()
        classes = {
            0: "Iris setosa",
            1: "Iris versicolor",
            2: "Iris virginica"
            }

        classe_nome = classes.get(predicted_class, "Classe desconhecida")


        return jsonify({"msg":f"Com base nessas informações {features}, essa é a previsão da classificação: {classe_nome}"}), 400


@app.route("/predictions", methods=['GET'])
# @token_required
def list_predictions():
    """
    """
    limit  = int(request.args.get("limit", 10))
    offset = int(request.args.get("offset", 0))

    db      = SessionLocal()
    preds   = db.query(Prediction).order_by(Prediction.id.desc()).limit(limit).offset(offset).all()
    db.close()

    if len(preds) == 0: return jsonify({"msg": "Tabelas sem nenhuma previsão"})

    results = []

    for p in preds:
        results.append({
            "id": p.id,
            "sepal_length"      : p.sepal_length,
            "sepal_width"       : p.sepal_width,
            "petal_length"      : p.petal_length, 
            "petal_width"       : p.petal_width,
            "predicted_class"   : p.predicted_class,
            "created_at"        : p.created_at.isoformat()
        }) 
    
    return jsonify(results)


if __name__ == '__main__':
    app.run(debug=True)
#    with app.app_context():
#        db.create_all()
#        print("Banco de dados criado!")
