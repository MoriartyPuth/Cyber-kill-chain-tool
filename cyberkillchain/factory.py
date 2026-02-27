import os

from dotenv import load_dotenv
from flask import Flask
from flask_socketio import SocketIO

from ai_advisor import AISecurityAdvisor
from models import db


def create_app():
    load_dotenv()
    app = Flask(__name__)
    app.secret_key = os.getenv("SECRET_KEY", "cyber_security_simulation_secret_2026")
    app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL", "sqlite:///cyber_killchain.db")
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    db.init_app(app)
    socketio = SocketIO(app, cors_allowed_origins="*")

    try:
        ai_advisor = AISecurityAdvisor()
        ai_enabled = True
    except ValueError:
        ai_advisor = None
        ai_enabled = False
        print("Warning: OpenAI API key not configured. AI features will be limited.")

    return app, socketio, ai_advisor, ai_enabled
