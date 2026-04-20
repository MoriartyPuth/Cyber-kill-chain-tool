import os

from dotenv import load_dotenv
from flask import Flask
from flask_socketio import SocketIO
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from ai_advisor import AISecurityAdvisor
from models import db

csrf = CSRFProtect()
limiter = Limiter(key_func=get_remote_address, default_limits=[])


def create_app():
    load_dotenv()
    app = Flask(__name__)

    secret_key = os.getenv("SECRET_KEY")
    if not secret_key:
        import secrets
        secret_key = secrets.token_hex(32)
        print("WARNING: SECRET_KEY not set in .env — using a temporary random key. Sessions will reset on restart.")
    app.secret_key = secret_key

    app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL", "sqlite:///cyber_killchain.db")
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    # Session security
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    # Only set Secure in production (HTTPS); skip in dev to avoid breaking local HTTP
    app.config["SESSION_COOKIE_SECURE"] = os.getenv("FLASK_ENV", "development") == "production"

    db.init_app(app)
    csrf.init_app(app)
    limiter.init_app(app)
    socketio = SocketIO(app, cors_allowed_origins="*")

    try:
        ai_advisor = AISecurityAdvisor()
        ai_enabled = True
    except ValueError:
        ai_advisor = None
        ai_enabled = False
        print("Warning: OpenAI API key not configured. AI features will be limited.")

    return app, socketio, ai_advisor, ai_enabled
