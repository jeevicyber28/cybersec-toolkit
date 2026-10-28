import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_wtf.csrf import CSRFProtect
from app.config import Config

db = SQLAlchemy()
login_manager = LoginManager()
csrf = CSRFProtect()

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Ensure required data directories exist
    os.makedirs(os.path.join(app.root_path, '..', 'data'), exist_ok=True)
    os.makedirs(os.path.join(app.root_path, 'static', 'uploads'), exist_ok=True)

    # Initialize extensions
    db.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)

    login_manager.login_view = 'auth.login'
    login_manager.login_message = 'Please log in to access this page.'
    login_manager.login_message_category = 'info'

    # Register Blueprints
    from app.routes.main import main_bp
    from app.routes.auth import auth_bp
    from app.routes.url_scanner import url_scanner_bp
    from app.routes.email_analyzer import email_analyzer_bp
    from app.routes.qr_scanner import qr_scanner_bp
    from app.routes.password_checker import password_checker_bp
    from app.routes.game import game_bp
    from app.routes.history import history_bp
    from app.routes.api import api_bp
    from app.routes.ssl_headers import ssl_headers_bp
    from app.routes.hash_studio import hash_studio_bp
    from app.routes.port_scanner import port_scanner_bp
    from app.routes.ip_intel import ip_intel_bp
    from app.routes.playbook import playbook_bp

    app.register_blueprint(main_bp)
    app.register_blueprint(auth_bp, url_prefix='/auth')
    app.register_blueprint(url_scanner_bp, url_prefix='/url-scanner')
    app.register_blueprint(email_analyzer_bp, url_prefix='/email-analyzer')
    app.register_blueprint(qr_scanner_bp, url_prefix='/qr-scanner')
    app.register_blueprint(password_checker_bp, url_prefix='/password-checker')
    app.register_blueprint(game_bp, url_prefix='/game')
    app.register_blueprint(history_bp, url_prefix='/history')
    app.register_blueprint(api_bp, url_prefix='/api')
    app.register_blueprint(ssl_headers_bp, url_prefix='/ssl-headers')
    app.register_blueprint(hash_studio_bp, url_prefix='/hash-studio')
    app.register_blueprint(port_scanner_bp, url_prefix='/port-scanner')
    app.register_blueprint(ip_intel_bp, url_prefix='/ip-intel')
    app.register_blueprint(playbook_bp, url_prefix='/playbook')

    # Exempt REST API from CSRF protection for Chrome extension & external callers
    csrf.exempt(api_bp)

    # Security Headers Hook
    @app.after_request
    def set_security_headers(response):
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'SAMEORIGIN'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        return response

    with app.app_context():
        db.create_all()

    return app
