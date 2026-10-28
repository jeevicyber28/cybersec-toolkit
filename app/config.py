import os

basedir = os.path.abspath(os.path.dirname(__file__))
project_root = os.path.dirname(basedir)

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'cybersec-toolkit-super-secret-key-2026')
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        'DATABASE_URL',
        f'sqlite:///{os.path.join(project_root, "data", "cybersec.db")}'
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # CSRF & Security headers
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = 7200
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    SESSION_COOKIE_SECURE = os.environ.get('FLASK_ENV') == 'production'
    
    # File Upload limits
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16 MB
    ALLOWED_IMAGE_EXTENSIONS = {'.png', '.jpg', '.jpeg', '.webp', '.bmp'}
    
    # ML Model & Data paths
    MODEL_PATH = os.path.join(project_root, 'data', 'phishing_model.joblib')
    METRICS_PATH = os.path.join(project_root, 'data', 'model_metrics.json')
    GAME_ITEMS_PATH = os.path.join(project_root, 'data', 'game_items.json')

class TestConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    WTF_CSRF_ENABLED = False
    WTF_CSRF_CHECK_DEFAULT = False
