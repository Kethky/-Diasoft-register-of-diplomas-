import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent.parent


class BaseConfig:
    SECRET_KEY = os.getenv('SECRET_KEY', 'dev-secret-key-change-me-123456789')
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    MAX_CONTENT_LENGTH = 5 * 1024 * 1024
    RATELIMIT_STORAGE_URI = os.getenv('RATELIMIT_STORAGE_URI', 'memory://')
    HR_API_KEYS = os.getenv('HR_API_KEYS', '')

    ADMIN_LOGIN = os.getenv('ADMIN_LOGIN', 'admin')
    ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD', 'admin123!')
    ADMIN_PASSWORD_HASH = os.getenv('ADMIN_PASSWORD_HASH', '')

    DB_PATH = str(BASE_DIR / 'database' / 'diploma_platform.db')
    KEYS_DIR = str(BASE_DIR / 'keys')
    SUSPICIOUS_REPORTS_LOG = str(BASE_DIR / 'suspicious_reports.log')
    QR_SIGNING_SALT = os.getenv('QR_SIGNING_SALT', 'diploma-qr-signature')

    FLASK_DEBUG = False
    DEBUG = False
    TESTING = False
    SESSION_COOKIE_SECURE = False
    PREFERRED_URL_SCHEME = 'http'


class DevelopmentConfig(BaseConfig):
    FLASK_DEBUG = True
    DEBUG = True
    ENV_NAME = 'development'


class ProductionConfig(BaseConfig):
    FLASK_DEBUG = False
    DEBUG = False
    ENV_NAME = 'production'
    SESSION_COOKIE_SECURE = True
    PREFERRED_URL_SCHEME = 'https'


config_by_name = {
    'dev': DevelopmentConfig,
    'development': DevelopmentConfig,
    'prod': ProductionConfig,
    'production': ProductionConfig,
}



def get_config_class():
    env_name = os.getenv('APP_ENV') or os.getenv('FLASK_ENV') or ('development' if os.getenv('FLASK_DEBUG', '0') == '1' else 'production')
    return config_by_name.get(env_name.lower(), DevelopmentConfig)
