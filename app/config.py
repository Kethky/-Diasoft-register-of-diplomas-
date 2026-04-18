import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent.parent


class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-key-change-me-123456789")
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SECURE = False
    SESSION_COOKIE_SAMESITE = "Lax"
    MAX_CONTENT_LENGTH = 5 * 1024 * 1024
    RATELIMIT_STORAGE_URI = os.getenv("RATELIMIT_STORAGE_URI", "memory://")
    FLASK_DEBUG = os.getenv("FLASK_DEBUG", "0") == "1"
    HR_API_KEYS = os.getenv("HR_API_KEYS", "")

    ADMIN_LOGIN = os.getenv("ADMIN_LOGIN", "admin")
    ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin123!")
    ADMIN_PASSWORD_HASH = os.getenv("ADMIN_PASSWORD_HASH", "")

    DB_PATH = str(BASE_DIR / "database" / "diploma_platform.db")
    KEYS_DIR = str(BASE_DIR / "keys")
    SUSPICIOUS_REPORTS_LOG = str(BASE_DIR / "suspicious_reports.log")
