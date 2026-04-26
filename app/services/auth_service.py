import bcrypt
import secrets

from flask import current_app

from app.repositories.diploma_repository import get_diploma_for_student_auth
from app.repositories.university_repository import get_university_by_login


def generate_student_secret() -> str:
    return secrets.token_urlsafe(12)


def hash_password(raw_value: str) -> str:
    return bcrypt.hashpw(raw_value.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(raw_value: str, stored_hash: str) -> bool:
    if not stored_hash:
        return False
    return bcrypt.checkpw(raw_value.encode("utf-8"), stored_hash.encode("utf-8"))


def check_student_auth(diploma_number: str, student_secret: str):
    row = get_diploma_for_student_auth(diploma_number)
    if not row:
        return None

    if verify_password(student_secret, row["secret_hash"]):
        return {
            'student_account_id': row['student_account_id'],
            'diploma_id': row['diploma_id'],
        }

    return None


def check_university_auth(login: str, password: str) -> dict:
    row = get_university_by_login(login)
    generic_error = {"success": False, "message": "Неверный логин или пароль"}

    if not row:
        return generic_error

    if verify_password(password, row["password_hash"]):
        return {
            "success": True,
            "university_code": row["university_code"],
            "name": row["name"],
            "message": "Вход выполнен",
        }

    return generic_error


def check_admin_auth(login: str, password: str) -> dict:
    generic_error = {"success": False, "message": "Неверный логин или пароль"}

    admin_login = current_app.config.get("ADMIN_LOGIN", "admin")
    admin_password_hash = current_app.config.get("ADMIN_PASSWORD_HASH", "")
    admin_password = current_app.config.get("ADMIN_PASSWORD", "")

    if login != admin_login:
        return generic_error

    if admin_password_hash:
        is_valid = verify_password(password, admin_password_hash)
    else:
        is_valid = password == admin_password

    if not is_valid:
        return generic_error

    return {"success": True, "message": "Вход выполнен"}
