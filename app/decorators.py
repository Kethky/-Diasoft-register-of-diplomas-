from functools import wraps

from flask import jsonify, request, session

from .services.security_service import is_ip_blocked


def require_csrf(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        sent_token = request.headers.get("X-CSRF-Token")
        session_token = session.get("csrf_token")
        if not sent_token or not session_token or sent_token != session_token:
            return jsonify({"error": "CSRF token invalid"}), 403
        return func(*args, **kwargs)

    return wrapper


def require_student(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if session.get("role") != "student" or "diploma_id" not in session:
            return jsonify({"error": "Не авторизован"}), 401
        return func(*args, **kwargs)

    return wrapper


def require_admin(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if session.get("role") != "admin":
            return jsonify({"error": "Не авторизован"}), 401
        return func(*args, **kwargs)

    return wrapper


def check_blocked_ip(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        ip = request.remote_addr
        if is_ip_blocked(ip):
            return (
                jsonify(
                    {
                        "error": "IP заблокирован за нарушение правил использования. Обратитесь к администратору."
                    }
                ),
                403,
            )
        return func(*args, **kwargs)

    return decorated_function
