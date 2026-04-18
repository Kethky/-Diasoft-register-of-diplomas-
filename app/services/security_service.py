import json
from datetime import datetime, timedelta

from flask import current_app, request, session
from itsdangerous import URLSafeTimedSerializer

from app.repositories.security_repository import (
    get_blocked_ip,
    insert_security_log,
    insert_verification_log,
    upsert_blocked_ip,
)


def get_serializer() -> URLSafeTimedSerializer:
    return URLSafeTimedSerializer(
        current_app.config["SECRET_KEY"],
        salt="diploma-temp-links",
    )


def generate_csrf_token() -> str:
    token = session.get("csrf_token")
    if token:
        return token

    import secrets

    token = secrets.token_urlsafe(32)
    session["csrf_token"] = token
    return token


def log_verification(
    diploma_id,
    university_code,
    diploma_number,
    verification_type,
    token,
    result,
) -> None:
    ip = request.remote_addr
    user_agent = request.headers.get("User-Agent", "Unknown")
    insert_verification_log(
        diploma_id=diploma_id,
        university_code=university_code,
        diploma_number=diploma_number,
        verification_type=verification_type,
        token=token,
        ip=ip,
        user_agent=user_agent,
        result=result,
    )


def get_hr_api_keys() -> list[str]:
    return [
        key.strip()
        for key in current_app.config.get("HR_API_KEYS", "").split(",")
        if key.strip()
    ]


def save_suspicious_report(university_code: int, diploma_number: str, comment: str) -> None:
    report = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "university_code": university_code,
        "diploma_number": diploma_number,
        "comment": comment,
    }

    log_file = current_app.config["SUSPICIOUS_REPORTS_LOG"]
    with open(log_file, "a", encoding="utf-8") as file_obj:
        file_obj.write(json.dumps(report, ensure_ascii=False) + "\n")


def is_ip_blocked(ip: str) -> bool:
    return get_blocked_ip(ip) is not None


def log_security_event(ip: str, endpoint: str, user_agent: str | None = None) -> None:
    if user_agent is None:
        user_agent = request.headers.get("User-Agent", "Unknown")
    insert_security_log(ip, endpoint, user_agent)


def block_ip(ip: str, reason: str, minutes: int = 30) -> None:
    blocked_until = (datetime.now() + timedelta(minutes=minutes)).strftime("%Y-%m-%d %H:%M:%S")
    upsert_blocked_ip(ip, reason, blocked_until)
