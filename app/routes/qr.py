from flask import Blueprint, current_app, jsonify, request, session

from app.decorators import check_blocked_ip, require_student
from app.extensions import limiter
from app.repositories.diploma_repository import get_diploma_by_id, revoke_active_token
from app.services.qr_service import build_temp_token, decode_qr_upload, generate_qr_base64
from app.services.security_service import log_verification

bp = Blueprint("qr_api", __name__)


@bp.route("/api/scan_qr", methods=["POST"])
@limiter.limit("20 per minute", error_message="Слишком много попыток сканирования.")
@limiter.limit("200 per hour", error_message="Достигнут лимит сканирований в час.")
@check_blocked_ip
def api_scan_qr():
    if "file" not in request.files:
        return jsonify({"success": False, "message": "Файл не выбран"}), 400

    file_storage = request.files["file"]
    if not file_storage or file_storage.filename == "":
        return jsonify({"success": False, "message": "Файл не выбран"}), 400

    try:
        result = decode_qr_upload(file_storage)
        if not result["success"]:
            return jsonify({"success": False, "message": result["message"]}), result["status_code"]

        log_verification(
            diploma_id=result.get("diploma_id"),
            university_code=result["university_code"],
            diploma_number=result["diploma_number"],
            verification_type="qr_scan",
            token=result.get("temp_token"),
            result="scanned",
        )

        payload = {
            "success": True,
            "university_code": result["university_code"],
            "diploma_number": result["diploma_number"],
        }
        if "temp_token" in result:
            payload["temp_token"] = result["temp_token"]
        return jsonify(payload)
    except Exception as error:
        current_app.logger.exception("QR scan failed")
        return jsonify({"success": False, "message": f"Ошибка при обработке QR-кода: {error}"}), 500


@bp.route("/api/generate_qr", methods=["POST"])
def api_generate_qr():
    data = request.get_json() or {}
    url = data.get("url")

    if not url:
        return jsonify({"success": False, "message": "URL не указан"}), 400

    try:
        qr_image = generate_qr_base64(url)
        return jsonify({"success": True, "qr_image": f"data:image/png;base64,{qr_image}"})
    except Exception as error:
        current_app.logger.exception("QR generation failed")
        return jsonify({"success": False, "message": f"Ошибка генерации QR: {error}"}), 500


@bp.route("/api/generate_temp_link", methods=["POST"])
@limiter.limit("10 per hour", error_message="Слишком много запросов на создание ссылок.")
@limiter.limit("30 per day", error_message="Достигнут дневной лимит создания ссылок.")
@check_blocked_ip
@require_student
def api_generate_temp_link():
    data = request.get_json() or {}
    expiry_seconds = int(data.get("expiry_seconds", 3600))

    max_seconds = 30 * 24 * 60 * 60
    min_seconds = 60
    expiry_seconds = min(max(expiry_seconds, min_seconds), max_seconds)

    diploma = get_diploma_by_id(session["diploma_id"])
    if not diploma:
        return jsonify({"success": False, "message": "Диплом не найден"}), 404

    token, _expiry_timestamp = build_temp_token(
        diploma_id=diploma["id"],
        university_code=diploma["university_code"],
        diploma_number=diploma["diploma_number"],
        expiry_seconds=expiry_seconds,
    )

    temp_link = f"{request.host_url}?token={token}"
    total_hours = expiry_seconds / 3600
    days = int(total_hours // 24)
    hours = int(total_hours % 24)

    return jsonify(
        {
            "success": True,
            "link": temp_link,
            "expires_in_seconds": expiry_seconds,
            "expires_in_days": days,
            "expires_in_hours": hours,
        }
    )


@bp.route("/api/revoke_qr", methods=["POST"])
@require_student
def api_revoke_qr():
    revoke_active_token(session["diploma_id"])
    return jsonify({"success": True, "message": "QR-код отозван"})
