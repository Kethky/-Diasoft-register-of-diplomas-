from flask import Blueprint, jsonify, request

from app.decorators import check_blocked_ip
from app.extensions import limiter
from app.services.crypto_service import verify_diploma_signature
from app.services.diploma_service import check_diploma_by_params
from app.services.qr_service import validate_temp_token
from app.services.security_service import log_verification, save_suspicious_report

bp = Blueprint("public_api", __name__)


@bp.route("/api/report_suspicious_activity", methods=["POST"])
def api_report_suspicious_activity():
    data = request.get_json() or {}
    university_code = data.get("university_code")
    diploma_number = data.get("diploma_number", "").strip()
    comment = data.get("comment", "").strip()

    if not university_code or not diploma_number or not comment:
        return jsonify({"success": False, "message": "Не хватает данных для отправки"}), 400

    result = check_diploma_by_params(university_code, diploma_number)
    if not result.get("found"):
        return jsonify({"success": False, "message": "Диплом не найден"}), 404

    if not result.get("valid"):
        return jsonify({"success": False, "message": "Жалобу можно отправить только для подлинного диплома"}), 400

    save_suspicious_report(university_code, diploma_number, comment)
    return jsonify({"success": True, "message": "Сообщение сохранено"})


@bp.route("/api/search_diploma", methods=["POST"])
@limiter.limit("30 per minute", error_message="Слишком много запросов. Подождите немного.")
@limiter.limit("300 per hour", error_message="Достигнут лимит запросов в час.")
@limiter.limit("1000 per day", error_message="Достигнут дневной лимит запросов.")
@check_blocked_ip
def api_search_diploma():
    data = request.get_json() or {}
    temp_token = data.get("temp_token")

    diploma_id = None
    verification_type = "manual"

    if temp_token:
        verification_type = "temp_link"
        try:
            token_result = validate_temp_token(temp_token)
            if not token_result["ok"]:
                return jsonify(token_result["payload"]), token_result["status_code"]

            diploma_id = token_result["diploma_id"]
            university_code = token_result["university_code"]
            diploma_number = token_result["diploma_number"]
        except Exception:
            return jsonify({"valid": False, "expired": False, "message": "Недействительная ссылка"}), 400
    else:
        university_code = data.get("university_code")
        diploma_number = data.get("diploma_number", "").strip()

    if not university_code or not diploma_number:
        return jsonify({"error": "Не указан код вуза или номер диплома"}), 400

    result = check_diploma_by_params(university_code, diploma_number)

    if result.get("found"):
        result["university_code"] = university_code
        result["diploma_number"] = diploma_number
        diploma_id = result.get("id")

        if result.get("digital_signature"):
            diploma_data = {
                "university_code": university_code,
                "diploma_number": diploma_number,
                "full_name": result["full_name"],
                "graduation_year": result["graduation_year"],
                "specialty": result["specialty"],
            }
            signature_valid = verify_diploma_signature(
                university_code, diploma_data, result["digital_signature"]
            )
            result["signature_valid"] = signature_valid
            result["signature_message"] = (
                "🔐 Цифровая подпись действительна"
                if signature_valid
                else "❌ Цифровая подпись недействительна"
            )
        else:
            result["signature_valid"] = False
            result["signature_message"] = "⚠️ Цифровая подпись отсутствует"

    log_verification(
        diploma_id=diploma_id,
        university_code=university_code,
        diploma_number=diploma_number,
        verification_type=verification_type,
        token=temp_token if temp_token else None,
        result=result.get("message", "unknown"),
    )

    if not temp_token and result.get("found"):
        result.pop("full_name", None)
        result.pop("graduation_year", None)
        result.pop("specialty", None)
        result.pop("digital_signature", None)
        result.pop("id", None)

    return jsonify(result)
