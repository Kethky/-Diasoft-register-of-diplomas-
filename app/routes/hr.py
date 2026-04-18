from datetime import datetime

from flask import Blueprint, jsonify, render_template, request, send_file

from app.decorators import check_blocked_ip
from app.extensions import limiter
from app.services.hr_service import (
    build_result_pdf,
    extract_requisites_from_upload,
    get_hr_history,
    get_hr_history_for_pdf,
    parse_batch_verification_file,
    verify_batch_rows,
    verify_hr_diploma,
)
from app.services.security_service import get_hr_api_keys, log_security_event

bp = Blueprint("hr_api", __name__)


def _validate_hr_api_key(api_key: str):
    hr_api_keys = get_hr_api_keys()
    if not hr_api_keys:
        return jsonify({"error": "HR API отключён: не настроены API ключи", "status": "error"}), 503

    if api_key not in hr_api_keys:
        log_security_event(request.remote_addr, request.path)
        return jsonify({"error": "Недействительный API ключ", "status": "error"}), 401
    return None


@bp.route("/hr")
@bp.route("/hr.html")
def hr_page():
    return render_template("hr.html")


@bp.route("/api/verify_diploma_for_hr", methods=["POST"])
@limiter.limit("100 per minute", error_message="Слишком много запросов. Подождите немного.")
@limiter.limit("1000 per hour", error_message="Достигнут лимит запросов в час.")
@limiter.limit("10000 per day", error_message="Достигнут дневной лимит запросов.")
@check_blocked_ip
def api_verify_diploma_for_hr():
    data = request.get_json() or {}
    api_key = data.get("api_key", "").strip()
    validation_error = _validate_hr_api_key(api_key)
    if validation_error:
        return validation_error

    diploma_number = data.get("diploma_number", "").strip()
    university_code = data.get("university_code")
    if not diploma_number:
        return jsonify({"error": "Не указан номер диплома", "status": "error"}), 400
    if not university_code:
        return jsonify({"error": "Не указан код вуза", "status": "error"}), 400

    result = verify_hr_diploma(
        university_code=university_code,
        diploma_number=diploma_number,
        full_name=data.get("full_name", ""),
        graduation_year=data.get("graduation_year"),
        specialty=data.get("specialty", ""),
        verification_mode=data.get("verification_mode", "quick"),
        input_source="manual",
        save_history=True,
    )

    status_code = 200
    if result["status"] == "not_found":
        status_code = 404
    elif result["status"] == "error":
        status_code = 400

    return jsonify(result), status_code


@bp.route("/api/verify_diplomas_batch", methods=["POST"])
@limiter.limit("10 per minute", error_message="Слишком много запросов. Подождите немного.")
@limiter.limit("100 per hour", error_message="Достигнут лимит запросов в час.")
@check_blocked_ip
def api_verify_diplomas_batch():
    data = request.get_json() or {}
    api_key = data.get("api_key", "").strip()
    validation_error = _validate_hr_api_key(api_key)
    if validation_error:
        return validation_error

    diplomas_list = data.get("diplomas", [])
    max_batch_size = 300
    if len(diplomas_list) > max_batch_size:
        return jsonify(
            {
                "error": f"Слишком много дипломов. Максимум {max_batch_size} за запрос",
                "status": "error",
            }
        ), 400

    result = verify_batch_rows(diplomas_list, verification_mode=data.get("verification_mode", "quick"))
    result["verified_at"] = datetime.now().isoformat(timespec="seconds")
    return jsonify(result)


@bp.route("/api/hr/batch-verify-upload", methods=["POST"])
@limiter.limit("10 per minute", error_message="Слишком много загрузок.")
@check_blocked_ip
def api_hr_batch_verify_upload():
    api_key = request.form.get("api_key", "").strip()
    validation_error = _validate_hr_api_key(api_key)
    if validation_error:
        return validation_error

    if "file" not in request.files:
        return jsonify({"error": "Файл не выбран"}), 400

    file = request.files["file"]
    if not file or not file.filename:
        return jsonify({"error": "Файл не выбран"}), 400

    try:
        rows = parse_batch_verification_file(file)
        if not rows:
            return jsonify({"error": "В файле нет подходящих строк для проверки"}), 400
        result = verify_batch_rows(rows, verification_mode=request.form.get("verification_mode", "quick"))
        result["verified_at"] = datetime.now().isoformat(timespec="seconds")
        return jsonify(result)
    except Exception as exc:
        return jsonify({"error": f"Ошибка пакетной проверки: {exc}"}), 400


@bp.route("/api/hr/extract-document", methods=["POST"])
@limiter.limit("20 per minute", error_message="Слишком много загрузок документов.")
@check_blocked_ip
def api_hr_extract_document():
    api_key = request.form.get("api_key", "").strip()
    validation_error = _validate_hr_api_key(api_key)
    if validation_error:
        return validation_error

    if "file" not in request.files:
        return jsonify({"error": "Файл не выбран"}), 400

    file = request.files["file"]
    if not file or not file.filename:
        return jsonify({"error": "Файл не выбран"}), 400

    try:
        extracted = extract_requisites_from_upload(file)
        return jsonify({"success": True, "item": extracted})
    except Exception as exc:
        return jsonify({"error": f"Не удалось извлечь реквизиты: {exc}"}), 400


@bp.route("/api/hr/history")
def api_hr_history():
    filters = {
        "university_code": request.args.get("university_code", "").strip(),
        "status": request.args.get("status", "").strip(),
        "date_from": request.args.get("date_from", "").strip(),
        "date_to": request.args.get("date_to", "").strip(),
        "limit": request.args.get("limit", 100),
    }
    return jsonify({"items": get_hr_history(filters)})


@bp.route("/api/hr/result-pdf", methods=["POST"])
def api_hr_result_pdf():
    data = request.get_json() or {}
    result = data.get("result") or {}
    if not result:
        return jsonify({"error": "Нет данных для PDF"}), 400
    pdf_buffer = build_result_pdf(result)
    return send_file(
        pdf_buffer,
        mimetype="application/pdf",
        as_attachment=True,
        download_name=f"hr_verification_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
    )


@bp.route("/api/hr/history/<int:history_id>/pdf")
def api_hr_history_pdf(history_id: int):
    item = get_hr_history_for_pdf(history_id)
    if not item:
        return jsonify({"error": "Запись истории не найдена"}), 404
    payload = item.get("details") or item
    pdf_buffer = build_result_pdf(payload)
    return send_file(
        pdf_buffer,
        mimetype="application/pdf",
        as_attachment=True,
        download_name=f"hr_history_{history_id}.pdf",
    )
