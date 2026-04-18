from datetime import datetime

from flask import Blueprint, jsonify, request, send_file, session

from app.decorators import check_blocked_ip
from app.extensions import limiter
from app.repositories.diploma_repository import clear_all_diplomas, delete_diploma
from app.services.diploma_service import (
    create_signed_diploma,
    get_university_diplomas,
    get_university_list,
    update_diploma_status,
)
from app.services.excel_service import build_excel_export, bulk_import_diplomas, load_dataframe_from_uploaded_file

bp = Blueprint("university_api", __name__)


def _require_university_session():
    return session.get("role") == "university"


@bp.route("/api/universities")
def api_get_universities():
    return jsonify(get_university_list())


@bp.route("/api/university/diplomas")
def api_get_university_diplomas():
    if not _require_university_session():
        return jsonify({"error": "Не авторизован"}), 401

    return jsonify(get_university_diplomas(session["university_code"]))


@bp.route("/api/university/add_diploma", methods=["POST"])
def api_add_diploma():
    if not _require_university_session():
        return jsonify({"error": "Не авторизован"}), 401

    data = request.get_json() or {}
    university_code = session["university_code"]
    full_name = data.get("full_name", "").strip()
    graduation_year = data.get("graduation_year", "")
    specialty = data.get("specialty", "").strip()
    diploma_number = data.get("diploma_number", "").strip()

    if not all([full_name, graduation_year, specialty, diploma_number]):
        return jsonify({"success": False, "message": "Заполните все поля"})

    try:
        graduation_year = int(graduation_year)
    except ValueError:
        return jsonify({"success": False, "message": "Год должен быть числом"})

    try:
        result = create_signed_diploma(
            university_code=university_code,
            full_name=full_name,
            graduation_year=graduation_year,
            specialty=specialty,
            diploma_number=diploma_number,
        )
        return jsonify(
            {
                "success": True,
                "message": "Диплом добавлен и подписан",
                "student_secret": result["student_secret"],
            }
        )
    except Exception as error:
        if error.__class__.__name__ == "IntegrityError":
            return jsonify({"success": False, "message": "Диплом с таким номером уже существует"})
        raise


@bp.route("/api/university/export_excel", methods=["GET"])
@check_blocked_ip
def api_export_excel():
    if not _require_university_session():
        return jsonify({"error": "Не авторизован"}), 401

    university_code = session["university_code"]
    diplomas = get_university_diplomas(university_code)
    if not diplomas:
        return jsonify({"error": "Нет дипломов для экспорта"}), 404

    output = build_excel_export(diplomas, university_code)
    filename = f"diplomas_{university_code}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"

    return send_file(
        output,
        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        as_attachment=True,
        download_name=filename,
    )


@bp.route("/api/university/toggle_status", methods=["POST"])
def api_toggle_status():
    if not _require_university_session():
        return jsonify({"error": "Не авторизован"}), 401

    data = request.get_json() or {}
    diploma_id = data.get("diploma_id")
    current_status = data.get("current_status")
    new_status = 0 if current_status == 1 else 1

    success = update_diploma_status(diploma_id, new_status, session["university_code"])
    if not success:
        return jsonify({"success": False, "message": "Ошибка при обновлении"})

    return jsonify({"success": True, "new_status": new_status})


@bp.route("/api/university/clear_all_diplomas", methods=["DELETE"])
def api_clear_all_diplomas():
    if not _require_university_session():
        return jsonify({"error": "Не авторизован"}), 401

    deleted_count = clear_all_diplomas(session["university_code"])
    return jsonify({"success": True, "deleted_count": deleted_count})


@bp.route("/api/university/delete_diploma", methods=["DELETE"])
def api_delete_diploma():
    if not _require_university_session():
        return jsonify({"error": "Не авторизован"}), 401

    data = request.get_json() or {}
    diploma_id = data.get("diploma_id")

    deleted = delete_diploma(diploma_id, session["university_code"])
    if not deleted:
        return jsonify({"success": False, "message": "Диплом не найден"})

    return jsonify({"success": True})


@bp.route("/api/university/upload_excel", methods=["POST"])
@limiter.limit("10 per day", error_message="Слишком много загрузок. Подождите до завтра.")
@check_blocked_ip
def api_upload_excel():
    if not _require_university_session():
        return jsonify({"error": "Не авторизован"}), 401

    if "file" not in request.files:
        return jsonify({"success": False, "message": "Файл не выбран"})

    file_storage = request.files["file"]
    if not file_storage or file_storage.filename == "":
        return jsonify({"success": False, "message": "Файл не выбран"})

    filename = file_storage.filename.lower()
    if not filename.endswith((".xlsx", ".xls", ".csv")):
        return jsonify({"success": False, "message": "Поддерживаются только .xlsx, .xls и .csv"})

    try:
        df = load_dataframe_from_uploaded_file(file_storage)
        if len(df) < 1:
            return jsonify({"success": False, "message": "Файл не содержит данных"})

        result = bulk_import_diplomas(df, session["university_code"])
        return jsonify({"success": True, **result})
    except Exception as error:
        return jsonify({"success": False, "message": f"Ошибка при обработке файла: {error}"})
