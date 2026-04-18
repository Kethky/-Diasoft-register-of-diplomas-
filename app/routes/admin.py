import csv
import io

from flask import Blueprint, jsonify, redirect, render_template, request, send_file, session, url_for

from app.decorators import check_blocked_ip, require_admin, require_csrf
from app.extensions import limiter
from app.services.admin_service import (
    add_university,
    clear_security_logs,
    clear_verification_logs,
    delete_student_secret_by_diploma,
    delete_university,
    generate_student_secrets,
    get_admin_student_secrets,
    get_security_logs,
    get_universities,
    get_verification_logs,
    reset_student_secret_by_diploma,
    reset_university_password,
    show_suspicious_reports,
)
from app.services.auth_service import check_admin_auth
from app.services.security_service import log_security_event

bp = Blueprint("admin", __name__)


@bp.route("/admin/login")
def admin_login_page():
    if session.get("role") == "admin":
        return redirect(url_for("admin.admin_panel"))
    return render_template("admin_login.html")


@bp.route("/login/admin", methods=["POST"])
@limiter.limit("10 per minute", error_message="Слишком много попыток входа.")
@limiter.limit("30 per hour", error_message="Достигнут лимит попыток входа.")
@check_blocked_ip
@require_csrf
def login_admin():
    data = request.get_json() or {}
    login = data.get("login", "").strip()
    password = data.get("password", "")

    result = check_admin_auth(login, password)
    if result["success"]:
        session.clear()
        session["role"] = "admin"
        session["admin_login"] = login
        session.modified = True
        return jsonify({"success": True, "redirect": "/admin"})

    log_security_event(request.remote_addr, "/login/admin")
    return jsonify({"success": False, "message": result["message"]}), 401


@bp.route("/admin")
def admin_panel():
    if session.get("role") != "admin":
        return redirect(url_for("admin.admin_login_page"))
    return render_template("admin.html")


@bp.route("/api/admin/student-secrets")
@require_admin
@require_csrf
def api_admin_student_secrets():
    sort_by = request.args.get("sort_by", "university_name")
    sort_dir = request.args.get("sort_dir", "asc")
    search = request.args.get("search", "").strip()
    rows = get_admin_student_secrets(sort_by=sort_by, sort_dir=sort_dir, search=search)
    return jsonify({"items": rows})


@bp.route("/api/admin/student-secrets/generate", methods=["POST"])
@require_admin
@require_csrf
def api_generate_student_secrets():
    results = generate_student_secrets()
    return jsonify({"success": True, "count": len(results), "items": results})


@bp.route("/api/admin/student-secrets/<int:diploma_id>/reset", methods=["POST"])
@require_admin
@require_csrf
def api_reset_student_secret(diploma_id: int):
    result = reset_student_secret_by_diploma(diploma_id)
    if not result:
        return jsonify({"success": False, "message": "Запись не найдена"}), 404
    return jsonify({"success": True, "item": result})


@bp.route("/api/admin/student-secrets/<int:diploma_id>/clear", methods=["POST"])
@require_admin
@require_csrf
def api_delete_admin_password(diploma_id: int):
    result = delete_student_secret_by_diploma(diploma_id)
    if not result:
        return jsonify({"success": False, "message": "Запись не найдена"}), 404
    return jsonify({"success": True, "item": result})


@bp.route("/api/admin/universities")
@require_admin
@require_csrf
def api_admin_universities():
    return jsonify({"items": get_universities()})


@bp.route("/api/admin/universities", methods=["POST"])
@require_admin
@require_csrf
def api_add_university():
    data = request.get_json() or {}
    name = data.get("name", "").strip()
    university_code = str(data.get("university_code", "")).strip()

    if not name:
        return jsonify({"success": False, "message": "Название не может быть пустым"}), 400

    if not university_code:
        return jsonify({"success": False, "message": "Код ВУЗа обязателен"}), 400

    try:
        result = add_university(name=name, university_code=university_code)
        return jsonify({"success": True, "item": result})
    except Exception as exc:
        return jsonify({"success": False, "message": str(exc)}), 400


@bp.route("/api/admin/universities/<university_code>", methods=["DELETE"])
@require_admin
@require_csrf
def api_delete_university(university_code: str):
    university_code = str(university_code).strip()
    result = delete_university(university_code)
    if not result:
        return jsonify({"success": False, "message": "ВУЗ не найден"}), 404
    return jsonify({"success": True, "item": result})



@bp.route("/api/admin/universities/<university_code>/reset-password", methods=["POST"])
@require_admin
@require_csrf
def api_reset_university_password(university_code: str):
    university_code = str(university_code).strip()
    result = reset_university_password(university_code)
    if not result:
        return jsonify({"success": False, "message": "ВУЗ не найден"}), 404
    return jsonify({"success": True, "item": result})


@bp.route("/api/admin/logs/security")
@require_admin
@require_csrf
def api_security_logs():
    limit = min(int(request.args.get("limit", 50)), 200)
    return jsonify({"items": get_security_logs(limit)})


@bp.route("/api/admin/logs/verification")
@require_admin
@require_csrf
def api_verification_logs():
    limit = min(int(request.args.get("limit", 50)), 200)
    return jsonify({"items": get_verification_logs(limit)})


@bp.route("/api/admin/logs/security/clear", methods=["POST"])
@require_admin
@require_csrf
def api_clear_security_logs():
    deleted = clear_security_logs()
    return jsonify({"success": True, "message": "Логи безопасности очищены", "deleted_count": deleted})


@bp.route("/api/admin/logs/verification/clear", methods=["POST"])
@require_admin
@require_csrf
def api_clear_verification_logs():
    deleted = clear_verification_logs()
    return jsonify({"success": True, "message": "Логи проверок дипломов очищены", "deleted_count": deleted})


@bp.route("/api/admin/reports/suspicious")
@require_admin
@require_csrf
def api_suspicious_reports():
    limit = min(int(request.args.get("limit", 50)), 200)
    return jsonify({"items": show_suspicious_reports(limit)})


@bp.route("/api/admin/student-secrets/export")
@require_admin
@require_csrf
def api_export_student_secrets_csv():
    sort_by = request.args.get("sort_by", "university_name")
    sort_dir = request.args.get("sort_dir", "asc")
    search = request.args.get("search", "").strip()
    rows = get_admin_student_secrets(sort_by=sort_by, sort_dir=sort_dir, search=search)

    output = io.StringIO()
    writer = csv.writer(output, delimiter=";")
    writer.writerow(["ВУЗ", "ФИО", "Номер диплома", "Пароль"])
    for row in rows:
        writer.writerow([
            row["university_name"],
            row["full_name"],
            row["diploma_number"],
            "Скрыт (хранится только хэш)",
        ])

    mem = io.BytesIO(output.getvalue().encode("utf-8-sig"))
    mem.seek(0)
    return send_file(mem, mimetype="text/csv", as_attachment=True, download_name="student_secrets_overview.csv")
