from flask import Blueprint, jsonify, redirect, request, session, url_for

from app.decorators import check_blocked_ip, require_student
from app.extensions import limiter
from app.repositories.diploma_repository import get_diploma_status, get_student_diplomas
from app.services.audit_service import log_audit_event
from app.services.auth_service import check_student_auth, check_university_auth
from app.services.security_service import log_security_event

bp = Blueprint("auth", __name__)


@bp.route("/login/student", methods=["POST"])
@limiter.limit("20 per minute", error_message="Слишком много попыток входа.")
@limiter.limit("100 per hour", error_message="Достигнут лимит попыток входа.")
@check_blocked_ip
def login_student():
    data = request.get_json() or {}
    diploma_number = data.get("diploma_number", "").strip()
    student_secret = data.get("student_secret", "").strip()

    if not diploma_number or not student_secret:
        return jsonify({"success": False, "message": "Заполните все поля"}), 400

    auth_result = check_student_auth(diploma_number, student_secret)
    if auth_result:
        session.clear()
        session["role"] = "student"
        session["student_account_id"] = auth_result["student_account_id"]
        session["selected_diploma_id"] = auth_result["diploma_id"]
        session["diploma_id"] = auth_result["diploma_id"]
        session.modified = True
        log_audit_event(action='student_login', entity_type='session', entity_id=auth_result['student_account_id'], details=auth_result)
        return jsonify({"success": True, "redirect": "/student"})

    log_security_event(request.remote_addr, "/login/student")
    return jsonify({"success": False, "message": "Неверный номер диплома или код доступа"}), 401


@bp.route("/login/university", methods=["POST"])
@limiter.limit("10 per minute", error_message="Слишком много попыток входа.")
@limiter.limit("30 per hour", error_message="Достигнут лимит попыток входа.")
@check_blocked_ip
def login_university():
    session.clear()
    data = request.get_json() or {}
    login = data.get("login", "").strip()
    password = data.get("password", "")

    result = check_university_auth(login, password)
    if result["success"]:
        session["role"] = "university"
        session["university_code"] = result["university_code"]
        session["university_name"] = result["name"]
        session.modified = True
        log_audit_event(action='university_login', entity_type='session', entity_id=result['university_code'], details={'name': result['name']})
        return jsonify({"success": True, "redirect": "/university"})

    log_security_event(request.remote_addr, "/login/university")
    return jsonify({"success": False, "message": result["message"]})


@bp.route("/api/student/status")
@require_student
def api_student_status():
    status = get_diploma_status(session["selected_diploma_id"])
    return jsonify({"status": status})


@bp.route("/api/student/diplomas")
@require_student
def api_student_diplomas():
    diplomas = get_student_diplomas(session["student_account_id"])
    return jsonify({"success": True, "diplomas": diplomas, "selected_diploma_id": session.get("selected_diploma_id")})


@bp.route("/api/student/select_diploma", methods=["POST"])
@require_student
def api_select_student_diploma():
    data = request.get_json() or {}
    diploma_id = data.get("diploma_id")
    try:
        diploma_id = int(diploma_id)
    except (TypeError, ValueError):
        return jsonify({"success": False, "message": "Некорректный диплом"}), 400

    diplomas = get_student_diplomas(session["student_account_id"])
    diploma_ids = {item['id'] for item in diplomas}
    if diploma_id not in diploma_ids:
        return jsonify({"success": False, "message": "Диплом не принадлежит текущему аккаунту"}), 403

    session["selected_diploma_id"] = diploma_id
    session["diploma_id"] = diploma_id
    session.modified = True
    return jsonify({"success": True})


@bp.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("pages.dashboard"))
