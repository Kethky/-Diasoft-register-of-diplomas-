from flask import Blueprint, jsonify, redirect, request, session, url_for

from app.decorators import check_blocked_ip, require_student
from app.extensions import limiter
from app.repositories.diploma_repository import get_diploma_status
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

    diploma_id = check_student_auth(diploma_number, student_secret)
    if diploma_id:
        session.clear()
        session["role"] = "student"
        session["diploma_id"] = diploma_id
        session.modified = True
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
        return jsonify({"success": True, "redirect": "/university"})

    log_security_event(request.remote_addr, "/login/university")
    return jsonify({"success": False, "message": result["message"]})


@bp.route("/api/student/status")
@require_student
def api_student_status():
    status = get_diploma_status(session["diploma_id"])
    return jsonify({"status": status})


@bp.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("pages.dashboard"))
