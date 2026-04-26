from flask import Blueprint, redirect, render_template, session, url_for

from app.repositories.diploma_repository import get_diploma_student_view
from app.services.diploma_service import get_current_student_diplomas, get_default_student_diploma, get_university_diplomas

bp = Blueprint("pages", __name__)


@bp.route("/")
def dashboard():
    return render_template("dashboard.html")


@bp.route("/index")
def index():
    return render_template("index.html")


@bp.route("/index.html")
def index_html():
    return redirect(url_for("pages.index"))


@bp.route("/dashboard.html")
def dashboard_html():
    return redirect(url_for("pages.dashboard"))


@bp.route("/university")
def university():
    if session.get("role") != "university":
        return redirect(url_for("pages.index"))

    university_code = session.get("university_code")
    university_name = session.get("university_name")
    diplomas = get_university_diplomas(university_code)

    return render_template("university.html", university_name=university_name, university_code=university_code, diplomas=diplomas)


@bp.route("/student")
def student():
    if session.get("role") != "student" or "student_account_id" not in session:
        return redirect(url_for("pages.index"))

    if "selected_diploma_id" not in session:
        default_diploma = get_default_student_diploma(session["student_account_id"])
        if not default_diploma:
            session.clear()
            return redirect(url_for("pages.index"))
        session["selected_diploma_id"] = default_diploma["id"]
        session["diploma_id"] = default_diploma["id"]

    diploma = get_diploma_student_view(session["selected_diploma_id"])
    if not diploma:
        session.clear()
        return redirect(url_for("pages.index"))

    diplomas = get_current_student_diplomas()
    return render_template(
        "student.html",
        full_name=diploma["full_name"],
        diploma_number=diploma["diploma_number"],
        status=diploma["status"],
        graduation_year=diploma["graduation_year"],
        specialty=diploma["specialty"],
        university_name=diploma.get("university_name") or diploma["university_code"],
        diplomas=diplomas,
        selected_diploma_id=diploma["id"],
    )


@bp.route("/debug/ip")
def debug_ip():
    from flask import jsonify, request

    return jsonify({"ip": request.remote_addr, "headers": dict(request.headers)})
