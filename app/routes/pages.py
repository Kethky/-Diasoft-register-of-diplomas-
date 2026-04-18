from flask import Blueprint, redirect, render_template, session, url_for

from app.repositories.diploma_repository import get_diploma_student_view
from app.services.diploma_service import get_university_diplomas

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

    return render_template(
        "university.html",
        university_name=university_name,
        university_code=university_code,
        diplomas=diplomas,
    )


@bp.route("/student")
def student():
    if session.get("role") != "student" or "diploma_id" not in session:
        return redirect(url_for("pages.index"))

    diploma = get_diploma_student_view(session["diploma_id"])
    if not diploma:
        session.clear()
        return redirect(url_for("pages.index"))

    return render_template(
        "student.html",
        full_name=diploma["full_name"],
        diploma_number=diploma["diploma_number"],
        status=diploma["status"],
        graduation_year=diploma["graduation_year"],
        specialty=diploma["specialty"],
        university_code=diploma["university_code"],
    )


@bp.route("/debug/ip")
def debug_ip():
    from flask import jsonify, request

    return jsonify({"ip": request.remote_addr, "headers": dict(request.headers)})
