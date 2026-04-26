from functools import lru_cache

from flask import session

from app.db import get_db_connection
from app.repositories.diploma_repository import (
    get_diploma_by_id,
    get_diploma_by_params,
    get_diploma_id,
    get_or_create_student_account,
    get_student_diplomas,
    get_student_primary_diploma,
    get_university_diplomas as repo_get_university_diplomas,
    insert_diploma_with_cursor,
    update_diploma_status as repo_update_diploma_status,
)
from app.repositories.university_repository import get_all_universities
from app.services.auth_service import generate_student_secret, hash_password
from app.services.crypto_service import calculate_diploma_hash, sign_diploma


@lru_cache(maxsize=1)
def get_university_list():
    universities = get_all_universities()
    return [{"code": row["university_code"], "name": row["name"]} for row in universities]


def clear_university_list_cache() -> None:
    get_university_list.cache_clear()


def get_current_student_diploma():
    if session.get("role") != "student" or "selected_diploma_id" not in session:
        return None
    return get_diploma_by_id(session["selected_diploma_id"])


def get_current_student_diplomas():
    if session.get("role") != "student" or "student_account_id" not in session:
        return []
    return get_student_diplomas(session["student_account_id"])


def get_default_student_diploma(student_account_id: int):
    return get_student_primary_diploma(student_account_id)


def get_university_diplomas(university_code):
    return repo_get_university_diplomas(university_code)


def update_diploma_status(diploma_id: int, new_status: int, university_code) -> bool:
    return repo_update_diploma_status(diploma_id, new_status, university_code)


def check_diploma_by_params(university_code, diploma_number: str) -> dict:
    row = get_diploma_by_params(university_code, diploma_number)
    if not row:
        return {"found": False, "valid": False, "message": "Сведений не найдено"}

    return {
        "found": True,
        "valid": row["status"] == 1,
        "full_name": row["full_name"],
        "graduation_year": row["graduation_year"],
        "specialty": row["specialty"],
        "message": "Подлинный" if row["status"] == 1 else "Аннулирован",
        "digital_signature": row["digital_signature"],
        "id": row["id"],
    }


def create_signed_diploma(university_code, full_name: str, graduation_year: int, specialty: str, diploma_number: str):
    hash_combined, _salt = calculate_diploma_hash(university_code, diploma_number, full_name, graduation_year, specialty)
    diploma_data_for_sign = {
        "university_code": university_code,
        "diploma_number": diploma_number,
        "full_name": full_name,
        "graduation_year": graduation_year,
        "specialty": specialty,
    }
    digital_signature = sign_diploma(university_code, diploma_data_for_sign)

    conn = get_db_connection()
    cursor = conn.cursor()
    student_secret = None
    try:
        existing_account = get_or_create_student_account(full_name, conn=conn)
        if existing_account:
            student_account = existing_account
            reused = True
        else:
            student_secret = generate_student_secret()
            student_secret_hash = hash_password(student_secret)
            student_account = get_or_create_student_account(full_name, secret_hash=student_secret_hash, conn=conn)
            reused = False

        insert_diploma_with_cursor(
            cursor=cursor,
            university_code=university_code,
            full_name=full_name,
            graduation_year=graduation_year,
            specialty=specialty,
            diploma_number=diploma_number,
            hash_combined=hash_combined,
            digital_signature=digital_signature,
            student_secret_hash=student_account["secret_hash"],
            student_account_id=student_account["id"],
        )
        diploma_id = cursor.lastrowid
        conn.commit()
        return {
            "student_secret": student_secret,
            "student_account_reused": reused,
            "student_account_id": student_account["id"],
            "diploma_id": diploma_id,
        }
    finally:
        conn.close()
