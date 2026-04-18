from functools import lru_cache

from flask import session

from app.repositories.diploma_repository import (
    get_diploma_by_id,
    get_diploma_by_params,
    get_diploma_id,
    get_university_diplomas as repo_get_university_diplomas,
    insert_diploma,
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
    if session.get("role") != "student" or "diploma_id" not in session:
        return None
    return get_diploma_by_id(session["diploma_id"])


def get_university_diplomas(university_code: int):
    return repo_get_university_diplomas(university_code)


def update_diploma_status(diploma_id: int, new_status: int, university_code: int) -> bool:
    return repo_update_diploma_status(diploma_id, new_status, university_code)


def check_diploma_by_params(university_code: int, diploma_number: str) -> dict:
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


def create_signed_diploma(
    university_code: int,
    full_name: str,
    graduation_year: int,
    specialty: str,
    diploma_number: str,
):
    hash_combined, _salt = calculate_diploma_hash(
        university_code, diploma_number, full_name, graduation_year, specialty
    )
    diploma_data_for_sign = {
        "university_code": university_code,
        "diploma_number": diploma_number,
        "full_name": full_name,
        "graduation_year": graduation_year,
        "specialty": specialty,
    }
    digital_signature = sign_diploma(university_code, diploma_data_for_sign)

    student_secret = generate_student_secret()
    student_secret_hash = hash_password(student_secret)

    insert_diploma(
        university_code=university_code,
        full_name=full_name,
        graduation_year=graduation_year,
        specialty=specialty,
        diploma_number=diploma_number,
        hash_combined=hash_combined,
        digital_signature=digital_signature,
        student_secret_hash=student_secret_hash,
    )

    return {
        "student_secret": student_secret,
        "digital_signature": digital_signature,
        "hash_combined": hash_combined,
        "diploma_id": get_diploma_id(university_code, diploma_number),
    }
