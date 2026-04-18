from pathlib import Path
import re
import secrets
import string

from flask import current_app

from app.repositories.diploma_repository import (
    clear_student_secret_hash,
    get_admin_student_secret_row,
    list_admin_student_secret_rows,
    list_diplomas_missing_student_secret_details,
    set_student_secret_hash,
)
from app.repositories.security_repository import (
    clear_security_logs as clear_security_logs_repo,
    clear_verification_logs as clear_verification_logs_repo,
    list_security_logs,
    list_verification_logs,
)
from app.repositories.university_repository import (
    delete_university_by_code,
    get_existing_logins,
    get_university_by_code,
    insert_university,
    list_universities,
    update_university_password_hash,
)
from app.services.auth_service import hash_password
from app.services.diploma_service import clear_university_list_cache


def show_suspicious_reports(limit: int = 50):
    log_path = Path(current_app.config["SUSPICIOUS_REPORTS_LOG"])
    if not log_path.exists():
        return []

    lines = [line.strip() for line in log_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    return lines[-limit:]


def transliterate(text: str) -> str:
    cyrillic = "абвгдеёжзийклмнопрстуфхцчшщъыьэюя"
    latin = [
        "a", "b", "v", "g", "d", "e", "e", "zh", "z", "i", "y", "k", "l", "m",
        "n", "o", "p", "r", "s", "t", "u", "f", "kh", "ts", "ch", "sh", "shch",
        "", "y", "", "e", "yu", "ya",
    ]
    trans_dict = {
        ord(c): l
        for c, l in zip(cyrillic + cyrillic.upper(), latin + [x.upper() for x in latin])
    }
    return text.translate(trans_dict).replace(" ", "_").lower()


def generate_login_from_name(university_name: str, existing_logins: set) -> str:
    first_word = university_name.split()[0] if university_name.split() else university_name
    base = transliterate(first_word)
    base = re.sub(r"[^a-z0-9]", "", base)
    if not base:
        base = "university"

    login = base
    counter = 1
    while login in existing_logins:
        login = f"{base}{counter}"
        counter += 1
    return login


def generate_password() -> str:
    length = secrets.randbelow(5) + 12
    lowercase = string.ascii_lowercase
    uppercase = string.ascii_uppercase
    digits = string.digits
    special = "!@#$%^&*"

    password_chars = [
        secrets.choice(lowercase),
        secrets.choice(uppercase),
        secrets.choice(digits),
        secrets.choice(special),
    ]
    all_chars = lowercase + uppercase + digits + special
    for _ in range(length - 4):
        password_chars.append(secrets.choice(all_chars))
    secrets.SystemRandom().shuffle(password_chars)
    return "".join(password_chars)


def add_university(name: str, university_code: str):
    name = name.strip()
    university_code = str(university_code).strip()

    if not name:
        raise ValueError("Название не может быть пустым.")

    if not university_code:
        raise ValueError("Код ВУЗа обязателен.")

    existing_university = get_university_by_code(university_code)
    if existing_university:
        raise ValueError(f"ВУЗ с кодом {university_code} уже существует.")

    existing_logins = get_existing_logins()
    login = generate_login_from_name(name, existing_logins)
    plain_password = generate_password()
    password_hash = hash_password(plain_password)

    insert_university(
        university_code=university_code,
        name=name,
        login=login,
        password_hash=password_hash,
    )
    clear_university_list_cache()

    return {
        "university_code": university_code,
        "name": name,
        "login": login,
        "password": plain_password,
    }


def delete_university(university_code: str):
    university_code = str(university_code).strip()
    university = get_university_by_code(university_code)
    if not university:
        return None

    deleted = delete_university_by_code(university_code)
    if deleted:
        clear_university_list_cache()
        return university
    return None


def get_universities():
    return list_universities()


def get_security_logs(limit: int = 50):
    return list_security_logs(limit)


def get_verification_logs(limit: int = 50):
    return list_verification_logs(limit)



def clear_security_logs():
    return clear_security_logs_repo()


def clear_verification_logs():
    return clear_verification_logs_repo()

def get_admin_student_secrets(sort_by: str = "university_name", sort_dir: str = "asc", search: str = ""):
    return list_admin_student_secret_rows(sort_by=sort_by, sort_dir=sort_dir, search=search)


def generate_student_secrets():
    results = []
    rows = list_diplomas_missing_student_secret_details()

    for row in rows:
        secret = secrets.token_urlsafe(12)
        secret_hash = hash_password(secret)
        set_student_secret_hash(row["id"], secret_hash)
        results.append(
            {
                "id": row["id"],
                "university_code": row["university_code"],
                "university_name": row["university_name"],
                "full_name": row["full_name"],
                "diploma_number": row["diploma_number"],
                "student_secret": secret,
            }
        )

    return results


def reset_student_secret_by_diploma(diploma_id: int):
    row = get_admin_student_secret_row(diploma_id)
    if not row:
        return None

    new_secret = secrets.token_urlsafe(12)
    new_secret_hash = hash_password(new_secret)
    set_student_secret_hash(diploma_id, new_secret_hash)

    return {
        "id": row["id"],
        "university_code": row["university_code"],
        "university_name": row["university_name"],
        "full_name": row["full_name"],
        "diploma_number": row["diploma_number"],
        "student_secret": new_secret,
    }


def delete_student_secret_by_diploma(diploma_id: int):
    row = get_admin_student_secret_row(diploma_id)
    if not row:
        return None

    updated = clear_student_secret_hash(diploma_id)
    if not updated:
        return None

    return row



def reset_university_password(university_code: str):
    university_code = str(university_code).strip()
    university = get_university_by_code(university_code)
    if not university:
        return None

    new_password = generate_password()
    password_hash = hash_password(new_password)
    updated = update_university_password_hash(university_code, password_hash)
    if not updated:
        return None

    return {
        "university_code": university["university_code"],
        "name": university["name"],
        "login": university["login"],
        "password": new_password,
    }
