from typing import Optional

from app.db import get_db_connection


def get_diploma_by_id(diploma_id: int) -> Optional[dict]:
    conn = get_db_connection()
    row = conn.execute(
        """
        SELECT id, university_code, full_name, graduation_year, specialty,
               diploma_number, status, active_token, active_token_expires_at,
               student_secret_hash, digital_signature
        FROM diplomas
        WHERE id = ?
        """,
        (diploma_id,),
    ).fetchone()
    conn.close()
    return dict(row) if row else None


def get_diploma_student_view(diploma_id: int) -> Optional[dict]:
    conn = get_db_connection()
    row = conn.execute(
        """
        SELECT id, full_name, diploma_number, status, graduation_year, specialty, university_code
        FROM diplomas
        WHERE id = ?
        """,
        (diploma_id,),
    ).fetchone()
    conn.close()
    return dict(row) if row else None


def get_diploma_for_student_auth(diploma_number: str) -> Optional[dict]:
    conn = get_db_connection()
    row = conn.execute(
        """
        SELECT id, student_secret_hash
        FROM diplomas
        WHERE diploma_number = ?
        """,
        (diploma_number,),
    ).fetchone()
    conn.close()
    return dict(row) if row else None


def get_diploma_by_params(university_code: int, diploma_number: str) -> Optional[dict]:
    conn = get_db_connection()
    row = conn.execute(
        """
        SELECT id, full_name, status, graduation_year, specialty, digital_signature,
               active_token, active_token_expires_at
        FROM diplomas
        WHERE university_code = ? AND diploma_number = ?
        """,
        (university_code, diploma_number),
    ).fetchone()
    conn.close()
    return dict(row) if row else None


def get_diploma_id(university_code: int, diploma_number: str) -> Optional[int]:
    conn = get_db_connection()
    row = conn.execute(
        """
        SELECT id
        FROM diplomas
        WHERE university_code = ? AND diploma_number = ?
        """,
        (university_code, diploma_number),
    ).fetchone()
    conn.close()
    return row["id"] if row else None


def get_university_diplomas(university_code: int):
    conn = get_db_connection()
    rows = conn.execute(
        """
        SELECT id, full_name, graduation_year, specialty, diploma_number, status
        FROM diplomas
        WHERE university_code = ?
        ORDER BY id
        """,
        (university_code,),
    ).fetchall()
    conn.close()
    return [dict(row) for row in rows]


def insert_diploma(
    university_code: int,
    full_name: str,
    graduation_year: int,
    specialty: str,
    diploma_number: str,
    hash_combined: str,
    digital_signature: str,
    student_secret_hash: str,
) -> None:
    conn = get_db_connection()
    conn.execute(
        """
        INSERT INTO diplomas (
            university_code, full_name, graduation_year, specialty,
            diploma_number, status, hash_combined, digital_signature,
            signature_created_at, student_secret_hash
        )
        VALUES (?, ?, ?, ?, ?, 1, ?, ?, CURRENT_TIMESTAMP, ?)
        """,
        (
            university_code,
            full_name,
            graduation_year,
            specialty,
            diploma_number,
            hash_combined,
            digital_signature,
            student_secret_hash,
        ),
    )
    conn.commit()
    conn.close()


def insert_diploma_with_cursor(
    cursor,
    university_code: int,
    full_name: str,
    graduation_year: int,
    specialty: str,
    diploma_number: str,
    hash_combined: str,
    digital_signature: str,
    student_secret_hash: str,
) -> None:
    cursor.execute(
        """
        INSERT INTO diplomas (
            university_code, full_name, graduation_year, specialty,
            diploma_number, status, hash_combined, digital_signature,
            signature_created_at, student_secret_hash
        )
        VALUES (?, ?, ?, ?, ?, 1, ?, ?, CURRENT_TIMESTAMP, ?)
        """,
        (
            university_code,
            full_name,
            graduation_year,
            specialty,
            diploma_number,
            hash_combined,
            digital_signature,
            student_secret_hash,
        ),
    )


def update_diploma_status(diploma_id: int, new_status: int, university_code: int) -> bool:
    conn = get_db_connection()
    cursor = conn.execute(
        """
        UPDATE diplomas
        SET status = ?
        WHERE id = ? AND university_code = ?
        """,
        (new_status, diploma_id, university_code),
    )
    conn.commit()
    updated = cursor.rowcount > 0
    conn.close()
    return updated


def clear_all_diplomas(university_code: int) -> int:
    conn = get_db_connection()
    cursor = conn.execute(
        "DELETE FROM diplomas WHERE university_code = ?",
        (university_code,),
    )
    conn.commit()
    deleted_count = cursor.rowcount
    conn.close()
    return deleted_count


def delete_diploma(diploma_id: int, university_code: int) -> bool:
    conn = get_db_connection()
    cursor = conn.execute(
        "DELETE FROM diplomas WHERE id = ? AND university_code = ?",
        (diploma_id, university_code),
    )
    conn.commit()
    deleted = cursor.rowcount > 0
    conn.close()
    return deleted


def clear_student_secret_hash(diploma_id: int) -> bool:
    conn = get_db_connection()
    cursor = conn.execute(
        "UPDATE diplomas SET student_secret_hash = NULL WHERE id = ?",
        (diploma_id,),
    )
    conn.commit()
    updated = cursor.rowcount > 0
    conn.close()
    return updated


def get_active_token(diploma_id: int, university_code: int, diploma_number: str):
    conn = get_db_connection()
    row = conn.execute(
        """
        SELECT active_token
        FROM diplomas
        WHERE id = ? AND university_code = ? AND diploma_number = ?
        """,
        (diploma_id, university_code, diploma_number),
    ).fetchone()
    conn.close()
    return row["active_token"] if row else None


def get_active_token_by_params(university_code: int, diploma_number: str):
    conn = get_db_connection()
    row = conn.execute(
        """
        SELECT active_token
        FROM diplomas
        WHERE university_code = ? AND diploma_number = ?
        """,
        (university_code, diploma_number),
    ).fetchone()
    conn.close()
    return row["active_token"] if row else None


def set_active_token(diploma_id: int, token: str, expiry_timestamp: int) -> None:
    conn = get_db_connection()
    conn.execute(
        """
        UPDATE diplomas
        SET active_token = ?, active_token_expires_at = datetime(?, 'unixepoch')
        WHERE id = ?
        """,
        (token, expiry_timestamp, diploma_id),
    )
    conn.commit()
    conn.close()


def revoke_active_token(diploma_id: int) -> None:
    conn = get_db_connection()
    conn.execute(
        """
        UPDATE diplomas
        SET active_token = NULL, active_token_expires_at = NULL
        WHERE id = ?
        """,
        (diploma_id,),
    )
    conn.commit()
    conn.close()


def get_diploma_status(diploma_id: int):
    conn = get_db_connection()
    row = conn.execute(
        "SELECT status FROM diplomas WHERE id = ?",
        (diploma_id,),
    ).fetchone()
    conn.close()
    return row["status"] if row else None


def get_hr_diploma(university_code: int, diploma_number: str):
    conn = get_db_connection()
    row = conn.execute(
        """
        SELECT d.id, d.university_code, d.diploma_number, d.full_name, d.status,
               d.graduation_year, d.specialty, d.digital_signature,
               u.name AS university_name
        FROM diplomas d
        LEFT JOIN universities u ON d.university_code = u.university_code
        WHERE d.diploma_number = ? AND d.university_code = ?
        """,
        (diploma_number, university_code),
    ).fetchone()
    conn.close()
    return dict(row) if row else None




def get_hr_diploma_by_number(diploma_number: str, full_name: str = ""):
    conn = get_db_connection()
    rows = conn.execute(
        """
        SELECT d.id, d.university_code, d.diploma_number, d.full_name, d.status,
               d.graduation_year, d.specialty, d.digital_signature,
               u.name AS university_name
        FROM diplomas d
        LEFT JOIN universities u ON d.university_code = u.university_code
        WHERE d.diploma_number = ?
        ORDER BY d.id ASC
        """,
        (diploma_number,),
    ).fetchall()
    conn.close()
    items = [dict(row) for row in rows]
    if not items:
        return None
    if len(items) == 1:
        return items[0]

    wanted = " ".join(str(full_name or "").strip().lower().split())
    if wanted:
        for item in items:
            current = " ".join(str(item.get("full_name") or "").strip().lower().split())
            if current == wanted:
                return item
    return None


def get_hr_diploma_by_university_name(university_name: str, diploma_number: str, full_name: str = ""):
    conn = get_db_connection()
    rows = conn.execute(
        """
        SELECT d.id, d.university_code, d.diploma_number, d.full_name, d.status,
               d.graduation_year, d.specialty, d.digital_signature,
               u.name AS university_name
        FROM diplomas d
        LEFT JOIN universities u ON d.university_code = u.university_code
        WHERE d.diploma_number = ? AND lower(u.name) = lower(?)
        ORDER BY d.id ASC
        """,
        (diploma_number, university_name),
    ).fetchall()
    conn.close()
    items = [dict(row) for row in rows]
    if not items:
        return None
    if len(items) == 1:
        return items[0]

    wanted = " ".join(str(full_name or "").strip().lower().split())
    if wanted:
        for item in items:
            current = " ".join(str(item.get("full_name") or "").strip().lower().split())
            if current == wanted:
                return item
    return items[0]


def create_cursor():
    conn = get_db_connection()
    return conn, conn.cursor()


def find_diploma_for_secret_reset(university_code: int, diploma_number: str):
    conn = get_db_connection()
    row = conn.execute(
        """
        SELECT id, full_name
        FROM diplomas
        WHERE university_code = ? AND diploma_number = ?
        """,
        (university_code, diploma_number),
    ).fetchone()
    conn.close()
    return dict(row) if row else None


def list_diplomas_missing_student_secret():
    conn = get_db_connection()
    rows = conn.execute(
        """
        SELECT id, university_code, diploma_number
        FROM diplomas
        WHERE student_secret_hash IS NULL OR student_secret_hash = ''
        """
    ).fetchall()
    conn.close()
    return [dict(row) for row in rows]


def list_diplomas_missing_student_secret_details():
    conn = get_db_connection()
    rows = conn.execute(
        """
        SELECT
            d.id,
            d.university_code,
            COALESCE(u.name, '(ВУЗ не найден)') AS university_name,
            d.full_name,
            d.diploma_number
        FROM diplomas d
        LEFT JOIN universities u ON d.university_code = u.university_code
        WHERE d.student_secret_hash IS NULL OR d.student_secret_hash = ''
        ORDER BY university_name ASC, d.full_name ASC
        """
    ).fetchall()
    conn.close()
    return [dict(row) for row in rows]


def set_student_secret_hash(diploma_id: int, secret_hash: str):
    conn = get_db_connection()
    conn.execute(
        "UPDATE diplomas SET student_secret_hash = ? WHERE id = ?",
        (secret_hash, diploma_id),
    )
    conn.commit()
    conn.close()


def get_admin_student_secret_row(diploma_id: int):
    conn = get_db_connection()
    row = conn.execute(
        """
        SELECT
            d.id,
            d.university_code,
            COALESCE(u.name, '(ВУЗ не найден)') AS university_name,
            d.full_name,
            d.diploma_number,
            d.student_secret_hash
        FROM diplomas d
        LEFT JOIN universities u ON d.university_code = u.university_code
        WHERE d.id = ?
        """,
        (diploma_id,),
    ).fetchone()
    conn.close()
    return dict(row) if row else None


def list_admin_student_secret_rows(sort_by: str = "university_name", sort_dir: str = "asc", search: str = ""):
    sort_map = {
        "university_name": "university_name",
        "full_name": "d.full_name",
        "diploma_number": "d.diploma_number",
    }
    order_column = sort_map.get(sort_by, "university_name")
    order_direction = "DESC" if str(sort_dir).lower() == "desc" else "ASC"

    params = []
    where_clause = ""
    if search:
        where_clause = """
        WHERE
            COALESCE(u.name, '(ВУЗ не найден)') LIKE ?
            OR d.full_name LIKE ?
            OR d.diploma_number LIKE ?
        """
        search_value = f"%{search}%"
        params.extend([search_value, search_value, search_value])

    query = f"""
        SELECT
            d.id,
            d.university_code,
            COALESCE(u.name, '(ВУЗ не найден)') AS university_name,
            d.full_name,
            d.diploma_number,
            CASE
                WHEN d.student_secret_hash IS NULL OR d.student_secret_hash = '' THEN 0
                ELSE 1
            END AS has_password
        FROM diplomas d
        LEFT JOIN universities u ON d.university_code = u.university_code
        {where_clause}
        ORDER BY {order_column} {order_direction}, d.id ASC
    """

    conn = get_db_connection()
    rows = conn.execute(query, params).fetchall()
    conn.close()
    return [dict(row) for row in rows]
