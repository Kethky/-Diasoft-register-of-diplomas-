from typing import Optional

from app.db import get_db_connection


def normalize_student_name(full_name: str) -> str:
    return " ".join((full_name or "").strip().lower().split())


def _build_account_payload(row, created: bool = False):
    if not row:
        return None
    data = dict(row)
    data["created"] = created
    return data


def get_or_create_student_account(full_name: str, secret_hash: Optional[str] = None, conn=None):
    owns_connection = conn is None
    conn = conn or get_db_connection()
    normalized = normalize_student_name(full_name)

    row = conn.execute(
        "SELECT id, full_name, normalized_full_name, secret_hash FROM student_accounts WHERE normalized_full_name = ?",
        (normalized,),
    ).fetchone()

    if row:
        payload = _build_account_payload(row, created=False)
        if owns_connection:
            conn.close()
        return payload

    if not secret_hash:
        if owns_connection:
            conn.close()
        return None

    cursor = conn.execute(
        "INSERT INTO student_accounts (full_name, normalized_full_name, secret_hash) VALUES (?, ?, ?)",
        (full_name.strip(), normalized, secret_hash),
    )
    account_id = cursor.lastrowid
    payload = {
        "id": account_id,
        "full_name": full_name.strip(),
        "normalized_full_name": normalized,
        "secret_hash": secret_hash,
        "created": True,
    }
    if owns_connection:
        conn.commit()
        conn.close()
    return payload


def get_student_account_by_diploma_number(diploma_number: str) -> Optional[dict]:
    conn = get_db_connection()
    row = conn.execute(
        """
        SELECT d.id AS diploma_id, d.student_account_id, sa.secret_hash
        FROM diplomas d
        JOIN student_accounts sa ON sa.id = d.student_account_id
        WHERE d.diploma_number = ?
        """,
        (diploma_number,),
    ).fetchone()
    conn.close()
    return dict(row) if row else None


def get_student_diplomas(student_account_id: int):
    conn = get_db_connection()
    rows = conn.execute(
        """
        SELECT d.id, d.full_name, d.diploma_number, d.status, d.graduation_year, d.specialty,
               d.university_code, COALESCE(u.name, d.university_code) AS university_name
        FROM diplomas d
        LEFT JOIN universities u ON u.university_code = d.university_code
        WHERE d.student_account_id = ?
        ORDER BY d.graduation_year DESC, d.id DESC
        """,
        (student_account_id,),
    ).fetchall()
    conn.close()
    return [dict(row) for row in rows]


def get_student_primary_diploma(student_account_id: int) -> Optional[dict]:
    diplomas = get_student_diplomas(student_account_id)
    return diplomas[0] if diplomas else None


def get_diploma_by_id(diploma_id: int) -> Optional[dict]:
    conn = get_db_connection()
    row = conn.execute(
        """
        SELECT d.id, d.university_code, d.full_name, d.graduation_year, d.specialty,
               d.diploma_number, d.status, d.active_token, d.active_token_expires_at,
               d.student_secret_hash, d.digital_signature, d.student_account_id
        FROM diplomas d
        WHERE d.id = ?
        """,
        (diploma_id,),
    ).fetchone()
    conn.close()
    return dict(row) if row else None


def get_diploma_student_view(diploma_id: int) -> Optional[dict]:
    conn = get_db_connection()
    row = conn.execute(
        """
        SELECT d.id, d.full_name, d.diploma_number, d.status, d.graduation_year, d.specialty,
               d.university_code, COALESCE(u.name, d.university_code) AS university_name, d.student_account_id
        FROM diplomas d
        LEFT JOIN universities u ON u.university_code = d.university_code
        WHERE d.id = ?
        """,
        (diploma_id,),
    ).fetchone()
    conn.close()
    return dict(row) if row else None


def get_diploma_for_student_auth(diploma_number: str) -> Optional[dict]:
    return get_student_account_by_diploma_number(diploma_number)


def get_diploma_by_params(university_code, diploma_number: str) -> Optional[dict]:
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


def get_diploma_id(university_code, diploma_number: str) -> Optional[int]:
    conn = get_db_connection()
    row = conn.execute(
        "SELECT id FROM diplomas WHERE university_code = ? AND diploma_number = ?",
        (university_code, diploma_number),
    ).fetchone()
    conn.close()
    return row["id"] if row else None


def get_university_diplomas(university_code):
    conn = get_db_connection()
    rows = conn.execute(
        """
        SELECT d.id, d.full_name, d.graduation_year, d.specialty, d.diploma_number, d.status
        FROM diplomas d
        WHERE d.university_code = ?
        ORDER BY d.id
        """,
        (university_code,),
    ).fetchall()
    conn.close()
    return [dict(row) for row in rows]


def insert_diploma(
    university_code,
    full_name: str,
    graduation_year: int,
    specialty: str,
    diploma_number: str,
    hash_combined: str,
    digital_signature: str,
    student_secret_hash: str,
    student_account_id: int,
) -> None:
    conn = get_db_connection()
    conn.execute(
        """
        INSERT INTO diplomas (
            university_code, full_name, graduation_year, specialty,
            diploma_number, status, hash_combined, digital_signature,
            signature_created_at, student_secret_hash, student_account_id
        )
        VALUES (?, ?, ?, ?, ?, 1, ?, ?, CURRENT_TIMESTAMP, ?, ?)
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
            student_account_id,
        ),
    )
    conn.commit()
    conn.close()


def insert_diploma_with_cursor(
    cursor,
    university_code,
    full_name: str,
    graduation_year: int,
    specialty: str,
    diploma_number: str,
    hash_combined: str,
    digital_signature: str,
    student_secret_hash: str,
    student_account_id: int,
) -> None:
    cursor.execute(
        """
        INSERT INTO diplomas (
            university_code, full_name, graduation_year, specialty,
            diploma_number, status, hash_combined, digital_signature,
            signature_created_at, student_secret_hash, student_account_id
        )
        VALUES (?, ?, ?, ?, ?, 1, ?, ?, CURRENT_TIMESTAMP, ?, ?)
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
            student_account_id,
        ),
    )


def update_diploma_status(diploma_id: int, new_status: int, university_code) -> bool:
    conn = get_db_connection()
    cursor = conn.execute(
        "UPDATE diplomas SET status = ? WHERE id = ? AND university_code = ?",
        (new_status, diploma_id, university_code),
    )
    conn.commit()
    updated = cursor.rowcount > 0
    conn.close()
    return updated


def clear_all_diplomas(university_code) -> int:
    conn = get_db_connection()
    cursor = conn.execute("DELETE FROM diplomas WHERE university_code = ?", (university_code,))
    conn.commit()
    deleted_count = cursor.rowcount
    conn.close()
    return deleted_count


def delete_diploma(diploma_id: int, university_code) -> bool:
    conn = get_db_connection()
    cursor = conn.execute(
        "DELETE FROM diplomas WHERE id = ? AND university_code = ?",
        (diploma_id, university_code),
    )
    conn.commit()
    deleted = cursor.rowcount > 0
    conn.close()
    return deleted


def _get_student_account_id_by_diploma(conn, diploma_id: int):
    row = conn.execute("SELECT student_account_id FROM diplomas WHERE id = ?", (diploma_id,)).fetchone()
    return row["student_account_id"] if row else None


def clear_student_secret_hash(diploma_id: int) -> bool:
    conn = get_db_connection()
    account_id = _get_student_account_id_by_diploma(conn, diploma_id)
    if not account_id:
        conn.close()
        return False
    conn.execute("UPDATE student_accounts SET secret_hash = '' WHERE id = ?", (account_id,))
    cursor = conn.execute("UPDATE diplomas SET student_secret_hash = '' WHERE student_account_id = ?", (account_id,))
    conn.commit()
    updated = cursor.rowcount > 0
    conn.close()
    return updated


def set_student_secret_hash(diploma_id: int, secret_hash: str) -> bool:
    conn = get_db_connection()
    account_id = _get_student_account_id_by_diploma(conn, diploma_id)
    if not account_id:
        conn.close()
        return False
    conn.execute("UPDATE student_accounts SET secret_hash = ? WHERE id = ?", (secret_hash, account_id))
    cursor = conn.execute("UPDATE diplomas SET student_secret_hash = ? WHERE student_account_id = ?", (secret_hash, account_id))
    conn.commit()
    updated = cursor.rowcount > 0
    conn.close()
    return updated


def get_admin_student_secret_row(diploma_id: int) -> Optional[dict]:
    conn = get_db_connection()
    row = conn.execute(
        """
        SELECT d.id, d.university_code, u.name AS university_name, d.full_name, d.diploma_number, d.student_secret_hash, d.student_account_id
        FROM diplomas d
        LEFT JOIN universities u ON u.university_code = d.university_code
        WHERE d.id = ?
        """,
        (diploma_id,),
    ).fetchone()
    conn.close()
    return dict(row) if row else None


def list_admin_student_secret_rows(sort_by: str = "university_name", sort_dir: str = "asc", search: str = ""):
    allowed = {
        "university_name": "u.name",
        "full_name": "d.full_name",
        "diploma_number": "d.diploma_number",
        "university_code": "d.university_code",
    }
    order_col = allowed.get(sort_by, "u.name")
    order_dir = "DESC" if str(sort_dir).lower() == "desc" else "ASC"
    conn = get_db_connection()
    params = []
    where = ""
    if search:
        where = "WHERE u.name LIKE ? OR d.full_name LIKE ? OR d.diploma_number LIKE ? OR d.university_code LIKE ?"
        like = f"%{search}%"
        params.extend([like, like, like, like])
    rows = conn.execute(
        f"""
        SELECT d.id, d.university_code, u.name AS university_name, d.full_name, d.diploma_number,
               CASE WHEN sa.secret_hash IS NULL OR sa.secret_hash = '' THEN 0 ELSE 1 END AS has_secret
        FROM diplomas d
        LEFT JOIN universities u ON u.university_code = d.university_code
        LEFT JOIN student_accounts sa ON sa.id = d.student_account_id
        {where}
        ORDER BY {order_col} {order_dir}, d.id DESC
        """,
        params,
    ).fetchall()
    conn.close()
    return [dict(row) for row in rows]


def list_diplomas_missing_student_secret_details():
    conn = get_db_connection()
    rows = conn.execute(
        """
        SELECT d.id, d.university_code, u.name AS university_name, d.full_name, d.diploma_number
        FROM diplomas d
        LEFT JOIN universities u ON u.university_code = d.university_code
        LEFT JOIN student_accounts sa ON sa.id = d.student_account_id
        WHERE sa.secret_hash IS NULL OR sa.secret_hash = ''
        ORDER BY d.id DESC
        """
    ).fetchall()
    conn.close()
    return [dict(row) for row in rows]


def get_active_token(diploma_id: int, university_code, diploma_number: str):
    conn = get_db_connection()
    row = conn.execute(
        "SELECT active_token FROM diplomas WHERE id = ? AND university_code = ? AND diploma_number = ?",
        (diploma_id, university_code, diploma_number),
    ).fetchone()
    conn.close()
    return row["active_token"] if row else None


def get_active_token_by_params(university_code, diploma_number: str):
    conn = get_db_connection()
    row = conn.execute(
        "SELECT active_token FROM diplomas WHERE university_code = ? AND diploma_number = ?",
        (university_code, diploma_number),
    ).fetchone()
    conn.close()
    return row["active_token"] if row else None


def set_active_token(diploma_id: int, token: str, expiry_timestamp: int) -> None:
    conn = get_db_connection()
    conn.execute(
        "UPDATE diplomas SET active_token = ?, active_token_expires_at = datetime(?, 'unixepoch') WHERE id = ?",
        (token, expiry_timestamp, diploma_id),
    )
    conn.commit()
    conn.close()


def revoke_active_token(diploma_id: int) -> None:
    conn = get_db_connection()
    conn.execute(
        "UPDATE diplomas SET active_token = NULL, active_token_expires_at = NULL WHERE id = ?",
        (diploma_id,),
    )
    conn.commit()
    conn.close()


def get_diploma_status(diploma_id: int):
    conn = get_db_connection()
    row = conn.execute("SELECT status FROM diplomas WHERE id = ?", (diploma_id,)).fetchone()
    conn.close()
    return row["status"] if row else None
