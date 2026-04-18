import json
from typing import Optional

from app.db import get_db_connection


def insert_hr_history(
    session_id: str,
    verification_mode: str,
    input_source: str,
    university_code,
    university_name,
    diploma_number,
    requested_full_name,
    matched_full_name,
    requested_graduation_year,
    matched_graduation_year,
    requested_specialty,
    matched_specialty,
    status: str,
    trust_level: str,
    trust_label: str,
    signature_valid,
    fields_match_status: str,
    details: dict,
) -> int:
    conn = get_db_connection()
    cursor = conn.execute(
        """
        INSERT INTO hr_verification_history (
            session_id, verification_mode, input_source, university_code, university_name,
            diploma_number, requested_full_name, matched_full_name,
            requested_graduation_year, matched_graduation_year,
            requested_specialty, matched_specialty,
            status, trust_level, trust_label, signature_valid,
            fields_match_status, details_json
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            session_id,
            verification_mode,
            input_source,
            university_code,
            university_name,
            diploma_number,
            requested_full_name,
            matched_full_name,
            requested_graduation_year,
            matched_graduation_year,
            requested_specialty,
            matched_specialty,
            status,
            trust_level,
            trust_label,
            1 if signature_valid else 0 if signature_valid is not None else None,
            fields_match_status,
            json.dumps(details, ensure_ascii=False),
        ),
    )
    conn.commit()
    item_id = cursor.lastrowid
    conn.close()
    return item_id


def list_hr_history(
    session_id: str,
    university_code=None,
    status: str = "",
    date_from: str = "",
    date_to: str = "",
    limit: int = 100,
):
    params = [session_id]
    where_clauses = ["session_id = ?"]

    if university_code not in (None, ""):
        where_clauses.append("CAST(university_code AS TEXT) = ?")
        params.append(str(university_code))

    if status:
        where_clauses.append("status = ?")
        params.append(status)

    if date_from:
        where_clauses.append("date(created_at) >= date(?)")
        params.append(date_from)

    if date_to:
        where_clauses.append("date(created_at) <= date(?)")
        params.append(date_to)

    params.append(min(limit, 500))
    conn = get_db_connection()
    rows = conn.execute(
        f"""
        SELECT id, verification_mode, input_source, university_code, university_name,
               diploma_number, requested_full_name, matched_full_name,
               requested_graduation_year, matched_graduation_year,
               requested_specialty, matched_specialty,
               status, trust_level, trust_label, signature_valid,
               fields_match_status, details_json, created_at
        FROM hr_verification_history
        WHERE {' AND '.join(where_clauses)}
        ORDER BY datetime(created_at) DESC, id DESC
        LIMIT ?
        """,
        params,
    ).fetchall()
    conn.close()

    items = []
    for row in rows:
        item = dict(row)
        try:
            item["details"] = json.loads(item.pop("details_json") or "{}")
        except json.JSONDecodeError:
            item["details"] = {}
            item.pop("details_json", None)
        items.append(item)
    return items


def get_hr_history_item(session_id: str, history_id: int) -> Optional[dict]:
    conn = get_db_connection()
    row = conn.execute(
        """
        SELECT id, verification_mode, input_source, university_code, university_name,
               diploma_number, requested_full_name, matched_full_name,
               requested_graduation_year, matched_graduation_year,
               requested_specialty, matched_specialty,
               status, trust_level, trust_label, signature_valid,
               fields_match_status, details_json, created_at
        FROM hr_verification_history
        WHERE session_id = ? AND id = ?
        """,
        (session_id, history_id),
    ).fetchone()
    conn.close()
    if not row:
        return None
    item = dict(row)
    try:
        item["details"] = json.loads(item.pop("details_json") or "{}")
    except json.JSONDecodeError:
        item["details"] = {}
        item.pop("details_json", None)
    return item
