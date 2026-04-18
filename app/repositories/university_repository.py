from typing import Optional

from app.db import get_db_connection


def get_all_universities():
    conn = get_db_connection()
    rows = conn.execute(
        "SELECT university_code, name FROM universities ORDER BY name"
    ).fetchall()
    conn.close()
    return [dict(row) for row in rows]


def get_university_by_login(login: str) -> Optional[dict]:
    conn = get_db_connection()
    row = conn.execute(
        """
        SELECT university_code, name, password_hash
        FROM universities
        WHERE login = ?
        """,
        (login,),
    ).fetchone()
    conn.close()
    return dict(row) if row else None


def get_all_university_codes():
    conn = get_db_connection()
    rows = conn.execute("SELECT university_code FROM universities").fetchall()
    conn.close()
    return [row["university_code"] for row in rows]


def get_existing_logins():
    conn = get_db_connection()
    rows = conn.execute("SELECT login FROM universities").fetchall()
    conn.close()
    return {row["login"] for row in rows}


def get_next_university_code() -> int:
    conn = get_db_connection()
    row = conn.execute("SELECT MAX(university_code) AS max_code FROM universities").fetchone()
    conn.close()
    max_code = row["max_code"] if row else None
    return 1 if max_code is None else max_code + 1


def insert_university(university_code: int, name: str, login: str, password_hash: str) -> None:
    conn = get_db_connection()
    conn.execute(
        """
        INSERT INTO universities (university_code, name, login, password_hash)
        VALUES (?, ?, ?, ?)
        """,
        (university_code, name, login, password_hash),
    )
    conn.commit()
    conn.close()


def get_university_by_code(university_code: int):
    conn = get_db_connection()
    row = conn.execute(
        """
        SELECT university_code, name, login, password_hash
        FROM universities
        WHERE university_code = ?
        """,
        (university_code,),
    ).fetchone()
    conn.close()
    return dict(row) if row else None


def update_university_password_hash(university_code: int, password_hash: str) -> bool:
    conn = get_db_connection()
    cursor = conn.execute(
        """
        UPDATE universities
        SET password_hash = ?
        WHERE university_code = ?
        """,
        (password_hash, university_code),
    )
    conn.commit()
    updated = cursor.rowcount > 0
    conn.close()
    return updated


def delete_university_by_code(university_code: int) -> bool:
    conn = get_db_connection()
    cursor = conn.execute(
        "DELETE FROM universities WHERE university_code = ?",
        (university_code,),
    )
    conn.commit()
    deleted = cursor.rowcount > 0
    conn.close()
    return deleted


def list_universities():
    conn = get_db_connection()
    rows = conn.execute(
        "SELECT university_code, name, login FROM universities ORDER BY university_code"
    ).fetchall()
    conn.close()
    return [dict(row) for row in rows]
