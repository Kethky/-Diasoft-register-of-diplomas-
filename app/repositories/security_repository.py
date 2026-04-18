from app.db import get_db_connection


def insert_verification_log(
    diploma_id,
    university_code,
    diploma_number,
    verification_type,
    token,
    ip,
    user_agent,
    result,
) -> None:
    conn = get_db_connection()
    conn.execute(
        """
        INSERT INTO verification_logs (
            diploma_id, university_code, diploma_number, verification_type,
            token, ip, user_agent, result
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            diploma_id,
            university_code,
            diploma_number,
            verification_type,
            token,
            ip,
            user_agent,
            result,
        ),
    )
    conn.commit()
    conn.close()


def insert_security_log(ip: str, endpoint: str, user_agent: str) -> None:
    conn = get_db_connection()
    conn.execute(
        "INSERT INTO security_logs (ip, endpoint, user_agent) VALUES (?, ?, ?)",
        (ip, endpoint, user_agent),
    )
    conn.commit()
    conn.close()


def get_blocked_ip(ip: str):
    conn = get_db_connection()
    row = conn.execute(
        """
        SELECT blocked_until
        FROM blocked_ips
        WHERE ip = ? AND blocked_until > datetime('now')
        """,
        (ip,),
    ).fetchone()
    conn.close()
    return row


def upsert_blocked_ip(ip: str, reason: str, blocked_until: str) -> None:
    conn = get_db_connection()
    conn.execute(
        """
        INSERT OR REPLACE INTO blocked_ips (ip, reason, blocked_until)
        VALUES (?, ?, ?)
        """,
        (ip, reason, blocked_until),
    )
    conn.commit()
    conn.close()


def list_security_logs(limit: int = 50):
    conn = get_db_connection()
    rows = conn.execute(
        """
        SELECT id, ip, endpoint, user_agent, timestamp
        FROM security_logs
        ORDER BY timestamp DESC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()
    conn.close()
    return [dict(row) for row in rows]


def list_verification_logs(limit: int = 50):
    conn = get_db_connection()
    rows = conn.execute(
        """
        SELECT id, diploma_number, verification_type, ip, user_agent, result, timestamp
        FROM verification_logs
        ORDER BY timestamp DESC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()
    conn.close()
    return [dict(row) for row in rows]



def clear_security_logs() -> int:
    conn = get_db_connection()
    cursor = conn.execute("DELETE FROM security_logs")
    conn.commit()
    deleted = cursor.rowcount if cursor.rowcount is not None else 0
    conn.close()
    return deleted


def clear_verification_logs() -> int:
    conn = get_db_connection()
    cursor = conn.execute("DELETE FROM verification_logs")
    conn.commit()
    deleted = cursor.rowcount if cursor.rowcount is not None else 0
    conn.close()
    return deleted
