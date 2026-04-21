from app.db import get_db_connection


def insert_audit_log(
    actor_role: str,
    actor_identifier: str,
    action: str,
    entity_type: str,
    entity_id: str | None,
    details: str | None,
    ip: str | None,
    user_agent: str | None,
) -> None:
    conn = get_db_connection()
    conn.execute(
        '''
        INSERT INTO audit_logs (
            actor_role, actor_identifier, action, entity_type, entity_id,
            details, ip, user_agent
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''',
        (actor_role, actor_identifier, action, entity_type, entity_id, details, ip, user_agent),
    )
    conn.commit()
    conn.close()



def list_audit_logs(limit: int = 50):
    conn = get_db_connection()
    rows = conn.execute(
        '''
        SELECT id, actor_role, actor_identifier, action, entity_type, entity_id,
               details, ip, user_agent, timestamp
        FROM audit_logs
        ORDER BY timestamp DESC, id DESC
        LIMIT ?
        ''',
        (limit,),
    ).fetchall()
    conn.close()
    return [dict(row) for row in rows]



def clear_audit_logs() -> int:
    conn = get_db_connection()
    cursor = conn.execute('DELETE FROM audit_logs')
    conn.commit()
    deleted = cursor.rowcount if cursor.rowcount is not None else 0
    conn.close()
    return deleted
