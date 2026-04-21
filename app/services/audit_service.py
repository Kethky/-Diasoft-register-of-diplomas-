import json

from flask import request, session

from app.repositories.audit_repository import clear_audit_logs, insert_audit_log, list_audit_logs



def _actor_context() -> tuple[str, str]:
    role = session.get('role') or 'system'
    if role == 'admin':
        identifier = session.get('admin_login') or 'admin'
    elif role == 'university':
        identifier = str(session.get('university_code') or session.get('university_name') or 'unknown_university')
    elif role == 'student':
        identifier = str(session.get('diploma_id') or 'student')
    else:
        identifier = 'system'
    return role, identifier



def log_audit_event(action: str, entity_type: str, entity_id=None, details=None, actor_role=None, actor_identifier=None) -> None:
    resolved_role, resolved_identifier = _actor_context()
    payload = None
    if details is not None:
        payload = json.dumps(details, ensure_ascii=False, sort_keys=True)

    insert_audit_log(
        actor_role=actor_role or resolved_role,
        actor_identifier=str(actor_identifier or resolved_identifier),
        action=action,
        entity_type=entity_type,
        entity_id=str(entity_id) if entity_id is not None else None,
        details=payload,
        ip=request.remote_addr if request else None,
        user_agent=request.headers.get('User-Agent', 'Unknown') if request else None,
    )



def get_audit_logs(limit: int = 50):
    return list_audit_logs(limit)



def purge_audit_logs() -> int:
    return clear_audit_logs()
