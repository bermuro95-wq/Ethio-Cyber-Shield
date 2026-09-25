from app.services.db import get_service_supabase
from flask import request
import logging

logger = logging.getLogger(__name__)

def log_action(user_id: str | None, action: str, entity_type: str = None, 
               entity_id: str = None, details: dict = None):
    """Record an audit log entry. Non-blocking best-effort."""
    try:
        sb = get_service_supabase()
        entry = {
            'user_id': user_id,
            'action': action,
            'entity_type': entity_type,
            'entity_id': entity_id,
            'details': details or {},
            'ip_address': request.remote_addr if request else None,
            'user_agent': request.headers.get('User-Agent', '')[:500] if request else None
        }
        sb.table('audit_logs').insert(entry).execute()
    except Exception as e:
        logger.error(f"Failed to write audit log: {e}")
