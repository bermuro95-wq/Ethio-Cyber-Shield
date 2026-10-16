"""
Multi-Tenancy Context & Management Service for Ethio-Cyber-Shield (ECS).
Enforces tenant scoping, organization resolution, and strict data boundary isolation.
"""
from flask import g, request, has_app_context, has_request_context
import uuid
import logging
from typing import Optional, Dict, Any, List

logger = logging.getLogger(__name__)

# Default organization UUID for single-tenant backward compatibility
DEFAULT_ORGANIZATION_ID = "00000000-0000-0000-0000-000000000001"
DEFAULT_ORGANIZATION_NAME = "Commercial Bank of Ethiopia (Primary)"


_EXPLICIT_ORGANIZATION_ID = None


def set_current_organization_id(org_id: str):
    """Explicitly sets the active organization ID in Flask application context or worker thread."""
    global _EXPLICIT_ORGANIZATION_ID
    _EXPLICIT_ORGANIZATION_ID = str(org_id) if org_id else None
    if has_app_context():
        g.organization_id = str(org_id) if org_id else DEFAULT_ORGANIZATION_ID


def get_current_organization_id() -> str:
    """
    Returns the currently active organization_id from context.
    Falls back to _EXPLICIT_ORGANIZATION_ID or DEFAULT_ORGANIZATION_ID.
    """
    if has_app_context():
        try:
            if hasattr(g, 'organization_id') and g.organization_id:
                return g.organization_id

            # Fallback: check if authenticated user context is set
            current_user = getattr(g, 'current_user', None)
            if isinstance(current_user, dict) and current_user.get('organization_id'):
                g.organization_id = str(current_user['organization_id'])
                return g.organization_id
        except RuntimeError:
            pass

    if _EXPLICIT_ORGANIZATION_ID:
        return _EXPLICIT_ORGANIZATION_ID

    # Fallback to default
    return DEFAULT_ORGANIZATION_ID


def resolve_tenant_from_request() -> str:
    """
    Resolves organization_id from HTTP request using priority order:
    1. Explicit 'X-ECS-Tenant' HTTP header
    2. Authenticated user's organization_id from JWT
    3. Target system key association
    4. Fallback to DEFAULT_ORGANIZATION_ID
    """
    if not has_request_context():
        return DEFAULT_ORGANIZATION_ID

    # 1. Header check
    header_org = request.headers.get('X-ECS-Tenant')
    if header_org:
        try:
            # Validate UUID format
            val = str(uuid.UUID(header_org.strip()))
            set_current_organization_id(val)
            return val
        except ValueError:
            pass

    # 2. Authenticated user context
    if has_app_context():
        current_user = getattr(g, 'current_user', None)
        if isinstance(current_user, dict) and current_user.get('organization_id'):
            org_id = str(current_user['organization_id'])
            set_current_organization_id(org_id)
            return org_id

    # 3. Target System Key Id lookup
    key_id = request.headers.get('X-ECS-Key-Id')
    if key_id:
        try:
            from app.services.db import get_service_supabase
            sb = get_service_supabase()
            res = sb.table('target_systems').select('organization_id').eq('key_id', key_id).limit(1).execute()
            if res.data and len(res.data) > 0:
                org_id = res.data[0].get('organization_id')
                if org_id:
                    set_current_organization_id(str(org_id))
                    return str(org_id)
        except Exception as e:
            logger.debug(f"Could not resolve organization from key_id {key_id}: {e}")

    # 4. Default fallback
    set_current_organization_id(DEFAULT_ORGANIZATION_ID)
    return DEFAULT_ORGANIZATION_ID
