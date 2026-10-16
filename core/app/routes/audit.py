from flask import Blueprint, request, jsonify, g
from app.services.auth_service import login_required, role_required
from app.services.db import get_service_supabase
from app.services.audit_service import (
    verify_audit_chain,
    export_audit_anchor,
    get_audit_logs
)
from app.services.tenant_service import get_current_organization_id

audit_bp = Blueprint('audit', __name__)

@audit_bp.route('', methods=['GET'])
@role_required('admin', 'analyst', 'auditor')
def list_audit_logs():
    org_id = (g.user.get('organization_id') if hasattr(g, 'user') else None) or get_current_organization_id()
    sb = get_service_supabase()
    query = sb.table('audit_logs').select(
        '*, user:users(id, full_name, email)'
    )

    action = request.args.get('action')
    entity_type = request.args.get('entity_type')
    user_id = request.args.get('user_id')
    limit = min(int(request.args.get('limit', 100)), 500)

    if org_id:
        try:
            query = query.eq('organization_id', org_id)
        except Exception:
            pass

    if action:
        query = query.eq('action', action)
    if entity_type:
        query = query.eq('entity_type', entity_type)
    if user_id:
        query = query.eq('user_id', user_id)

    logs = []
    try:
        res = query.order('created_at', desc=True).limit(limit).execute()
        logs = res.data or []
    except Exception:
        pass

    if not logs:
        logs = get_audit_logs(organization_id=org_id, limit=limit, chronological=False)

    return jsonify(logs)


@audit_bp.route('/verify', methods=['POST'])
@role_required('admin', 'analyst', 'auditor')
def verify_audit_chain_endpoint():
    """Validates cryptographic integrity of the hash chain for the active tenant."""
    org_id = (g.user.get('organization_id') if hasattr(g, 'user') else None) or get_current_organization_id()
    result = verify_audit_chain(organization_id=org_id)
    return jsonify(result)


@audit_bp.route('/anchor', methods=['POST'])
@role_required('admin', 'analyst', 'auditor')
def export_audit_anchor_endpoint():
    """Generates a signed audit anchor package for statutory review."""
    org_id = (g.user.get('organization_id') if hasattr(g, 'user') else None) or get_current_organization_id()
    anchor = export_audit_anchor(organization_id=org_id)
    return jsonify(anchor)
