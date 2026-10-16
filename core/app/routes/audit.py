from flask import Blueprint, request, jsonify
from app.services.auth_service import login_required, role_required
from app.services.db import get_service_supabase

audit_bp = Blueprint('audit', __name__)

@audit_bp.route('', methods=['GET'])
@role_required('admin', 'analyst')
def list_audit_logs():
    sb = get_service_supabase()
    query = sb.table('audit_logs').select(
        '*, user:users(id, full_name, email)'
    )

    action = request.args.get('action')
    entity_type = request.args.get('entity_type')
    user_id = request.args.get('user_id')
    limit = min(int(request.args.get('limit', 100)), 500)

    if action:
        query = query.eq('action', action)
    if entity_type:
        query = query.eq('entity_type', entity_type)
    if user_id:
        query = query.eq('user_id', user_id)

    query = query.order('created_at', desc=True).limit(limit)
    res = query.execute()
    return jsonify(res.data or [])
