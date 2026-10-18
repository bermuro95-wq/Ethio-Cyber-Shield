from flask import Blueprint, request, jsonify, g
from app.services.auth_service import login_required, role_required
from app.services.db import get_service_supabase
from app.services.audit_service import log_action

watchlists_bp = Blueprint('watchlists', __name__)
VALID_TYPES = ['account', 'device', 'ip', 'email', 'domain']
VALID_SEV = ['low', 'medium', 'high', 'critical']

@watchlists_bp.route('', methods=['GET'])
@login_required
def list_watchlists():
    sb = get_service_supabase()
    q = sb.table('watchlists').select('*')
    et = request.args.get('entity_type')
    active = request.args.get('active')
    search = request.args.get('search')
    if et:
        q = q.eq('entity_type', et)
    if active == 'true':
        q = q.eq('is_active', True)
    elif active == 'false':
        q = q.eq('is_active', False)
    if search:
        q = q.or_(f'value.ilike.%{search}%,label.ilike.%{search}%')
    res = q.order('created_at', desc=True).limit(200).execute()
    return jsonify(res.data or [])

@watchlists_bp.route('', methods=['POST'])
@role_required('admin', 'analyst')
def create_watchlist():
    data = request.get_json() or {}
    et = (data.get('entity_type') or '').strip()
    value = (data.get('value') or '').strip()
    if et not in VALID_TYPES:
        return jsonify({'error': f'entity_type must be one of {VALID_TYPES}'}), 400
    if not value:
        return jsonify({'error': 'value is required'}), 400
    sev = data.get('severity', 'high')
    if sev not in VALID_SEV:
        sev = 'high'
    payload = {
        'entity_type': et,
        'value': value[:500],
        'label': (data.get('label') or '')[:255] or None,
        'severity': sev,
        'notes': data.get('notes') or None,
        'is_active': data.get('is_active', True) is not False,
        'created_by': g.user['id']
    }
    sb = get_service_supabase()
    try:
        res = sb.table('watchlists').insert(payload).execute()
    except Exception as e:
        return jsonify({'error': f'Could not create (maybe duplicate): {e}'}), 400
    if not res.data:
        return jsonify({'error': 'Insert failed'}), 500
    row = res.data[0]
    log_action(g.user['id'], 'watchlist_created', 'watchlist', row['id'], payload)
    return jsonify(row), 201

@watchlists_bp.route('/<item_id>', methods=['PUT'])
@role_required('admin', 'analyst')
def update_watchlist(item_id):
    data = request.get_json() or {}
    sb = get_service_supabase()
    existing = sb.table('watchlists').select('*').eq('id', item_id).execute()
    if not existing.data:
        return jsonify({'error': 'Not found'}), 404
    updates = {}
    if 'value' in data and data['value']:
        updates['value'] = str(data['value'])[:500]
    if 'label' in data:
        updates['label'] = (data.get('label') or '')[:255] or None
    if 'notes' in data:
        updates['notes'] = data.get('notes')
    if 'severity' in data and data['severity'] in VALID_SEV:
        updates['severity'] = data['severity']
    if 'is_active' in data:
        updates['is_active'] = bool(data['is_active'])
    if 'entity_type' in data and data['entity_type'] in VALID_TYPES:
        updates['entity_type'] = data['entity_type']
    if not updates:
        return jsonify({'error': 'No valid fields'}), 400
    res = sb.table('watchlists').update(updates).eq('id', item_id).execute()
    log_action(g.user['id'], 'watchlist_updated', 'watchlist', item_id, updates)
    return jsonify(res.data[0] if res.data else updates)

@watchlists_bp.route('/<item_id>', methods=['DELETE'])
@role_required('admin', 'analyst')
def delete_watchlist(item_id):
    sb = get_service_supabase()
    existing = sb.table('watchlists').select('id').eq('id', item_id).execute()
    if not existing.data:
        return jsonify({'error': 'Not found'}), 404
    sb.table('watchlists').delete().eq('id', item_id).execute()
    log_action(g.user['id'], 'watchlist_deleted', 'watchlist', item_id)
    return jsonify({'message': 'Deleted'})

@watchlists_bp.route('/clear', methods=['POST'])
@role_required('admin')
def clear_watchlists():
    """Deactivate all or delete all inactive — admin only."""
    data = request.get_json() or {}
    mode = data.get('mode', 'deactivate')
    sb = get_service_supabase()
    if mode == 'delete_all':
        sb.table('watchlists').delete().neq('id', '00000000-0000-0000-0000-000000000000').execute()
        log_action(g.user['id'], 'watchlist_cleared', 'watchlist', None, {'mode': 'delete_all'})
        return jsonify({'message': 'All watchlist entries deleted'})
    sb.table('watchlists').update({'is_active': False}).eq('is_active', True).execute()
    log_action(g.user['id'], 'watchlist_cleared', 'watchlist', None, {'mode': 'deactivate'})
    return jsonify({'message': 'All watchlist entries deactivated'})
