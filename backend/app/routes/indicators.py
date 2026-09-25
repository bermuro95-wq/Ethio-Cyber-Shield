from flask import Blueprint, request, jsonify, g
from app.services.auth_service import login_required, role_required
from app.services.db import get_service_supabase
from app.services.audit_service import log_action
from app.services.security_rules import create_alert_from_event
import re

indicators_bp = Blueprint('indicators', __name__)

VALID_TYPES = ['ip', 'domain', 'url', 'email', 'file_hash']
VALID_STATUSES = ['unknown', 'suspicious', 'malicious', 'benign']

def validate_indicator(itype: str, value: str) -> bool:
    value = value.strip()
    if not value:
        return False
    if itype == 'ip':
        # Simple IPv4 check
        parts = value.split('.')
        if len(parts) != 4:
            return False
        try:
            return all(0 <= int(p) <= 255 for p in parts)
        except ValueError:
            return False
    if itype == 'email':
        return bool(re.match(r'^[^@]+@[^@]+\.[^@]+$', value))
    if itype == 'domain':
        return bool(re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$', value))
    if itype == 'url':
        return value.startswith(('http://', 'https://'))
    if itype == 'file_hash':
        return bool(re.match(r'^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$', value))
    return True

@indicators_bp.route('', methods=['GET'])
@login_required
def list_indicators():
    sb = get_service_supabase()
    query = sb.table('indicators').select('*')

    status = request.args.get('status')
    itype = request.args.get('type')
    search = request.args.get('search')

    if status:
        query = query.eq('status', status)
    if itype:
        query = query.eq('indicator_type', itype)
    if search:
        query = query.ilike('value', f'%{search}%')

    query = query.order('created_at', desc=True).limit(100)
    res = query.execute()
    return jsonify(res.data or [])

@indicators_bp.route('/<indicator_id>', methods=['GET'])
@login_required
def get_indicator(indicator_id):
    sb = get_service_supabase()
    res = sb.table('indicators').select('*').eq('id', indicator_id).execute()
    if not res.data:
        return jsonify({'error': 'Indicator not found'}), 404

    indicator = res.data[0]
    # Linked incidents
    links = sb.table('incident_indicators').select(
        'incident:incidents(id, title, severity, status)'
    ).eq('indicator_id', indicator_id).execute()
    indicator['incidents'] = [l.get('incident') for l in (links.data or []) if l.get('incident')]
    return jsonify(indicator)

@indicators_bp.route('', methods=['POST'])
@role_required('admin', 'analyst')
def create_indicator():
    data = request.get_json() or {}
    itype = data.get('indicator_type')
    value = (data.get('value') or '').strip()
    status = data.get('status', 'unknown')
    description = (data.get('description') or '').strip()
    source = (data.get('source') or '').strip()

    if itype not in VALID_TYPES:
        return jsonify({'error': f'Invalid type. Allowed: {VALID_TYPES}'}), 400
    if status not in VALID_STATUSES:
        return jsonify({'error': f'Invalid status. Allowed: {VALID_STATUSES}'}), 400
    if not validate_indicator(itype, value):
        return jsonify({'error': f'Invalid value format for type {itype}'}), 400

    payload = {
        'indicator_type': itype,
        'value': value,
        'status': status,
        'description': description[:1000],
        'source': source[:255],
        'created_by': g.user['id']
    }

    sb = get_service_supabase()
    try:
        res = sb.table('indicators').insert(payload).execute()
    except Exception as e:
        return jsonify({'error': 'Indicator may already exist or database error'}), 400

    if not res.data:
        return jsonify({'error': 'Failed to create indicator'}), 500

    ind = res.data[0]
    log_action(g.user['id'], 'indicator_created', 'indicator', ind['id'], {
        'type': itype, 'value': value, 'status': status
    })

    if status == 'malicious':
        create_alert_from_event(
            alert_type='malicious_indicator',
            title=f"Malicious Indicator Added: {value}",
            description=description or f"New malicious {itype} indicator",
            severity='high',
            related_indicator_id=ind['id'],
            user_id=g.user['id']
        )

    return jsonify(ind), 201

@indicators_bp.route('/<indicator_id>', methods=['PUT'])
@role_required('admin', 'analyst')
def update_indicator(indicator_id):
    data = request.get_json() or {}
    sb = get_service_supabase()

    existing = sb.table('indicators').select('*').eq('id', indicator_id).execute()
    if not existing.data:
        return jsonify({'error': 'Indicator not found'}), 404

    update = {}
    if 'status' in data:
        if data['status'] not in VALID_STATUSES:
            return jsonify({'error': 'Invalid status'}), 400
        update['status'] = data['status']
    if 'description' in data:
        update['description'] = str(data['description'])[:1000]
    if 'source' in data:
        update['source'] = str(data['source'])[:255]

    if not update:
        return jsonify({'error': 'No valid fields'}), 400

    res = sb.table('indicators').update(update).eq('id', indicator_id).execute()
    log_action(g.user['id'], 'indicator_updated', 'indicator', indicator_id, update)

    if update.get('status') == 'malicious':
        create_alert_from_event(
            alert_type='malicious_indicator',
            title=f"Indicator marked malicious",
            description=f"Indicator {existing.data[0].get('value')} status changed to malicious",
            severity='high',
            related_indicator_id=indicator_id,
            user_id=g.user['id']
        )

    return jsonify(res.data[0] if res.data else {'id': indicator_id})
