from flask import Blueprint, request, jsonify, g
from app.services.auth_service import login_required, role_required
from app.services.db import get_service_supabase
from app.services.audit_service import log_action
from app.services.security_rules import get_fraud_thresholds

settings_bp = Blueprint('settings', __name__)

DEFAULT_FRAUD = {
    'high_amount': 500000,
    'critical_amount': 1500000,
    'night_amount': 200000,
    'burst_count': 4,
    'burst_window_minutes': 30,
    'velocity_amount': 800000,
    'new_device_amount': 200000,
    'multi_account_device': 3,
    'shared_ip_accounts': 4,
    'large_withdrawal': 300000,
    'rapid_transfer_amount': 150000,
    'rapid_window_minutes': 10,
}

@settings_bp.route('/fraud-rules', methods=['GET'])
@login_required
def get_fraud_rules():
    return jsonify(get_fraud_thresholds())

@settings_bp.route('/fraud-rules', methods=['PUT'])
@role_required('admin')
def update_fraud_rules():
    data = request.get_json() or {}
    current = get_fraud_thresholds()
    updated = dict(current)
    for k, default in DEFAULT_FRAUD.items():
        if k in data:
            try:
                if isinstance(default, int) and not isinstance(default, bool):
                    updated[k] = int(data[k])
                else:
                    updated[k] = float(data[k])
            except (TypeError, ValueError):
                return jsonify({'error': f'Invalid value for {k}'}), 400
            if updated[k] < 0:
                return jsonify({'error': f'{k} must be >= 0'}), 400
    sb = get_service_supabase()
    # upsert
    existing = sb.table('system_settings').select('key').eq('key', 'fraud_rules').execute()
    payload = {'key': 'fraud_rules', 'value': updated, 'updated_by': g.user['id']}
    if existing.data:
        sb.table('system_settings').update({'value': updated, 'updated_by': g.user['id']}).eq('key', 'fraud_rules').execute()
    else:
        sb.table('system_settings').insert(payload).execute()
    log_action(g.user['id'], 'settings_updated', 'settings', None, {'fraud_rules': updated})
    return jsonify(updated)
