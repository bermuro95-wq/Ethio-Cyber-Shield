from flask import Blueprint, request, jsonify, g
from app.services.auth_service import login_required, role_required
from app.services.db import get_service_supabase
from app.services.audit_service import log_action
from app.services.security_rules import analyze_transaction, create_alert_from_event, correlate_cyber_fraud

transactions_bp = Blueprint('transactions', __name__)

VALID_TYPES = ['transfer', 'withdrawal', 'deposit', 'payment', 'other']

@transactions_bp.route('', methods=['GET'])
@login_required
def list_transactions():
    sb = get_service_supabase()
    query = sb.table('transactions').select('*')

    suspicious = request.args.get('suspicious')
    account = request.args.get('account')
    search = request.args.get('search')

    if suspicious == 'true':
        query = query.eq('is_suspicious', True)
    if account:
        query = query.eq('account_number', account)
    if search:
        query = query.or_(f'account_number.ilike.%{search}%,device_id.ilike.%{search}%')

    query = query.order('transaction_time', desc=True).limit(100)
    res = query.execute()
    return jsonify(res.data or [])

@transactions_bp.route('/<tx_id>', methods=['GET'])
@login_required
def get_transaction(tx_id):
    sb = get_service_supabase()
    res = sb.table('transactions').select('*').eq('id', tx_id).execute()
    if not res.data:
        return jsonify({'error': 'Transaction not found'}), 404
    return jsonify(res.data[0])

@transactions_bp.route('', methods=['POST'])
@role_required('admin', 'analyst')
def create_transaction():
    data = request.get_json() or {}
    account = (data.get('account_number') or '').strip()
    amount = data.get('amount')
    tx_type = data.get('transaction_type', 'transfer')
    device_id = (data.get('device_id') or '').strip()
    ip_address = (data.get('ip_address') or '').strip()
    location = (data.get('location') or '').strip()
    transaction_time = data.get('transaction_time')
    currency = data.get('currency', 'ETB')
    related_incident_id = data.get('related_incident_id')

    if not account:
        return jsonify({'error': 'account_number is required'}), 400
    try:
        amount = float(amount)
        if amount <= 0:
            raise ValueError()
    except (TypeError, ValueError):
        return jsonify({'error': 'Valid positive amount is required'}), 400
    if tx_type not in VALID_TYPES:
        return jsonify({'error': f'Invalid transaction_type. Allowed: {VALID_TYPES}'}), 400

    payload = {
        'account_number': account[:100],
        'amount': amount,
        'currency': currency,
        'transaction_type': tx_type,
        'device_id': device_id[:255] if device_id else None,
        'ip_address': ip_address[:45] if ip_address else None,
        'location': location[:255] if location else None,
        'created_by': g.user['id']
    }
    if transaction_time:
        payload['transaction_time'] = transaction_time
    if related_incident_id:
        payload['related_incident_id'] = related_incident_id

    sb = get_service_supabase()
    res = sb.table('transactions').insert(payload).execute()
    if not res.data:
        return jsonify({'error': 'Failed to create transaction'}), 500

    tx = res.data[0]
    log_action(g.user['id'], 'transaction_created', 'transaction', tx['id'], {
        'account': account, 'amount': amount
    })

    # Automatically run fraud rules
    analysis = analyze_transaction(tx['id'])
    if analysis.get('is_suspicious'):
        sev = analysis.get('severity') or analysis.get('risk_level') or 'high'
        create_alert_from_event(
            alert_type='suspicious_transaction',
            title=f"Suspicious Transaction Detected [{analysis.get('risk_level', 'high').upper()}]",
            description='; '.join(analysis.get('reasons', [])),
            severity=sev if sev in ('low', 'medium', 'high', 'critical') else 'high',
            related_transaction_id=tx['id'],
            related_incident_id=related_incident_id,
            user_id=g.user['id']
        )
        # Correlation
        correlate_cyber_fraud(transaction_id=tx['id'])

    # Refresh and return
    refreshed = sb.table('transactions').select('*').eq('id', tx['id']).execute()
    return jsonify(refreshed.data[0] if refreshed.data else tx), 201

@transactions_bp.route('/<tx_id>/analyze', methods=['POST'])
@role_required('admin', 'analyst')
def analyze_tx(tx_id):
    result = analyze_transaction(tx_id)
    if result.get('is_suspicious'):
        sev = result.get('severity') or result.get('risk_level') or 'high'
        create_alert_from_event(
            alert_type='suspicious_transaction',
            title=f"Suspicious Transaction Flagged [{result.get('risk_level', 'high').upper()}]",
            description='; '.join(result.get('reasons', [])),
            severity=sev if sev in ('low', 'medium', 'high', 'critical') else 'high',
            related_transaction_id=tx_id,
            user_id=g.user['id']
        )
    log_action(g.user['id'], 'transaction_analyzed', 'transaction', tx_id, result)
    return jsonify(result)


@transactions_bp.route('/<tx_id>', methods=['DELETE'])
@role_required('admin', 'analyst')
def delete_transaction(tx_id):
    sb = get_service_supabase()
    existing = sb.table('transactions').select('id').eq('id', tx_id).execute()
    if not existing.data:
        return jsonify({'error': 'Not found'}), 404
    sb.table('transactions').delete().eq('id', tx_id).execute()
    log_action(g.user['id'], 'transaction_deleted', 'transaction', tx_id)
    return jsonify({'message': 'Deleted'})

@transactions_bp.route('/<tx_id>', methods=['PUT'])
@role_required('admin', 'analyst')
def update_transaction(tx_id):
    data = request.get_json() or {}
    sb = get_service_supabase()
    existing = sb.table('transactions').select('*').eq('id', tx_id).execute()
    if not existing.data:
        return jsonify({'error': 'Not found'}), 404
    allowed = ['account_number', 'amount', 'currency', 'transaction_type', 'device_id',
               'ip_address', 'location', 'status', 'transaction_time']
    updates = {}
    for k in allowed:
        if k in data:
            updates[k] = data[k]
    if 'amount' in updates:
        try:
            updates['amount'] = float(updates['amount'])
            if updates['amount'] <= 0:
                return jsonify({'error': 'amount must be positive'}), 400
        except (TypeError, ValueError):
            return jsonify({'error': 'invalid amount'}), 400
    if not updates:
        return jsonify({'error': 'No fields'}), 400
    res = sb.table('transactions').update(updates).eq('id', tx_id).execute()
    log_action(g.user['id'], 'transaction_updated', 'transaction', tx_id, updates)
    return jsonify(res.data[0] if res.data else updates)
