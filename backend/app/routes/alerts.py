from flask import Blueprint, request, jsonify, g
from app.services.auth_service import login_required, role_required
from app.services.db import get_service_supabase
from app.services.audit_service import log_action
from datetime import datetime, timezone

alerts_bp = Blueprint('alerts', __name__)

@alerts_bp.route('', methods=['GET'])
@login_required
def list_alerts():
    sb = get_service_supabase()
    query = sb.table('alerts').select('*')

    status = request.args.get('status')
    severity = request.args.get('severity')
    alert_type = request.args.get('type')

    if status:
        query = query.eq('status', status)
    if severity:
        query = query.eq('severity', severity)
    if alert_type:
        query = query.eq('alert_type', alert_type)

    query = query.order('created_at', desc=True).limit(100)
    res = query.execute()
    return jsonify(res.data or [])

@alerts_bp.route('/<alert_id>', methods=['GET'])
@login_required
def get_alert(alert_id):
    sb = get_service_supabase()
    res = sb.table('alerts').select('*').eq('id', alert_id).execute()
    if not res.data:
        return jsonify({'error': 'Alert not found'}), 404
    return jsonify(res.data[0])

@alerts_bp.route('/<alert_id>/acknowledge', methods=['POST'])
@role_required('admin', 'analyst')
def acknowledge_alert(alert_id):
    sb = get_service_supabase()
    existing = sb.table('alerts').select('*').eq('id', alert_id).execute()
    if not existing.data:
        return jsonify({'error': 'Alert not found'}), 404

    now = datetime.now(timezone.utc).isoformat()
    res = sb.table('alerts').update({
        'status': 'acknowledged',
        'acknowledged_by': g.user['id'],
        'acknowledged_at': now
    }).eq('id', alert_id).execute()

    log_action(g.user['id'], 'alert_acknowledged', 'alert', alert_id)
    return jsonify(res.data[0] if res.data else {'status': 'acknowledged'})

@alerts_bp.route('/<alert_id>/resolve', methods=['POST'])
@role_required('admin', 'analyst')
def resolve_alert(alert_id):
    data = request.get_json() or {}
    status = data.get('status', 'resolved')
    if status not in ('resolved', 'false_positive'):
        status = 'resolved'

    sb = get_service_supabase()
    existing = sb.table('alerts').select('*').eq('id', alert_id).execute()
    if not existing.data:
        return jsonify({'error': 'Alert not found'}), 404

    now = datetime.now(timezone.utc).isoformat()
    res = sb.table('alerts').update({
        'status': status,
        'resolved_by': g.user['id'],
        'resolved_at': now
    }).eq('id', alert_id).execute()

    log_action(g.user['id'], 'alert_resolved', 'alert', alert_id, {'final_status': status})
    return jsonify(res.data[0] if res.data else {'status': status})


@alerts_bp.route('/<alert_id>/assign', methods=['POST'])
@role_required('admin', 'analyst')
def assign_alert(alert_id):
    data = request.get_json() or {}
    assignee = data.get('assigned_to')  # user uuid or null to unassign
    sb = get_service_supabase()
    existing = sb.table('alerts').select('*').eq('id', alert_id).execute()
    if not existing.data:
        return jsonify({'error': 'Alert not found'}), 404
    res = sb.table('alerts').update({'assigned_to': assignee or None}).eq('id', alert_id).execute()
    log_action(g.user['id'], 'alert_assigned', 'alert', alert_id, {'assigned_to': assignee})
    return jsonify(res.data[0] if res.data else {'assigned_to': assignee})


@alerts_bp.route('/<alert_id>/notes', methods=['GET'])
@login_required
def list_notes(alert_id):
    sb = get_service_supabase()
    res = sb.table('alert_notes').select('*').eq('alert_id', alert_id).order('created_at', desc=True).execute()
    return jsonify(res.data or [])


@alerts_bp.route('/<alert_id>/notes', methods=['POST'])
@role_required('admin', 'analyst')
def add_note(alert_id):
    data = request.get_json() or {}
    note = (data.get('note') or '').strip()
    if not note:
        return jsonify({'error': 'note is required'}), 400
    sb = get_service_supabase()
    existing = sb.table('alerts').select('id').eq('id', alert_id).execute()
    if not existing.data:
        return jsonify({'error': 'Alert not found'}), 404
    res = sb.table('alert_notes').insert({
        'alert_id': alert_id,
        'user_id': g.user['id'],
        'note': note[:4000]
    }).execute()
    log_action(g.user['id'], 'alert_note_added', 'alert', alert_id)
    return jsonify(res.data[0] if res.data else {'note': note}), 201


@alerts_bp.route('/<alert_id>', methods=['DELETE'])
@role_required('admin')
def delete_alert(alert_id):
    sb = get_service_supabase()
    existing = sb.table('alerts').select('id').eq('id', alert_id).execute()
    if not existing.data:
        return jsonify({'error': 'Alert not found'}), 404
    sb.table('alert_notes').delete().eq('alert_id', alert_id).execute()
    sb.table('alerts').delete().eq('id', alert_id).execute()
    log_action(g.user['id'], 'alert_deleted', 'alert', alert_id)
    return jsonify({'message': 'Deleted'})
