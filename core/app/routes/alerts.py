from flask import Blueprint, request, jsonify, g
from app.services.auth_service import login_required, role_required
from app.services.db import get_service_supabase
from app.services.audit_service import log_action
from datetime import datetime, timezone

alerts_bp = Blueprint('alerts', __name__)

_ALERT_ORGS = {}

def _get_alert_org(alert_id: str, alert_dict: dict = None) -> str | None:
    if alert_dict and alert_dict.get('organization_id'):
        return str(alert_dict['organization_id'])
    return _ALERT_ORGS.get(str(alert_id))

@alerts_bp.route('', methods=['GET'])
@login_required
def list_alerts():
    org_id = g.user.get('organization_id') if hasattr(g, 'user') and g.user else None
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
    try:
        q_org = query.eq('organization_id', org_id) if org_id else query
        res = q_org.execute()
    except Exception:
        base_q = sb.table('alerts').select('*')
        if status: base_q = base_q.eq('status', status)
        if severity: base_q = base_q.eq('severity', severity)
        if alert_type: base_q = base_q.eq('alert_type', alert_type)
        res = base_q.order('created_at', desc=True).limit(100).execute()
    alerts = res.data or []
    if org_id:
        alerts = [
            a for a in alerts
            if not _get_alert_org(a.get('id'), a) or _get_alert_org(a.get('id'), a) == str(org_id)
        ]
    return jsonify(alerts)

@alerts_bp.route('/<alert_id>', methods=['GET'])
@login_required
def get_alert(alert_id):
    sb = get_service_supabase()
    res = sb.table('alerts').select('*').eq('id', alert_id).execute()
    if not res.data:
        return jsonify({'error': 'Alert not found'}), 404
    alert = res.data[0]
    org_id = g.user.get('organization_id') if hasattr(g, 'user') else None
    a_org = _get_alert_org(alert.get('id'), alert)
    if org_id and a_org and a_org != str(org_id):
        return jsonify({'error': 'Alert not found'}), 404
    return jsonify(alert)

@alerts_bp.route('/<alert_id>/acknowledge', methods=['POST'])
@role_required('admin', 'analyst')
def acknowledge_alert(alert_id):
    sb = get_service_supabase()
    existing = sb.table('alerts').select('*').eq('id', alert_id).execute()
    if not existing.data:
        return jsonify({'error': 'Alert not found'}), 404
    alert = existing.data[0]
    org_id = g.user.get('organization_id') if hasattr(g, 'user') else None
    a_org = _get_alert_org(alert.get('id'), alert)
    if org_id and a_org and a_org != str(org_id):
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
    alert = existing.data[0]
    org_id = g.user.get('organization_id') if hasattr(g, 'user') else None
    a_org = _get_alert_org(alert.get('id'), alert)
    if org_id and a_org and a_org != str(org_id):
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
