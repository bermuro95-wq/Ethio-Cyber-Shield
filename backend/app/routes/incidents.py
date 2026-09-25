from flask import Blueprint, request, jsonify, g
from app.services.auth_service import login_required, role_required
from app.services.db import get_service_supabase
from app.services.audit_service import log_action
from app.services.security_rules import run_full_analysis_on_incident, create_alert_from_event
import logging

logger = logging.getLogger(__name__)
incidents_bp = Blueprint('incidents', __name__)

VALID_TYPES = ['phishing', 'account_takeover', 'suspicious_login', 'fraud', 'malware', 'social_engineering', 'other']
VALID_SEVERITIES = ['low', 'medium', 'high', 'critical']
VALID_STATUSES = ['open', 'investigating', 'contained', 'resolved', 'closed']

@incidents_bp.route('', methods=['GET'])
@login_required
def list_incidents():
    sb = get_service_supabase()
    query = sb.table('incidents').select('*, assigned:users!assigned_to(id, full_name, email)')

    # Filters
    status = request.args.get('status')
    severity = request.args.get('severity')
    itype = request.args.get('type')
    search = request.args.get('search')
    risk = request.args.get('risk_level')

    if status:
        query = query.eq('status', status)
    if severity:
        query = query.eq('severity', severity)
    if itype:
        query = query.eq('incident_type', itype)
    if risk:
        query = query.eq('risk_level', risk)
    if search:
        query = query.or_(f'title.ilike.%{search}%,description.ilike.%{search}%')

    query = query.order('created_at', desc=True).limit(100)
    res = query.execute()
    return jsonify(res.data or [])

@incidents_bp.route('/<incident_id>', methods=['GET'])
@login_required
def get_incident(incident_id):
    sb = get_service_supabase()
    res = sb.table('incidents').select(
        '*, assigned:users!assigned_to(id, full_name, email), creator:users!created_by(id, full_name)'
    ).eq('id', incident_id).execute()
    if not res.data:
        return jsonify({'error': 'Incident not found'}), 404

    incident = res.data[0]

    # Linked indicators
    links = sb.table('incident_indicators').select(
        '*, indicator:indicators(*)'
    ).eq('incident_id', incident_id).execute()
    incident['indicators'] = [l.get('indicator') for l in (links.data or []) if l.get('indicator')]

    # Related alerts
    alerts = sb.table('alerts').select('*').eq('related_incident_id', incident_id).execute()
    incident['alerts'] = alerts.data or []

    return jsonify(incident)

@incidents_bp.route('', methods=['POST'])
@role_required('admin', 'analyst')
def create_incident():
    data = request.get_json() or {}
    title = (data.get('title') or '').strip()
    description = (data.get('description') or '').strip()
    incident_type = data.get('incident_type')
    severity = data.get('severity', 'medium')
    status = data.get('status', 'open')
    incident_date = data.get('incident_date')
    assigned_to = data.get('assigned_to')

    if not title:
        return jsonify({'error': 'Title is required'}), 400
    if incident_type not in VALID_TYPES:
        return jsonify({'error': f'Invalid incident_type. Allowed: {VALID_TYPES}'}), 400
    if severity not in VALID_SEVERITIES:
        return jsonify({'error': f'Invalid severity. Allowed: {VALID_SEVERITIES}'}), 400
    if status not in VALID_STATUSES:
        return jsonify({'error': f'Invalid status. Allowed: {VALID_STATUSES}'}), 400

    # Basic XSS / injection sanitization (simple)
    title = title[:255]
    description = description[:5000]

    payload = {
        'title': title,
        'description': description,
        'incident_type': incident_type,
        'severity': severity,
        'status': status,
        'created_by': g.user['id']
    }
    if incident_date:
        payload['incident_date'] = incident_date
    if assigned_to:
        payload['assigned_to'] = assigned_to

    sb = get_service_supabase()
    res = sb.table('incidents').insert(payload).execute()
    if not res.data:
        return jsonify({'error': 'Failed to create incident'}), 500

    incident = res.data[0]
    log_action(g.user['id'], 'incident_created', 'incident', incident['id'], {
        'title': title, 'type': incident_type, 'severity': severity
    })

    # Auto-alert for critical
    if severity == 'critical':
        create_alert_from_event(
            alert_type='critical_incident',
            title=f"Critical Incident: {title}",
            description=description[:500],
            severity='critical',
            related_incident_id=incident['id'],
            user_id=g.user['id']
        )

    return jsonify(incident), 201

@incidents_bp.route('/<incident_id>', methods=['PUT'])
@role_required('admin', 'analyst')
def update_incident(incident_id):
    data = request.get_json() or {}
    sb = get_service_supabase()

    # Check exists
    existing = sb.table('incidents').select('id').eq('id', incident_id).execute()
    if not existing.data:
        return jsonify({'error': 'Incident not found'}), 404

    allowed = ['title', 'description', 'incident_type', 'severity', 'status', 'assigned_to', 'incident_date']
    update = {}
    for k in allowed:
        if k in data:
            update[k] = data[k]

    if 'incident_type' in update and update['incident_type'] not in VALID_TYPES:
        return jsonify({'error': 'Invalid incident_type'}), 400
    if 'severity' in update and update['severity'] not in VALID_SEVERITIES:
        return jsonify({'error': 'Invalid severity'}), 400
    if 'status' in update and update['status'] not in VALID_STATUSES:
        return jsonify({'error': 'Invalid status'}), 400

    if not update:
        return jsonify({'error': 'No valid fields to update'}), 400

    res = sb.table('incidents').update(update).eq('id', incident_id).execute()
    log_action(g.user['id'], 'incident_updated', 'incident', incident_id, update)

    return jsonify(res.data[0] if res.data else {'id': incident_id})

@incidents_bp.route('/<incident_id>/analyze', methods=['POST'])
@role_required('admin', 'analyst')
def analyze_incident(incident_id):
    result = run_full_analysis_on_incident(incident_id, g.user['id'])
    return jsonify(result)

@incidents_bp.route('/<incident_id>/indicators', methods=['POST'])
@role_required('admin', 'analyst')
def link_indicator(incident_id):
    data = request.get_json() or {}
    indicator_id = data.get('indicator_id')
    notes = data.get('notes', '')

    if not indicator_id:
        return jsonify({'error': 'indicator_id required'}), 400

    sb = get_service_supabase()
    # Verify both exist
    inc = sb.table('incidents').select('id').eq('id', incident_id).execute()
    ind = sb.table('indicators').select('id, status, value').eq('id', indicator_id).execute()
    if not inc.data or not ind.data:
        return jsonify({'error': 'Incident or Indicator not found'}), 404

    try:
        res = sb.table('incident_indicators').insert({
            'incident_id': incident_id,
            'indicator_id': indicator_id,
            'notes': notes
        }).execute()
    except Exception as e:
        return jsonify({'error': 'Already linked or error'}), 400

    log_action(g.user['id'], 'indicator_linked', 'incident', incident_id, {
        'indicator_id': indicator_id
    })

    # Re-run risk if malicious
    if ind.data[0].get('status') == 'malicious':
        run_full_analysis_on_incident(incident_id, g.user['id'])
        create_alert_from_event(
            alert_type='malicious_indicator',
            title="Malicious Indicator Linked to Incident",
            description=f"Indicator {ind.data[0].get('value')} linked to incident",
            severity='high',
            related_incident_id=incident_id,
            related_indicator_id=indicator_id,
            user_id=g.user['id']
        )

    return jsonify(res.data[0] if res.data else {'linked': True}), 201
