from flask import Blueprint, request, jsonify, g
from app.services.auth_service import login_required, role_required
from app.services.db import get_service_supabase
from app.services.audit_service import log_action
from app.services.tenant_service import DEFAULT_ORGANIZATION_ID
from app.services.tenant_mgmt_service import is_superadmin
from datetime import datetime, timezone
import logging

logger = logging.getLogger(__name__)
alerts_bp = Blueprint('alerts', __name__)

_ALERT_ORGS = {}

def _get_alert_org(alert_id: str, alert_dict: dict = None) -> str | None:
    if alert_dict and alert_dict.get('organization_id'):
        return str(alert_dict['organization_id'])
    return _ALERT_ORGS.get(str(alert_id))

@alerts_bp.route('', methods=['GET'])
@login_required
def list_alerts():
    user = g.user
    is_sup = is_superadmin(user)
    tenant_param = request.args.get('tenant_id')
    all_tenants_param = request.args.get('all_tenants', '').lower() in ('true', '1')

    # Determine filter org
    filter_org = None
    if is_sup:
        if tenant_param and tenant_param not in ('all', ''):
            filter_org = tenant_param
        elif not all_tenants_param and tenant_param not in ('all',):
            # Check if superadmin explicitly requested all or a specific tenant header
            header_tenant = request.headers.get('X-ECS-Tenant')
            if header_tenant and header_tenant != 'all':
                filter_org = header_tenant
    else:
        # Regular tenant user strictly scoped to own organization
        filter_org = user.get('organization_id') or DEFAULT_ORGANIZATION_ID

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

    if filter_org:
        try:
            query = query.eq('organization_id', filter_org)
        except Exception:
            pass

    query = query.order('created_at', desc=True).limit(100)
    try:
        res = query.execute()
        alerts = res.data or []
    except Exception as e:
        logger.debug(f"Alerts query execution fallback: {e}")
        base_q = sb.table('alerts').select('*')
        if status: base_q = base_q.eq('status', status)
        if severity: base_q = base_q.eq('severity', severity)
        if alert_type: base_q = base_q.eq('alert_type', alert_type)
        if filter_org:
            try: base_q = base_q.eq('organization_id', filter_org)
            except Exception: pass
        res = base_q.order('created_at', desc=True).limit(100).execute()
        alerts = res.data or []

    # Strict isolation filter for non-superadmins
    if not is_sup and filter_org:
        alerts = [
            a for a in alerts
            if not _get_alert_org(a.get('id'), a) or _get_alert_org(a.get('id'), a) == str(filter_org)
        ]

    # Organizations & Targets mapping for institutional context
    org_map = {}
    try:
        org_res = sb.table('organizations').select('id, name, slug').execute()
        for o in (org_res.data or []):
            org_map[str(o.get('id'))] = o.get('name') or o.get('slug')
    except Exception:
        pass

    target_map = {}
    try:
        tgt_res = sb.table('target_systems').select('id, name').execute()
        for t in (tgt_res.data or []):
            target_map[str(t.get('id'))] = t.get('name')
    except Exception:
        pass

    # Enrich alerts with full attack dossier, geo & institutional metadata
    try:
        from app.services.enrichment_service import get_alert_dossier, synthesize_attack_dossier
        for a in alerts:
            dossier = get_alert_dossier(a.get('id')) or synthesize_attack_dossier(a)
            a['dossier'] = dossier
            a['source_ip'] = dossier['geo']['ip']
            a['risk_score'] = dossier['risk_score']
            a['device_details'] = dossier['device']
            a['geo_details'] = dossier['geo']
            a['target_details'] = dossier['target']

            # Institutional annotation
            oid = str(a.get('organization_id') or DEFAULT_ORGANIZATION_ID)
            a['tenant_id'] = oid
            a['tenant_name'] = org_map.get(oid) or ('Commercial Bank of Ethiopia' if oid == DEFAULT_ORGANIZATION_ID else 'Organization')

            tid = str(a.get('target_system_id') or '')
            if tid in target_map:
                a['target_name'] = target_map[tid]
            elif dossier.get('target', {}).get('name'):
                a['target_name'] = dossier['target']['name']
            else:
                a['target_name'] = 'Banking Core System'
    except Exception as e:
        logger.debug(f"Alert dossier enrichment warning: {e}")

    return jsonify(alerts)

@alerts_bp.route('/<alert_id>', methods=['GET'])
@login_required
def get_alert(alert_id):
    sb = get_service_supabase()
    res = sb.table('alerts').select('*').eq('id', alert_id).execute()
    if not res.data:
        return jsonify({'error': 'Alert not found'}), 404
    alert = res.data[0]

    is_sup = is_superadmin(g.user)
    org_id = g.user.get('organization_id') if hasattr(g, 'user') else None
    a_org = _get_alert_org(alert.get('id'), alert)
    if not is_sup and org_id and a_org and a_org != str(org_id):
        return jsonify({'error': 'Alert not found'}), 403

    try:
        from app.services.enrichment_service import get_alert_dossier, synthesize_attack_dossier
        dossier = get_alert_dossier(alert.get('id')) or synthesize_attack_dossier(alert)
        alert['dossier'] = dossier
        alert['source_ip'] = dossier['geo']['ip']
        alert['risk_score'] = dossier['risk_score']
        alert['device_details'] = dossier['device']
        alert['geo_details'] = dossier['geo']
        alert['target_details'] = dossier['target']

        # Institutional annotation
        try:
            oid = str(alert.get('organization_id') or DEFAULT_ORGANIZATION_ID)
            alert['tenant_id'] = oid
            ores = sb.table('organizations').select('name').eq('id', oid).execute()
            alert['tenant_name'] = ores.data[0]['name'] if ores.data else 'Commercial Bank of Ethiopia'
        except Exception:
            alert['tenant_name'] = 'Commercial Bank of Ethiopia'
    except Exception as e:
        logger.debug(f"Single alert dossier enrichment warning: {e}")

    return jsonify(alert)

    try:
        from app.services.enrichment_service import get_alert_dossier, synthesize_attack_dossier
        dossier = get_alert_dossier(alert.get('id')) or synthesize_attack_dossier(alert)
        alert['dossier'] = dossier
        alert['source_ip'] = dossier['geo']['ip']
        alert['risk_score'] = dossier['risk_score']
        alert['device_details'] = dossier['device']
        alert['geo_details'] = dossier['geo']
        alert['target_details'] = dossier['target']
    except Exception as e:
        logger.debug(f"Single alert dossier enrichment warning: {e}")

    return jsonify(alert)

@alerts_bp.route('/<alert_id>/dossier', methods=['GET'])
@login_required
def get_alert_dossier_route(alert_id):
    from app.services.enrichment_service import get_alert_dossier, synthesize_attack_dossier
    dossier = get_alert_dossier(alert_id)
    if not dossier:
        sb = get_service_supabase()
        res = sb.table('alerts').select('*').eq('id', alert_id).execute()
        if not res.data:
            return jsonify({'error': 'Alert not found'}), 404
        dossier = synthesize_attack_dossier(res.data[0])
    return jsonify(dossier), 200

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
    if not is_superadmin(g.user) and org_id and a_org and a_org != str(org_id):
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
    if not is_superadmin(g.user) and org_id and a_org and a_org != str(org_id):
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


@alerts_bp.route('/reset', methods=['POST', 'DELETE'])
@role_required('admin')
def reset_all_alerts():
    user = g.user
    if not is_superadmin(user):
        return jsonify({'error': 'Superadmin privileges required to reset all alerts'}), 403

    sb = get_service_supabase()
    deleted_alerts = 0
    
    # 1. Clear alert notes
    try:
        sb.table('alert_notes').delete().neq('id', '00000000-0000-0000-0000-000000000000').execute()
    except Exception as e:
        logger.debug(f"Alert notes clear: {e}")

    # 2. Clear alerts
    try:
        res = sb.table('alerts').delete().neq('id', '00000000-0000-0000-0000-000000000000').execute()
        deleted_alerts = len(res.data) if res.data else 0
    except Exception as e:
        logger.debug(f"Alerts clear: {e}")

    # 3. Clear security events if requested
    data = request.get_json(silent=True) or {}
    clear_events = data.get('clear_events', True)
    if clear_events:
        try:
            sb.table('security_events').delete().neq('id', '00000000-0000-0000-0000-000000000000').execute()
        except Exception as e:
            logger.debug(f"Security events clear: {e}")

    # 4. Clear in-memory attack dossier store
    try:
        from app.services.enrichment_service import _ALERT_DOSSIER_STORE
        _ALERT_DOSSIER_STORE.clear()
    except Exception:
        pass

    log_action(user['id'], 'alerts_reset_all', 'alerts', 'all', {'deleted_alerts': deleted_alerts})

    return jsonify({
        'message': 'All alert telemetry has been successfully cleared. Monitoring reset from scratch.',
        'deleted_alerts': deleted_alerts
    }), 200


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
