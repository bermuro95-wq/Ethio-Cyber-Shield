"""
Target Systems Management API for Ethio-Cyber Shield.
Allows registering, configuring, and testing connections to target banking applications.
"""
from flask import Blueprint, request, jsonify, g
from app.services.auth_service import login_required, role_required
from app.services.db import get_service_supabase
from app.services.audit_service import log_action
from app.services.target_system_service import (
    check_target_health,
    list_active_targets,
    get_target_by_id,
    run_target_scenario,
    execute_target_control,
    _LOCAL_TARGETS,
)
from app.services.response_policy import (
    is_auto_containment_enabled,
    set_auto_containment_enabled,
    revert_containment,
)
from app.services.poller_service import poll_target_once
from datetime import datetime, timezone
import logging
from app.services.tenant_service import DEFAULT_ORGANIZATION_ID, get_current_organization_id
from app.services.tenant_mgmt_service import is_superadmin

logger = logging.getLogger(__name__)
targets_bp = Blueprint('targets', __name__)


@targets_bp.route('', methods=['GET'])
@login_required
def get_targets():
    """
    List configured target systems with health and sync statistics.
    Superadmin can view all targets or filter by ?tenant_id=.
    Tenant admins/analysts receive only targets scoped to their organization.
    """
    sb = get_service_supabase()
    is_sup = is_superadmin(g.user)
    tenant_param = request.args.get('tenant_id')
    all_tenants_param = request.args.get('all_tenants', '').lower() in ('true', '1')

    filter_org = None
    if is_sup:
        if tenant_param and tenant_param not in ('all', ''):
            filter_org = tenant_param
        elif not all_tenants_param and tenant_param not in ('all',):
            header_tenant = request.headers.get('X-ECS-Tenant')
            if header_tenant and header_tenant != 'all':
                filter_org = header_tenant
    else:
        filter_org = g.user.get('organization_id') or get_current_organization_id()

    targets = []
    try:
        query = sb.table('target_systems').select('*')
        if filter_org:
            query = query.eq('organization_id', filter_org)
        res = query.order('created_at', desc=True).execute()
        targets = res.data or []
    except Exception as e:
        logger.debug(f"Target systems query fallback: {e}")

    if not targets:
        from app.services.target_system_service import _LOCAL_TARGETS
        all_local = list(_LOCAL_TARGETS.values())
        if filter_org:
            targets = [dict(t) for t in all_local if str(t.get('organization_id') or DEFAULT_ORGANIZATION_ID) == str(filter_org)]
        else:
            targets = [dict(t) for t in all_local]

    # Organizations mapping for institutional context
    org_map = {}
    try:
        org_res = sb.table('organizations').select('id, name').execute()
        for o in (org_res.data or []):
            org_map[str(o.get('id'))] = o.get('name')
    except Exception:
        pass

    # Mask secrets in API responses & annotate organization
    for t in targets:
        sec = t.get('secret_key') or ''
        t['secret_key_masked'] = f"{sec[:4]}...{sec[-4:]}" if len(sec) >= 8 else '****'
        t.pop('secret_key', None)
        oid = str(t.get('organization_id') or DEFAULT_ORGANIZATION_ID)
        t['tenant_id'] = oid
        t['tenant_name'] = org_map.get(oid) or ('Commercial Bank of Ethiopia (Primary)' if oid == DEFAULT_ORGANIZATION_ID else 'Organization')

    return jsonify(targets), 200


@targets_bp.route('/<target_id>', methods=['GET'])
@login_required
def get_single_target(target_id):
    """
    Get detailed information for a single target system.
    """
    target = get_target_by_id(target_id)
    if not target:
        return jsonify({'error': 'Target system not found'}), 404

    target_copy = dict(target)
    sec = target_copy.get('secret_key') or ''
    target_copy['secret_key_masked'] = f"{sec[:4]}...{sec[-4:]}" if len(sec) >= 8 else '****'
    target_copy.pop('secret_key', None)
    return jsonify(target_copy), 200


@targets_bp.route('', methods=['POST'])
@role_required('admin')
def register_target():
    """
    Registers a new target system to be monitored and mitigated by ECS.
    Encrypts secret_key using envelope encryption.
    """
    data = request.get_json() or {}
    name = (data.get('name') or '').strip()
    base_url = (data.get('base_url') or '').strip().rstrip('/')
    key_id = (data.get('key_id') or '').strip()
    secret_key = (data.get('secret_key') or '').strip()
    sync_mode = data.get('sync_mode', 'bidirectional')
    poll_interval = int(data.get('poll_interval_seconds') or 5)

    if not name or not base_url or not key_id or not secret_key:
        return jsonify({'error': 'name, base_url, key_id, and secret_key are required'}), 400

    if sync_mode not in ('push', 'pull', 'bidirectional'):
        return jsonify({'error': 'sync_mode must be push, pull, or bidirectional'}), 400

    sb = get_service_supabase()
    from app.services.crypto_service import encrypt_secret
    if is_superadmin(g.user):
        org_id = data.get('organization_id') or g.user.get('organization_id') or get_current_organization_id()
    else:
        org_id = g.user.get('organization_id') or get_current_organization_id()

    # Test health before creating
    health = check_target_health(base_url)
    health_status = 'healthy' if health.get('status') == 'healthy' else 'degraded'

    target_record = {
        'organization_id': org_id,
        'name': name,
        'base_url': base_url,
        'key_id': key_id,
        'secret_key': encrypt_secret(secret_key),
        'sync_mode': sync_mode,
        'poll_interval_seconds': poll_interval,
        'is_active': True,
        'health_status': health_status,
        'last_health_check': datetime.now(timezone.utc).isoformat(),
    }

    try:
        res = sb.table('target_systems').insert(target_record).execute()
        if not res.data:
            return jsonify({'error': 'Failed to insert target system'}), 500

        created = res.data[0]
        log_action(g.user['id'], 'target_registered', 'target_system', created['id'], {
            'name': name, 'base_url': base_url, 'key_id': key_id
        })

        created.pop('secret_key', None)
        return jsonify(created), 201
    except Exception as e:
        logger.warning(f"Database insert for target_system fallback to memory: {e}")
        import uuid
        local_id = f"target-{uuid.uuid4().hex[:12]}"
        created = dict(target_record)
        created['id'] = local_id
        created['created_at'] = datetime.now(timezone.utc).isoformat()
        _LOCAL_TARGETS[local_id] = created
        try:
            log_action(g.user['id'], 'target_registered', 'target_system', None, {
                'name': name, 'base_url': base_url, 'key_id': key_id
            })
        except Exception:
            pass
        created_ret = dict(created)
        created_ret.pop('secret_key', None)
        return jsonify(created_ret), 201


@targets_bp.route('/<target_id>', methods=['DELETE'])
@role_required('admin')
def delete_target_endpoint(target_id):
    """
    Deletes or deactivates a target system registration.
    """
    sb = get_service_supabase()
    try:
        sb.table('target_systems').delete().eq('id', target_id).execute()
    except Exception as e:
        logger.debug(f"Target delete DB fallback: {e}")

    _LOCAL_TARGETS.pop(target_id, None)

    try:
        log_action(g.user['id'], 'target_deleted', 'target_system', None, {'target_id': target_id})
    except Exception:
        pass

    return jsonify({'status': 'deleted', 'id': target_id}), 200


@targets_bp.route('/<target_id>', methods=['PUT'])
@role_required('admin')
def update_target(target_id):
    """
    Updates target system parameters.
    """
    data = request.get_json() or {}
    sb = get_service_supabase()

    target = get_target_by_id(target_id)
    if not target:
        return jsonify({'error': 'Target system not found'}), 404

    updates = {}
    if 'name' in data:
        updates['name'] = str(data['name']).strip()
    if 'base_url' in data:
        updates['base_url'] = str(data['base_url']).strip().rstrip('/')
    if 'key_id' in data:
        updates['key_id'] = str(data['key_id']).strip()
    if 'secret_key' in data and data['secret_key']:
        updates['secret_key'] = str(data['secret_key']).strip()
    if 'sync_mode' in data and data['sync_mode'] in ('push', 'pull', 'bidirectional'):
        updates['sync_mode'] = data['sync_mode']
    if 'poll_interval_seconds' in data:
        updates['poll_interval_seconds'] = int(data['poll_interval_seconds'])
    if 'is_active' in data:
        updates['is_active'] = bool(data['is_active'])

    updates['updated_at'] = datetime.now(timezone.utc).isoformat()

    res = sb.table('target_systems').update(updates).eq('id', target_id).execute()
    log_action(g.user['id'], 'target_updated', 'target_system', target_id, updates)

    updated = res.data[0] if res.data else {}
    updated.pop('secret_key', None)
    return jsonify(updated), 200


@targets_bp.route('/<target_id>/test-connection', methods=['POST'])
@targets_bp.route('/<target_id>/test-health', methods=['POST'])
@login_required
def test_connection(target_id):
    """
    Pings the target system's health endpoint and updates stored status.
    """
    target = get_target_by_id(target_id)
    if not target:
        return jsonify({'error': 'Target system not found'}), 404

    base_url = target.get('base_url')
    health = check_target_health(base_url)
    health_status = 'healthy' if health.get('status') == 'healthy' else 'down'

    sb = get_service_supabase()
    sb.table('target_systems').update({
        'health_status': health_status,
        'last_health_check': datetime.now(timezone.utc).isoformat()
    }).eq('id', target_id).execute()

    return jsonify({
        'target_id': target_id,
        'health_status': health_status,
        'details': health
    }), 200


@targets_bp.route('/<target_id>/trigger-scenario', methods=['POST'])
@role_required('admin', 'analyst')
def trigger_scenario(target_id):
    """
    Remotely triggers an attack or normal scenario on the target application via lab:run scope.
    """
    target = get_target_by_id(target_id)
    if not target:
        return jsonify({'error': 'Target system not found'}), 404

    data = request.get_json() or {}
    scenario = data.get('scenario') or 'account_takeover'
    target_account = data.get('target_account')

    try:
        resp_json, status_code = run_target_scenario(
            scenario_name=scenario,
            target_account=target_account,
            base_url=target.get('base_url'),
            key_id=target.get('key_id'),
            secret=target.get('secret_key')
        )
        log_action(g.user['id'], 'scenario_triggered', 'target_system', target_id, {
            'scenario': scenario, 'status_code': status_code
        })
        return jsonify(resp_json), status_code
    except Exception as e:
        logger.error(f"Failed to trigger scenario: {e}")
        return jsonify({'error': f"Failed to trigger scenario: {str(e)}"}), 502


@targets_bp.route('/<target_id>/poll-now', methods=['POST'])
@role_required('admin', 'analyst')
def poll_now(target_id):
    """
    Manually triggers an immediate pull sync cycle for the specified target system.
    """
    result = poll_target_once(target_id)
    log_action(g.user['id'], 'target_sync_triggered', 'target_system', target_id, result)
    return jsonify(result), 200


@targets_bp.route('/<target_id>/stats', methods=['GET'])
@login_required
def target_stats(target_id):
    """
    Retrieves telemetry volume statistics for a specific target system.
    """
    sb = get_service_supabase()
    target = get_target_by_id(target_id)
    if not target:
        return jsonify({'error': 'Target system not found'}), 404

    events_res = sb.table('security_events').select('id', count='exact').eq('target_system_id', target_id).execute()
    alerts_res = sb.table('alerts').select('id', count='exact').eq('target_system_id', target_id).execute()
    actions_res = sb.table('response_actions').select('id', count='exact').eq('target_system_id', target_id).execute()

    return jsonify({
        'target_id': target_id,
        'name': target.get('name'),
        'total_events': events_res.count or len(events_res.data or []),
        'total_alerts': alerts_res.count or len(alerts_res.data or []),
        'total_response_actions': actions_res.count or len(actions_res.data or []),
        'last_synced_seq': target.get('last_synced_seq'),
        'health_status': target.get('health_status'),
        'last_health_check': target.get('last_health_check'),
    }), 200


@targets_bp.route('/actions', methods=['GET'])
@login_required
def list_response_actions():
    """
    List all executed containment response actions across connected targets.
    """
    sb = get_service_supabase()
    query = sb.table('response_actions').select('*').order('created_at', desc=True).limit(100)
    incident_id = request.args.get('incident_id')
    if incident_id:
        query = query.eq('incident_id', incident_id)
    res = query.execute()
    return jsonify(res.data or []), 200


@targets_bp.route('/<target_id>/execute-control', methods=['POST'])
@role_required('admin', 'analyst')
def dispatch_target_control(target_id):
    """
    Manually dispatches an active security control (freeze, revoke, block, lock, step-up) to a target system.
    """
    target = get_target_by_id(target_id)
    if not target:
        return jsonify({'error': 'Target system not found'}), 404

    data = request.get_json() or {}
    action_type = (data.get('action_type') or '').replace('-', '_')
    target_entity_id = data.get('target_entity_id') or data.get('entity_id')
    reason = data.get('reason') or f"Manual analyst containment via ECS"
    alert_id = data.get('alert_id')
    incident_id = data.get('incident_id')

    if not action_type or not target_entity_id:
        return jsonify({'error': 'action_type and target_entity_id are required'}), 400

    result = execute_target_control(
        action_type=action_type,
        target_entity_id=target_entity_id,
        reason=reason,
        alert_id=alert_id,
        target_id=target_id,
        incident_id=incident_id,
        requested_by=g.user['id']
    )
    return jsonify(result), 200 if result.get('status') == 'confirmed' else 400


@targets_bp.route('/actions/<action_id>/revert', methods=['POST'])
@role_required('admin', 'analyst')
def revert_action_endpoint(action_id):
    """
    Reverts a previously confirmed mitigation action (e.g. unfreezing transaction or restoring session).
    """
    data = request.get_json() or {}
    reason = data.get('reason') or "Analyst manual rollback"
    result = revert_containment(action_id, reason=reason, user_id=g.user['id'])
    return jsonify(result), 200 if result.get('status') == 'confirmed' else 400


@targets_bp.route('/settings/auto-containment', methods=['GET'])
@login_required
def get_auto_containment():
    """Returns current auto-containment policy state."""
    return jsonify({'auto_containment_enabled': is_auto_containment_enabled()}), 200


@targets_bp.route('/settings/auto-containment', methods=['POST'])
@role_required('admin')
def set_auto_containment():
    """Toggles the auto-containment policy state."""
    data = request.get_json() or {}
    enabled = bool(data.get('enabled', True))
    success = set_auto_containment_enabled(enabled, user_id=g.user['id'])
    if not success:
        return jsonify({'error': 'Failed to update auto-containment setting'}), 500
    return jsonify({'auto_containment_enabled': enabled, 'status': 'updated'}), 200


_TARGET_STATE_STORE = {}

@targets_bp.route('/state', methods=['GET', 'POST', 'OPTIONS'])
def target_state_sync():
    """
    Synchronizes ephemeral target banking system state (accounts, profiles, registered customers)
    across isolated serverless execution environments.
    """
    global _TARGET_STATE_STORE
    if request.method == 'OPTIONS':
        return '', 200

    if request.method == 'POST':
        data = request.get_json(silent=True) or {}
        if data:
            if 'users' in data and isinstance(data['users'], list):
                _TARGET_STATE_STORE['users'] = data['users']
            if 'tables' in data and isinstance(data['tables'], dict):
                if 'tables' not in _TARGET_STATE_STORE:
                    _TARGET_STATE_STORE['tables'] = {}
                _TARGET_STATE_STORE['tables'].update(data['tables'])
        return jsonify({'status': 'synced', 'timestamp': datetime.now(timezone.utc).isoformat()}), 200

    return jsonify(_TARGET_STATE_STORE), 200



