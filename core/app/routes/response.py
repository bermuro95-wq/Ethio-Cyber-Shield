"""
Ethio-Cyber-Shield (ECS) — Safe Response, Guardrails & Playbooks REST API (Phase 4.1, 4.2, 4.3).

Provides endpoints for:
- /api/response/modes: Configure and inspect response modes (observe, recommend, approve, auto).
- /api/response/modes/would-have-done: Retrieve shadow mode simulation reports.
- /api/response/guardrails: Manage emergency kill switch, allowlists, blast-radius limits, cooldowns.
- /api/response/playbooks: Inspect, dry-run, and execute declarative response playbooks.
- /api/response/connectors: View connector specifications, reversibility, and control contracts.
- /api/response/approvals: Two-person / dual-custody approval workflows.
- /api/response/actions/<id>/rollback: Idempotent reversal of dispatched mitigations.
Multi-tenant partitioned strictly by organization_id UUID NOT NULL.
"""
from flask import Blueprint, request, jsonify, g
from app.services.auth_service import login_required, role_required
from app.services.response_modes_service import ResponseModesService
from app.services.guardrails_service import GuardrailsService
from app.services.playbook_service import PlaybookService

response_bp = Blueprint('response', __name__)


# =========================================================================
# 1. RESPONSE MODES (Phase 4.1)
# =========================================================================

@response_bp.route('/modes', methods=['GET'])
@login_required
def get_modes():
    """Lists effective response modes per action type for the tenant."""
    org_id = g.organization_id
    modes = ResponseModesService.list_modes(org_id)
    return jsonify({
        'status': 'success',
        'organization_id': org_id,
        'count': len(modes),
        'data': modes
    }), 200


@response_bp.route('/modes', methods=['POST'])
@login_required
@role_required('admin')
def set_mode():
    """Configures response posture (observe, recommend, approve, auto) for an action type."""
    org_id = g.organization_id
    data = request.get_json() or {}
    action_type = data.get('action_type')
    mode = data.get('mode')
    requires_two_person = bool(data.get('requires_two_person', False))

    if not action_type or not mode:
        return jsonify({'error': 'action_type and mode are required'}), 400

    try:
        updated = ResponseModesService.set_mode(
            org_id=org_id,
            action_type=action_type,
            mode=mode,
            requires_two_person=requires_two_person,
            updated_by=getattr(g, 'user_id', None)
        )
        return jsonify({
            'status': 'success',
            'data': updated
        }), 200
    except ValueError as e:
        return jsonify({'error': str(e)}), 400


@response_bp.route('/modes/would-have-done', methods=['GET'])
@login_required
def get_would_have_done_report():
    """Returns the shadow-mode simulation report of would-have-done mitigations."""
    org_id = g.organization_id
    days = int(request.args.get('days', 14))
    report = ResponseModesService.generate_would_have_done_report(org_id=org_id, days=days)
    return jsonify({
        'status': 'success',
        'data': report
    }), 200


# =========================================================================
# 2. GUARDRAILS (Phase 4.2)
# =========================================================================

@response_bp.route('/guardrails', methods=['GET'])
@login_required
def get_guardrails():
    """Returns the guardrail configuration and blast-radius rate limits for the tenant."""
    org_id = g.organization_id
    cfg = GuardrailsService.get_guardrail_config(org_id)
    return jsonify({
        'status': 'success',
        'organization_id': org_id,
        'data': cfg
    }), 200


@response_bp.route('/guardrails', methods=['PUT'])
@login_required
@role_required('admin')
def update_guardrails():
    """Updates guardrail parameters (rate limits, cooldowns, min confidence)."""
    org_id = g.organization_id
    data = request.get_json() or {}
    updated = GuardrailsService.configure_guardrails(org_id, **data)
    return jsonify({
        'status': 'success',
        'data': updated
    }), 200


@response_bp.route('/guardrails/kill-switch', methods=['POST'])
@login_required
@role_required('admin', 'analyst', 'responder')
def toggle_kill_switch():
    """Toggles the emergency containment kill switch for the tenant."""
    org_id = g.organization_id
    data = request.get_json() or {}
    enabled = bool(data.get('enabled', True))
    updated = GuardrailsService.set_kill_switch(org_id, enabled=enabled, updated_by=getattr(g, 'user_id', None))
    return jsonify({
        'status': 'success',
        'data': updated
    }), 200


@response_bp.route('/guardrails/allowlist', methods=['GET'])
@login_required
def list_allowlist():
    """Lists allowlisted protected entities for the tenant."""
    org_id = g.organization_id
    etype = request.args.get('entity_type')
    items = GuardrailsService.list_allowlist(org_id, entity_type=etype)
    return jsonify({
        'status': 'success',
        'count': len(items),
        'organization_id': org_id,
        'data': items
    }), 200


@response_bp.route('/guardrails/allowlist', methods=['POST'])
@login_required
@role_required('admin', 'analyst', 'responder')
def add_allowlist():
    """Adds a protected entity or IP range to the allowlist."""
    org_id = g.organization_id
    data = request.get_json() or {}
    etype = data.get('entity_type')
    eid = data.get('entity_id')
    reason = data.get('reason', 'Authorized Protected Entity')

    if not etype or not eid:
        return jsonify({'error': 'entity_type and entity_id are required'}), 400

    rec = GuardrailsService.add_to_allowlist(
        org_id=org_id,
        entity_type=etype,
        entity_id=eid,
        reason=reason,
        created_by=getattr(g, 'user_id', None)
    )
    return jsonify({
        'status': 'success',
        'data': rec
    }), 201


@response_bp.route('/guardrails/allowlist/<entity_type>/<entity_id>', methods=['DELETE'])
@login_required
@role_required('admin', 'analyst')
def remove_allowlist(entity_type: str, entity_id: str):
    """Removes a protected entity from the allowlist."""
    org_id = g.organization_id
    GuardrailsService.remove_from_allowlist(org_id, entity_type, entity_id)
    return jsonify({
        'status': 'success',
        'message': f"Removed {entity_type}:{entity_id} from allowlist"
    }), 200


@response_bp.route('/guardrails/logs', methods=['GET'])
@login_required
def list_guardrail_logs():
    """Retrieves guardrail evaluation audit history."""
    org_id = g.organization_id
    limit = int(request.args.get('limit', 50))
    logs = GuardrailsService.list_guardrail_logs(org_id, limit=limit)
    return jsonify({
        'status': 'success',
        'count': len(logs),
        'organization_id': org_id,
        'data': logs
    }), 200


# =========================================================================
# 3. PLAYBOOKS & CONNECTORS (Phase 4.3)
# =========================================================================

@response_bp.route('/connectors', methods=['GET'])
@login_required
def get_connectors():
    """Returns the specifications, reversibility, and control contracts of all response connectors."""
    connectors = PlaybookService.list_connectors()
    return jsonify({
        'status': 'success',
        'count': len(connectors),
        'data': connectors
    }), 200


@response_bp.route('/playbooks', methods=['GET'])
@login_required
def list_playbooks():
    """Lists declarative response playbooks available to the tenant."""
    org_id = g.organization_id
    playbooks = PlaybookService.list_playbooks(org_id)
    return jsonify({
        'status': 'success',
        'count': len(playbooks),
        'organization_id': org_id,
        'data': playbooks
    }), 200


@response_bp.route('/playbooks/<playbook_id>', methods=['GET'])
@login_required
def get_playbook(playbook_id: str):
    """Retrieves a single declarative response playbook."""
    org_id = g.organization_id
    pb = PlaybookService.get_playbook(org_id, playbook_id)
    if not pb:
        return jsonify({'error': f"Playbook '{playbook_id}' not found"}), 404
    return jsonify({
        'status': 'success',
        'data': pb
    }), 200


@response_bp.route('/playbooks/<playbook_id>/dry-run', methods=['POST'])
@login_required
@role_required('admin', 'analyst', 'responder')
def dry_run_playbook(playbook_id: str):
    """Executes a dry-run simulation of a playbook against provided incident or event context."""
    org_id = g.organization_id
    context = request.get_json() or {}
    try:
        trace = PlaybookService.dry_run_playbook(org_id, playbook_id, context)
        return jsonify({
            'status': 'success',
            'data': trace
        }), 200
    except ValueError as e:
        return jsonify({'error': str(e)}), 404


@response_bp.route('/approvals', methods=['GET'])
@login_required
def list_approvals():
    """Lists staged action approval requests."""
    org_id = g.organization_id
    status = request.args.get('status')
    approvals = PlaybookService.list_approvals(org_id, status=status)
    return jsonify({
        'status': 'success',
        'count': len(approvals),
        'organization_id': org_id,
        'data': approvals
    }), 200


@response_bp.route('/approvals/<approval_id>/approve', methods=['POST'])
@login_required
@role_required('admin', 'analyst', 'responder')
def approve_action(approval_id: str):
    """Signs off on a pending action approval request."""
    org_id = g.organization_id
    user_id = getattr(g, 'user_id', None) or 'user'
    try:
        res = PlaybookService.submit_approval(org_id, approval_id, approver_id=user_id)
        return jsonify({
            'status': 'success',
            'data': res
        }), 200
    except ValueError as e:
        return jsonify({'error': str(e)}), 400


@response_bp.route('/approvals/<approval_id>/reject', methods=['POST'])
@login_required
@role_required('admin', 'analyst')
def reject_action(approval_id: str):
    """Rejects a staged action approval request."""
    org_id = g.organization_id
    data = request.get_json() or {}
    reason = data.get('reason', 'Rejected by analyst')
    user_id = getattr(g, 'user_id', None) or 'user'
    try:
        res = PlaybookService.reject_approval(org_id, approval_id, approver_id=user_id, reason=reason)
        return jsonify({
            'status': 'success',
            'data': res
        }), 200
    except ValueError as e:
        return jsonify({'error': str(e)}), 400


@response_bp.route('/actions/<action_id>/rollback', methods=['POST'])
@login_required
@role_required('admin', 'analyst', 'responder')
def rollback_action(action_id: str):
    """Triggers rollback/reversion of a confirmed reversible action."""
    org_id = g.organization_id
    data = request.get_json() or {}
    reason = data.get('reason', 'Analyst Rollback')
    user_id = getattr(g, 'user_id', None)
    res = PlaybookService.rollback_action(org_id, action_id=action_id, reason=reason, user_id=user_id)
    return jsonify({
        'status': 'success',
        'data': res
    }), 200
