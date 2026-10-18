"""
Connectors & Per-Target Scheduler Management REST API for Ethio-Cyber-Shield (ECS).
Provides endpoints for:
- Listing connector schedulers and health status (/api/connectors/schedulers)
- Inspecting specific connector scheduler metrics (/api/connectors/schedulers/<id>)
- Triggering immediate on-demand polling (/api/connectors/schedulers/<id>/trigger)
- Pausing and resuming connector schedules (/api/connectors/schedulers/<id>/pause, /resume)
- Reconfiguring polling intervals and backoff parameters (/api/connectors/schedulers/<id>/configure)
"""
from flask import Blueprint, request, jsonify, g
from app.services.auth_service import login_required, role_required
from app.services.connector_scheduler_service import (
    get_connector_scheduler_manager
)

connectors_bp = Blueprint('connectors', __name__)


@connectors_bp.route('/schedulers', methods=['GET'])
@login_required
def list_schedulers():
    """Lists all connector schedulers scoped to the authenticated organization."""
    mgr = get_connector_scheduler_manager()
    org_id = g.organization_id
    schedulers = mgr.list_schedulers(org_id=org_id)
    return jsonify({
        'organization_id': org_id,
        'total_schedulers': len(schedulers),
        'schedulers': schedulers
    }), 200


@connectors_bp.route('/schedulers/<connector_id>', methods=['GET'])
@login_required
def get_scheduler_detail(connector_id):
    """Retrieves detailed execution state and backoff metrics for a connector."""
    mgr = get_connector_scheduler_manager()
    org_id = g.organization_id
    sched = mgr.get_scheduler(connector_id, org_id=org_id)
    if not sched:
        return jsonify({'error': f"Connector scheduler '{connector_id}' not found"}), 404
    return jsonify(sched), 200


@connectors_bp.route('/schedulers/<connector_id>/pause', methods=['POST'])
@login_required
@role_required('admin', 'analyst')
def pause_scheduler(connector_id):
    """Pauses scheduled execution for a connector."""
    mgr = get_connector_scheduler_manager()
    org_id = g.organization_id
    success = mgr.pause_connector(connector_id, org_id=org_id)
    if not success:
        return jsonify({'error': f"Connector scheduler '{connector_id}' not found"}), 404
    return jsonify({'status': 'paused', 'connector_id': connector_id}), 200


@connectors_bp.route('/schedulers/<connector_id>/resume', methods=['POST'])
@login_required
@role_required('admin', 'analyst')
def resume_scheduler(connector_id):
    """Resumes scheduled execution for a paused connector."""
    mgr = get_connector_scheduler_manager()
    org_id = g.organization_id
    success = mgr.resume_connector(connector_id, org_id=org_id)
    if not success:
        return jsonify({'error': f"Connector scheduler '{connector_id}' not found"}), 404
    return jsonify({'status': 'resumed', 'connector_id': connector_id}), 200


@connectors_bp.route('/schedulers/<connector_id>/configure', methods=['POST'])
@login_required
@role_required('admin')
def configure_scheduler(connector_id):
    """Updates polling interval and backoff parameters for a connector."""
    mgr = get_connector_scheduler_manager()
    org_id = g.organization_id
    data = request.get_json() or {}

    interval_seconds = data.get('interval_seconds')
    backoff_multiplier = data.get('backoff_multiplier')
    max_backoff_seconds = data.get('max_backoff_seconds')

    success = mgr.configure_connector(
        connector_id=connector_id,
        org_id=org_id,
        interval_seconds=interval_seconds,
        backoff_multiplier=backoff_multiplier,
        max_backoff_seconds=max_backoff_seconds
    )
    if not success:
        return jsonify({'error': f"Connector scheduler '{connector_id}' not found"}), 404

    sched = mgr.get_scheduler(connector_id, org_id=org_id)
    return jsonify(sched), 200


@connectors_bp.route('/schedulers/<connector_id>/trigger', methods=['POST'])
@login_required
@role_required('admin', 'analyst')
def trigger_scheduler(connector_id):
    """Dispatches an immediate out-of-band poll cycle for a connector."""
    mgr = get_connector_scheduler_manager()
    org_id = g.organization_id

    future = mgr.trigger_connector(connector_id, org_id=org_id)
    if not future:
        return jsonify({'error': f"Connector scheduler '{connector_id}' not found"}), 404

    try:
        result = future.result(timeout=10.0)
        return jsonify({'status': 'completed', 'result': result}), 200
    except Exception as e:
        return jsonify({'status': 'error', 'error': str(e)}), 502
