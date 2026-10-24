"""
Ethio-Cyber-Shield (ECS) — Alert Quality & Fatigue Reduction REST API (Phase 3.7).

Provides endpoints for:
- GET /api/alerts/quality/metrics: SOC fatigue reduction rates, duplicate ratios, health grades.
- GET /api/alerts/quality/suppressions: List active time-based suppression rules.
- POST /api/alerts/quality/suppressions: Create time-based maintenance/test suppression windows.
- DELETE /api/alerts/quality/suppressions/<id>: Early revocation of suppression windows.
- POST /api/alerts/quality/evaluate: Evaluation of candidate alerts (dedupe/suppress/group).
Multi-tenant partitioned strictly by organization_id UUID NOT NULL.
"""
from flask import Blueprint, request, jsonify, g
from app.services.auth_service import login_required, role_required
from app.services.alert_quality_service import AlertQualityService

alert_quality_bp = Blueprint('alert_quality', __name__)


@alert_quality_bp.route('/metrics', methods=['GET'])
@login_required
def get_quality_metrics():
    """Returns SOC alert fatigue reduction metrics, deduplication ratios, and health grade."""
    org_id = g.organization_id
    metrics = AlertQualityService.get_fatigue_metrics(org_id=org_id)
    return jsonify({
        'status': 'success',
        'organization_id': org_id,
        'data': metrics
    }), 200


@alert_quality_bp.route('/suppressions', methods=['GET'])
@login_required
def list_suppressions():
    """Lists active, unexpired alert suppression rules for the tenant."""
    org_id = g.organization_id
    entity_type = request.args.get('entity_type')
    entity_id = request.args.get('entity_id')
    suppressions = AlertQualityService.list_active_suppressions(
        org_id=org_id,
        entity_type=entity_type,
        entity_id=entity_id
    )
    return jsonify({
        'status': 'success',
        'count': len(suppressions),
        'organization_id': org_id,
        'data': suppressions
    }), 200


@alert_quality_bp.route('/suppressions', methods=['POST'])
@login_required
@role_required('admin', 'analyst', 'responder')
def create_suppression():
    """Creates a time-based suppression window on an entity or rule."""
    org_id = g.organization_id
    data = request.get_json() or {}
    entity_type = data.get('entity_type')
    entity_id = data.get('entity_id')

    if not entity_type or not entity_id:
        return jsonify({'error': 'entity_type and entity_id are required'}), 400

    rule_id = data.get('rule_id', '*')
    reason = data.get('reason', 'Authorized Maintenance Window')
    duration_minutes = int(data.get('duration_minutes', 60))
    created_by = getattr(g, 'user_id', None) or getattr(g, 'email', 'system')

    suppression = AlertQualityService.create_suppression_rule(
        org_id=org_id,
        entity_type=entity_type,
        entity_id=entity_id,
        rule_id=rule_id,
        reason=reason,
        duration_minutes=duration_minutes,
        created_by=created_by
    )

    return jsonify({
        'status': 'success',
        'data': suppression
    }), 201


@alert_quality_bp.route('/suppressions/<suppression_id>', methods=['DELETE'])
@login_required
@role_required('admin', 'analyst')
def revoke_suppression(suppression_id: str):
    """Revokes an active alert suppression rule early."""
    org_id = g.organization_id
    AlertQualityService.revoke_suppression_rule(org_id=org_id, suppression_id=suppression_id)
    return jsonify({
        'status': 'success',
        'message': 'Suppression rule revoked successfully',
        'id': suppression_id
    }), 200


@alert_quality_bp.route('/evaluate', methods=['POST'])
@login_required
def evaluate_candidate_alert():
    """Dry-run or manual evaluation of a candidate alert through deduplication and suppression."""
    org_id = g.organization_id
    data = request.get_json() or {}
    result = AlertQualityService.process_candidate_alert(candidate_alert=data, org_id=org_id)
    return jsonify({
        'status': 'success',
        'data': result
    }), 200
