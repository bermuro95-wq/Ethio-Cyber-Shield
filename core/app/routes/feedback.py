"""
Analyst Feedback & Suppression Suggestions REST API Routes for Ethio-Cyber-Shield (ECS) v3.0 (Phase 4.6).
Endpoints:
  POST /api/feedback                             - Record analyst triage verdict (TP, FP, benign positive, test)
  GET  /api/feedback                             - List feedback history
  GET  /api/feedback/stats                       - Precision, FPR & rule tuning diagnostics
  GET  /api/feedback/suppression-suggestions     - Auto-generated suppression candidates
  POST /api/feedback/suppression-suggestions/apply- 1-click active suppression rule creation
"""
from flask import Blueprint, request, jsonify, g
from app.services.auth_service import login_required, role_required
from app.services.analyst_feedback_service import AnalystFeedbackService
from app.services.tenant_service import get_current_organization_id
import logging

logger = logging.getLogger(__name__)
feedback_bp = Blueprint('feedback', __name__)


def _get_org_id() -> str:
    org_id = g.user.get('organization_id') if hasattr(g, 'user') and g.user else None
    return str(org_id or get_current_organization_id() or "00000000-0000-0000-0000-000000000001")


@feedback_bp.route('', methods=['POST'])
@role_required('admin', 'analyst')
def submit_feedback():
    """Submits analyst feedback verdict on an alert or incident detection."""
    org_id = _get_org_id()
    data = request.get_json() or {}

    rule_id = data.get('rule_id')
    verdict = data.get('verdict')

    if not rule_id or not verdict:
        return jsonify({'error': 'rule_id and verdict are required'}), 400

    user_id = g.user.get('id') if hasattr(g, 'user') else None

    try:
        rec = AnalystFeedbackService.submit_feedback(
            org_id=org_id,
            rule_id=rule_id,
            verdict=verdict,
            reason_category=data.get('reason_category', 'benign_business_activity'),
            analyst_notes=data.get('analyst_notes'),
            alert_id=data.get('alert_id'),
            incident_id=data.get('incident_id'),
            entity_type=data.get('entity_type'),
            entity_value=data.get('entity_value'),
            user_id=user_id
        )
        return jsonify(rec), 201
    except ValueError as e:
        return jsonify({'error': str(e)}), 400


@feedback_bp.route('', methods=['GET'])
@login_required
def list_feedback():
    """Lists feedback records."""
    org_id = _get_org_id()
    rule_id = request.args.get('rule_id')
    verdict = request.args.get('verdict')
    limit = int(request.args.get('limit', 100))

    records = AnalystFeedbackService.list_feedback(org_id, rule_id=rule_id, verdict=verdict, limit=limit)
    return jsonify(records), 200


@feedback_bp.route('/stats', methods=['GET'])
@login_required
def get_tuning_stats():
    """Calculates precision, FPR, and tuning alerts per rule."""
    org_id = _get_org_id()
    rule_id = request.args.get('rule_id')

    stats = AnalystFeedbackService.get_rule_tuning_stats(org_id, rule_id=rule_id)
    return jsonify(stats), 200


@feedback_bp.route('/suppression-suggestions', methods=['GET'])
@login_required
def get_suppression_suggestions():
    """Analyzes recurring false-positive invariants and suggests suppression rules."""
    org_id = _get_org_id()
    rule_id = request.args.get('rule_id')

    suggestions = AnalystFeedbackService.generate_suppression_suggestions(org_id, rule_id=rule_id)
    return jsonify(suggestions), 200


@feedback_bp.route('/suppression-suggestions/apply', methods=['POST'])
@role_required('admin', 'analyst')
def apply_suppression_suggestion():
    """Applies a suppression rule suggestion directly into active alert suppressions."""
    org_id = _get_org_id()
    data = request.get_json() or {}
    suggestion = data.get('suggestion') or data.get('suggestion_id')

    if not suggestion:
        return jsonify({'error': 'suggestion or suggestion_id is required'}), 400

    user_id = g.user.get('id') if hasattr(g, 'user') else None

    try:
        active_rule = AnalystFeedbackService.apply_suppression_suggestion(
            org_id=org_id,
            suggestion_id_or_payload=suggestion,
            user_id=user_id
        )
        return jsonify(active_rule), 201
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
