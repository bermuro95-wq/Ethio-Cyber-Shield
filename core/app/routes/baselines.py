"""
Explainable Behavioral Baselines REST API for ECS v3.0 (Phase 3.4).

Provides endpoints for:
- GET /api/baselines: List entity baselines for tenant
- GET /api/baselines/summary: High-level baseline metrics and coverage
- GET /api/baselines/<entity_type>/<entity_id>: Retrieve entity behavioral baseline profile
- POST /api/baselines/<entity_type>/<entity_id>/recalculate: Force on-demand baseline recalculation
- POST /api/baselines/evaluate: Evaluate an event or candidate transaction against entity baseline
- POST /api/baselines/<entity_type>/<entity_id>/seed: Seed or update an entity baseline profile
"""
from flask import Blueprint, request, jsonify, g
from app.services.auth_service import login_required, role_required
from app.services.behavioral_baseline_service import BehavioralBaselineService

baselines_bp = Blueprint('baselines', __name__)


@baselines_bp.route('', methods=['GET'])
@login_required
def list_baselines():
    """Lists entity baselines for the authenticated tenant."""
    org_id = g.organization_id
    entity_type = request.args.get('entity_type')
    status = request.args.get('status')
    limit = int(request.args.get('limit', 50))

    items = BehavioralBaselineService.list_baselines(
        org_id=org_id,
        entity_type=entity_type,
        status=status,
        limit=limit
    )

    return jsonify({
        'organization_id': org_id,
        'count': len(items),
        'baselines': items
    }), 200


@baselines_bp.route('/summary', methods=['GET'])
@login_required
def get_summary():
    """Returns high-level statistics of entity baselines for the authenticated tenant."""
    org_id = g.organization_id
    summary = BehavioralBaselineService.get_baseline_summary(org_id)
    return jsonify(summary), 200


@baselines_bp.route('/<entity_type>/<entity_id>', methods=['GET'])
@login_required
def get_baseline(entity_type, entity_id):
    """Retrieves computed behavioral baseline for a specific entity."""
    org_id = g.organization_id
    auto_compute = request.args.get('auto_compute', 'true').lower() in ('true', '1')

    baseline = BehavioralBaselineService.get_baseline(
        org_id=org_id,
        entity_type=entity_type,
        entity_id=entity_id,
        auto_compute=auto_compute
    )

    if not baseline:
        return jsonify({
            'error': f"Baseline for {entity_type} '{entity_id}' not found",
            'organization_id': org_id
        }), 404

    return jsonify({
        'organization_id': org_id,
        'baseline': baseline
    }), 200


@baselines_bp.route('/<entity_type>/<entity_id>/recalculate', methods=['POST'])
@login_required
@role_required('analyst')
def recalculate_baseline(entity_type, entity_id):
    """Forces recalculation of an entity baseline over specified lookback window."""
    org_id = g.organization_id
    payload = request.get_json() or {}

    lookback_days = int(payload.get('lookback_days', 90))
    min_samples = int(payload.get('min_samples', 5))

    updated = BehavioralBaselineService.calculate_baseline(
        org_id=org_id,
        entity_type=entity_type,
        entity_id=entity_id,
        lookback_days=lookback_days,
        min_samples=min_samples,
        save=True
    )

    return jsonify({
        'status': 'recalculated',
        'organization_id': org_id,
        'baseline': updated
    }), 200


@baselines_bp.route('/evaluate', methods=['POST'])
@login_required
def evaluate_event():
    """
    Evaluates an event or candidate transaction against entity behavioral baseline.
    Returns explainable deviations, plain-English explanations, and fallback state.
    """
    org_id = g.organization_id
    payload = request.get_json()
    if not payload:
        return jsonify({'error': 'Event payload is required'}), 400

    evaluation = BehavioralBaselineService.evaluate_event_against_baseline(
        event=payload,
        org_id=org_id
    )

    return jsonify({
        'status': 'evaluated',
        'organization_id': org_id,
        'evaluation': evaluation
    }), 200


@baselines_bp.route('/<entity_type>/<entity_id>/seed', methods=['POST'])
@login_required
@role_required('admin')
def seed_baseline(entity_type, entity_id):
    """Seeds or overrides an entity baseline profile directly."""
    org_id = g.organization_id
    payload = request.get_json()
    if not payload:
        return jsonify({'error': 'Baseline profile payload is required'}), 400

    seeded = BehavioralBaselineService.seed_baseline(
        org_id=org_id,
        entity_type=entity_type,
        entity_id=entity_id,
        baseline_data=payload,
        save_db=True
    )

    return jsonify({
        'status': 'seeded',
        'organization_id': org_id,
        'baseline': seeded
    }), 201
