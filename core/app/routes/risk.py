"""
Ethio-Cyber-Shield (ECS) — Explainable Risk Model v2 REST API (Phase 3.5).
Provides endpoints for:
- GET /api/risk/model/spec: Model specification, formulas, confidence factors, recency decay, and non-probability notice.
- POST /api/risk/evaluate: Dry-run and live risk calculation for candidate events or detections.
- GET /api/risk/criticality: List entity criticality configurations for the tenant.
- POST /api/risk/criticality: Create or update entity criticality (Admin/Responder only).
- DELETE /api/risk/criticality/<id>: Delete entity criticality override (Admin only).
- GET /api/risk/entities/<entity_type>/<entity_id>: Composite active decayed risk profile and entity history.
"""
from flask import Blueprint, request, jsonify, g
from app.services.auth_service import login_required, role_required
from app.services.risk_model_service import (
    RiskModelV2Service,
    CRITICALITY_TIERS,
    CONFIDENCE_FACTORS,
    RECENCY_DECAY_TIERS,
    SEVERITY_RATIONALES,
    NON_PROBABILITY_DECLARATION,
)

risk_bp = Blueprint('risk', __name__)


@risk_bp.route('/model/spec', methods=['GET'])
@login_required
def get_model_spec():
    """Returns the declarative specification, formulas, and parameters of Risk Model v2."""
    return jsonify({
        'status': 'success',
        'data': {
            'model_name': 'Ethio-Cyber-Shield Explainable Risk Model',
            'model_version': '2.0',
            'score_range': [0, 100],
            'non_probability_notice': NON_PROBABILITY_DECLARATION,
            'criticality_tiers': CRITICALITY_TIERS,
            'confidence_factors': CONFIDENCE_FACTORS,
            'recency_decay_tiers': RECENCY_DECAY_TIERS,
            'severity_rationales': SEVERITY_RATIONALES,
            'mathematical_formulation': {
                'step_1_rules': "confidence_adjusted_rules = sum(round(rule_weight * confidence_factor))",
                'step_2_baseline': "pre_score = confidence_adjusted_rules + baseline_anomaly_score",
                'step_3_criticality': "if pre_score == 0: 0 else: round(pre_score * criticality_multiplier) + criticality_boost",
                'step_4_clamp': "final_score = min(100, max(0, criticality_adjusted_score))"
            }
        }
    }), 200


@risk_bp.route('/evaluate', methods=['POST'])
@login_required
def evaluate_risk():
    """Dry-run or evaluate risk given fired rules, baseline score, and entity metadata."""
    org_id = g.organization_id
    data = request.get_json() or {}

    fired_rules = data.get('fired_rules', [])
    baseline_score = int(data.get('baseline_score', 0))
    entity_type = data.get('entity_type', 'account')
    entity_id = data.get('entity_id', 'unknown')
    custom_criticality = data.get('custom_criticality')

    result = RiskModelV2Service.calculate_risk(
        fired_rules=fired_rules,
        baseline_score=baseline_score,
        entity_type=entity_type,
        entity_id=entity_id,
        org_id=org_id,
        custom_criticality=custom_criticality
    )

    return jsonify({
        'status': 'success',
        'organization_id': org_id,
        'data': result
    }), 200


@risk_bp.route('/criticality', methods=['GET'])
@login_required
def list_criticality():
    """Lists entity criticality configurations for the tenant."""
    org_id = g.organization_id
    entity_type = request.args.get('entity_type')
    tier = request.args.get('tier')

    items = RiskModelV2Service.list_entity_criticalities(
        org_id=org_id,
        entity_type=entity_type,
        tier=tier
    )

    return jsonify({
        'status': 'success',
        'organization_id': org_id,
        'count': len(items),
        'data': items
    }), 200


@risk_bp.route('/criticality', methods=['POST'])
@login_required
@role_required('admin', 'responder')
def set_criticality():
    """Sets or updates entity criticality configuration."""
    org_id = g.organization_id
    data = request.get_json() or {}

    entity_type = data.get('entity_type')
    entity_id = data.get('entity_id')
    tier = data.get('criticality_tier')
    boost = data.get('criticality_score_boost')
    owner_unit = data.get('owner_unit')
    notes = data.get('notes')

    if not entity_type or not entity_id or not tier:
        return jsonify({'error': 'entity_type, entity_id, and criticality_tier are required'}), 400

    try:
        record = RiskModelV2Service.set_entity_criticality(
            org_id=org_id,
            entity_type=entity_type,
            entity_id=entity_id,
            tier=tier,
            boost=int(boost) if boost is not None else None,
            owner_unit=owner_unit,
            notes=notes
        )
        return jsonify({
            'status': 'success',
            'organization_id': org_id,
            'data': record
        }), 201
    except ValueError as e:
        return jsonify({'error': str(e)}), 400


@risk_bp.route('/criticality/<item_id>', methods=['DELETE'])
@login_required
@role_required('admin')
def delete_criticality(item_id):
    """Deletes an entity criticality configuration."""
    org_id = g.organization_id
    deleted = RiskModelV2Service.delete_entity_criticality(org_id, item_id)
    return jsonify({
        'status': 'success',
        'organization_id': org_id,
        'message': f"Criticality configuration '{item_id}' removed"
    }), 200


@risk_bp.route('/entities/<entity_type>/<entity_id>', methods=['GET'])
@login_required
def get_entity_profile(entity_type, entity_id):
    """Retrieves composite decayed risk profile, recent detections, and criticality tier for an entity."""
    org_id = g.organization_id
    lookback = int(request.args.get('lookback_hours', 24))

    profile = RiskModelV2Service.get_entity_risk_profile(
        org_id=org_id,
        entity_type=entity_type,
        entity_id=entity_id,
        lookback_hours=lookback
    )

    return jsonify({
        'status': 'success',
        'organization_id': org_id,
        'data': profile
    }), 200
