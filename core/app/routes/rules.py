"""
Detection Rules & Per-Tenant Overrides REST API for Ethio-Cyber-Shield (ECS) v3.0 (Phase 3.1).

Provides endpoints for:
- Listing declarative rules with effective tenant configurations (/api/rules)
- Inspecting individual rule specifications (/api/rules/<id>)
- Reading, setting, and resetting per-tenant rule overrides (/api/rules/<id>/override)
"""
from flask import Blueprint, request, jsonify, g
from app.services.auth_service import login_required, role_required
from app.services.rule_engine_service import get_rule_engine

rules_bp = Blueprint('rules', __name__)


@rules_bp.route('', methods=['GET'])
@login_required
def list_rules():
    """Lists all detection rules with effective configuration for the authenticated tenant."""
    engine = get_rule_engine()
    org_id = g.organization_id
    pack_filter = request.args.get('pack')
    layer_filter = request.args.get('layer')

    all_rules = engine.list_rules(org_id=org_id)
    if pack_filter:
        all_rules = [r for r in all_rules if r.get('pack') == pack_filter]
    if layer_filter:
        all_rules = [r for r in all_rules if r.get('layer') == layer_filter.upper()]

    return jsonify({
        'organization_id': org_id,
        'total_rules': len(all_rules),
        'rules': all_rules
    }), 200


@rules_bp.route('/<rule_id>', methods=['GET'])
@login_required
def get_rule_detail(rule_id):
    """Retrieves full declarative specification for a single rule."""
    engine = get_rule_engine()
    org_id = g.organization_id
    rule = engine.get_rule(rule_id, org_id=org_id)
    if not rule:
        return jsonify({'error': f"Rule '{rule_id}' not found"}), 404
    return jsonify({'organization_id': org_id, 'rule': rule}), 200


@rules_bp.route('/<rule_id>/override', methods=['GET'])
@login_required
def get_rule_override(rule_id):
    """Gets tenant-specific override parameters for a rule."""
    engine = get_rule_engine()
    org_id = g.organization_id
    override = engine.get_tenant_override(org_id, rule_id)
    return jsonify({'organization_id': org_id, 'rule_id': rule_id, 'override': override}), 200


@rules_bp.route('/<rule_id>/override', methods=['PUT', 'POST'])
@login_required
@role_required('admin')
def set_rule_override(rule_id):
    """Sets or updates tenant-specific threshold, weight, or lifecycle overrides for a rule."""
    engine = get_rule_engine()
    org_id = g.organization_id
    rule = engine.get_rule(rule_id)
    if not rule:
        return jsonify({'error': f"Rule '{rule_id}' not found"}), 404

    data = request.get_json() or {}
    is_enabled = data.get('is_enabled')
    threshold_overrides = data.get('threshold_overrides')
    weight_override = data.get('weight_override')
    severity_override = data.get('severity_override')
    lifecycle_state_override = data.get('lifecycle_state_override')

    override = engine.set_tenant_override(
        org_id=org_id,
        rule_id=rule_id,
        is_enabled=is_enabled,
        threshold_overrides=threshold_overrides,
        weight_override=weight_override,
        severity_override=severity_override,
        lifecycle_state_override=lifecycle_state_override
    )
    return jsonify({'organization_id': org_id, 'rule_id': rule_id, 'override': override}), 200


@rules_bp.route('/<rule_id>/override', methods=['DELETE'])
@login_required
@role_required('admin')
def delete_rule_override(rule_id):
    """Removes tenant override, resetting rule to platform default for this tenant."""
    engine = get_rule_engine()
    org_id = g.organization_id
    engine.delete_tenant_override(org_id, rule_id)
    return jsonify({'status': 'deleted', 'organization_id': org_id, 'rule_id': rule_id}), 200
