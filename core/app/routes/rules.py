"""
Detection Rules, Lifecycle Tooling, Backtesting & Precision Feedback REST API for ECS v3.0 (Phase 3.1 & 3.2).

Provides endpoints for:
- Listing and inspecting declarative rules (/api/rules, /api/rules/<id>)
- Reading, setting, and resetting per-tenant rule overrides (/api/rules/<id>/override)
- Historical backtesting runs and "what would have fired" preview (/api/rules/<id>/backtest, /api/rules/preview)
- Rule lifecycle state transitions and audit history (/api/rules/<id>/lifecycle)
- Analyst precision feedback and false-positive tuning suggestions (/api/rules/<id>/feedback, /api/rules/<id>/metrics)
- Organization-wide detection precision overview (/api/rules/metrics/summary)
"""
from flask import Blueprint, request, jsonify, g
from app.services.auth_service import login_required, role_required
from app.services.rule_engine_service import get_rule_engine
from app.services.rule_lifecycle_service import (
    RuleBacktestEngine,
    RuleLifecycleManager,
    RulePrecisionService
)

rules_bp = Blueprint('rules', __name__)


# =========================================================================
# 1. CORE DECLARATIVE RULES & OVERRIDES
# =========================================================================

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


# =========================================================================
# 2. HISTORICAL BACKTESTING & WHAT-WOULD-HAVE-FIRED PREVIEW
# =========================================================================

@rules_bp.route('/<rule_id>/backtest', methods=['POST'])
@login_required
@role_required('analyst', 'admin')
def run_rule_backtest(rule_id):
    """Triggers a historical backtest run for a rule over the last N days."""
    org_id = g.organization_id
    user_id = getattr(g, 'user_id', None)
    data = request.get_json() or {}

    days = int(data.get('days') or 7)
    custom_thresholds = data.get('custom_thresholds')

    try:
        run_record = RuleBacktestEngine.run_backtest(
            org_id=org_id,
            rule_id=rule_id,
            time_range_days=days,
            custom_thresholds=custom_thresholds,
            user_id=user_id
        )
        return jsonify({
            'status': 'success',
            'organization_id': org_id,
            'backtest_run': run_record
        }), 200
    except ValueError as ve:
        return jsonify({'error': str(ve)}), 404
    except Exception as e:
        return jsonify({'error': f"Failed to execute backtest: {e}"}), 500


@rules_bp.route('/<rule_id>/backtest', methods=['GET'])
@login_required
def list_rule_backtests(rule_id):
    """Lists historical backtest runs for a specific rule."""
    org_id = g.organization_id
    runs = RuleBacktestEngine.list_backtest_runs(org_id=org_id, rule_id=rule_id)
    return jsonify({
        'organization_id': org_id,
        'rule_id': rule_id,
        'total_runs': len(runs),
        'backtest_runs': runs
    }), 200


@rules_bp.route('/backtests/<run_id>', methods=['GET'])
@login_required
def get_backtest_run(run_id):
    """Retrieves a specific backtest run report."""
    org_id = g.organization_id
    record = RuleBacktestEngine.get_backtest_run(org_id=org_id, run_id=run_id)
    if not record:
        return jsonify({'error': f"Backtest run '{run_id}' not found"}), 404
    return jsonify({'organization_id': org_id, 'backtest_run': record}), 200


@rules_bp.route('/preview', methods=['POST'])
@login_required
@role_required('analyst', 'admin')
def preview_rule():
    """
    Evaluates 'what would have fired' over the last N days for a candidate rule
    or custom threshold parameters without persisting permanent runs.
    """
    org_id = g.organization_id
    data = request.get_json() or {}
    rule_spec = data.get('rule_spec') or {}
    days = int(data.get('days') or 7)

    if not rule_spec:
        return jsonify({'error': "Missing 'rule_spec' payload for preview"}), 400

    try:
        preview = RuleBacktestEngine.preview_rule_evaluation(
            org_id=org_id,
            rule_spec=rule_spec,
            time_range_days=days
        )
        return jsonify({
            'organization_id': org_id,
            'preview': preview
        }), 200
    except Exception as e:
        return jsonify({'error': f"Preview evaluation error: {e}"}), 500


# =========================================================================
# 3. RULE LIFECYCLE MANAGEMENT (draft -> backtest -> shadow -> live)
# =========================================================================

@rules_bp.route('/<rule_id>/lifecycle', methods=['POST'])
@login_required
@role_required('admin')
def transition_lifecycle_state(rule_id):
    """Transitions a rule's lifecycle state (draft -> backtest -> shadow -> live)."""
    org_id = g.organization_id
    user_id = getattr(g, 'user_id', None)
    data = request.get_json() or {}

    to_state = data.get('to_state')
    reason = data.get('reason', '')
    backtest_run_id = data.get('backtest_run_id')
    force = bool(data.get('force', False))

    if not to_state:
        return jsonify({'error': "Missing required field 'to_state'"}), 400

    try:
        res = RuleLifecycleManager.transition_state(
            org_id=org_id,
            rule_id=rule_id,
            to_state=to_state,
            reason=reason,
            user_id=user_id,
            backtest_run_id=backtest_run_id,
            force=force
        )
        return jsonify({'organization_id': org_id, **res}), 200
    except ValueError as ve:
        return jsonify({'error': str(ve)}), 400
    except Exception as e:
        return jsonify({'error': f"Lifecycle transition error: {e}"}), 500


@rules_bp.route('/<rule_id>/lifecycle', methods=['GET'])
@login_required
def get_lifecycle_history(rule_id):
    """Retrieves the audit trail of lifecycle transitions for a rule."""
    org_id = g.organization_id
    history = RuleLifecycleManager.get_lifecycle_history(org_id=org_id, rule_id=rule_id)
    return jsonify({
        'organization_id': org_id,
        'rule_id': rule_id,
        'total_transitions': len(history),
        'history': history
    }), 200


# =========================================================================
# 4. ANALYST PRECISION FEEDBACK & TUNING METRICS
# =========================================================================

@rules_bp.route('/<rule_id>/feedback', methods=['POST'])
@login_required
@role_required('analyst', 'admin')
def record_analyst_feedback(rule_id):
    """Records analyst feedback on a detection (true_positive, false_positive, etc.)."""
    org_id = g.organization_id
    user_id = getattr(g, 'user_id', None)
    data = request.get_json() or {}

    verdict = data.get('verdict')
    if not verdict:
        return jsonify({'error': "Missing required field 'verdict'"}), 400

    detection_id = data.get('detection_id')
    alert_id = data.get('alert_id')
    analyst_notes = data.get('analyst_notes', '')
    suggested_suppression = data.get('suggested_suppression')

    try:
        feedback = RulePrecisionService.record_feedback(
            org_id=org_id,
            rule_id=rule_id,
            verdict=verdict,
            detection_id=detection_id,
            alert_id=alert_id,
            analyst_notes=analyst_notes,
            suggested_suppression=suggested_suppression,
            user_id=user_id
        )
        return jsonify({'organization_id': org_id, 'feedback': feedback}), 201
    except ValueError as ve:
        return jsonify({'error': str(ve)}), 400
    except Exception as e:
        return jsonify({'error': f"Feedback recording error: {e}"}), 500


@rules_bp.route('/<rule_id>/metrics', methods=['GET'])
@login_required
def get_rule_precision_metrics(rule_id):
    """Retrieves precision, false-positive rate, and automated tuning suggestions for a rule."""
    org_id = g.organization_id
    metrics = RulePrecisionService.get_rule_precision_metrics(org_id=org_id, rule_id=rule_id)
    return jsonify(metrics), 200


@rules_bp.route('/metrics/summary', methods=['GET'])
@login_required
def get_organization_precision_summary():
    """Retrieves organization-wide summary of rule precision across all rules."""
    org_id = g.organization_id
    summary = RulePrecisionService.get_organization_precision_summary(org_id=org_id)
    return jsonify(summary), 200
