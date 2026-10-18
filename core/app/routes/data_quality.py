"""
Health & Data-Quality REST API for Ethio-Cyber-Shield (ECS) v3.0 (Phase 2.7).

Provides endpoints for:
- Overall Data Quality Score and throughput overview (/overview)
- Monitored sources configuration and status (/sources)
- Real-time silent-source anomaly alerts (/silent-alerts)
- Schema violation statistics and diagnostic logs (/violations)
- Programmatic violation reporting (/record-violation)
"""
from flask import Blueprint, request, jsonify, g
from app.services.auth_service import login_required, role_required
from app.services.data_quality_service import (
    register_or_update_source,
    list_monitored_sources,
    check_silent_sources,
    record_schema_violation,
    get_schema_violations_summary,
    get_ingestion_throughput,
    calculate_data_quality_score,
    clear_data_quality_stores
)

data_quality_bp = Blueprint('data_quality', __name__)


@data_quality_bp.route('/overview', methods=['GET'])
@login_required
def get_data_quality_overview():
    """
    Returns an explainable data quality summary for the authenticated organization:
    - Overall 0-100 score and letter grade (A/B/C/D/F)
    - Weighted breakdown (schema compliance, source vitality, field richness)
    - Throughput telemetry (1m, 5m, 1h, 24h)
    - Monitored, active, and silent source counts
    """
    org_id = g.organization_id
    score_report = calculate_data_quality_score(org_id)
    throughput = get_ingestion_throughput(org_id)
    silent_report = check_silent_sources(org_id)

    response_payload = {
        'organization_id': org_id,
        'evaluated_at': score_report['evaluated_at'],
        'quality_score': score_report['quality_score'],
        'grade': score_report['grade'],
        'grade_description': score_report['grade_description'],
        'breakdown': score_report['breakdown'],
        'weights': score_report['weights'],
        'rationale': score_report['rationale'],
        'throughput': throughput,
        'monitored_sources_count': silent_report['monitored_sources_count'],
        'active_sources_count': silent_report['active_sources_count'],
        'silent_sources_count': silent_report['silent_sources_count'],
        'tenant_silent': silent_report['tenant_silent'],
        'status': 'critical' if silent_report['tenant_silent'] else ('degraded' if silent_report['silent_sources_count'] > 0 or score_report['quality_score'] < 80 else 'healthy')
    }
    return jsonify(response_payload), 200


@data_quality_bp.route('/sources', methods=['GET'])
@login_required
def get_monitored_sources():
    """Lists all monitored ingestion sources and their live health status for the tenant."""
    org_id = g.organization_id
    sources = list_monitored_sources(org_id)
    return jsonify({
        'organization_id': org_id,
        'total_sources': len(sources),
        'sources': sources
    }), 200


@data_quality_bp.route('/sources', methods=['POST'])
@login_required
@role_required('admin', 'analyst')
def configure_monitored_source():

    """Registers or updates a monitored telemetry source configuration."""
    org_id = g.organization_id
    data = request.get_json() or {}

    source_id = data.get('source_id')
    source_name = data.get('source_name')
    if not source_id or not source_name:
        return jsonify({'error': "Fields 'source_id' and 'source_name' are required"}), 400

    source_type = data.get('source_type', 'webhook')
    silence_threshold = int(data.get('silence_threshold_seconds') or 900)
    is_active = data.get('is_active', True)

    source = register_or_update_source(
        org_id=org_id,
        source_id=source_id,
        source_name=source_name,
        source_type=source_type,
        silence_threshold_seconds=silence_threshold,
        is_active=is_active
    )
    return jsonify(source), 201


@data_quality_bp.route('/silent-alerts', methods=['GET'])
@login_required
def get_silent_alerts():
    """Evaluates and returns live silent-source and tenant-silence anomaly alerts."""
    org_id = g.organization_id
    report = check_silent_sources(org_id)
    return jsonify(report), 200


@data_quality_bp.route('/violations', methods=['GET'])
@login_required
def get_schema_violations():
    """Returns aggregated schema violation counts, categorization breakdown, and recent logs."""
    org_id = g.organization_id
    window_secs = request.args.get('window_seconds', default=86400, type=int)
    summary = get_schema_violations_summary(org_id, time_window_seconds=window_secs)
    return jsonify(summary), 200


@data_quality_bp.route('/record-violation', methods=['POST'])
@login_required
def record_violation_endpoint():
    """Allows collectors or edge agents to log malformed / rejected telemetry events."""
    org_id = g.organization_id
    data = request.get_json() or {}

    violation_type = data.get('violation_type', 'SCHEMA_VALIDATION_ERROR')
    error_message = data.get('error_message')
    if not error_message:
        return jsonify({'error': "Field 'error_message' is required"}), 400

    source_id = data.get('source_id')
    source_name = data.get('source_name')
    raw_snippet = data.get('raw_snippet')

    violation = record_schema_violation(
        org_id=org_id,
        source_id=source_id,
        source_name=source_name,
        violation_type=violation_type,
        error_message=error_message,
        raw_sample=raw_snippet
    )
    return jsonify({'status': 'recorded', 'violation': violation}), 201


@data_quality_bp.route('/reset', methods=['POST'])
@login_required
@role_required(['admin'])
def reset_stores():
    """Admin-only endpoint to clear in-memory stores for tests."""
    clear_data_quality_stores()
    return jsonify({'status': 'cleared'}), 200
