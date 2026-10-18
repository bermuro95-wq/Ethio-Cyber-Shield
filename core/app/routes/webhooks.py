"""
Inbound Webhook Receiver & Field Mapping API for Ethio-Cyber-Shield (ECS).
Provides endpoints for:
- Inbound third-party webhook ingestion (/inbound/<source_id>)
- Webhook sources management (/sources)
- Interactive test-with-sample mapping runner (/test-mapping)
"""
from flask import Blueprint, request, jsonify, g
from app.services.auth_service import login_required, role_required
from app.services.webhook_service import (
    create_webhook_source,
    get_webhook_source,
    list_webhook_sources,
    update_webhook_source,
    delete_webhook_source,
    process_inbound_webhook,
    _clean_source_output
)
from app.services.field_mapper import test_mapping

webhooks_bp = Blueprint('webhooks', __name__)


# =========================================================================
# 1. INBOUND RECEIVER ENDPOINT (PUBLIC FOR WEBHOOK DISPATCHERS)
# =========================================================================

@webhooks_bp.route('/inbound/<source_id>', methods=['POST'])
def receive_inbound_webhook(source_id):
    """
    Public inbound receiver endpoint for external payment gateways, core banking,
    and telco webhook notifications. Authenticates via signature headers and normalizes
    events into canonical ECS Event Contract v1.1.
    """
    raw_body = request.get_data() or b''
    json_payload = request.get_json(silent=True) or {}

    status_code, response_data = process_inbound_webhook(
        source_id=source_id,
        headers=dict(request.headers),
        raw_body=raw_body,
        json_payload=json_payload
    )

    return jsonify(response_data), status_code


# =========================================================================
# 2. WEBHOOK SOURCES CRUD (TENANT-SCOPED)
# =========================================================================

@webhooks_bp.route('/sources', methods=['GET'])
@login_required
def list_sources():
    """Lists all configured webhook sources for the authenticated organization."""
    sources = list_webhook_sources(g.organization_id)
    return jsonify(sources), 200


@webhooks_bp.route('/sources', methods=['POST'])
@role_required('admin', 'responder')
def register_source():
    """
    Registers a new inbound webhook source with encrypted secret credentials
    and declarative mapping rules.
    """
    data = request.get_json() or {}
    source_id = (data.get('source_id') or '').strip()
    name = (data.get('name') or '').strip()

    if not name:
        return jsonify({'error': 'name is required'}), 400

    created = create_webhook_source(data, org_id=g.organization_id)
    return jsonify(created), 201


@webhooks_bp.route('/sources/<source_id>', methods=['GET'])
@login_required
def get_source_detail(source_id):
    """Retrieves configuration and statistics for a specific webhook source."""
    source = get_webhook_source(source_id, org_id=g.organization_id)
    if not source:
        return jsonify({'error': 'Webhook source not found'}), 404

    return jsonify(_clean_source_output(source)), 200


@webhooks_bp.route('/sources/<source_id>', methods=['PUT'])
@role_required('admin', 'responder')
def update_source_config(source_id):
    """Updates configuration, active status, or mapping rules for a webhook source."""
    data = request.get_json() or {}
    updated = update_webhook_source(source_id, data, org_id=g.organization_id)
    if not updated:
        return jsonify({'error': 'Webhook source not found or unauthorized'}), 404

    return jsonify(updated), 200


@webhooks_bp.route('/sources/<source_id>', methods=['DELETE'])
@role_required('admin')
def delete_source_config(source_id):
    """Deletes a webhook source."""
    success = delete_webhook_source(source_id, org_id=g.organization_id)
    if not success:
        return jsonify({'error': 'Webhook source not found or unauthorized'}), 404

    return jsonify({'status': 'deleted', 'source_id': source_id}), 200


# =========================================================================
# 3. TEST-WITH-SAMPLE RUNNER
# =========================================================================

@webhooks_bp.route('/test-mapping', methods=['POST'])
@login_required
def run_test_mapping():
    """
    Dry-run endpoint allowing developers and security engineers to test JSONPath
    mappings against sample payloads before enabling webhook sources.
    """
    data = request.get_json() or {}
    sample_payload = data.get('sample_payload') or {}
    mapping_rules = data.get('mapping_rules') or {}

    diagnostics = test_mapping(
        sample_payload=sample_payload,
        mapping_rules=mapping_rules,
        default_org_id=g.organization_id
    )

    return jsonify(diagnostics), 200
