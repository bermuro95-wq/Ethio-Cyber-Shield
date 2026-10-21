"""
Endpoint & Email Telemetry Adapters REST API Routes for Ethio-Cyber-Shield (ECS) v3.0 (Phase 8.2).
Endpoints:
  POST /api/adapters/endpoint/ingest - Ingest Sysmon/Wazuh/Defender host telemetry
  POST /api/adapters/email/ingest    - Ingest email headers & analyze DMARC/BEC
  GET  /api/adapters/events          - List normalized adapter events
"""
from flask import Blueprint, request, jsonify, g
from app.services.auth_service import login_required, role_required
from app.services.tenant_service import get_current_organization_id
from app.services.endpoint_email_adapter_service import EndpointEmailAdapterService
import logging

logger = logging.getLogger(__name__)
adapters_bp = Blueprint('adapters', __name__)


def _get_org_id() -> str:
    org_id = g.user.get('organization_id') if hasattr(g, 'user') and g.user else None
    return str(org_id or get_current_organization_id() or "00000000-0000-0000-0000-000000000001")


@adapters_bp.route('/endpoint/ingest', methods=['POST'])
@login_required
def ingest_endpoint():
    """Ingests host process telemetry and flags ransomware precursors."""
    org_id = _get_org_id()
    data = request.get_json() or {}
    source_fmt = data.get('format', 'sysmon')
    log_payload = data.get('log') or data

    normalized = EndpointEmailAdapterService.ingest_endpoint_log(
        org_id=org_id,
        raw_log=log_payload,
        source_format=source_fmt
    )
    return jsonify(normalized), 201


@adapters_bp.route('/email/ingest', methods=['POST'])
@login_required
def ingest_email():
    """Ingests email messages, evaluates DMARC/SPF, and detects BEC VIP impersonation."""
    org_id = _get_org_id()
    data = request.get_json() or {}
    executives = data.get('known_executives')
    email_data = data.get('email') or data

    normalized = EndpointEmailAdapterService.ingest_email_event(
        org_id=org_id,
        email_data=email_data,
        known_executives=executives
    )
    return jsonify(normalized), 201


@adapters_bp.route('/events', methods=['GET'])
@login_required
def list_events():
    """Lists recent normalized adapter telemetry events for tenant."""
    org_id = _get_org_id()
    limit = int(request.args.get('limit', 50))
    events = EndpointEmailAdapterService.list_ingested_events(org_id=org_id, limit=limit)
    return jsonify({'organization_id': org_id, 'count': len(events), 'events': events}), 200
