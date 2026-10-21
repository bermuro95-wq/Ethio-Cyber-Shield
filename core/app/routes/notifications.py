"""
Multi-Channel Notifications REST API Routes for Ethio-Cyber-Shield (ECS) v3.0 (Phase 4.5).
Endpoints:
  GET  /api/notifications/configs          - List channel configs (secrets masked)
  PUT  /api/notifications/configs/<channel>- Update channel config (encrypted at rest)
  POST /api/notifications/test/<channel>   - Send test notification
  GET  /api/notifications/logs             - Delivery audit logs
  POST /api/notifications/escalate-sla     - Trigger SLA breach watchdog
"""
from flask import Blueprint, request, jsonify, g
from app.services.auth_service import login_required, role_required
from app.services.notification_service import NotificationService
from app.services.tenant_service import get_current_organization_id
import logging

logger = logging.getLogger(__name__)
notifications_bp = Blueprint('notifications', __name__)


def _get_org_id() -> str:
    org_id = g.user.get('organization_id') if hasattr(g, 'user') and g.user else None
    return str(org_id or get_current_organization_id() or "00000000-0000-0000-0000-000000000001")


@notifications_bp.route('/configs', methods=['GET'])
@login_required
def list_configs():
    """Lists channel configurations with secrets masked."""
    org_id = _get_org_id()
    configs = NotificationService.list_configs(org_id)
    return jsonify(configs), 200


@notifications_bp.route('/configs/<channel>', methods=['GET'])
@login_required
def get_config(channel):
    """Retrieves specific channel configuration."""
    org_id = _get_org_id()
    config = NotificationService.get_channel_config(org_id, channel)
    if not config:
        return jsonify({'error': f"Config for channel '{channel}' not found"}), 404
    return jsonify(config), 200


@notifications_bp.route('/configs/<channel>', methods=['PUT'])
@role_required('admin')
def set_config(channel):
    """Configures a notification channel with envelope-encrypted secrets."""
    org_id = _get_org_id()
    data = request.get_json() or {}

    config_data = data.get('config_data', {})
    is_enabled = data.get('is_enabled', True)
    min_severity = data.get('min_severity', 'medium')
    quiet_hours_enabled = data.get('quiet_hours_enabled', False)
    quiet_hours_start = data.get('quiet_hours_start', '22:00')
    quiet_hours_end = data.get('quiet_hours_end', '06:00')
    quiet_hours_override_severity = data.get('quiet_hours_override_severity', 'critical')

    try:
        updated = NotificationService.set_channel_config(
            org_id=org_id,
            channel=channel,
            config_data=config_data,
            is_enabled=is_enabled,
            min_severity=min_severity,
            quiet_hours_enabled=quiet_hours_enabled,
            quiet_hours_start=quiet_hours_start,
            quiet_hours_end=quiet_hours_end,
            quiet_hours_override_severity=quiet_hours_override_severity
        )
        return jsonify(updated), 200
    except ValueError as e:
        return jsonify({'error': str(e)}), 400


@notifications_bp.route('/test/<channel>', methods=['POST'])
@role_required('admin', 'analyst')
def test_channel(channel):
    """Dispatches a synthetic test notification through the designated channel."""
    org_id = _get_org_id()
    data = request.get_json() or {}

    test_payload = {
        'id': 'test-notification-001',
        'title': data.get('title', 'ECS Security Notification Diagnostic Test'),
        'severity': data.get('severity', 'high'),
        'risk_score': int(data.get('risk_score', 85)),
        'amount': data.get('amount', 50000.0),
        'description': data.get('description', 'Diagnostic alert test from Ethio-Cyber-Shield platform.')
    }

    result = NotificationService.dispatch_alert(org_id, test_payload, channels=[channel])
    return jsonify(result), 200


@notifications_bp.route('/logs', methods=['GET'])
@login_required
def list_logs():
    """Lists notification dispatch logs for current tenant."""
    org_id = _get_org_id()
    limit = int(request.args.get('limit', 50))
    logs = NotificationService.list_logs(org_id, limit=limit)
    return jsonify(logs), 200


@notifications_bp.route('/escalate-sla', methods=['POST'])
@role_required('admin', 'analyst')
def trigger_sla_escalation():
    """Manually triggers SLA breach evaluation and escalation notifications."""
    org_id = _get_org_id()
    escalated = NotificationService.check_and_escalate_sla_breaches(org_id)
    return jsonify({'escalated_count': len(escalated), 'escalations': escalated}), 200
