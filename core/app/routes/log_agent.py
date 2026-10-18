"""
Log Agent Preview & Testing API for Ethio-Cyber-Shield (ECS).
Provides endpoints to test log parsers against raw log lines.
"""
from flask import Blueprint, request, jsonify, g
from app.services.auth_service import login_required
from connectors.log_agent.parser import parse_log_line

log_agent_bp = Blueprint('log_agent', __name__)


@log_agent_bp.route('/parse', methods=['POST'])
@login_required
def parse_log_sample():
    """
    Parses a single log line (Nginx, Apache, Syslog, CEF) and returns the
    resulting canonical ECS Event Contract v1.1 event.
    """
    data = request.get_json() or {}
    log_line = (data.get('log_line') or '').strip()
    log_format = (data.get('format') or 'auto').strip()
    source_system = data.get('source_system')

    if not log_line:
        return jsonify({'error': 'log_line is required'}), 400

    parsed = parse_log_line(
        line=log_line,
        format_type=log_format,
        organization_id=g.organization_id,
        source_system=source_system
    )

    if not parsed:
        return jsonify({
            'success': False,
            'error': f"Failed to parse log line with format '{log_format}'"
        }), 422

    return jsonify({
        'success': True,
        'parsed_event': parsed
    }), 200
