"""
Exposure Management & Attack Surface Context REST API Routes for Ethio-Cyber-Shield (ECS) v3.0 (Phase 8.3).
Endpoints:
  POST /api/exposure/assets              - Register external asset into inventory
  GET  /api/exposure/assets              - List registered attack surface assets
  POST /api/exposure/assets/<id>/scan    - Execute TLS/header/port exposure scan
"""
from flask import Blueprint, request, jsonify, g
from app.services.auth_service import login_required, role_required
from app.services.tenant_service import get_current_organization_id
from app.services.exposure_service import ExposureService
import logging

logger = logging.getLogger(__name__)
exposure_bp = Blueprint('exposure', __name__)


def _get_org_id() -> str:
    org_id = g.user.get('organization_id') if hasattr(g, 'user') and g.user else None
    return str(org_id or get_current_organization_id() or "00000000-0000-0000-0000-000000000001")


@exposure_bp.route('/assets', methods=['POST'])
@role_required('admin', 'analyst')
def register_asset():
    """Registers a new external asset (domain, IP, endpoint) for attack surface monitoring."""
    org_id = _get_org_id()
    data = request.get_json() or {}
    asset_type = data.get('asset_type')
    identifier = data.get('identifier')

    if not asset_type or not identifier:
        return jsonify({'error': 'asset_type and identifier are required'}), 400

    asset = ExposureService.register_asset(
        org_id=org_id,
        asset_type=asset_type,
        identifier=identifier,
        environment=data.get('environment', 'production'),
        tags=data.get('tags')
    )
    return jsonify(asset), 201


@exposure_bp.route('/assets', methods=['GET'])
@login_required
def list_assets():
    """Lists all attack surface assets for the current tenant."""
    org_id = _get_org_id()
    assets = ExposureService.list_assets(org_id=org_id)
    return jsonify({'organization_id': org_id, 'assets': assets, 'total': len(assets)}), 200


@exposure_bp.route('/assets/<asset_id>/scan', methods=['POST'])
@role_required('admin', 'analyst')
def scan_asset(asset_id):
    """Executes or records exposure evaluation scan (TLS, headers, ports)."""
    org_id = _get_org_id()
    data = request.get_json() or {}

    try:
        updated_asset = ExposureService.scan_asset_exposure(
            org_id=org_id,
            asset_id=asset_id,
            scan_data=data
        )
        return jsonify(updated_asset), 200
    except ValueError as e:
        return jsonify({'error': str(e)}), 404
