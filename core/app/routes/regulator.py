"""
Regulator & Sector-Wide Telemetry REST API Routes for Ethio-Cyber-Shield (ECS) v3.0 (Phase 8.5).
Endpoints:
  GET /api/regulator/sector-overview - Aggregated cross-institution sector defense dashboard
"""
from flask import Blueprint, request, jsonify, g
from app.services.auth_service import login_required, role_required
from app.services.regulator_dashboard_service import RegulatorDashboardService
import logging

logger = logging.getLogger(__name__)
regulator_bp = Blueprint('regulator', __name__)


@regulator_bp.route('/sector-overview', methods=['GET'])
@login_required
def get_sector_overview():
    """
    Returns anonymized cross-institution sector-wide defensive intelligence and compliance KPIs.
    Strictly scrubs all individual bank identities conforming to Principle #4.
    """
    sector_filter = request.args.get('sector')
    overview = RegulatorDashboardService.get_sector_overview(sector_filter=sector_filter)
    return jsonify(overview), 200
