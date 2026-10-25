from flask import Blueprint, jsonify, request, g
from app.services.auth_service import login_required
from app.services.db import get_service_supabase
from app.services.tenant_service import get_current_organization_id
from app.services.metrics_service import MetricsService

dashboard_bp = Blueprint('dashboard', __name__)


def _get_org_id() -> str:
    from app.services.tenant_mgmt_service import is_superadmin
    tenant_req = request.args.get('tenant_id') or request.headers.get('X-ECS-Tenant')
    if tenant_req and tenant_req != 'all' and hasattr(g, 'user') and is_superadmin(g.user):
        return str(tenant_req)
    org_id = g.user.get('organization_id') if hasattr(g, 'user') and g.user else None
    return str(org_id or get_current_organization_id() or "00000000-0000-0000-0000-000000000001")


@dashboard_bp.route('/stats', methods=['GET'])
@login_required
def get_stats():
    sb = get_service_supabase()
    
    # Incidents
    all_inc = sb.table('incidents').select('id, status, severity, risk_level').execute()
    incidents = all_inc.data or []
    
    total_incidents = len(incidents)
    open_incidents = sum(1 for i in incidents if i.get('status') in ('open', 'investigating'))
    high_risk_incidents = sum(1 for i in incidents if i.get('risk_level') in ('high', 'critical'))
    critical_incidents = sum(1 for i in incidents if i.get('severity') == 'critical')

    # Indicators
    all_ind = sb.table('indicators').select('id, status').execute()
    indicators = all_ind.data or []
    total_indicators = len(indicators)
    malicious_indicators = sum(1 for i in indicators if i.get('status') == 'malicious')
    suspicious_indicators = sum(1 for i in indicators if i.get('status') == 'suspicious')

    # Transactions
    all_tx = sb.table('transactions').select('id, is_suspicious').execute()
    transactions = all_tx.data or []
    total_transactions = len(transactions)
    suspicious_transactions = sum(1 for t in transactions if t.get('is_suspicious'))

    # Alerts
    all_alerts = sb.table('alerts').select('id, status, severity').execute()
    alerts = all_alerts.data or []
    open_alerts = sum(1 for a in alerts if a.get('status') == 'open')
    critical_alerts = sum(1 for a in alerts if a.get('severity') == 'critical' and a.get('status') == 'open')

    # Recent activity (last 10 audit logs)
    audit = sb.table('audit_logs').select('*').order('created_at', desc=True).limit(10).execute()

    # Incident type breakdown
    type_counts = {}
    for i in incidents:
        t = i.get('incident_type', 'other')
        type_counts[t] = type_counts.get(t, 0) + 1

    return jsonify({
        'incidents': {
            'total': total_incidents,
            'open': open_incidents,
            'high_risk': high_risk_incidents,
            'critical': critical_incidents
        },
        'indicators': {
            'total': total_indicators,
            'malicious': malicious_indicators,
            'suspicious': suspicious_indicators
        },
        'transactions': {
            'total': total_transactions,
            'suspicious': suspicious_transactions
        },
        'alerts': {
            'open': open_alerts,
            'critical_open': critical_alerts
        },
        'incident_types': type_counts,
        'recent_activity': audit.data or []
    })


@dashboard_bp.route('/executive', methods=['GET'])
@login_required
def get_executive_dashboard():
    """
    Returns high-level executive and operational KPIs:
    MTTD, MTTA, MTTC, MTTR, ETB protected, 48h compliance rate, noise reduction.
    Supports low_bandwidth=true flag for rural branches.
    """
    org_id = _get_org_id()
    low_bw = (
        request.args.get('low_bandwidth', '').lower() in ('true', '1', 'yes') or
        request.args.get('compact', '').lower() in ('true', '1', 'yes')
    )
    metrics = MetricsService.get_executive_metrics(org_id, low_bandwidth=low_bw)
    return jsonify(metrics), 200
