from flask import Blueprint, jsonify
from app.services.auth_service import login_required
from app.services.db import get_service_supabase

dashboard_bp = Blueprint('dashboard', __name__)

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
