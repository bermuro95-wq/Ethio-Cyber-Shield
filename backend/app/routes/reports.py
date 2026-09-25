from flask import Blueprint, request, jsonify, g, Response
from app.services.auth_service import login_required, role_required
from app.services.db import get_service_supabase
from datetime import datetime, timedelta, timezone
import csv
import io

reports_bp = Blueprint('reports', __name__)

@reports_bp.route('/summary', methods=['GET'])
@login_required
def summary_report():
    """JSON summary for dashboards / simple report."""
    days = min(int(request.args.get('days', 7)), 90)
    since = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    sb = get_service_supabase()

    txs = sb.table('transactions').select('id, amount, is_suspicious').gte('transaction_time', since).limit(5000).execute().data or []
    alerts = sb.table('alerts').select('id, severity, status').gte('created_at', since).limit(2000).execute().data or []
    incidents = sb.table('incidents').select('id, status, severity, risk_level').gte('created_at', since).limit(2000).execute().data or []

    sus = [t for t in txs if t.get('is_suspicious')]
    return jsonify({
        'period_days': days,
        'generated_at': datetime.now(timezone.utc).isoformat(),
        'transactions': {
            'total': len(txs),
            'suspicious': len(sus),
            'suspicious_amount_etb': round(sum(float(t.get('amount') or 0) for t in sus), 2),
        },
        'alerts': {
            'total': len(alerts),
            'open': sum(1 for a in alerts if a.get('status') == 'open'),
            'critical': sum(1 for a in alerts if a.get('severity') == 'critical'),
        },
        'incidents': {
            'total': len(incidents),
            'open': sum(1 for i in incidents if i.get('status') in ('open', 'investigating')),
            'high_risk': sum(1 for i in incidents if i.get('risk_level') in ('high', 'critical')),
        }
    })

@reports_bp.route('/export.csv', methods=['GET'])
@role_required('admin', 'analyst')
def export_csv():
    """CSV export: type=transactions|alerts|incidents|watchlists"""
    kind = (request.args.get('type') or 'transactions').lower()
    days = min(int(request.args.get('days', 30)), 365)
    since = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    sb = get_service_supabase()

    output = io.StringIO()
    writer = csv.writer(output)

    if kind == 'alerts':
        rows = sb.table('alerts').select('*').gte('created_at', since).order('created_at', desc=True).limit(5000).execute().data or []
        writer.writerow(['id', 'title', 'alert_type', 'severity', 'status', 'created_at', 'description'])
        for r in rows:
            writer.writerow([r.get('id'), r.get('title'), r.get('alert_type'), r.get('severity'),
                             r.get('status'), r.get('created_at'), (r.get('description') or '')[:500]])
    elif kind == 'incidents':
        rows = sb.table('incidents').select('*').gte('created_at', since).order('created_at', desc=True).limit(5000).execute().data or []
        writer.writerow(['id', 'title', 'incident_type', 'severity', 'status', 'risk_level', 'risk_score', 'created_at'])
        for r in rows:
            writer.writerow([r.get('id'), r.get('title'), r.get('incident_type'), r.get('severity'),
                             r.get('status'), r.get('risk_level'), r.get('risk_score'), r.get('created_at')])
    elif kind == 'watchlists':
        rows = sb.table('watchlists').select('*').order('created_at', desc=True).limit(5000).execute().data or []
        writer.writerow(['id', 'entity_type', 'value', 'label', 'severity', 'is_active', 'notes', 'created_at'])
        for r in rows:
            writer.writerow([r.get('id'), r.get('entity_type'), r.get('value'), r.get('label'),
                             r.get('severity'), r.get('is_active'), r.get('notes'), r.get('created_at')])
    else:
        rows = sb.table('transactions').select('*').gte('transaction_time', since).order('transaction_time', desc=True).limit(5000).execute().data or []
        writer.writerow(['id', 'account_number', 'amount', 'currency', 'transaction_type', 'device_id',
                         'ip_address', 'location', 'is_suspicious', 'status', 'transaction_time', 'suspicion_reasons'])
        for r in rows:
            reasons = '; '.join(r.get('suspicion_reasons') or [])
            writer.writerow([r.get('id'), r.get('account_number'), r.get('amount'), r.get('currency'),
                             r.get('transaction_type'), r.get('device_id'), r.get('ip_address'), r.get('location'),
                             r.get('is_suspicious'), r.get('status'), r.get('transaction_time'), reasons[:500]])

    output.seek(0)
    filename = f'ecs_{kind}_{days}d.csv'
    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': f'attachment; filename={filename}'}
    )
