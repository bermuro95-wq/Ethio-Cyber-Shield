"""
Live Threat Detection API
Real-time monitoring endpoints for graphs and live SOC view.
Pure Python — no AI/ML.
"""
from flask import Blueprint, request, jsonify, Response, stream_with_context, g
from app.services.auth_service import login_required
from app.services.db import get_service_supabase
from datetime import datetime, timedelta, timezone
from dateutil import parser
import json
import time

live_bp = Blueprint('live', __name__)


def _parse_time(val):
    if not val:
        return None
    try:
        t = parser.isoparse(val)
        if t.tzinfo is None:
            t = t.replace(tzinfo=timezone.utc)
        return t
    except Exception:
        return None


@live_bp.route('/summary', methods=['GET'])
@login_required
def live_summary():
    """
    Current threat posture — numbers for live cards.
    Query: minutes (default 60) — lookback window.
    """
    minutes = min(int(request.args.get('minutes', 60)), 1440)
    since = (datetime.now(timezone.utc) - timedelta(minutes=minutes)).isoformat()
    sb = get_service_supabase()

    tx_res = sb.table('transactions').select(
        'id, amount, is_suspicious, transaction_time, status, account_number'
    ).gte('transaction_time', since).order('transaction_time', desc=True).limit(500).execute()
    txs = tx_res.data or []

    alerts_res = sb.table('alerts').select(
        'id, title, severity, status, alert_type, created_at, related_transaction_id'
    ).gte('created_at', since).order('created_at', desc=True).limit(100).execute()
    alerts = alerts_res.data or []

    open_alerts = [a for a in alerts if a.get('status') == 'open']
    suspicious_txs = [t for t in txs if t.get('is_suspicious')]
    total_amount = sum(float(t.get('amount') or 0) for t in txs)
    suspicious_amount = sum(float(t.get('amount') or 0) for t in suspicious_txs)

    critical_open = sum(1 for a in open_alerts if a.get('severity') == 'critical')
    high_open = sum(1 for a in open_alerts if a.get('severity') == 'high')

    return jsonify({
        'window_minutes': minutes,
        'transactions': {
            'total': len(txs),
            'suspicious': len(suspicious_txs),
            'total_amount_etb': round(total_amount, 2),
            'suspicious_amount_etb': round(suspicious_amount, 2),
        },
        'alerts': {
            'total': len(alerts),
            'open': len(open_alerts),
            'critical_open': critical_open,
            'high_open': high_open,
        },
        'threat_level': (
            'critical' if critical_open > 0 else
            'high' if high_open > 0 or len(suspicious_txs) >= 3 else
            'medium' if len(suspicious_txs) >= 1 else
            'low'
        ),
        'generated_at': datetime.now(timezone.utc).isoformat()
    })


@live_bp.route('/timeline', methods=['GET'])
@login_required
def live_timeline():
    """
    Time-bucketed series for live graphs.
    Query:
      minutes  — lookback (default 60)
      bucket   — minutes per bar (default 5)
    Returns buckets with transaction counts, suspicious counts, alert counts, amounts.
    """
    minutes = min(int(request.args.get('minutes', 60)), 1440)
    bucket_min = max(1, min(int(request.args.get('bucket', 5)), 60))
    now = datetime.now(timezone.utc)
    since = now - timedelta(minutes=minutes)
    sb = get_service_supabase()

    tx_res = sb.table('transactions').select(
        'id, amount, is_suspicious, transaction_time'
    ).gte('transaction_time', since.isoformat()).limit(2000).execute()
    txs = tx_res.data or []

    alert_res = sb.table('alerts').select(
        'id, severity, created_at'
    ).gte('created_at', since.isoformat()).limit(1000).execute()
    alerts = alert_res.data or []

    # Build empty buckets from oldest to newest
    num_buckets = max(1, minutes // bucket_min)
    buckets = []
    for i in range(num_buckets):
        start = since + timedelta(minutes=i * bucket_min)
        end = start + timedelta(minutes=bucket_min)
        buckets.append({
            'start': start.isoformat(),
            'end': end.isoformat(),
            'label': start.strftime('%H:%M'),
            'tx_count': 0,
            'suspicious_count': 0,
            'alert_count': 0,
            'critical_alert_count': 0,
            'amount_etb': 0.0,
            'suspicious_amount_etb': 0.0,
        })

    def bucket_index(ts):
        t = _parse_time(ts)
        if not t:
            return None
        delta = (t - since).total_seconds() / 60.0
        idx = int(delta // bucket_min)
        if 0 <= idx < num_buckets:
            return idx
        return None

    for t in txs:
        idx = bucket_index(t.get('transaction_time'))
        if idx is None:
            continue
        amt = float(t.get('amount') or 0)
        buckets[idx]['tx_count'] += 1
        buckets[idx]['amount_etb'] += amt
        if t.get('is_suspicious'):
            buckets[idx]['suspicious_count'] += 1
            buckets[idx]['suspicious_amount_etb'] += amt

    for a in alerts:
        idx = bucket_index(a.get('created_at'))
        if idx is None:
            continue
        buckets[idx]['alert_count'] += 1
        if a.get('severity') == 'critical':
            buckets[idx]['critical_alert_count'] += 1

    for b in buckets:
        b['amount_etb'] = round(b['amount_etb'], 2)
        b['suspicious_amount_etb'] = round(b['suspicious_amount_etb'], 2)

    return jsonify({
        'window_minutes': minutes,
        'bucket_minutes': bucket_min,
        'buckets': buckets,
        'generated_at': now.isoformat()
    })


@live_bp.route('/recent-events', methods=['GET'])
@login_required
def recent_events():
    """
    Unified live event feed: recent suspicious transactions + open alerts.
    Used by the live threats page list.
    """
    limit = min(int(request.args.get('limit', 30)), 100)
    minutes = min(int(request.args.get('minutes', 120)), 1440)
    since = (datetime.now(timezone.utc) - timedelta(minutes=minutes)).isoformat()
    sb = get_service_supabase()

    events = []

    tx_res = sb.table('transactions').select('*')\
        .eq('is_suspicious', True)\
        .gte('transaction_time', since)\
        .order('transaction_time', desc=True).limit(limit).execute()
    for t in (tx_res.data or []):
        events.append({
            'kind': 'transaction',
            'id': t['id'],
            'time': t.get('transaction_time'),
            'title': f"Suspicious {t.get('transaction_type', 'tx')} — {float(t.get('amount') or 0):,.0f} ETB",
            'detail': '; '.join(t.get('suspicion_reasons') or []) or 'Flagged by rules',
            'severity': 'high',
            'account': t.get('account_number'),
            'device_id': t.get('device_id'),
            'ip_address': t.get('ip_address'),
            'status': t.get('status'),
        })

    alert_res = sb.table('alerts').select('*')\
        .gte('created_at', since)\
        .order('created_at', desc=True).limit(limit).execute()
    for a in (alert_res.data or []):
        events.append({
            'kind': 'alert',
            'id': a['id'],
            'time': a.get('created_at'),
            'title': a.get('title'),
            'detail': a.get('description') or '',
            'severity': a.get('severity') or 'medium',
            'status': a.get('status'),
            'alert_type': a.get('alert_type'),
            'related_transaction_id': a.get('related_transaction_id'),
        })

    events.sort(key=lambda e: e.get('time') or '', reverse=True)
    events = events[:limit]

    return jsonify({
        'events': events,
        'count': len(events),
        'generated_at': datetime.now(timezone.utc).isoformat()
    })


@live_bp.route('/stream', methods=['GET'])
def live_stream():
    """
    Server-Sent Events stream of new alerts.
    Token via query ?token=JWT because EventSource cannot set Authorization header.
    Polls Supabase every few seconds and pushes new open alerts.
    """
    # Lightweight auth via query token
    token = request.args.get('token') or ''
    if not token:
        return jsonify({'error': 'token required'}), 401

    from app.services.auth_service import decode_token
    try:
        payload = decode_token(token)
        if not payload:
            return jsonify({'error': 'invalid token'}), 401
    except Exception:
        return jsonify({'error': 'invalid token'}), 401

    last_seen = request.args.get('since')  # ISO timestamp
    if not last_seen:
        last_seen = (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat()

    def generate():
        nonlocal last_seen
        # Heartbeat + poll loop (client reconnects if needed)
        for _ in range(120):  # ~4 minutes of connection then client reconnects
            try:
                sb = get_service_supabase()
                res = sb.table('alerts').select(
                    'id, title, description, severity, status, alert_type, created_at, related_transaction_id'
                ).gt('created_at', last_seen).order('created_at', asc=True).limit(20).execute()
                rows = res.data or []
                for row in rows:
                    last_seen = row['created_at']
                    data = json.dumps(row)
                    yield f"event: alert\ndata: {data}\n\n"
                # heartbeat so proxies don't kill the connection
                yield f"event: ping\ndata: {json.dumps({'ts': datetime.now(timezone.utc).isoformat()})}\n\n"
            except Exception as e:
                yield f"event: error\ndata: {json.dumps({'error': str(e)})}\n\n"
            time.sleep(2)

    return Response(
        stream_with_context(generate()),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'X-Accel-Buffering': 'no',
            'Connection': 'keep-alive',
        }
    )
