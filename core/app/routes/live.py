"""
Live Threat Detection API
Real-time monitoring endpoints for graphs and live SOC view.
Pure Python — no AI/ML.
"""
from flask import Blueprint, request, jsonify, Response, stream_with_context, g
from app.services.auth_service import login_required, role_required
from app.services.db import get_service_supabase
from app.services.audit_service import log_action
from app.services.target_system_service import get_target_by_id, list_active_targets, run_target_scenario
from app.services.poller_service import poll_target_once
from datetime import datetime, timedelta, timezone
from dateutil import parser
import json
import time
import logging

logger = logging.getLogger(__name__)
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

    contained_count = 0
    try:
        act_res = sb.table('response_actions').select('id', count='exact').eq('status', 'confirmed').execute()
        contained_count = act_res.count or len(act_res.data or [])
    except Exception:
        pass

    blocked_ips_count = 0
    try:
        ind_res = sb.table('indicators').select('id', count='exact').eq('indicator_type', 'ip').execute()
        blocked_ips_count = ind_res.count or len(ind_res.data or [])
    except Exception:
        pass

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
        'contained_actions': contained_count,
        'blocked_ips': blocked_ips_count,
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
    events = []

    try:
        sb = get_service_supabase()

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
    except Exception as e:
        logger.warning(f"Error fetching recent live events: {e}")

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
        # Default to now - 15 seconds to catch immediately preceding alert
        last_seen = (datetime.now(timezone.utc) - timedelta(seconds=15)).isoformat()

    def generate():
        nonlocal last_seen
        # Heartbeat + poll loop (client reconnects cleanly if needed)
        for _ in range(30):  # ~90 seconds lifecycle per connection
            try:
                sb = get_service_supabase()
                res = sb.table('alerts').select(
                    'id, title, description, severity, status, alert_type, created_at, related_transaction_id'
                ).gt('created_at', last_seen).order('created_at', desc=False).limit(20).execute()
                rows = res.data or []
                for row in rows:
                    last_seen = row['created_at']
                    try:
                        from app.services.enrichment_service import get_alert_dossier, synthesize_attack_dossier
                        dossier = get_alert_dossier(row.get('id')) or synthesize_attack_dossier(row)
                        row['dossier'] = dossier
                        row['source_ip'] = dossier['geo']['ip']
                        row['risk_score'] = dossier['risk_score']
                        row['device_details'] = dossier['device']
                        row['geo_details'] = dossier['geo']
                        row['target_details'] = dossier['target']
                    except Exception:
                        pass
                    data = json.dumps(row)
                    yield f"event: alert\ndata: {data}\n\n"
                # Heartbeat ping
                yield f"event: ping\ndata: {json.dumps({'ts': datetime.now(timezone.utc).isoformat()})}\n\n"
            except (GeneratorExit, BrokenPipeError, ConnectionResetError):
                # Client closed tab, refreshed, or navigated away — exit immediately to free thread
                break
            except Exception as e:
                logger.debug(f"SSE stream poll notice: {e}")
                try:
                    yield f"event: ping\ndata: {json.dumps({'ts': datetime.now(timezone.utc).isoformat()})}\n\n"
                except Exception:
                    break
            time.sleep(3)

    return Response(
        stream_with_context(generate()),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'X-Accel-Buffering': 'no',
            'Connection': 'keep-alive',
        }
    )


@live_bp.route('/scenarios', methods=['GET'])
@login_required
def list_scenarios():
    """
    Returns available lab attack scenarios and demonstration scenarios for analysts and judges.
    """
    return jsonify({
        'scenarios': [
            {
                'id': 'account_takeover',
                'name': 'Account Takeover Chain (ATO-001)',
                'severity': 'critical',
                'description': 'Simulates password guessing bursts, authentication from unrecognized hardware, mule beneficiary addition, and high-value 180,000 ETB transfer held in review.',
                'expected_detection': 'ATO-001 Correlation (Risk 100/100, Critical Alert, Auto Incident, Tri-Fold Containment: Freeze Transfer, Revoke Session, Block IP)'
            },
            {
                'id': 'credential_stuffing',
                'name': 'Multi-Account Credential Stuffing (AUTH-002)',
                'severity': 'high',
                'description': 'Rapid succession of failed logins from a single IP address targeting distinct accounts within 60 seconds.',
                'expected_detection': 'AUTH-002 Signature (Risk 75/100, High Alert, Automated IP Block)'
            },
            {
                'id': 'rapid_transfers',
                'name': 'Rapid Succession Fraud (TX-001 & TX-003)',
                'severity': 'high',
                'description': 'High-value transfers exceeding 100,000 ETB occurring during Addis Ababa local night hours (00:00 - 05:00).',
                'expected_detection': 'TX-001 & TX-003 (Risk 70/100, High Alert, Automated Transfer Freeze)'
            },
            {
                'id': 'admin_probe',
                'name': 'Unauthorized Privilege Abuse (PRIV-001)',
                'severity': 'high',
                'description': 'Customer identity attempting administrative endpoint traversal and privilege escalation.',
                'expected_detection': 'PRIV-001 (Risk 65/100, High Alert, Session Revocation / Step-up challenge)'
            },
            {
                'id': 'normal_traffic',
                'name': 'Legitimate Banking Baseline',
                'severity': 'low',
                'description': 'Standard daytime banking activities: legitimate user logins, balance checks, and compliant merchant transfers.',
                'expected_detection': 'Risk Score 0/100, Clean Baseline, No Alerts'
            }
        ]
    }), 200


@live_bp.route('/trigger-scenario', methods=['POST'])
@role_required('admin', 'analyst')
def trigger_lab_scenario():
    """
    Remotely triggers an attack scenario on the connected target system and syncs telemetry.
    """
    data = request.get_json() or {}
    target_id = data.get('target_id')
    scenario = data.get('scenario') or 'account_takeover'
    target_account = data.get('target_account')
    simulated_ip = data.get('simulated_ip')
    sync_immediately = data.get('sync_immediately', True)

    target = None
    if target_id:
        target = get_target_by_id(target_id)
    else:
        # Fallback to the first active target system
        active_targets = list_active_targets()
        if active_targets:
            target = active_targets[0]
            target_id = target.get('id')

    if not target:
        return jsonify({'error': 'No active target system found. Please configure a target in Settings.'}), 400

    try:
        resp_json, status_code = run_target_scenario(
            scenario_name=scenario,
            target_account=target_account,
            base_url=target.get('base_url'),
            key_id=target.get('key_id'),
            secret=target.get('secret_key'),
            simulated_ip=simulated_ip
        )

        # Audit
        try:
            log_action(g.user['id'], 'lab_scenario_triggered', 'target_system', target_id, {
                'scenario': scenario, 'status_code': status_code
            })
        except Exception:
            pass

        # Trigger immediate pull sync to bring generated telemetry into ECS immediately
        sync_result = None
        if sync_immediately and target_id:
            try:
                sync_result = poll_target_once(target_id)
            except Exception as sync_err:
                logger.warning(f"Immediate sync after scenario failed: {sync_err}")

        return jsonify({
            'status': 'executed',
            'scenario': scenario,
            'target_name': target.get('name'),
            'target_response': resp_json,
            'sync_result': sync_result,
            'status_code': status_code
        }), 200 if status_code in (200, 201) else status_code

    except Exception as e:
        logger.error(f"Failed to execute lab scenario {scenario}: {e}")
        return jsonify({'error': f"Failed to execute scenario on target: {str(e)}"}), 502


@live_bp.route('/stream-events', methods=['GET'])
@login_required
def stream_events():
    """
    Returns latest canonical security_events for real-time threat streaming tables.
    """
    limit = min(int(request.args.get('limit', 50)), 200)
    target_id = request.args.get('target_id')
    event_type = request.args.get('event_type')

    sb = get_service_supabase()
    query = sb.table('security_events').select('*').order('occurred_at', desc=True).limit(limit)

    if target_id:
        query = query.eq('target_system_id', target_id)
    if event_type:
        query = query.eq('event_type', event_type)

    try:
        res = query.execute()
        return jsonify(res.data or []), 200
    except Exception as e:
        logger.error(f"Error fetching stream events: {e}")
        return jsonify([]), 200

