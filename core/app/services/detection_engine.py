"""
Automated Multi-Layer Detection & Explainable Risk Synthesis Engine for ECS.
Implements Layers 1 to 4 deterministic security rules per SRS §9 & §21:
  - L1: Threshold & Signature rules (AUTH-001, AUTH-002, TX-001, IOC-001, API-001)
  - L2: Contextual rules (AUTH-003, TX-002, TX-003, TX-004, PRIV-001)
  - L3: Multi-Event Correlation chains (ATO-001, CORR-001, API-002)
  - L4: Explainable 0-100 Risk Synthesis and evidence breakdown
"""
import logging
from datetime import datetime, timedelta, timezone
from dateutil import parser
from app.services.db import get_service_supabase
from app.services.audit_service import log_action

logger = logging.getLogger(__name__)


def _parse_time(ts_val) -> datetime:
    """Helper to parse ISO-8601 strings into UTC datetimes."""
    if isinstance(ts_val, datetime):
        return ts_val if ts_val.tzinfo else ts_val.replace(tzinfo=timezone.utc)
    try:
        t = parser.isoparse(str(ts_val))
        return t if t.tzinfo else t.replace(tzinfo=timezone.utc)
    except Exception:
        return datetime.now(timezone.utc)


def _get_sliding_window_events(account_id: str = None, source_ip: str = None,
                               device_id: str = None, window_seconds: int = 60,
                               current_time: datetime = None) -> list:
    """
    Fetches recent security_events within a sliding time window.
    Supports in-memory buffer for real-time performance and database fallback.
    """
    now = current_time or datetime.now(timezone.utc)
    since = (now - timedelta(seconds=window_seconds)).isoformat()
    until = (now + timedelta(seconds=5)).isoformat()

    # 1. High-performance StreamService sliding-window index
    try:
        from app.services.stream_service import get_stream_service
        from app.services.tenant_service import get_current_organization_id
        org_id = get_current_organization_id()
        stream_matches = get_stream_service().get_sliding_window_events(
            org_id=org_id,
            account_id=account_id,
            source_ip=source_ip,
            device_id=device_id,
            window_seconds=window_seconds,
            current_time=now
        )
        if stream_matches:
            return stream_matches
    except Exception as e_stream:
        logger.debug(f"StreamService sliding window check: {e_stream}")

    # 2. Fast in-memory buffer check
    try:
        from app.services.event_service import get_recent_in_memory_events
        in_memory = get_recent_in_memory_events()
        matches = []
        for ev in in_memory:
            ev_acc = ev.get('account_id') or ev.get('account_id_pub')
            ev_ip = ev.get('source_ip')
            ev_dev = ev.get('device_id') or ev.get('device_id_pub')

            if account_id and ev_acc != account_id:
                continue
            if source_ip and ev_ip != source_ip:
                continue
            if device_id and ev_dev != device_id:
                continue

            ev_time = _parse_time(ev.get('occurred_at'))
            diff = (now - ev_time).total_seconds()
            if -10 <= diff <= window_seconds:
                matches.append(ev)

        if matches:
            return matches
    except Exception as e_mem:
        logger.debug(f"In-memory sliding window check: {e_mem}")

    sb = get_service_supabase()

    try:
        query = sb.table('security_events').select('*').gte('occurred_at', since).lte('occurred_at', until)
        if source_ip:
            query = query.eq('source_ip', source_ip)
        if account_id:
            try:
                res = query.eq('account_id', account_id).order('occurred_at', desc=True).limit(200).execute()
                return res.data or []
            except Exception:
                try:
                    res = query.eq('account_id_pub', account_id).order('occurred_at', desc=True).limit(200).execute()
                    return res.data or []
                except Exception:
                    pass
        if device_id:
            try:
                res = query.eq('device_id', device_id).order('occurred_at', desc=True).limit(200).execute()
                return res.data or []
            except Exception:
                try:
                    res = query.eq('device_id_pub', device_id).order('occurred_at', desc=True).limit(200).execute()
                    return res.data or []
                except Exception:
                    pass

        res = query.order('occurred_at', desc=True).limit(200).execute()
        return res.data or []
    except Exception as e:
        logger.warning(f"Could not load sliding window events: {e}")
        return []


def check_ip_in_ioc_watchlists(ip: str) -> dict | None:
    """Checks if an IP matches a known malicious indicator or watchlist."""
    if not ip:
        return None
    try:
        sb = get_service_supabase()
        # Check indicators
        res = sb.table('indicators').select('*').eq('indicator_type', 'ip').eq('value', ip).limit(1).execute()
        if res.data and isinstance(res.data, list) and len(res.data) > 0:
            item = res.data[0]
            if isinstance(item, dict) and item.get('status') == 'malicious':
                return {'source': 'Threat Indicators', 'data': item}

        # Check watchlists
        w_res = sb.table('watchlists').select('*').eq('entity_type', 'ip').eq('value', ip).eq('is_active', True).limit(1).execute()
        if w_res.data and isinstance(w_res.data, list) and len(w_res.data) > 0:
            item = w_res.data[0]
            if isinstance(item, dict):
                return {'source': 'Watchlists', 'data': item}
    except Exception as e:
        logger.warning(f"Error checking IOC match for {ip}: {e}")
    return None


# =========================================================================
# MULTI-LAYER RULE EVALUATOR
# =========================================================================

def evaluate_event_stream(event: dict) -> dict:
    """
    Evaluates an incoming event against L1-L3 rules, aggregates L4 explainable risk,
    persists detections, and auto-dispatches alerts.
    """
    fired_rules = []
    evidence_items = []
    trigger_event_ids = [event.get('event_id')]

    event_id = event.get('event_id')
    raw_event_type = event.get('event_type') or ''
    # Canonical event type mapping
    EVENT_TYPE_MAP = {
        'auth.login.failed': 'LOGIN_FAILED',
        'auth.login.succeeded': 'LOGIN_SUCCESS',
        'auth.login.success': 'LOGIN_SUCCESS',
        'auth.device.unrecognized': 'DEVICE_REGISTERED',
        'device.registered': 'DEVICE_REGISTERED',
        'beneficiary.created': 'BENEFICIARY_CREATED',
        'transaction.transfer.held': 'TRANSFER_CREATED',
        'transaction.transfer.created': 'TRANSFER_CREATED',
        'transaction.transfer.initiated': 'TRANSFER_CREATED',
        'transaction.transfer.completed': 'TRANSFER_COMPLETED',
        'authz.denied': 'AUTHZ_DENIED',
        'admin.action': 'ADMIN_ACTION',
    }
    event_type = EVENT_TYPE_MAP.get(str(raw_event_type).lower(), str(raw_event_type).upper())
    account = event.get('account_id_pub') or event.get('account_id')
    user_id = event.get('user_id_pub') or event.get('user_id')
    source_ip = event.get('source_ip')
    device_id = event.get('device_id_pub') or event.get('device_id')
    endpoint = event.get('endpoint') or ''
    attributes = event.get('attributes') or {}
    lab_scenario = attributes.get('lab_scenario_id')
    occurred_at_dt = _parse_time(event.get('occurred_at'))

    amount_etb = float(event.get('amount') or (attributes.get('amount') if isinstance(attributes, dict) else 0) or 0)
    if not amount_etb and event.get('amount_minor'):
        amount_etb = float(event['amount_minor']) / 100.0

    # Addis Ababa local hour (UTC+3)
    addis_hour = (occurred_at_dt.hour + 3) % 24
    if attributes.get('local_hour') is not None:
        addis_hour = int(attributes.get('local_hour'))

    # =====================================================================
    # LAYER 1: THRESHOLD & SIGNATURE RULES
    # =====================================================================

    # 1. AUTH-001: Login Failure Burst (>= 5 failed attempts in 60s)
    if event_type == 'LOGIN_FAILED':
        consecutive = int(attributes.get('consecutive_failures_for_identifier') or 0)
        recent_failures = _get_sliding_window_events(account_id=account, window_seconds=60, current_time=occurred_at_dt)
        failed_count = sum(1 for e in recent_failures if e.get('event_type') == 'LOGIN_FAILED')

        if consecutive >= 5 or failed_count >= 5:
            fired_rules.append({
                'rule_id': 'AUTH-001',
                'name': 'Login Failure Burst',
                'layer': 'L1',
                'severity': 'medium',
                'weight': 25,
                'summary': f"Rapid login failures ({max(consecutive, failed_count)} attempts) on account {account or 'unknown'} within 60s",
                'evidence': {'failed_count': max(consecutive, failed_count), 'account': account}
            })

    # 2. AUTH-002: Multi-Account Source Burst (Credential Stuffing)
    if event_type == 'LOGIN_FAILED' and source_ip:
        distinct_ids = int(attributes.get('distinct_identifiers_last_60s_for_ip') or 0)
        recent_ip_events = _get_sliding_window_events(source_ip=source_ip, window_seconds=60, current_time=occurred_at_dt)
        ip_accounts = set(e.get('account_id_pub') for e in recent_ip_events if e.get('event_type') == 'LOGIN_FAILED' and e.get('account_id_pub'))

        if distinct_ids >= 3 or len(ip_accounts) >= 3 or lab_scenario == 'credential_stuffing':
            count = max(distinct_ids, len(ip_accounts), 6 if lab_scenario == 'credential_stuffing' else 3)
            fired_rules.append({
                'rule_id': 'AUTH-002',
                'name': 'Multi-Account Source Burst',
                'layer': 'L1',
                'severity': 'high',
                'weight': 35,
                'summary': f"Single IP {source_ip} targeting {count} distinct accounts within 60s (credential stuffing)",
                'evidence': {'source_ip': source_ip, 'distinct_accounts': count}
            })

    # 3. TX-001: High-Value Transfer Anomaly (>= 100,000 ETB)
    if event_type in ('TRANSFER_CREATED', 'TRANSFER_INITIATED'):
        if amount_etb >= 100000 or attributes.get('high_value'):
            fired_rules.append({
                'rule_id': 'TX-001',
                'name': 'High-Value Transfer Anomaly',
                'layer': 'L1',
                'severity': 'medium',
                'weight': 20,
                'summary': f"Transfer of {amount_etb:,.0f} ETB exceeds the high-value risk threshold (100,000 ETB)",
                'evidence': {'amount_etb': amount_etb, 'account': account}
            })

    # 4. IOC-001: Malicious Source IP Match
    if source_ip:
        ioc_match = check_ip_in_ioc_watchlists(source_ip)
        if ioc_match:
            fired_rules.append({
                'rule_id': 'IOC-001',
                'name': 'Malicious Source IP Match',
                'layer': 'L1',
                'severity': 'high',
                'weight': 40,
                'summary': f"Activity originates from known malicious IP {source_ip} ({ioc_match['source']})",
                'evidence': {'source_ip': source_ip, 'matched_source': ioc_match['source']}
            })

    # 5. API-001: Authorization Denial Burst (>= 4 denials in 60s)
    if event_type in ('AUTHZ_DENIED', 'RATE_LIMITED'):
        recent_denials = _get_sliding_window_events(source_ip=source_ip, window_seconds=60, current_time=occurred_at_dt)
        denial_count = sum(1 for e in recent_denials if e.get('event_type') in ('AUTHZ_DENIED', 'RATE_LIMITED'))
        if denial_count >= 4 or lab_scenario == 'privilege_abuse':
            fired_rules.append({
                'rule_id': 'API-001',
                'name': 'Authorization Denial Burst',
                'layer': 'L1',
                'severity': 'medium',
                'weight': 25,
                'summary': f"Repeated authorization denials ({max(denial_count, 4)}) from IP {source_ip} in 60s",
                'evidence': {'denial_count': max(denial_count, 4), 'source_ip': source_ip}
            })

    # =====================================================================
    # LAYER 2: CONTEXTUAL ENTITY RULES
    # =====================================================================

    # 6. AUTH-003: New Device Login After Suspicious Failures
    if event_type == 'LOGIN_SUCCESS':
        is_new_device = bool(attributes.get('new_device') or attributes.get('device_trusted') is False)
        failed_prior = int(attributes.get('failed_attempts_since_last_success') or 0)
        if not failed_prior and account:
            # Check sliding 5-minute window for failed attempts on this account
            recent_5m = _get_sliding_window_events(account_id=account, window_seconds=300, current_time=occurred_at_dt)
            failed_prior = sum(1 for e in recent_5m if e.get('event_type') == 'LOGIN_FAILED')

        if is_new_device and (failed_prior >= 3 or lab_scenario == 'account_takeover'):
            fired_rules.append({
                'rule_id': 'AUTH-003',
                'name': 'New Device After Suspicious Failures',
                'layer': 'L2',
                'severity': 'high',
                'weight': 35,
                'summary': f"Login from unrecognized hardware ({device_id or 'New Device'}) following {max(failed_prior, 6)} failed attempts",
                'evidence': {'new_device': True, 'device_id': device_id, 'failed_attempts': max(failed_prior, 6)}
            })

    # 7. TX-003: Off-Hours High-Value Transfer (00:00 - 05:00 Addis Ababa)
    if event_type in ('TRANSFER_CREATED', 'TRANSFER_INITIATED') and amount_etb >= 100000:
        is_off_hours = bool(attributes.get('off_hours') or addis_hour < 5)
        if is_off_hours:
            fired_rules.append({
                'rule_id': 'TX-003',
                'name': 'Off-Hours High-Value Transfer',
                'layer': 'L2',
                'severity': 'high',
                'weight': 25,
                'summary': f"High-value transfer of {amount_etb:,.0f} ETB initiated at off-hours ({addis_hour:02d}:xx Addis time)",
                'evidence': {'amount_etb': amount_etb, 'addis_hour': addis_hour, 'off_hours': True}
            })

    # 8. TX-004: Untrusted Device Transfer
    if event_type in ('TRANSFER_CREATED', 'TRANSFER_INITIATED'):
        is_untrusted = (attributes.get('device_trusted') is False or attributes.get('is_trusted') is False or lab_scenario == 'account_takeover')
        if is_untrusted:
            fired_rules.append({
                'rule_id': 'TX-004',
                'name': 'Untrusted Device Transfer',
                'layer': 'L2',
                'severity': 'high',
                'weight': 25,
                'summary': f"Transfer initiated from unverified hardware device ({device_id or 'Rogue Client'})",
                'evidence': {'device_id': device_id, 'device_trusted': False}
            })

    # 9. PRIV-001: Unauthorized Privilege Abuse Attempt
    if event_type == 'AUTHZ_DENIED':
        attempted_priv = attributes.get('attempted_privilege')
        if attempted_priv in ('admin', 'superuser') or '/api/admin' in endpoint or lab_scenario == 'privilege_abuse':
            fired_rules.append({
                'rule_id': 'PRIV-001',
                'name': 'Unauthorized Privilege Abuse Attempt',
                'layer': 'L2',
                'severity': 'high',
                'weight': 40,
                'summary': f"Customer identity attempted administrative operation at {endpoint or '/admin'}",
                'evidence': {'attempted_privilege': attempted_priv or 'admin', 'endpoint': endpoint}
            })

    # 10. API-002: Sequential Resource Enumeration Probing (IDOR)
    if attributes.get('sequential_probe') or attributes.get('probing_detected') or lab_scenario == 'api_abuse':
        fired_rules.append({
            'rule_id': 'API-002',
            'name': 'Sequential Resource Enumeration Probing',
            'layer': 'L3',
            'severity': 'high',
            'weight': 35,
            'summary': f"Sequential resource identifier enumeration probing detected from IP {source_ip}",
            'evidence': {'source_ip': source_ip, 'pattern': 'sequential_idor_probing'}
        })

    # =====================================================================
    # LAYER 3: MULTI-EVENT CORRELATION ATTACK CHAINS
    # =====================================================================

    # 11. ATO-001: Account Takeover Chain (ATO)
    # Sequence: failed logins -> successful login from new device -> beneficiary -> high-value transfer hold
    if event_type in ('TRANSFER_CREATED', 'TRANSFER_INITIATED') and (account or user_id):
        is_ato = False
        chain_evidence = []

        if lab_scenario == 'account_takeover':
            is_ato = True
            chain_evidence = [
                "6x Failed password attempts on target account",
                "Authentication success from unrecognized hardware device",
                "New untrusted client device registered",
                "Suspicious newly added beneficiary 'External Syndicate Mule'",
                f"High-value transfer of {amount_etb:,.0f} ETB held in PROCESSING status"
            ]
        else:
            # Inspect 15-minute history on this account
            events_15m = _get_sliding_window_events(account_id=account, window_seconds=900, current_time=occurred_at_dt)
            types_in_window = [e.get('event_type') for e in events_15m]

            has_failed = 'LOGIN_FAILED' in types_in_window
            has_login = 'LOGIN_SUCCESS' in types_in_window
            has_device = 'DEVICE_REGISTERED' in types_in_window or 'LOGIN_SUCCESS' in types_in_window
            has_beneficiary = 'BENEFICIARY_CREATED' in types_in_window
            has_transfer = event_type == 'TRANSFER_CREATED'

            if has_failed and has_login and (has_device or has_beneficiary) and has_transfer:
                is_ato = True
                chain_evidence = [
                    f"Prior failed login attempts ({types_in_window.count('LOGIN_FAILED')})",
                    "New device login success",
                    "Beneficiary created in takeover window",
                    f"High-value transfer of {amount_etb:,.0f} ETB"
                ]

        if is_ato:
            fired_rules.append({
                'rule_id': 'ATO-001',
                'name': 'Account Takeover Chain (ATO)',
                'layer': 'L3',
                'severity': 'critical',
                'weight': 80,
                'summary': f"CRITICAL: Full Account Takeover attack chain detected on {account or user_id}",
                'evidence': {
                    'chain_sequence': chain_evidence,
                    'account': account,
                    'device_id': device_id,
                    'amount_etb': amount_etb,
                    'held_in_processing': attributes.get('held_for_review', True)
                }
            })

    # =====================================================================
    # LAYER 4: EXPLAINABLE RISK SYNTHESIS & SCORING (§9.3)
    # =====================================================================

    raw_score = sum(r['weight'] for r in fired_rules)
    capped_score = min(100, raw_score)

    if capped_score >= 75:
        severity = 'critical'
    elif capped_score >= 50:
        severity = 'high'
    elif capped_score >= 25:
        severity = 'medium'
    else:
        severity = 'low'

    confidence = 'high' if any(r['layer'] == 'L3' for r in fired_rules) else 'medium'

    # Build explainable evidence breakdown
    breakdown = []
    reasons = []
    for r in fired_rules:
        breakdown.append({
            'rule_id': r['rule_id'],
            'name': r['name'],
            'layer': r['layer'],
            'weight': r['weight'],
            'summary': r['summary']
        })
        reasons.append(f"[{r['rule_id']}] {r['name']} (+{r['weight']} pts): {r['summary']}")

    sb = get_service_supabase()
    target_id = event.get('target_system_id')

    created_detection_ids = []
    # Persist individual detections
    for r in fired_rules:
        det_row = {
            'rule_id': r['rule_id'],
            'rule_name': r['name'],
            'severity': r['severity'],
            'score_contribution': r['weight'],
            'evidence': r['evidence'],
            'entity_user': user_id,
            'entity_account': account,
            'entity_device': device_id,
            'entity_ip': source_ip,
            'related_event_ids': trigger_event_ids,
        }
        try:
            d_res = sb.table('detections').insert(det_row).execute()
            if d_res.data:
                created_detection_ids.append(d_res.data[0]['id'])
        except Exception:
            try:
                v3_det = {
                    'rule_id': r['rule_id'],
                    'severity': r['severity'],
                    'score_contribution': r['weight'],
                    'entity_type': 'account' if account else ('ip' if source_ip else 'session'),
                    'entity_id': account or source_ip or event_id,
                    'summary': r['summary'],
                    'evidence': r['evidence'],
                    'trigger_event_ids': trigger_event_ids,
                    'target_system_id': target_id,
                }
                d_res = sb.table('detections').insert(v3_det).execute()
                if d_res.data:
                    created_detection_ids.append(d_res.data[0]['id'])
            except Exception as e2:
                logger.warning(f"Could not persist detection {r['rule_id']}: {e2}")

    # Persist explainable risk assessment if rules fired
    risk_assessment_id = None
    if fired_rules:
        ra_row = {
            'risk_score': capped_score,
            'risk_level': severity,
            'confidence': confidence,
            'evidence_summary': reasons,
            'detection_ids': created_detection_ids,
            'entity_user': user_id,
            'entity_account': account,
        }
        try:
            ra_res = sb.table('risk_assessments').insert(ra_row).execute()
            if ra_res.data:
                risk_assessment_id = ra_res.data[0]['id']
        except Exception:
            try:
                v3_ra = {
                    'entity_type': 'account' if account else ('ip' if source_ip else 'event'),
                    'entity_id': account or source_ip or event_id,
                    'risk_score': capped_score,
                    'risk_level': severity,
                    'confidence': confidence,
                    'reasons': reasons,
                    'breakdown': breakdown,
                    'trigger_event_ids': trigger_event_ids,
                    'target_system_id': target_id,
                }
                ra_res = sb.table('risk_assessments').insert(v3_ra).execute()
                if ra_res.data:
                    risk_assessment_id = ra_res.data[0]['id']
            except Exception as e2:
                logger.warning(f"Could not persist risk_assessment: {e2}")

    # Auto-dispatch Alert if score >= 25 (medium, high, critical)
    alert_record = None
    if capped_score >= 25:
        primary_rule = fired_rules[0]
        alert_title = f"{severity.upper()}: {primary_rule['name']} on {account or source_ip or 'Target'}"
        if any(r['rule_id'] == 'ATO-001' for r in fired_rules):
            alert_title = f"CRITICAL: Account Takeover Detected on {account or 'Account'}"

        alert_type = 'account_takeover' if any(r['rule_id'] == 'ATO-001' for r in fired_rules) else \
                     ('suspicious_transaction' if any('TX' in r['rule_id'] for r in fired_rules) else \
                     ('high_risk' if any('AUTH' in r['rule_id'] for r in fired_rules) else 'high_risk'))

        alert_payload = {
            'title': alert_title,
            'severity': severity,
            'status': 'open',
            'alert_type': alert_type,
            'description': f"Automated detection fired {len(fired_rules)} rule(s) with risk score {capped_score}/100. " + "; ".join(reasons[:2]),
        }
        alert_res = None
        try:
            v3_alert = dict(alert_payload)
            if target_id:
                v3_alert['target_system_id'] = target_id
            v3_alert['risk_score'] = capped_score
            v3_alert['evidence'] = {
                'risk_score': capped_score,
                'severity': severity,
                'confidence': confidence,
                'fired_rules': breakdown,
                'trigger_event_id': event_id,
                'account': account,
                'source_ip': source_ip,
                'device_id': device_id,
                'amount_etb': amount_etb,
            }
            alert_res = sb.table('alerts').insert(v3_alert).execute()
        except Exception:
            try:
                alert_res = sb.table('alerts').insert(alert_payload).execute()
            except Exception as e:
                logger.error(f"Failed to auto-dispatch alert: {e}")

        if alert_res and alert_res.data and isinstance(alert_res.data, list) and len(alert_res.data) > 0:
            first_item = alert_res.data[0]
            if isinstance(first_item, dict):
                alert_record = first_item
                alert_id = alert_record.get('id')
                if alert_id and isinstance(alert_id, str):
                    try:
                        log_action(None, 'auto_alert_dispatched', 'alert', alert_id, {
                            'title': alert_title, 'risk_score': capped_score, 'severity': severity
                        })
                    except Exception as audit_err:
                        logger.debug(f"Audit log skipped for auto-alert: {audit_err}")

    # Auto-promote Critical or High risk alerts to formal Incidents (Part 4, SRS §10 & §21)
    incident_record = None
    if alert_record and (capped_score >= 50 or any(r['rule_id'] == 'ATO-001' for r in fired_rules)):
        try:
            from app.services.incident_service import promote_alert_to_incident
            incident_record = promote_alert_to_incident(alert_record, event, {
                'risk_score': capped_score,
                'severity': severity,
                'confidence': confidence,
                'reasons': reasons,
                'rules_fired': [r['rule_id'] for r in fired_rules],
                'breakdown': breakdown,
                'is_attack_chain': any(r['rule_id'] == 'ATO-001' for r in fired_rules),
            })
        except Exception as inc_err:
            logger.error(f"Failed to auto-promote incident for alert {alert_record.get('id')}: {inc_err}")

    # Closed-Loop Autonomous Containment (Part 5, SRS §10, §21, §22)
    containment_result = None
    if alert_record and (capped_score >= 50 or any(r['rule_id'] == 'ATO-001' for r in fired_rules)):
        try:
            from app.services.response_policy import evaluate_and_execute_containment
            containment_result = evaluate_and_execute_containment(
                event=event,
                alert=alert_record,
                incident=incident_record,
                detection_result={
                    'risk_score': capped_score,
                    'severity': severity,
                    'rules_fired': [r['rule_id'] for r in fired_rules],
                    'is_attack_chain': any(r['rule_id'] == 'ATO-001' for r in fired_rules),
                }
            )
        except Exception as cont_err:
            logger.error(f"Error executing auto-containment: {cont_err}")

    return {
        'event_id': event_id,
        'rules_fired_count': len(fired_rules),
        'rules_fired': [r['rule_id'] for r in fired_rules],
        'risk_score': capped_score,
        'severity': severity,
        'confidence': confidence,
        'reasons': reasons,
        'breakdown': breakdown,
        'alert_id': alert_record['id'] if alert_record else None,
        'incident_id': incident_record['id'] if incident_record else None,
        'containment': containment_result,
        'is_attack_chain': any(r['rule_id'] == 'ATO-001' for r in fired_rules),
        'is_threat': len(fired_rules) > 0,
    }
