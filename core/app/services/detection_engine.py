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
            ev_acc = ev.get('account_id') or ev.get('account_id_pub') or (ev.get('attributes') or {}).get('identifier') or ev.get('user_id') or ev.get('user_id_pub')
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
        # If in-memory buffer is active and holds recent telemetry, avoid slow network DB queries
        if len(in_memory) > 0:
            return []
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


_IOC_CACHE = {}
_IOC_CACHE_EXPIRY = {}

def check_ip_in_ioc_watchlists(ip: str) -> dict | None:
    """Checks if an IP matches a known malicious indicator or watchlist (cached 60s)."""
    if not ip:
        return None

    import time
    now_ts = time.time()
    if ip in _IOC_CACHE and now_ts < _IOC_CACHE_EXPIRY.get(ip, 0):
        return _IOC_CACHE[ip]

    matched_result = None
    try:
        sb = get_service_supabase()
        # Check indicators
        res = sb.table('indicators').select('*').eq('indicator_type', 'ip').eq('value', ip).limit(1).execute()
        if res.data and isinstance(res.data, list) and len(res.data) > 0:
            item = res.data[0]
            if isinstance(item, dict) and item.get('status') == 'malicious':
                matched_result = {'source': 'Threat Indicators', 'data': item}

        if not matched_result:
            # Check watchlists
            w_res = sb.table('watchlists').select('*').eq('entity_type', 'ip').eq('value', ip).eq('is_active', True).limit(1).execute()
            if w_res.data and isinstance(w_res.data, list) and len(w_res.data) > 0:
                item = w_res.data[0]
                if isinstance(item, dict):
                    matched_result = {'source': 'Watchlists', 'data': item}
    except Exception as e:
        logger.warning(f"Error checking IOC match for {ip}: {e}")

    _IOC_CACHE[ip] = matched_result
    _IOC_CACHE_EXPIRY[ip] = now_ts + 60
    return matched_result


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

    amount_etb = float(event.get('amount') or event.get('amount_etb') or (attributes.get('amount') if isinstance(attributes, dict) else 0) or (attributes.get('amount_etb') if isinstance(attributes, dict) else 0) or 0)
    if not amount_etb and event.get('amount_minor'):
        amount_etb = float(event['amount_minor']) / 100.0

    # Addis Ababa local hour (UTC+3)
    addis_hour = (occurred_at_dt.hour + 3) % 24
    if attributes.get('local_hour') is not None:
        addis_hour = int(attributes.get('local_hour'))

    # =====================================================================
    # LAYERS 1-3: DECLARATIVE RULES-AS-DATA EVALUATION (Phase 3.1)
    # Evaluates Sigma-inspired declarative rules with tenant overrides & lifecycle states
    # =====================================================================
    try:
        from app.services.rule_engine_service import get_rule_engine
        engine = get_rule_engine()
        org_id = event.get('organization_id')
        fired_rules = engine.evaluate_event(event, org_id=org_id)
    except Exception as e_rule:
        logger.error(f"Declarative rule engine evaluation error: {e_rule}")
        fired_rules = []

    # =====================================================================
    # BEHAVIORAL BASELINE EVALUATION (Phase 3.4)
    # Evaluates statistical baselines (amounts, hours, devices, geos)
    # Outputs plain explanations ("amount is 9× this account's 90-day median")
    # Falls back deterministically when history is thin (< 5 events)
    # =====================================================================
    baseline_eval = None
    try:
        from app.services.behavioral_baseline_service import BehavioralBaselineService
        BehavioralBaselineService.record_event_for_baseline(event, org_id)
        baseline_eval = BehavioralBaselineService.evaluate_event_against_baseline(event, org_id)
    except Exception as e_base:
        logger.debug(f"Behavioral baseline evaluation skipped: {e_base}")
        baseline_eval = {'is_anomalous': False, 'anomaly_score': 0, 'signals': [], 'explanations': [], 'deterministic_fallback': True}

    # =====================================================================
    # LAYER 4: EXPLAINABLE RISK MODEL V2 SYNTHESIS & SCORING (Phase 3.5)
    # Additive 0-100 model with rule confidence, entity criticality,
    # recency decay, and deterministic non-probability rationale
    # =====================================================================
    baseline_score = baseline_eval.get('anomaly_score', 0) if baseline_eval and baseline_eval.get('is_anomalous') else 0
    target_entity_type = 'account' if account else ('system' if event.get('target_system_id') else ('user' if user_id else ('ip' if source_ip else 'event')))
    target_entity_id = account or user_id or source_ip or event.get('target_system_id') or event_id

    try:
        from app.services.risk_model_service import RiskModelV2Service
        risk_v2 = RiskModelV2Service.calculate_risk(
            fired_rules=fired_rules,
            baseline_score=baseline_score,
            entity_type=target_entity_type,
            entity_id=target_entity_id,
            org_id=org_id
        )
        capped_score = risk_v2['risk_score']
        severity = risk_v2['severity']
        confidence = risk_v2['confidence']
        reasons = risk_v2['reasons']
    except Exception as e_v2:
        logger.error(f"Risk Model v2 calculation fallback: {e_v2}")
        raw_score = sum(r['weight'] for r in fired_rules if not r.get('is_shadow')) + baseline_score
        capped_score = min(100, raw_score)
        severity = 'critical' if capped_score >= 75 else ('high' if capped_score >= 50 else ('medium' if capped_score >= 25 else 'low'))
        confidence = 'high' if any(r.get('layer') == 'L3' and not r.get('is_shadow') for r in fired_rules) else 'medium'
        risk_v2 = None
        reasons = []

    # Build explainable evidence breakdown
    breakdown = []
    reasons = list(risk_v2.get('reasons', [])) if risk_v2 else []
    for r in fired_rules:
        breakdown.append({
            'rule_id': r['rule_id'],
            'name': r['name'],
            'layer': r['layer'],
            'weight': r['weight'],
            'summary': r['summary'],
            'is_shadow': r.get('is_shadow', False),
            'lifecycle_state': r.get('lifecycle_state', 'live')
        })
        if not risk_v2:
            shadow_suffix = " [SHADOW - NO IMPACT]" if r.get('is_shadow') else ""
            effective_pts = 0 if r.get('is_shadow') else r['weight']
            reasons.append(f"[{r['rule_id']}] {r['name']} (+{effective_pts} pts): {r['summary']}{shadow_suffix}")

    if baseline_eval and baseline_eval.get('is_anomalous'):
        for sig in baseline_eval.get('signals', []):
            breakdown.append({
                'rule_id': f"BASE-{sig.get('dimension', 'STAT').upper()}",
                'name': f"Behavioral Baseline Deviation ({sig.get('dimension', '').title()})",
                'layer': 'L2',
                'weight': sig.get('deviation_score', 0),
                'summary': sig.get('explanation', ''),
                'is_shadow': False,
                'lifecycle_state': 'live'
            })
            baseline_reason = f"[BASELINE-{sig.get('dimension', 'STAT').upper()}] {sig.get('explanation')} (+{sig.get('deviation_score')} pts)"
            if baseline_reason not in reasons:
                reasons.append(baseline_reason)
    elif baseline_eval and baseline_eval.get('deterministic_fallback') and baseline_eval.get('explanations') and not fired_rules:
        reasons.append(f"[BASELINE-FALLBACK] {baseline_eval['explanations'][0]}")

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
    quality_res = None
    if capped_score >= 25:
        primary_rule = next((r for r in fired_rules if not r.get('is_shadow')), fired_rules[0])
        alert_title = f"{severity.upper()}: {primary_rule['name']} on {account or source_ip or 'Target'}"
        if any(r['rule_id'] == 'ATO-001' and not r.get('is_shadow') for r in fired_rules):
            alert_title = f"CRITICAL: Account Takeover Detected on {account or 'Account'}"

        alert_type = 'account_takeover' if any(r['rule_id'] == 'ATO-001' and not r.get('is_shadow') for r in fired_rules) else \
                     ('suspicious_transaction' if any('TX' in r['rule_id'] and not r.get('is_shadow') for r in fired_rules) else \
                     ('high_risk' if any('AUTH' in r['rule_id'] and not r.get('is_shadow') for r in fired_rules) else 'high_risk'))

        primary_rule_id = primary_rule.get('rule_id') if primary_rule else 'GENERAL'
        entity_type = 'account' if account else ('ip' if source_ip else 'device' if device_id else 'target')
        entity_id = account or source_ip or device_id or target_id or 'unknown'

        candidate_alert = {
            'organization_id': org_id,
            'title': alert_title,
            'severity': severity,
            'status': 'open',
            'alert_type': alert_type,
            'risk_score': capped_score,
            'primary_rule_id': primary_rule_id,
            'entity_type': entity_type,
            'entity_id': entity_id,
            'description': f"Automated detection fired {len(fired_rules)} rule(s) with risk score {capped_score}/100. " + "; ".join(reasons[:2]),
            'trigger_event_id': event_id,
            'target_system_id': target_id,
            'evidence': {
                'risk_score': capped_score,
                'severity': severity,
                'confidence': confidence,
                'fired_rules': breakdown,
                'trigger_event_id': event_id,
                'account': account,
                'source_ip': source_ip,
                'device_id': device_id,
                'amount_etb': amount_etb,
                'user_agent': event.get('user_agent') or attributes.get('user_agent') or attributes.get('headers', {}).get('User-Agent') or attributes.get('headers', {}).get('user-agent'),
                'sec_ch_ua_platform': attributes.get('sec_ch_ua_platform') or attributes.get('sec-ch-ua-platform'),
                'device_mac': attributes.get('device_mac') or attributes.get('mac_address'),
                'network_type': attributes.get('network_type') or attributes.get('connection_type'),
                'attributes': attributes,
            }
        }

        try:
            from app.services.alert_quality_service import AlertQualityService
            quality_res = AlertQualityService.process_candidate_alert(candidate_alert, org_id=org_id)
            if quality_res and quality_res.get('action') in ('created', 'deduplicated'):
                alert_record = quality_res.get('alert')
                alert_id = alert_record.get('id') if alert_record else None
                if alert_id:
                    try:
                        from app.services.enrichment_service import synthesize_attack_dossier, store_alert_dossier
                        dossier = synthesize_attack_dossier(alert_record, event)
                        store_alert_dossier(alert_id, dossier)
                    except Exception as d_err:
                        logger.debug(f"Could not synthesize attack dossier: {d_err}")

                if quality_res.get('action') == 'created' and alert_id and isinstance(alert_id, str):
                    try:
                        log_action(None, 'auto_alert_dispatched', 'alert', alert_id, {
                            'title': alert_title, 'risk_score': capped_score, 'severity': severity
                        })
                    except Exception as audit_err:
                        logger.debug(f"Audit log skipped for auto-alert: {audit_err}")
        except Exception as q_err:
            logger.error(f"Alert quality processing fallback: {q_err}")
            # Direct clean insert fallback
            try:
                valid_types = {'account_takeover', 'suspicious_transaction', 'high_risk', 'other'}
                raw_at = candidate_alert.get('alert_type')
                clean_type = raw_at if raw_at in valid_types else ('high_risk' if candidate_alert.get('severity') in ('high', 'critical') else 'other')
                clean_cand = {
                    'organization_id': org_id or candidate_alert.get('organization_id') or '00000000-0000-0000-0000-000000000001',
                    'title': candidate_alert.get('title', 'Security Alert'),
                    'description': candidate_alert.get('description', ''),
                    'severity': candidate_alert.get('severity', 'medium'),
                    'status': candidate_alert.get('status', 'open'),
                    'alert_type': clean_type,
                    'risk_score': candidate_alert.get('risk_score', 0),
                    'evidence': candidate_alert.get('evidence', {}),
                }
                try:
                    alert_res = sb.table('alerts').insert(clean_cand).execute()
                except Exception:
                    legacy_cand = {
                        'title': clean_cand['title'],
                        'description': clean_cand['description'],
                        'severity': clean_cand['severity'],
                        'status': clean_cand['status'],
                        'alert_type': clean_cand['alert_type'],
                    }
                    alert_res = sb.table('alerts').insert(legacy_cand).execute()
                if alert_res and alert_res.data and len(alert_res.data) > 0:
                    alert_record = alert_res.data[0]
            except Exception as direct_err:
                logger.error(f"Alert insert fallback failed: {direct_err}")

    # Auto-promote Critical or High risk alerts to formal Incidents (Part 4, SRS §10 & §21)
    incident_record = None
    if alert_record and (capped_score >= 50 or any(r['rule_id'] == 'ATO-001' and not r.get('is_shadow') for r in fired_rules)):
        if not quality_res or quality_res.get('action') == 'created':
            try:
                from app.services.incident_service import promote_alert_to_incident
                incident_record = promote_alert_to_incident(alert_record, event, {
                    'risk_score': capped_score,
                    'severity': severity,
                    'confidence': confidence,
                    'reasons': reasons,
                    'rules_fired': [r['rule_id'] for r in fired_rules if not r.get('is_shadow')],
                    'breakdown': breakdown,
                    'is_attack_chain': any(r['rule_id'] == 'ATO-001' and not r.get('is_shadow') for r in fired_rules),
                })
            except Exception as inc_err:
                logger.error(f"Failed to auto-promote incident for alert {alert_record.get('id')}: {inc_err}")

    # Closed-Loop Autonomous Containment (Part 5, SRS §10, §21, §22)
    containment_result = None
    if alert_record and (capped_score >= 50 or any(r['rule_id'] == 'ATO-001' and not r.get('is_shadow') for r in fired_rules)):
        if not quality_res or quality_res.get('action') in ('created', 'deduplicated', 'escalated'):
            try:
                from app.services.response_policy import evaluate_and_execute_containment
                containment_result = evaluate_and_execute_containment(
                    event=event,
                    alert=alert_record,
                    incident=incident_record,
                    detection_result={
                        'risk_score': capped_score,
                        'severity': severity,
                        'rules_fired': [r['rule_id'] for r in fired_rules if not r.get('is_shadow')],
                        'is_attack_chain': any(r['rule_id'] == 'ATO-001' and not r.get('is_shadow') for r in fired_rules),
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
        'is_attack_chain': any(r['rule_id'] == 'ATO-001' and not r.get('is_shadow') for r in fired_rules),
        'is_threat': capped_score > 0 or any(not r.get('is_shadow') for r in fired_rules),
        'behavioral_baseline': baseline_eval,
        'deterministic_fallback': baseline_eval.get('deterministic_fallback', True) if baseline_eval else True,
        'risk_model_v2': risk_v2,
        'alert_quality': quality_res,
    }
