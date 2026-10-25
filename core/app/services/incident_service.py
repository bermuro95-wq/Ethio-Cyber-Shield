"""
Autonomous Incident Promotion & Threat Intelligence Linking Service for ECS.
Promotes high-confidence and critical alerts into formal security incidents,
links IOCs, resolves active incident deduplication windows, and builds visual attack graphs.
Conforms to SRS §10, §21, and §22.
"""
import logging
import uuid
from datetime import datetime, timedelta, timezone
from dateutil import parser
from app.services.db import get_service_supabase
from app.services.audit_service import log_action

logger = logging.getLogger(__name__)


def _is_valid_uuid(val) -> bool:
    if not val:
        return False
    try:
        uuid.UUID(str(val))
        return True
    except (ValueError, AttributeError):
        return False


def _parse_time(ts_val) -> datetime:
    if isinstance(ts_val, datetime):
        return ts_val if ts_val.tzinfo else ts_val.replace(tzinfo=timezone.utc)
    try:
        t = parser.isoparse(str(ts_val))
        return t if t.tzinfo else t.replace(tzinfo=timezone.utc)
    except Exception:
        return datetime.now(timezone.utc)


def find_active_incident_for_entity(entity_type: str, entity_value: str, window_hours: int = 4, organization_id: str = None) -> dict | None:
    """
    Checks if an open or investigating incident already exists for this entity
    within the deduplication window (default 4 hours), scoped by organization_id.
    """
    if not entity_value:
        return None

    from app.services.tenant_service import get_current_organization_id
    org_id = organization_id or get_current_organization_id()

    sb = get_service_supabase()
    now = datetime.now(timezone.utc)
    cutoff = (now - timedelta(hours=window_hours)).isoformat()

    try:
        # Search active incidents
        base_query = sb.table('incidents').select('*')\
            .in_('status', ['open', 'investigating'])\
            .gte('incident_date', cutoff)\
            .order('incident_date', desc=True)

        try:
            if org_id:
                res = base_query.eq('organization_id', org_id).execute()
            else:
                res = base_query.execute()
        except Exception:
            res = sb.table('incidents').select('*')\
                .in_('status', ['open', 'investigating'])\
                .gte('incident_date', cutoff)\
                .order('incident_date', desc=True).execute()

        incidents = res.data or []

        # Find matching entity in title, description, or risk_reasons
        for inc in incidents:
            title = inc.get('title') or ''
            desc = inc.get('description') or ''
            reasons = str(inc.get('risk_reasons') or [])
            if entity_value in title or entity_value in desc or entity_value in reasons:
                return inc

        return None
    except Exception as e:
        logger.warning(f"Error querying active incidents for entity {entity_value}: {e}")
        return None


def link_threat_indicators(incident_id: str, event: dict, detection_result: dict) -> list:
    """
    Extracts observable IOCs (IP, device, account) from event, upserts them into
    the indicators table, and links them to the incident via incident_indicators.
    Also cross-references active watchlists.
    """
    sb = get_service_supabase()
    from app.services.tenant_service import get_current_organization_id
    org_id = event.get('organization_id') or get_current_organization_id()
    linked_ids = []

    source_ip = event.get('source_ip')
    event_id = event.get('event_id')
    event_type = event.get('event_type')
    risk_score = detection_result.get('risk_score', 0)
    target_id = event.get('target_system_id')
    status = 'malicious' if risk_score >= 75 or detection_result.get('is_attack_chain') else 'suspicious'

    if source_ip:
        try:
            # 1. Upsert indicator
            ind_row = {
                'organization_id': org_id,
                'indicator_type': 'ip',
                'value': source_ip,
                'status': status,
                'description': f"Automated IOC observed in {event_type} ({event_id}) with risk score {risk_score}/100",
                'source': f"Target Telemetry ({event.get('source_system') or 'Target'})",
            }
            try:
                ind_res = sb.table('indicators').upsert(ind_row, on_conflict='organization_id,indicator_type,value').execute()
            except Exception:
                ind_row.pop('organization_id', None)
                ind_res = sb.table('indicators').upsert(ind_row, on_conflict='indicator_type,value').execute()

            indicator_id = None
            if ind_res.data:
                indicator_id = ind_res.data[0]['id']
            else:
                # Fetch existing id
                existing = sb.table('indicators').select('id').eq('indicator_type', 'ip').eq('value', source_ip).limit(1).execute()
                if existing.data:
                    indicator_id = existing.data[0]['id']

            # 2. Link to incident_indicators
            if indicator_id and incident_id:
                sb.table('incident_indicators').upsert({
                    'incident_id': incident_id,
                    'indicator_id': indicator_id,
                    'notes': f"Linked by ECS Threat Engine: {'; '.join(detection_result.get('rules_fired', []))}"
                }, on_conflict='incident_id,indicator_id').execute()
                linked_ids.append(indicator_id)

            # 3. Cross-reference watchlists
            try:
                w_res = sb.table('watchlists').select('*').eq('entity_type', 'ip').eq('value', source_ip).eq('is_active', True).limit(1).execute()
                if w_res.data:
                    wl = w_res.data[0]
                    logger.info(f"Matched watchlist item for IP {source_ip}: {wl.get('label')}")
            except Exception as wl_err:
                logger.debug(f"Watchlist lookup skipped: {wl_err}")

        except Exception as e:
            logger.warning(f"Error linking threat indicator {source_ip} to incident {incident_id}: {e}")

    return linked_ids


def promote_alert_to_incident(alert: dict = None, event: dict = None, detection_result: dict = None,
                              alert_id: str = None, target_id: str = None, **kwargs) -> dict | None:
    """
    Automated incident promotion engine.
    Promotes Critical / High alerts into formal incidents, links indicators, and attaches alerts.
    """
    import uuid
    if alert is None and alert_id:
        alert = {'id': alert_id}
    elif alert is None:
        alert = {'id': f"alt-auto-{uuid.uuid4().hex[:8]}"}

    if event is None and 'trigger_event' in kwargs:
        event = kwargs['trigger_event']
    event = event or {}

    detection_result = detection_result or kwargs.get('detection') or {}
    risk_score = detection_result.get('risk_score', 0)
    severity = detection_result.get('severity', 'medium')
    is_attack_chain = detection_result.get('is_attack_chain', False)

    # Only promote alerts with High or Critical severity (risk_score >= 50 or attack chain)
    if risk_score < 50 and not is_attack_chain and severity not in ('critical', 'high'):
        return None

    sb = get_service_supabase()
    from app.services.tenant_service import get_current_organization_id
    org_id = event.get('organization_id') or get_current_organization_id()

    now_dt = datetime.now(timezone.utc)
    now_iso = now_dt.isoformat()

    account = event.get('account_id_pub') or event.get('account_id')
    user_id = event.get('user_id_pub') or event.get('user_id')
    source_ip = event.get('source_ip')
    entity_val = account or user_id or source_ip or "Target-System"
    target_id = target_id or event.get('target_system_id')
    alert_id = alert.get('id') if isinstance(alert, dict) else alert_id

    # Check for existing active incident in 4-hour window
    existing_incident = find_active_incident_for_entity(
        'account' if account else ('ip' if source_ip else 'user'),
        entity_val,
        window_hours=4,
        organization_id=org_id
    )

    if existing_incident:
        incident_id = existing_incident['id']
        # Update existing incident with elevated risk score and newly fired rules
        existing_reasons = existing_incident.get('risk_reasons') or []
        new_reasons = list(dict.fromkeys(existing_reasons + detection_result.get('reasons', [])))
        new_risk_score = max(existing_incident.get('risk_score') or 0, risk_score)
        new_severity = 'critical' if new_risk_score >= 75 else ('high' if new_risk_score >= 50 else 'medium')

        update_payload = {
            'risk_score': new_risk_score,
            'risk_level': new_severity,
            'risk_reasons': new_reasons,
            'updated_at': now_iso,
        }
        try:
            sb.table('incidents').update(update_payload).eq('id', incident_id).execute()
        except Exception as e:
            logger.warning(f"Could not update incident {incident_id}: {e}")

        # Link alert to this incident
        if alert_id:
            try:
                sb.table('alerts').update({'related_incident_id': incident_id}).eq('id', alert_id).execute()
            except Exception as e:
                logger.debug(f"Could not link alert {alert_id} to existing incident {incident_id}: {e}")

        # Link threat indicators
        link_threat_indicators(incident_id, event, detection_result)
        existing_incident.update(update_payload)
        return existing_incident

    # Otherwise, create a new formal incident
    if is_attack_chain or any('ATO' in r for r in detection_result.get('rules_fired', [])):
        incident_type = 'account_takeover'
        title = f"CRITICAL: Account Takeover Incident on {entity_val}"
    elif any('TX' in r for r in detection_result.get('rules_fired', [])):
        incident_type = 'fraud'
        title = f"HIGH: Suspicious Transaction Incident on {entity_val}"
    elif any('AUTH' in r for r in detection_result.get('rules_fired', [])):
        incident_type = 'account_takeover'
        title = f"HIGH: Credential Attack Incident on {entity_val}"
    else:
        incident_type = 'other'
        title = f"HIGH: Threat Incident on {entity_val}"

    # Ensure incident_type complies with check constraint
    valid_inc_types = {'account_takeover', 'fraud', 'phishing', 'malware', 'other'}
    if incident_type not in valid_inc_types:
        incident_type = 'other'

    rules_list_str = "\n".join(f"- {r}" for r in detection_result.get('reasons', []))
    description = (
        f"### Automated Incident Promoted by ECS Detection Engine\n\n"
        f"**Source System:** {event.get('source_system') or 'ShieldBank Testbed'}\n"
        f"**Target Entity:** `{entity_val}`\n"
        f"**Initial Trigger Event ID:** `{event.get('event_id')}`\n"
        f"**Risk Score:** **{risk_score}/100** ({severity.upper()})\n"
        f"**Confidence:** **{detection_result.get('confidence', 'high').upper()}**\n\n"
        f"#### Triggered Security Rules:\n"
        f"{rules_list_str}\n\n"
        f"**Recommended Containment:** Verify active transactions and revoke unverified sessions."
    )

    incident_payload = {
        'organization_id': org_id or '00000000-0000-0000-0000-000000000001',
        'title': title,
        'description': description,
        'incident_type': incident_type,
        'severity': severity,
        'status': 'open',
        'incident_date': event.get('occurred_at') or now_iso,
        'risk_score': risk_score,
        'risk_level': severity,
        'risk_reasons': detection_result.get('reasons', []),
    }

    created_incident = None
    try:
        res = sb.table('incidents').insert(incident_payload).execute()
        if res.data:
            created_incident = res.data[0]
    except Exception as e:
        try:
            legacy_inc = {k: v for k, v in incident_payload.items() if k != 'organization_id'}
            res = sb.table('incidents').insert(legacy_inc).execute()
            if res.data:
                created_incident = res.data[0]
        except Exception as e2:
            logger.error(f"Failed to auto-create incident: {e2}")

    if not created_incident:
        import uuid
        created_incident = {
            **incident_payload,
            'id': f"00000000-0000-0000-0000-{uuid.uuid4().hex[:12]}",
        }

    incident_id = created_incident['id']

    # Link alert to new incident
    if alert_id:
        try:
            sb.table('alerts').update({'related_incident_id': incident_id}).eq('id', alert_id).execute()
        except Exception as e:
            logger.debug(f"Could not link alert {alert_id} to new incident {incident_id}: {e}")

    # Link threat indicators
    link_threat_indicators(incident_id, event, detection_result)

    # Audit log
    try:
        log_action(None, 'auto_incident_promoted', 'incident', incident_id, {
            'title': title, 'risk_score': risk_score, 'severity': severity, 'alert_id': alert_id
        })
    except Exception as audit_err:
        logger.debug(f"Audit log skipped for auto-incident: {audit_err}")

    logger.info(f"Auto-promoted incident {incident_id} ({title}) with risk score {risk_score}")
    return created_incident


def get_incident_attack_graph(incident_id: str) -> dict:
    """
    Compiles an explainable visual attack graph representation for an incident.
    Returns:
      - incident: core details & risk scores
      - alerts: linked alerts
      - indicators: linked threat observables
      - timeline: chronology of security events
      - explainability: rule breakdown & evidence
    """
    sb = get_service_supabase()

    # 1. Incident
    inc_res = sb.table('incidents').select('*').eq('id', incident_id).execute()
    if not inc_res.data:
        return {'error': 'Incident not found'}
    incident = inc_res.data[0]

    # 2. Linked Alerts
    alerts_res = sb.table('alerts').select('*').eq('related_incident_id', incident_id).execute()
    alerts = alerts_res.data or []

    # 3. Linked Indicators
    link_res = sb.table('incident_indicators').select('*, indicator:indicators(*)').eq('incident_id', incident_id).execute()
    indicators = [l.get('indicator') for l in (link_res.data or []) if l.get('indicator')]

    # 4. Trigger events & Timeline
    trigger_event_ids = []
    for a in alerts:
        ev_data = a.get('evidence') or {}
        if isinstance(ev_data, dict) and ev_data.get('trigger_event_id'):
            trigger_event_ids.append(ev_data['trigger_event_id'])

    timeline_events = []
    if trigger_event_ids:
        try:
            ev_res = sb.table('security_events').select('*').in_('event_id', trigger_event_ids).order('occurred_at', desc=False).execute()
            timeline_events = ev_res.data or []
        except Exception as e:
            logger.warning(f"Could not load timeline events: {e}")

    # Build Graph nodes and edges for visualization
    nodes = [
        {'id': f"inc_{incident['id']}", 'label': incident['title'], 'type': 'incident', 'severity': incident['severity']}
    ]
    edges = []

    for idx, a in enumerate(alerts):
        node_id = f"alert_{a['id']}"
        nodes.append({'id': node_id, 'label': a['title'], 'type': 'alert', 'severity': a['severity']})
        edges.append({'from': f"inc_{incident['id']}", 'to': node_id, 'relation': 'contains_alert'})

    for idx, ind in enumerate(indicators):
        node_id = f"ind_{ind['id']}"
        nodes.append({'id': node_id, 'label': f"{ind['indicator_type'].upper()}: {ind['value']}", 'type': 'indicator', 'status': ind['status']})
        edges.append({'from': f"inc_{incident['id']}", 'to': node_id, 'relation': 'linked_indicator'})

    for idx, ev in enumerate(timeline_events):
        node_id = f"ev_{ev['event_id']}"
        nodes.append({'id': node_id, 'label': f"{ev['event_type']} ({ev['occurred_at']})", 'type': 'event', 'result': ev.get('result')})
        edges.append({'from': f"inc_{incident['id']}", 'to': node_id, 'relation': 'correlated_event'})

    return {
        'incident': incident,
        'alerts_count': len(alerts),
        'alerts': alerts,
        'indicators_count': len(indicators),
        'indicators': indicators,
        'timeline': timeline_events,
        'nodes': nodes,
        'edges': edges,
        'graph': {
            'nodes': nodes,
            'edges': edges,
        }
    }
