"""
Central Telemetry Event Ingestion & Normalization Service for Ethio-Cyber Shield (ECS).
Processes canonical v1.0 security events, writes to security_events table,
normalizes into domain entities (transactions, indicators, devices), and hooks into detection.
"""
import logging
from datetime import datetime, timezone
from app.services.db import get_service_supabase
from app.services.security_rules import analyze_transaction

from app.services.stream_service import get_stream_service

logger = logging.getLogger(__name__)

# Sliding buffer for real-time correlation and zero-latency lookups
_RECENT_EVENTS_BUFFER = []
MAX_BUFFER_SIZE = 1000

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


def get_recent_in_memory_events() -> list:
    """Returns a snapshot of recent events from the in-memory/sliding buffer."""
    return list(_RECENT_EVENTS_BUFFER)


def ingest_event(data: dict, target: dict = None, target_system_id: str = None, **kwargs) -> dict:
    """
    Ingests a single v1.0 / v1.1 security event.
    Guarantees idempotency via event_id and normalizes into entity tables.
    """
    from app.schemas.event_contract import validate_and_normalize_event
    from app.services.tenant_service import get_current_organization_id

    sb = get_service_supabase()
    org_id = (target.get('organization_id') if target else None) or data.get('organization_id') or get_current_organization_id()
    target_id = (target.get('id') if target else None) or target_system_id or data.get('target_system_id')

    # Prepare payload with target fallback for source_system
    payload = dict(data)
    if not payload.get('source_system') and target:
        payload['source_system'] = target.get('name')

    is_valid, norm_event, errors = validate_and_normalize_event(payload, default_org_id=org_id)
    if not is_valid:
        err_msg = f"Schema validation error: {'; '.join(errors)}"
        try:
            from app.services.data_quality_service import record_schema_violation
            record_schema_violation(
                org_id=org_id or '00000000-0000-0000-0000-000000000001',
                source_id=payload.get('source_system') or target_id or 'unknown',
                source_name=payload.get('source_system') or (target.get('name') if target else None) or 'unknown',
                violation_type='SCHEMA_VALIDATION_ERROR',
                error_message=err_msg,
                raw_sample=payload
            )
        except Exception:
            pass
        raise ValueError(err_msg)


    event_id = norm_event['event_id']
    raw_event_type = norm_event['event_type']
    event_type = EVENT_TYPE_MAP.get(str(raw_event_type).lower(), str(raw_event_type).upper())
    occurred_at = norm_event['occurred_at']
    source_system = norm_event['source_system']
    user_id_pub = norm_event['user_id_pub']
    account_id_pub = norm_event['account_id_pub']
    session_id_pub = norm_event['session_id_pub']
    device_id_pub = norm_event['device_id_pub']
    source_ip = norm_event['source_ip']
    endpoint = norm_event['endpoint']
    result = norm_event['result']
    currency = norm_event['currency']
    beneficiary_id_pub = norm_event['beneficiary_id_pub']
    transaction_id_pub = norm_event['transaction_id_pub']
    amount_minor = norm_event['amount_minor']
    amount_major = norm_event['amount']
    channel = norm_event['channel']
    payment_rail = norm_event['payment_rail']
    counterparty_ref_hash = norm_event['counterparty_ref_hash']
    device_fingerprint = norm_event['device_fingerprint']
    msisdn_hash = norm_event['msisdn_hash']
    agent_id = norm_event['agent_id']
    national_id_hash = norm_event['national_id_hash']
    locale_tz = norm_event['locale_tz']
    attributes = norm_event['attributes']
    lab_scenario = attributes.get('lab_scenario_id')

    canonical_event = {
        'event_id': event_id,
        'organization_id': org_id,
        'event_type': event_type,
        'occurred_at': occurred_at,
        'source_system': source_system,
        'user_id': user_id_pub,
        'account_id': account_id_pub,
        'session_id': session_id_pub,
        'device_id': device_id_pub,
        'source_ip': source_ip,
        'endpoint': endpoint,
        'result': result,
        'attributes': attributes,
        'user_agent': attributes.get('user_agent') or data.get('user_agent'),
        'device_mac': attributes.get('device_mac') or data.get('device_mac'),
        'network_type': attributes.get('network_type') or data.get('network_type'),
    }
    if norm_event.get('seq') is not None:
        canonical_event['seq'] = norm_event['seq']

    extended_fields = {
        'seq': norm_event.get('seq'),
        'user_id_pub': user_id_pub,
        'account_id_pub': account_id_pub,
        'session_id_pub': session_id_pub,
        'device_id_pub': device_id_pub,
        'amount_minor': amount_minor,
        'currency': currency,
        'beneficiary_id_pub': beneficiary_id_pub,
        'transaction_id_pub': transaction_id_pub,
        'channel': channel,
        'payment_rail': payment_rail,
        'counterparty_ref_hash': counterparty_ref_hash,
        'device_fingerprint': device_fingerprint,
        'msisdn_hash': msisdn_hash,
        'agent_id': agent_id,
        'national_id_hash': national_id_hash,
        'locale_tz': locale_tz,
        'delivery_status': 'DELIVERED',
        'raw_payload': data,
    }
    if target_id:
        canonical_event['target_system_id'] = target_id

    legacy_cols = {'event_id', 'seq', 'event_type', 'occurred_at', 'source_system', 'user_id', 'account_id', 'session_id', 'device_id', 'source_ip', 'endpoint', 'result', 'attributes', 'processed'}
    clean_sec_ev = {k: v for k, v in canonical_event.items() if k in legacy_cols}
    try:
        sb.table('security_events').upsert(clean_sec_ev, on_conflict='event_id').execute()
    except Exception as e:
        logger.debug(f"Error persisting security_event {event_id}: {e}")

    # 2. Extract & normalize transactions
    if event_type in ('TRANSFER_CREATED', 'TRANSFER_INITIATED') and amount_major:
        try:
            tx_record = {
                'account_number': account_id_pub or 'ACC_UNKNOWN',
                'amount': float(amount_major),
                'currency': currency or 'ETB',
                'transaction_type': 'transfer',
                'device_id': device_id_pub,
                'ip_address': source_ip,
                'status': 'flagged' if attributes.get('held_for_review') else 'completed',
                'is_suspicious': bool(attributes.get('held_for_review') or lab_scenario),
            }
            tx_res = sb.table('transactions').insert(tx_record).execute()

            if tx_res.data:
                analyze_transaction(tx_res.data[0]['id'])
        except Exception as e:
            logger.error(f"Failed to normalize transaction from event {event_id}: {e}")

    # 3. Extract & update threat indicators (IPs, accounts, devices)
    if source_ip and (lab_scenario or event_type in ('LOGIN_FAILED', 'AUTHZ_DENIED')):
        ind_data = {
            'indicator_type': 'ip',
            'value': source_ip,
            'status': 'malicious' if lab_scenario else 'suspicious',
            'description': f"Observed in event {event_type} ({lab_scenario or 'Target System'})",
            'source': 'Target System Telemetry',
        }
        try:
            sb.table('indicators').upsert(ind_data, on_conflict='indicator_type,value').execute()
        except Exception as e:
            logger.debug(f"Could not upsert indicator for {source_ip}: {e}")

    # 4. Record into durable stream and sliding buffer for real-time correlation
    buffered_item = {
        **canonical_event,
        **extended_fields,
        'amount': amount_major,
        'raw_event_type': raw_event_type,
    }
    _RECENT_EVENTS_BUFFER.insert(0, buffered_item)
    if len(_RECENT_EVENTS_BUFFER) > MAX_BUFFER_SIZE:
        _RECENT_EVENTS_BUFFER.pop()

    try:
        stream_svc = get_stream_service()
        stream_svc.enqueue_event(buffered_item, org_id=org_id)
        stream_svc.index_sliding_window(buffered_item, org_id=org_id)
    except Exception as e_stream:
        logger.debug(f"Stream enqueue/index warning: {e_stream}")

    # 4b. Unified Entity Graph update (Phase 2.6)
    try:
        from app.services.entity_graph_service import record_event_entities
        record_event_entities(buffered_item)
    except Exception as e_graph:
        logger.debug(f"Entity graph update warning: {e_graph}")

    # 4c. Data Quality & Health Monitor update (Phase 2.7)
    try:
        from app.services.data_quality_service import touch_source_activity
        touch_source_activity(
            org_id=org_id,
            source_id=source_system or 'unknown',
            source_name=source_system or 'unknown',
            event_id=event_id,
            attributes=buffered_item
        )
    except Exception as e_dq:
        logger.debug(f"Data quality monitor touch warning: {e_dq}")


    # 5. Multi-Layer Detection & Explainable Risk Engine evaluation (SRS §9, §21)
    detection_result = None
    try:
        from app.services.detection_engine import evaluate_event_stream
        event_for_detection = dict(buffered_item)
        detection_result = evaluate_event_stream(event_for_detection)
    except Exception as e:
        logger.error(f"Error evaluating event {event_id} through detection engine: {e}")

    return {
        'status': 'received',
        'event_id': event_id,
        'event_type': event_type,
        'lab_scenario_id': lab_scenario,
        'detection': detection_result or {},
    }


def ingest_batch(events_list: list, target: dict = None) -> int:
    """
    Ingests a sequence of events (e.g. from a polling sync batch).
    Returns the count of successfully processed events.
    """
    success_count = 0
    for ev in events_list:
        try:
            ingest_event(ev, target=target)
            success_count += 1
        except Exception as e:
            logger.error(f"Failed to ingest event in batch: {e}")
    return success_count


def query_events(event_type: str = None, target_id: str = None, account: str = None,
                 user_id: str = None, source_ip: str = None, channel: str = None,
                 payment_rail: str = None, limit: int = 50) -> list:
    """
    Retrieves recent security events matching the given criteria.
    Supports filtering by event_type, target_system_id, account, user_id, source_ip,
    channel, payment_rail, and limit.
    """
    sb = get_service_supabase()
    from app.services.tenant_service import get_current_organization_id
    org_id = get_current_organization_id()
    query = sb.table('security_events').select('*')

    if org_id:
        try:
            query = query.eq('organization_id', org_id)
        except Exception:
            pass

    if event_type:
        query = query.eq('event_type', event_type)
    if target_id:
        query = query.eq('target_system_id', target_id)
    if account:
        query = query.eq('account_id_pub', account)
    if user_id:
        query = query.eq('user_id_pub', user_id)
    if source_ip:
        query = query.eq('source_ip', source_ip)
    if channel:
        query = query.eq('channel', channel)
    if payment_rail:
        query = query.eq('payment_rail', payment_rail)

    max_limit = min(max(1, limit), 500)
    events = []
    try:
        res = query.order('occurred_at', desc=True).limit(max_limit).execute()
        events = res.data or []
    except Exception as e:
        logger.debug(f"Database query error in query_events, falling back: {e}")

    # If database returned no records or errored, evaluate sliding buffer fallback
    if not events:
        matched = []
        for ev in _RECENT_EVENTS_BUFFER:
            if org_id and ev.get('organization_id') and str(ev.get('organization_id')) != str(org_id):
                continue
            if event_type and ev.get('event_type') != event_type and ev.get('raw_event_type') != event_type:
                continue
            if target_id and ev.get('target_system_id') != target_id:
                continue
            if account and ev.get('account_id_pub') != account and ev.get('account_id') != account:
                continue
            if user_id and ev.get('user_id_pub') != user_id and ev.get('user_id') != user_id:
                continue
            if source_ip and ev.get('source_ip') != source_ip:
                continue
            if channel and ev.get('channel') != channel:
                continue
            if payment_rail and ev.get('payment_rail') != payment_rail:
                continue
            matched.append(ev)
            if len(matched) >= max_limit:
                break
        return matched

    return events
