"""
Health & Data-Quality Monitoring Service for Ethio-Cyber-Shield (ECS) v3.0 (Phase 2.7).

Provides:
1. Monitored source tracking & registration (webhooks, SDKs, log collectors, APIs).
2. Silent-source anomaly detection with progressive warning/critical severity.
3. Tenant-level silence alert detection ('no events from tenant X in 15 min').
4. Schema violation metrics, categorization, and sanitized diagnostic storage.
5. Ingestion throughput telemetry (1m, 5m, 1h, 24h sliding counters).
6. Explainable, deterministic composite Data Quality Score (0-100) and letter grade.
7. Strict multi-tenant isolation (all data partitioned by organization_id UUID).
"""
import uuid
import logging
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any, List, Tuple

from app.services.db import get_service_supabase
from app.services.tenant_service import get_current_organization_id

logger = logging.getLogger(__name__)

# In-memory sliding stores for high-throughput zero-latency caching & self-contained tests
# Keys scoped strictly by organization_id: (org_id, source_id) -> source_dict
_LOCAL_DQ_SOURCES: Dict[Tuple[str, str], Dict[str, Any]] = {}
_DQ_SOURCES_TABLE_EXISTS = True
# (org_id) -> list of violation dicts (bounded to last 500)
_LOCAL_SCHEMA_VIOLATIONS: Dict[str, List[Dict[str, Any]]] = {}
# (org_id) -> list of (timestamp_epoch_float, event_id, attributes)
_LOCAL_EVENT_TIMESTAMPS: Dict[str, List[Tuple[float, str, Dict[str, Any]]]] = {}

# Default silence anomaly threshold: 15 minutes (900 seconds)
DEFAULT_SILENCE_THRESHOLD_SECONDS = 900
MAX_VIOLATIONS_PER_ORG = 500
MAX_EVENT_TIMESTAMPS_PER_ORG = 2000

SENSITIVE_KEYS = {
    'password', 'secret', 'secret_token', 'token', 'authorization',
    'bearer', 'api_key', 'apikey', 'private_key', 'pan', 'pin', 'cvv'
}


def clear_data_quality_stores():
    """Resets all in-memory data quality telemetry stores. Useful for testing."""
    global _LOCAL_DQ_SOURCES, _LOCAL_SCHEMA_VIOLATIONS, _LOCAL_EVENT_TIMESTAMPS
    _LOCAL_DQ_SOURCES.clear()
    _LOCAL_SCHEMA_VIOLATIONS.clear()
    _LOCAL_EVENT_TIMESTAMPS.clear()


def sanitize_payload(payload: Any) -> Any:
    """Recursively redacts sensitive customer credentials, keys, and tokens from error snippets."""
    if isinstance(payload, dict):
        sanitized = {}
        for k, v in payload.items():
            if str(k).lower() in SENSITIVE_KEYS or any(s in str(k).lower() for s in ['secret', 'password', 'token']):
                sanitized[k] = '[REDACTED]'
            elif isinstance(v, (dict, list)):
                sanitized[k] = sanitize_payload(v)
            else:
                sanitized[k] = v
        return sanitized
    elif isinstance(payload, list):
        return [sanitize_payload(item) for item in payload]
    return payload


def register_or_update_source(
    org_id: str,
    source_id: str,
    source_name: str,
    source_type: str = 'webhook',
    silence_threshold_seconds: int = DEFAULT_SILENCE_THRESHOLD_SECONDS,
    is_active: bool = True
) -> Dict[str, Any]:
    """
    Registers or updates an ingestion source configuration with custom silence thresholds.
    Ensures strict tenant scoping.
    """
    now_iso = datetime.now(timezone.utc).isoformat()
    key = (str(org_id), str(source_id))

    existing = _LOCAL_DQ_SOURCES.get(key)
    if existing:
        existing['source_name'] = source_name or existing.get('source_name')
        existing['source_type'] = source_type or existing.get('source_type')
        existing['silence_threshold_seconds'] = silence_threshold_seconds
        existing['is_active'] = is_active
        existing['updated_at'] = now_iso
        record = existing
    else:
        record = {
            'id': str(uuid.uuid4()),
            'organization_id': str(org_id),
            'source_id': str(source_id),
            'source_name': str(source_name or source_id),
            'source_type': str(source_type),
            'silence_threshold_seconds': int(silence_threshold_seconds or DEFAULT_SILENCE_THRESHOLD_SECONDS),
            'last_event_at': None,
            'total_events': 0,
            'total_violations': 0,
            'is_active': is_active,
            'created_at': now_iso,
            'updated_at': now_iso
        }
        _LOCAL_DQ_SOURCES[key] = record

    # Attempt PostgreSQL persistence
    try:
        sb = get_service_supabase()
        sb.table('data_quality_sources').upsert(record, on_conflict='organization_id,source_id').execute()
    except Exception as e:
        logger.debug(f"Data quality source DB upsert fallback: {e}")

    return dict(record)


def touch_source_activity(
    org_id: str,
    source_id: str,
    source_name: Optional[str] = None,
    event_id: Optional[str] = None,
    attributes: Optional[Dict[str, Any]] = None,
    timestamp: Optional[str] = None
) -> Dict[str, Any]:
    """
    Records incoming event activity for a source and increments throughput telemetry.
    Auto-registers source if previously unseen.
    """
    now_dt = datetime.fromisoformat(timestamp) if timestamp else datetime.now(timezone.utc)
    if now_dt.tzinfo is None:
        now_dt = now_dt.replace(tzinfo=timezone.utc)
    now_iso = now_dt.isoformat()
    now_epoch = now_dt.timestamp()

    org_key = str(org_id)
    key = (org_key, str(source_id))

    record = _LOCAL_DQ_SOURCES.get(key)
    if not record:
        record = register_or_update_source(
            org_id=org_key,
            source_id=str(source_id),
            source_name=source_name or str(source_id)
        )

    record['last_event_at'] = now_iso
    record['total_events'] = int(record.get('total_events', 0)) + 1
    record['updated_at'] = now_iso
    _LOCAL_DQ_SOURCES[key] = record

    # Track in rolling throughput buffer
    if org_key not in _LOCAL_EVENT_TIMESTAMPS:
        _LOCAL_EVENT_TIMESTAMPS[org_key] = []
    
    _LOCAL_EVENT_TIMESTAMPS[org_key].append((
        now_epoch,
        event_id or f"evt_{uuid.uuid4().hex[:8]}",
        attributes or {}
    ))

    # Bounded buffer size
    if len(_LOCAL_EVENT_TIMESTAMPS[org_key]) > MAX_EVENT_TIMESTAMPS_PER_ORG:
        _LOCAL_EVENT_TIMESTAMPS[org_key] = _LOCAL_EVENT_TIMESTAMPS[org_key][-MAX_EVENT_TIMESTAMPS_PER_ORG:]

    # Attempt asynchronous / background DB update
    global _DQ_SOURCES_TABLE_EXISTS
    if _DQ_SOURCES_TABLE_EXISTS:
        try:
            sb = get_service_supabase()
            sb.table('data_quality_sources').update({
                'last_event_at': now_iso,
                'total_events': record['total_events'],
                'updated_at': now_iso
            }).eq('organization_id', org_key).eq('source_id', str(source_id)).execute()
        except Exception as e:
            if 'PGRST205' in str(e) or 'does not exist' in str(e):
                _DQ_SOURCES_TABLE_EXISTS = False
            logger.debug(f"Data quality source touch DB update fallback: {e}")

    return dict(record)


def list_monitored_sources(org_id: str, now: Optional[datetime] = None) -> List[Dict[str, Any]]:
    """
    Lists all monitored sources for an organization, calculating live silence status
    and elapsed silence duration.
    """
    if now is None:
        now = datetime.now(timezone.utc)
    elif now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)

    org_key = str(org_id)
    sources: List[Dict[str, Any]] = []

    # Check database first
    try:
        sb = get_service_supabase()
        res = sb.table('data_quality_sources').select('*').eq('organization_id', org_key).execute()
        if res.data:
            for s in res.data:
                _LOCAL_DQ_SOURCES[(org_key, s['source_id'])] = s
    except Exception as e:
        logger.debug(f"Could not load data quality sources from DB: {e}")

    for (o, s_id), src in _LOCAL_DQ_SOURCES.items():
        if o != org_key:
            continue

        item = dict(src)
        last_event_str = item.get('last_event_at')
        threshold = int(item.get('silence_threshold_seconds') or DEFAULT_SILENCE_THRESHOLD_SECONDS)

        if last_event_str:
            last_event_dt = datetime.fromisoformat(last_event_str)
            if last_event_dt.tzinfo is None:
                last_event_dt = last_event_dt.replace(tzinfo=timezone.utc)
            silence_secs = max(0, int((now - last_event_dt).total_seconds()))
            item['silence_duration_seconds'] = silence_secs

            if silence_secs > threshold:
                item['status'] = 'silent'
            else:
                item['status'] = 'active'
        else:
            item['silence_duration_seconds'] = None
            item['status'] = 'stale'

        sources.append(item)

    sources.sort(key=lambda x: x.get('source_name', ''))
    return sources


def check_silent_sources(org_id: str, now: Optional[datetime] = None) -> Dict[str, Any]:
    """
    Inspects all monitored sources for the tenant to identify silent sources.
    Assigns:
    - 'warning': silent duration between 1x and 2x threshold.
    - 'critical': silent duration > 2x threshold.
    Also detects Tenant-Level silence ('no events from tenant X in 15 min').
    """
    if now is None:
        now = datetime.now(timezone.utc)
    elif now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)

    sources = list_monitored_sources(org_id, now=now)
    active_count = 0
    silent_count = 0
    alerts: List[Dict[str, Any]] = []

    most_recent_event_dt: Optional[datetime] = None

    for src in sources:
        if not src.get('is_active', True):
            continue

        last_event_str = src.get('last_event_at')
        threshold = int(src.get('silence_threshold_seconds') or DEFAULT_SILENCE_THRESHOLD_SECONDS)
        threshold_min = threshold // 60

        if last_event_str:
            last_event_dt = datetime.fromisoformat(last_event_str)
            if last_event_dt.tzinfo is None:
                last_event_dt = last_event_dt.replace(tzinfo=timezone.utc)
            
            if most_recent_event_dt is None or last_event_dt > most_recent_event_dt:
                most_recent_event_dt = last_event_dt

            silence_secs = max(0, int((now - last_event_dt).total_seconds()))
            silence_min = silence_secs // 60

            if silence_secs > threshold:
                silent_count += 1
                severity = 'critical' if silence_secs > (2 * threshold) else 'warning'
                alerts.append({
                    'alert_id': f"silence-{org_id}-{src['source_id']}",
                    'type': 'source_silence',
                    'organization_id': org_id,
                    'source_id': src['source_id'],
                    'source_name': src.get('source_name', src['source_id']),
                    'source_type': src.get('source_type', 'unknown'),
                    'severity': severity,
                    'last_event_at': last_event_str,
                    'silence_duration_seconds': silence_secs,
                    'threshold_seconds': threshold,
                    'message': (
                        f"Silent source anomaly: No events received from source '{src.get('source_name')}' "
                        f"for {silence_min} minutes (threshold: {threshold_min}m)"
                    ),
                    'detected_at': now.isoformat()
                })
            else:
                active_count += 1
        else:
            # Source registered but has never sent events
            silent_count += 1
            alerts.append({
                'alert_id': f"stale-{org_id}-{src['source_id']}",
                'type': 'source_silence',
                'organization_id': org_id,
                'source_id': src['source_id'],
                'source_name': src.get('source_name', src['source_id']),
                'source_type': src.get('source_type', 'unknown'),
                'severity': 'warning',
                'last_event_at': None,
                'silence_duration_seconds': None,
                'threshold_seconds': threshold,
                'message': f"Source '{src.get('source_name')}' is registered but has never emitted telemetry",
                'detected_at': now.isoformat()
            })

    # Evaluate Tenant-Level Silence ("no events from tenant X in 15 min")
    tenant_silent = False
    tenant_silence_threshold = DEFAULT_SILENCE_THRESHOLD_SECONDS

    if most_recent_event_dt:
        tenant_silence_secs = max(0, int((now - most_recent_event_dt).total_seconds()))
        if tenant_silence_secs > tenant_silence_threshold:
            tenant_silent = True
            alerts.insert(0, {
                'alert_id': f"tenant-silent-{org_id}",
                'type': 'tenant_silence',
                'organization_id': org_id,
                'severity': 'critical',
                'last_event_at': most_recent_event_dt.isoformat(),
                'silence_duration_seconds': tenant_silence_secs,
                'threshold_seconds': tenant_silence_threshold,
                'message': (
                    f"No events received from tenant '{org_id}' in the last "
                    f"{tenant_silence_secs // 60} minutes (threshold: {tenant_silence_threshold // 60}m)"
                ),
                'detected_at': now.isoformat()
            })
    elif sources and active_count == 0:
        tenant_silent = True
        alerts.insert(0, {
            'alert_id': f"tenant-silent-{org_id}",
            'type': 'tenant_silence',
            'organization_id': org_id,
            'severity': 'critical',
            'last_event_at': None,
            'silence_duration_seconds': None,
            'threshold_seconds': tenant_silence_threshold,
            'message': f"No events received from tenant '{org_id}' across any monitored sources",
            'detected_at': now.isoformat()
        })

    return {
        'organization_id': org_id,
        'evaluated_at': now.isoformat(),
        'monitored_sources_count': len(sources),
        'active_sources_count': active_count,
        'silent_sources_count': silent_count,
        'tenant_silent': tenant_silent,
        'alerts_count': len(alerts),
        'alerts': alerts
    }


def record_schema_violation(
    org_id: str,
    source_id: Optional[str],
    source_name: Optional[str],
    violation_type: str,
    error_message: str,
    raw_sample: Optional[Dict[str, Any]] = None,
    occurred_at: Optional[str] = None
) -> Dict[str, Any]:
    """
    Records a malformed, rejected, or unmapped telemetry event into diagnostic stores.
    Sanitizes raw snippets to prevent credential leakage.
    Increments source and org violation counters.
    """
    now_dt = datetime.fromisoformat(occurred_at) if occurred_at else datetime.now(timezone.utc)
    if now_dt.tzinfo is None:
        now_dt = now_dt.replace(tzinfo=timezone.utc)
    now_iso = now_dt.isoformat()

    org_key = str(org_id)
    sanitized_sample = sanitize_payload(raw_sample or {})

    record = {
        'id': str(uuid.uuid4()),
        'organization_id': org_key,
        'source_id': str(source_id or 'unknown'),
        'source_name': str(source_name or source_id or 'unknown'),
        'violation_type': str(violation_type),
        'error_message': str(error_message),
        'raw_snippet': sanitized_sample,
        'occurred_at': now_iso
    }

    # Increment in source store
    if source_id:
        src = _LOCAL_DQ_SOURCES.get((org_key, str(source_id)))
        if src:
            src['total_violations'] = int(src.get('total_violations', 0)) + 1
            src['updated_at'] = now_iso

    # Append to rolling org violations
    if org_key not in _LOCAL_SCHEMA_VIOLATIONS:
        _LOCAL_SCHEMA_VIOLATIONS[org_key] = []
    _LOCAL_SCHEMA_VIOLATIONS[org_key].append(record)

    if len(_LOCAL_SCHEMA_VIOLATIONS[org_key]) > MAX_VIOLATIONS_PER_ORG:
        _LOCAL_SCHEMA_VIOLATIONS[org_key] = _LOCAL_SCHEMA_VIOLATIONS[org_key][-MAX_VIOLATIONS_PER_ORG:]

    # Persist in DB
    try:
        sb = get_service_supabase()
        sb.table('schema_violations').insert(record).execute()
    except Exception as e:
        logger.debug(f"Schema violation DB insert fallback: {e}")

    return dict(record)


def get_schema_violations_summary(
    org_id: str,
    time_window_seconds: int = 86400,
    now: Optional[datetime] = None
) -> Dict[str, Any]:
    """
    Aggregates schema violations for an organization in the specified time window (default: 24h).
    Returns breakdown by violation type, by source, and recent diagnostic entries.
    """
    if now is None:
        now = datetime.now(timezone.utc)
    elif now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)

    org_key = str(org_id)
    cutoff_dt = now - timedelta(seconds=time_window_seconds)

    # Check DB first
    violations: List[Dict[str, Any]] = []
    try:
        sb = get_service_supabase()
        res = sb.table('schema_violations').select('*').eq('organization_id', org_key).gte('occurred_at', cutoff_dt.isoformat()).order('occurred_at', desc=True).limit(MAX_VIOLATIONS_PER_ORG).execute()
        if res.data:
            violations = res.data
    except Exception as e:
        logger.debug(f"Could not load schema violations from DB: {e}")

    if not violations:
        in_mem = _LOCAL_SCHEMA_VIOLATIONS.get(org_key, [])
        for v in in_mem:
            v_dt = datetime.fromisoformat(v['occurred_at'])
            if v_dt.tzinfo is None:
                v_dt = v_dt.replace(tzinfo=timezone.utc)
            if v_dt >= cutoff_dt:
                violations.append(v)

    by_type: Dict[str, int] = {}
    by_source: Dict[str, int] = {}

    for v in violations:
        v_type = v.get('violation_type', 'UNKNOWN')
        v_src = v.get('source_id', 'unknown')
        by_type[v_type] = by_type.get(v_type, 0) + 1
        by_source[v_src] = by_source.get(v_src, 0) + 1

    return {
        'organization_id': org_key,
        'time_window_seconds': time_window_seconds,
        'total_violations': len(violations),
        'by_type': by_type,
        'by_source': by_source,
        'recent_violations': violations[:50]
    }


def get_ingestion_throughput(org_id: str, now: Optional[datetime] = None) -> Dict[str, Any]:
    """
    Calculates sliding-window ingestion throughput telemetry:
    - 1m, 5m, 15m, 1h, 24h event counts
    - rate_per_sec_1m
    - total_events all-time
    """
    if now is None:
        now = datetime.now(timezone.utc)
    elif now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)

    now_epoch = now.timestamp()
    org_key = str(org_id)

    events = _LOCAL_EVENT_TIMESTAMPS.get(org_key, [])

    count_1m = sum(1 for (t, _, _) in events if now_epoch - t <= 60)
    count_5m = sum(1 for (t, _, _) in events if now_epoch - t <= 300)
    count_15m = sum(1 for (t, _, _) in events if now_epoch - t <= 900)
    count_1h = sum(1 for (t, _, _) in events if now_epoch - t <= 3600)
    count_24h = sum(1 for (t, _, _) in events if now_epoch - t <= 86400)

    # Compute total from sources
    total_events = sum(
        int(s.get('total_events', 0))
        for (o, _), s in _LOCAL_DQ_SOURCES.items()
        if o == org_key
    )
    if total_events == 0:
        total_events = len(events)

    rate_1m = round(count_1m / 60.0, 3)

    return {
        'organization_id': org_key,
        'timestamp': now.isoformat(),
        'events_1m': count_1m,
        'events_5m': count_5m,
        'events_15m': count_15m,
        'events_1h': count_1h,
        'events_24h': count_24h,
        'total_events': total_events,
        'rate_per_sec_1m': rate_1m
    }


def calculate_data_quality_score(org_id: str, now: Optional[datetime] = None) -> Dict[str, Any]:
    """
    Computes an explainable, deterministic composite Data Quality Score (0-100) and letter grade:
    - Schema Compliance (40% weight): Valid events / (Valid + Violations)
    - Source Vitality (35% weight): Active monitored sources / Total active sources
    - Field Richness (25% weight): Presence of channel, device, source_ip, and rail in recent events
    """
    if now is None:
        now = datetime.now(timezone.utc)
    elif now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)

    org_key = str(org_id)

    # 1. Schema Compliance (40%)
    throughput = get_ingestion_throughput(org_key, now=now)
    violations_summary = get_schema_violations_summary(org_key, time_window_seconds=86400, now=now)

    valid_events_24h = throughput['events_24h']
    violations_24h = violations_summary['total_violations']

    total_attempts_24h = valid_events_24h + violations_24h
    if total_attempts_24h == 0:
        compliance_score = 100.0
    else:
        compliance_score = round(100.0 * (valid_events_24h / total_attempts_24h), 1)

    # 2. Source Vitality (35%)
    sources = list_monitored_sources(org_key, now=now)
    active_monitored = [s for s in sources if s.get('is_active', True)]
    if not active_monitored:
        vitality_score = 100.0
        active_count = 0
        total_sources_count = 0
    else:
        active_count = sum(1 for s in active_monitored if s.get('status') == 'active')
        total_sources_count = len(active_monitored)
        vitality_score = round(100.0 * (active_count / total_sources_count), 1)

    # 3. Field Richness (25%)
    events = _LOCAL_EVENT_TIMESTAMPS.get(org_key, [])
    sample_events = events[-50:] if events else []

    if not sample_events:
        richness_score = 100.0
    else:
        richness_fractions = []
        for (_, _, attrs) in sample_events:
            fields_present = 0
            # Check 4 key enrichment fields
            if attrs.get('channel'):
                fields_present += 1
            if attrs.get('device_fingerprint') or attrs.get('device_id'):
                fields_present += 1
            if attrs.get('source_ip'):
                fields_present += 1
            if attrs.get('payment_rail') or attrs.get('counterparty_ref_hash'):
                fields_present += 1
            richness_fractions.append(fields_present / 4.0)

        richness_score = round(100.0 * (sum(richness_fractions) / len(richness_fractions)), 1)

    # Composite Score
    composite_score = round(
        (0.40 * compliance_score) +
        (0.35 * vitality_score) +
        (0.25 * richness_score),
        1
    )

    # Letter Grade
    if composite_score >= 90.0:
        grade = 'A'
        grade_desc = 'Excellent'
    elif composite_score >= 80.0:
        grade = 'B'
        grade_desc = 'Good'
    elif composite_score >= 70.0:
        grade = 'C'
        grade_desc = 'Degraded'
    elif composite_score >= 50.0:
        grade = 'D'
        grade_desc = 'Poor'
    else:
        grade = 'F'
        grade_desc = 'Critical'

    rationale = (
        f"Data Quality Score: {composite_score}/100 (Grade {grade} - {grade_desc}). "
        f"Schema compliance: {compliance_score}% ({valid_events_24h} valid / {violations_24h} violations), "
        f"Source vitality: {vitality_score}% ({active_count} active / {total_sources_count} monitored sources), "
        f"Field richness: {richness_score}% (average enrichment fields populated)."
    )

    return {
        'organization_id': org_key,
        'evaluated_at': now.isoformat(),
        'quality_score': composite_score,
        'grade': grade,
        'grade_description': grade_desc,
        'breakdown': {
            'schema_compliance': compliance_score,
            'source_vitality': vitality_score,
            'field_richness': richness_score
        },
        'weights': {
            'schema_compliance': 0.40,
            'source_vitality': 0.35,
            'field_richness': 0.25
        },
        'metrics_24h': {
            'valid_events': valid_events_24h,
            'schema_violations': violations_24h,
            'active_sources': active_count,
            'total_sources': total_sources_count
        },
        'rationale': rationale
    }
