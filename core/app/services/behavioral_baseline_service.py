"""
Ethio-Cyber-Shield (ECS) — Explainable Behavioral Baselines Service (Phase 3.4).
Implements per-entity statistical baselines (amounts, operating hours, devices, geos, channels)
with plain-language explainability (e.g., 'amount is 9.0× this account's 90-day median')
and deterministic fallback when history is thin (< 5 events).
Multi-tenant partitioned by organization_id UUID NOT NULL.
"""
import uuid
import logging
import statistics
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional, Set, Tuple

from app.services.db import get_service_supabase
from app.services.tenant_service import get_current_organization_id

logger = logging.getLogger(__name__)

# East Africa Time (Addis Ababa, UTC+3)
EAT_TZ = timezone(timedelta(hours=3))

# In-memory stores for ultra-low latency lookups and test suite isolation
_LOCAL_BASELINES: Dict[str, Dict[str, Any]] = {}
_LOCAL_EVENTS: Dict[str, List[Dict[str, Any]]] = {}
_BASELINES_TABLE_EXISTS = True


def clear_baseline_caches():
    """Resets all in-memory baseline stores (used primarily in test suites)."""
    _LOCAL_BASELINES.clear()
    _LOCAL_EVENTS.clear()


def _baseline_key(org_id: str, entity_type: str, entity_id: str) -> str:
    return f"{str(org_id).strip()}:{str(entity_type).lower().strip()}:{str(entity_id).strip()}"


def _to_eat_datetime(dt_val: Any) -> datetime:
    """Converts a string ISO timestamp or datetime to East Africa Time (UTC+3)."""
    if isinstance(dt_val, str):
        try:
            # Handle trailing Z
            iso_str = dt_val.replace('Z', '+00:00')
            parsed = datetime.fromisoformat(iso_str)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed.astimezone(EAT_TZ)
        except Exception:
            return datetime.now(EAT_TZ)
    elif isinstance(dt_val, datetime):
        if dt_val.tzinfo is None:
            dt_val = dt_val.replace(tzinfo=timezone.utc)
        return dt_val.astimezone(EAT_TZ)
    return datetime.now(EAT_TZ)


class BehavioralBaselineService:
    """
    Stateless and cached evaluation of entity behavioral profiles.
    Strictly scoped by organization_id UUID.
    """

    @classmethod
    def record_event_for_baseline(cls, event: Dict[str, Any], org_id: Optional[str] = None):
        """
        Caches event in local tenant buffer for real-time baseline updating and backtesting.
        """
        oid = org_id or event.get('organization_id') or get_current_organization_id()
        if not oid:
            return
        oid = str(oid).strip()
        if oid not in _LOCAL_EVENTS:
            _LOCAL_EVENTS[oid] = []
        _LOCAL_EVENTS[oid].append(event)

    @classmethod
    def seed_baseline(
        cls,
        org_id: str,
        entity_type: str,
        entity_id: str,
        baseline_data: Dict[str, Any],
        save_db: bool = False
    ) -> Dict[str, Any]:
        """
        Seeds or updates an entity baseline directly (for testing or external onboarding).
        """
        key = _baseline_key(org_id, entity_type, entity_id)
        now_iso = datetime.now(timezone.utc).isoformat()

        record = {
            'id': baseline_data.get('id') or str(uuid.uuid4()),
            'organization_id': org_id,
            'entity_type': str(entity_type).lower().strip(),
            'entity_id': str(entity_id).strip(),
            'lookback_days': baseline_data.get('lookback_days', 90),
            'sample_count': baseline_data.get('sample_count', 0),
            'amount_stats': baseline_data.get('amount_stats', {}),
            'temporal_profile': baseline_data.get('temporal_profile', {}),
            'known_devices': list(baseline_data.get('known_devices', [])),
            'known_locations': list(baseline_data.get('known_locations', [])),
            'known_channels': list(baseline_data.get('known_channels', [])),
            'status': baseline_data.get('status', 'sufficient'),
            'last_calculated_at': now_iso,
            'created_at': baseline_data.get('created_at', now_iso),
            'updated_at': now_iso
        }
        _LOCAL_BASELINES[key] = record

        global _BASELINES_TABLE_EXISTS
        if save_db and _BASELINES_TABLE_EXISTS:
            try:
                sb = get_service_supabase()
                sb.table('entity_behavioral_baselines').upsert(record, on_conflict='organization_id,entity_type,entity_id').execute()
            except Exception as e:
                if 'PGRST205' in str(e) or 'does not exist' in str(e):
                    _BASELINES_TABLE_EXISTS = False
                logger.debug(f"Failed to persist seeded baseline to DB: {e}")

        return record

    @classmethod
    def calculate_baseline(
        cls,
        org_id: str,
        entity_type: str,
        entity_id: str,
        lookback_days: int = 90,
        min_samples: int = 5,
        save: bool = True
    ) -> Dict[str, Any]:
        """
        Calculates explainable baseline statistics over the specified lookback window.
        """
        org_id = str(org_id).strip()
        etype = str(entity_type).lower().strip()
        eid = str(entity_id).strip()

        now = datetime.now(timezone.utc)
        start_time = now - timedelta(days=lookback_days)

        # 1. Fetch matching historical events from local buffer and/or DB
        events: List[Dict[str, Any]] = []

        # Local cache check
        if org_id in _LOCAL_EVENTS:
            for ev in _LOCAL_EVENTS[org_id]:
                matches = False
                if etype == 'account':
                    matches = (ev.get('account_id') == eid or ev.get('account_id_pub') == eid or
                               (isinstance(ev.get('attributes'), dict) and ev['attributes'].get('account_id') == eid))
                elif etype == 'ip':
                    matches = (ev.get('source_ip') == eid)
                elif etype == 'device':
                    matches = (ev.get('device_id') == eid or ev.get('device_id_pub') == eid or
                               ev.get('device_fingerprint') == eid)
                elif etype == 'user':
                    matches = (ev.get('user_id') == eid or
                               (isinstance(ev.get('attributes'), dict) and ev['attributes'].get('user_id') == eid))

                if matches:
                    events.append(ev)

        # DB query if available
        try:
            sb = get_service_supabase()
            query = sb.table('security_events').select('*').eq('organization_id', org_id)
            if etype == 'account':
                query = query.eq('account_id_pub', eid)
            elif etype == 'ip':
                query = query.eq('source_ip', eid)
            elif etype == 'device':
                query = query.eq('device_id_pub', eid)

            query = query.gte('occurred_at', start_time.isoformat()).order('occurred_at', desc=True).limit(500)
            res = query.execute()
            if res and res.data:
                # Merge deduplicated by event_id
                seen_ids = {e.get('event_id') or e.get('id') for e in events if (e.get('event_id') or e.get('id'))}
                for row in res.data:
                    row_id = row.get('event_id') or row.get('id')
                    if row_id not in seen_ids:
                        events.append(row)
        except Exception as e:
            logger.debug(f"DB event lookup skipped or unavailable: {e}")

        sample_count = len(events)
        status = 'sufficient' if sample_count >= min_samples else 'insufficient_data'

        # 2. Extract metrics
        amounts: List[float] = []
        eat_hours: List[int] = []
        eat_days: List[int] = []
        devices: Set[str] = set()
        locations: Set[str] = set()
        channels: Set[str] = set()

        for ev in events:
            # Amount
            amt = None
            if ev.get('amount') is not None:
                amt = float(ev.get('amount'))
            elif ev.get('amount_minor') is not None:
                amt = float(ev.get('amount_minor')) / 100.0
            elif isinstance(ev.get('attributes'), dict) and ev['attributes'].get('amount') is not None:
                amt = float(ev['attributes']['amount'])

            if amt is not None and amt > 0:
                amounts.append(amt)

            # Temporal (EAT)
            occ = ev.get('occurred_at') or ev.get('created_at')
            if isinstance(ev.get('attributes'), dict) and ev['attributes'].get('local_hour') is not None:
                eat_hours.append(int(ev['attributes']['local_hour']) % 24)
            elif occ:
                eat_dt = _to_eat_datetime(occ)
                eat_hours.append(eat_dt.hour)
                eat_days.append(eat_dt.weekday())

            # Devices
            dev = ev.get('device_id') or ev.get('device_id_pub') or ev.get('device_fingerprint')
            if dev:
                devices.add(str(dev).strip())

            # Locations / IPs
            ip = ev.get('source_ip')
            if ip:
                locations.add(str(ip).strip())
            if isinstance(ev.get('attributes'), dict):
                loc = ev['attributes'].get('city') or ev['attributes'].get('location')
                if loc:
                    locations.add(str(loc).strip())

            # Channels
            ch = ev.get('channel') or (isinstance(ev.get('attributes'), dict) and ev['attributes'].get('channel'))
            if ch:
                channels.add(str(ch).lower().strip())

        # Compute Amount Stats
        amount_stats: Dict[str, Any] = {}
        if amounts:
            sorted_amt = sorted(amounts)
            p90_idx = int(0.9 * (len(sorted_amt) - 1))
            amount_stats = {
                'count': len(amounts),
                'min': round(min(amounts), 2),
                'max': round(max(amounts), 2),
                'mean': round(statistics.mean(amounts), 2),
                'median': round(statistics.median(amounts), 2),
                'std_dev': round(statistics.stdev(amounts), 2) if len(amounts) > 1 else 0.0,
                'p90': round(sorted_amt[p90_idx], 2)
            }

        # Compute Temporal Profile
        temporal_profile: Dict[str, Any] = {}
        if eat_hours:
            unique_hours = sorted(set(eat_hours))
            hr_counts = {h: eat_hours.count(h) for h in unique_hours}
            min_hr = min(unique_hours)
            max_hr = max(unique_hours)
            temporal_profile = {
                'active_hours': unique_hours,
                'hourly_distribution': hr_counts,
                'typical_window': {
                    'start_hour': min_hr,
                    'end_hour': max_hr
                },
                'typical_days': sorted(set(eat_days)) if eat_days else [0, 1, 2, 3, 4]
            }

        baseline_record = {
            'id': str(uuid.uuid4()),
            'organization_id': org_id,
            'entity_type': etype,
            'entity_id': eid,
            'lookback_days': lookback_days,
            'sample_count': sample_count,
            'amount_stats': amount_stats,
            'temporal_profile': temporal_profile,
            'known_devices': sorted(list(devices)),
            'known_locations': sorted(list(locations)),
            'known_channels': sorted(list(channels)),
            'status': status,
            'last_calculated_at': now.isoformat(),
            'created_at': now.isoformat(),
            'updated_at': now.isoformat()
        }

        # Save to local cache
        key = _baseline_key(org_id, etype, eid)
        _LOCAL_BASELINES[key] = baseline_record

        # Persist to PostgreSQL if requested
        global _BASELINES_TABLE_EXISTS
        if save and _BASELINES_TABLE_EXISTS:
            try:
                sb = get_service_supabase()
                sb.table('entity_behavioral_baselines').upsert(baseline_record, on_conflict='organization_id,entity_type,entity_id').execute()
            except Exception as e:
                if 'PGRST205' in str(e) or 'does not exist' in str(e):
                    _BASELINES_TABLE_EXISTS = False
                logger.debug(f"Failed to persist baseline to DB: {e}")

        return baseline_record

    @classmethod
    def get_baseline(
        cls,
        org_id: str,
        entity_type: str,
        entity_id: str,
        auto_compute: bool = True
    ) -> Optional[Dict[str, Any]]:
        """
        Retrieves baseline from memory cache or database. Auto-computes if missing.
        """
        org_id = str(org_id).strip()
        etype = str(entity_type).lower().strip()
        eid = str(entity_id).strip()
        key = _baseline_key(org_id, etype, eid)

        # 1. Local Cache
        if key in _LOCAL_BASELINES:
            return _LOCAL_BASELINES[key]

        # 2. Database Lookup
        global _BASELINES_TABLE_EXISTS
        if _BASELINES_TABLE_EXISTS:
            try:
                sb = get_service_supabase()
                res = sb.table('entity_behavioral_baselines').select('*')\
                    .eq('organization_id', org_id)\
                    .eq('entity_type', etype)\
                    .eq('entity_id', eid)\
                    .execute()
                if res and res.data and len(res.data) > 0:
                    rec = res.data[0]
                    _LOCAL_BASELINES[key] = rec
                    return rec
            except Exception as e:
                if 'PGRST205' in str(e) or 'does not exist' in str(e):
                    _BASELINES_TABLE_EXISTS = False
                logger.debug(f"DB baseline fetch error: {e}")

        # 3. Auto-compute if requested
        if auto_compute:
            return cls.calculate_baseline(org_id, etype, eid)

        return None

    @classmethod
    def evaluate_event_against_baseline(
        cls,
        event: Dict[str, Any],
        org_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Evaluates event across 4 statistical dimensions (amounts, hours, devices, geos/channels).
        Returns explainable deviations with plain English summaries.
        Falls back deterministically when data is thin.
        """
        oid = org_id or event.get('organization_id') or get_current_organization_id()
        if not oid:
            oid = "00000000-0000-0000-0000-000000000001"
        oid = str(oid).strip()

        account_id = event.get('account_id') or event.get('account_id_pub')
        if not account_id and isinstance(event.get('attributes'), dict):
            account_id = event['attributes'].get('account_id')

        # Fallback entity: source_ip if no account
        entity_type = 'account' if account_id else 'ip'
        entity_id = account_id or event.get('source_ip') or 'unknown'

        baseline = cls.get_baseline(oid, entity_type, entity_id)

        # -------------------------------------------------------------
        # Deterministic Fallback when History is Thin (< 5 events)
        # -------------------------------------------------------------
        sample_count = baseline.get('sample_count', 0) if baseline else 0
        if not baseline or baseline.get('status') == 'insufficient_data' or sample_count < 5:
            fallback_reason = (
                f"Insufficient historical baseline ({sample_count} < 5 events); "
                "fallback to platform policy defaults"
            )
            return {
                'entity_type': entity_type,
                'entity_id': entity_id,
                'organization_id': oid,
                'is_anomalous': False,
                'anomaly_score': 0,
                'data_sufficiency': 'insufficient',
                'sample_count': sample_count,
                'deterministic_fallback': True,
                'signals': [],
                'explanations': [fallback_reason],
                'evaluated_at': datetime.now(timezone.utc).isoformat()
            }

        # -------------------------------------------------------------
        # Sufficient Baseline: Evaluate 4 Explainable Dimensions
        # -------------------------------------------------------------
        signals: List[Dict[str, Any]] = []
        lookback_days = baseline.get('lookback_days', 90)

        # 1. Amount Multiplier vs Median
        amount_val = None
        if event.get('amount') is not None:
            amount_val = float(event['amount'])
        elif event.get('amount_minor') is not None:
            amount_val = float(event['amount_minor']) / 100.0
        elif isinstance(event.get('attributes'), dict) and event['attributes'].get('amount') is not None:
            amount_val = float(event['attributes']['amount'])

        amount_stats = baseline.get('amount_stats', {})
        median_val = amount_stats.get('median', 0.0)

        if amount_val is not None and amount_val > 0 and median_val > 0:
            ratio = amount_val / median_val
            if ratio >= 3.0:
                if ratio >= 10.0:
                    dev_score = 45
                    severity = 'critical'
                elif ratio >= 5.0:
                    dev_score = 35
                    severity = 'high'
                else:
                    dev_score = 20
                    severity = 'medium'

                explanation = (
                    f"amount is {ratio:.1f}× this account's {lookback_days}-day median "
                    f"({median_val:,.0f} ETB)"
                )
                signals.append({
                    'dimension': 'amount',
                    'deviation_score': dev_score,
                    'severity': severity,
                    'ratio': round(ratio, 2),
                    'metric_value': amount_val,
                    'baseline_value': median_val,
                    'explanation': explanation
                })

        # 2. Temporal Profile (Operating Hours EAT)
        temporal_profile = baseline.get('temporal_profile', {})
        active_hours = temporal_profile.get('active_hours', [])
        typical_window = temporal_profile.get('typical_window', {})

        event_hour = None
        if isinstance(event.get('attributes'), dict) and event['attributes'].get('local_hour') is not None:
            event_hour = int(event['attributes']['local_hour']) % 24
        else:
            occ = event.get('occurred_at') or event.get('created_at')
            if occ:
                event_hour = _to_eat_datetime(occ).hour

        if event_hour is not None and active_hours and typical_window:
            start_hr = typical_window.get('start_hour', 0)
            end_hr = typical_window.get('end_hour', 23)

            # If activity is outside established active window
            if event_hour not in active_hours and (event_hour < start_hr or event_hour > end_hr):
                explanation = (
                    f"Activity at {event_hour:02d}:00 EAT is outside typical operating window "
                    f"({start_hr:02d}:00 - {end_hr:02d}:00 EAT) for this account"
                )
                signals.append({
                    'dimension': 'temporal',
                    'deviation_score': 25,
                    'severity': 'medium',
                    'metric_value': event_hour,
                    'baseline_value': typical_window,
                    'explanation': explanation
                })

        # 3. Known Device Check
        known_devices = baseline.get('known_devices', [])
        event_device = event.get('device_id') or event.get('device_id_pub') or event.get('device_fingerprint')
        if not event_device and isinstance(event.get('attributes'), dict):
            event_device = event['attributes'].get('device_id') or event['attributes'].get('device_fingerprint')

        if event_device and known_devices:
            dev_str = str(event_device).strip()
            if dev_str not in known_devices:
                explanation = (
                    f"Device '{dev_str}' has never been observed for this account "
                    f"in the past {lookback_days} days"
                )
                signals.append({
                    'dimension': 'device',
                    'deviation_score': 25,
                    'severity': 'medium',
                    'metric_value': dev_str,
                    'baseline_value': known_devices,
                    'explanation': explanation
                })

        # 4. Known Location / IP Check
        known_locations = baseline.get('known_locations', [])
        event_ip = event.get('source_ip')
        if event_ip and known_locations and len(known_locations) >= 2:
            ip_str = str(event_ip).strip()
            if ip_str not in known_locations:
                explanation = (
                    f"Access from unfamiliar IP '{ip_str}' differs from typical "
                    f"baseline locations"
                )
                signals.append({
                    'dimension': 'location',
                    'deviation_score': 15,
                    'severity': 'low',
                    'metric_value': ip_str,
                    'baseline_value': known_locations,
                    'explanation': explanation
                })

        # 5. Channel Anomaly (e.g. USSD vs App)
        known_channels = baseline.get('known_channels', [])
        event_ch = event.get('channel') or (isinstance(event.get('attributes'), dict) and event['attributes'].get('channel'))
        if event_ch and known_channels and len(known_channels) >= 1:
            ch_str = str(event_ch).lower().strip()
            if ch_str not in known_channels:
                explanation = f"Transaction via channel '{ch_str}' is unprecedented for this account"
                signals.append({
                    'dimension': 'channel',
                    'deviation_score': 20,
                    'severity': 'medium',
                    'metric_value': ch_str,
                    'baseline_value': known_channels,
                    'explanation': explanation
                })

        # Synthesis
        total_score = min(sum(s['deviation_score'] for s in signals), 100)
        is_anomalous = total_score >= 20

        return {
            'entity_type': entity_type,
            'entity_id': entity_id,
            'organization_id': oid,
            'is_anomalous': is_anomalous,
            'anomaly_score': total_score,
            'data_sufficiency': 'sufficient',
            'sample_count': sample_count,
            'deterministic_fallback': False,
            'signals': signals,
            'explanations': [s['explanation'] for s in signals],
            'evaluated_at': datetime.now(timezone.utc).isoformat()
        }

    @classmethod
    def get_baseline_summary(cls, org_id: str) -> Dict[str, Any]:
        """
        Returns high-level statistics of baselines for a specific tenant.
        """
        oid = str(org_id).strip()
        baselines = [b for k, b in _LOCAL_BASELINES.items() if b.get('organization_id') == oid]

        # Attempt to augment from DB
        try:
            sb = get_service_supabase()
            res = sb.table('entity_behavioral_baselines').select('*').eq('organization_id', oid).execute()
            if res and res.data:
                seen_keys = {b['id'] for b in baselines}
                for r in res.data:
                    if r.get('id') not in seen_keys:
                        baselines.append(r)
        except Exception:
            pass

        sufficient_count = sum(1 for b in baselines if b.get('status') == 'sufficient')
        insufficient_count = sum(1 for b in baselines if b.get('status') == 'insufficient_data')

        accounts_count = sum(1 for b in baselines if b.get('entity_type') == 'account')
        ips_count = sum(1 for b in baselines if b.get('entity_type') == 'ip')
        devices_count = sum(1 for b in baselines if b.get('entity_type') == 'device')

        avg_samples = (
            round(sum(b.get('sample_count', 0) for b in baselines) / len(baselines), 1)
            if baselines else 0.0
        )

        return {
            'organization_id': oid,
            'total_baselines': len(baselines),
            'sufficient_baselines': sufficient_count,
            'insufficient_baselines': insufficient_count,
            'accounts_count': accounts_count,
            'ips_count': ips_count,
            'devices_count': devices_count,
            'average_samples_per_entity': avg_samples,
            'timestamp': datetime.now(timezone.utc).isoformat()
        }

    @classmethod
    def list_baselines(
        cls,
        org_id: str,
        entity_type: Optional[str] = None,
        status: Optional[str] = None,
        limit: int = 50
    ) -> List[Dict[str, Any]]:
        """
        Lists tenant baselines with optional entity_type and status filters.
        """
        oid = str(org_id).strip()
        results = [b for k, b in _LOCAL_BASELINES.items() if b.get('organization_id') == oid]

        if entity_type:
            results = [b for b in results if b.get('entity_type') == str(entity_type).lower().strip()]
        if status:
            results = [b for b in results if b.get('status') == status]

        return results[:limit]
