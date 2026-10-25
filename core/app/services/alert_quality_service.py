"""
Ethio-Cyber-Shield (ECS) — Alert Quality & Fatigue Reduction Service (Phase 3.7).

Implements:
1. Deterministic alert fingerprinting via SHA-256 over invariant incident attributes.
2. Sliding-window alert deduplication with counter increment and dynamic severity escalation.
3. Time-based suppression windows for scheduled maintenance, load testing, or tuning.
4. Entity-centric alert grouping and attack-chain correlation.
5. Real-time alert fatigue reduction metrics (reduction rate, dedupe ratio, fatigue health grade).
Multi-tenant partitioned strictly by organization_id UUID NOT NULL.
"""
import uuid
import hashlib
import logging
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional, Tuple

from app.services.db import get_service_supabase
from app.services.tenant_service import get_current_organization_id

logger = logging.getLogger(__name__)

# Default time windows
DEFAULT_DEDUPE_WINDOW_SECONDS = 900       # 15 minutes
DEFAULT_GROUPING_WINDOW_SECONDS = 1800     # 30 minutes
DEFAULT_SUPPRESSION_MINUTES = 60          # 1 hour

# In-memory stores for ultra-low latency deduplication and unit test isolation
_LOCAL_SUPPRESSIONS: Dict[str, Dict[str, Any]] = {}
_LOCAL_OPEN_ALERTS: Dict[str, Dict[str, Any]] = {}       # Keyed by (org_id, fingerprint)
_LOCAL_ENTITY_GROUPS: Dict[str, Dict[str, Any]] = {}     # Keyed by (org_id, entity_type, entity_id)
_TENANT_METRICS: Dict[str, Dict[str, int]] = {}          # Keyed by org_id


def clear_alert_quality_caches():
    """Resets in-memory deduplication, grouping, and metrics stores for testing."""
    _LOCAL_SUPPRESSIONS.clear()
    _LOCAL_OPEN_ALERTS.clear()
    _LOCAL_ENTITY_GROUPS.clear()
    _TENANT_METRICS.clear()


def _parse_utc_datetime(dt_val: Any) -> datetime:
    if isinstance(dt_val, str):
        try:
            iso_str = dt_val.replace('Z', '+00:00')
            parsed = datetime.fromisoformat(iso_str)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed.astimezone(timezone.utc)
        except Exception:
            return datetime.now(timezone.utc)
    elif isinstance(dt_val, datetime):
        if dt_val.tzinfo is None:
            dt_val = dt_val.replace(tzinfo=timezone.utc)
        return dt_val.astimezone(timezone.utc)
    return datetime.now(timezone.utc)


class AlertQualityService:
    """
    Stateless and cached alert quality processing engine.
    """

    @classmethod
    def generate_fingerprint(
        cls,
        org_id: str,
        rule_id: str,
        entity_type: str,
        entity_id: str,
        alert_type: str
    ) -> str:
        """
        Produces a deterministic SHA-256 fingerprint for invariant incident attributes.
        """
        raw = f"{str(org_id).strip()}:{str(rule_id).strip()}:{str(entity_type).lower().strip()}:{str(entity_id).strip()}:{str(alert_type).lower().strip()}"
        return hashlib.sha256(raw.encode('utf-8')).hexdigest()

    @classmethod
    def _get_tenant_metrics(cls, org_id: str) -> Dict[str, int]:
        oid = str(org_id).strip()
        if oid not in _TENANT_METRICS:
            _TENANT_METRICS[oid] = {
                'total_evaluated': 0,
                'created': 0,
                'deduplicated': 0,
                'suppressed': 0
            }
        return _TENANT_METRICS[oid]

    # =========================================================================
    # 1. SUPPRESSION WINDOW MANAGEMENT
    # =========================================================================

    @classmethod
    def create_suppression_rule(
        cls,
        org_id: str,
        entity_type: str,
        entity_id: str,
        rule_id: str = "*",
        reason: str = "Authorized Maintenance Window",
        duration_minutes: int = DEFAULT_SUPPRESSION_MINUTES,
        created_by: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Creates a time-based suppression rule on an entity or specific detection rule.
        """
        oid = str(org_id).strip()
        etype = str(entity_type).lower().strip()
        eid = str(entity_id).strip()
        rid = str(rule_id).strip()
        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(minutes=duration_minutes)

        supp_id = str(uuid.uuid4())
        record = {
            'id': supp_id,
            'organization_id': oid,
            'entity_type': etype,
            'entity_id': eid,
            'rule_id': rid,
            'reason': reason,
            'duration_minutes': duration_minutes,
            'created_at': now.isoformat(),
            'expires_at': expires_at.isoformat(),
            'created_by': created_by or "system",
            'is_active': True
        }

        _LOCAL_SUPPRESSIONS[supp_id] = record

        # Persist to database if available
        try:
            sb = get_service_supabase()
            sb.table('alert_suppression_rules').insert(record).execute()
        except Exception as e:
            logger.debug(f"Could not persist alert_suppression_rule to db: {e}")

        return dict(record)

    @classmethod
    def revoke_suppression_rule(cls, org_id: str, suppression_id: str) -> bool:
        """
        Revokes an active suppression rule early.
        """
        oid = str(org_id).strip()
        sid = str(suppression_id).strip()

        if sid in _LOCAL_SUPPRESSIONS:
            if _LOCAL_SUPPRESSIONS[sid].get('organization_id') == oid:
                _LOCAL_SUPPRESSIONS[sid]['is_active'] = False

        try:
            sb = get_service_supabase()
            sb.table('alert_suppression_rules').update({'is_active': False})\
                .eq('organization_id', oid).eq('id', sid).execute()
        except Exception as e:
            logger.debug(f"Suppression rule database revocation fallback: {e}")

        return True

    @classmethod
    def list_active_suppressions(
        cls,
        org_id: str,
        entity_type: Optional[str] = None,
        entity_id: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Lists unexpired active suppression rules for the tenant.
        """
        oid = str(org_id).strip()
        now = datetime.now(timezone.utc)
        active: List[Dict[str, Any]] = []

        # Local cache
        for s in _LOCAL_SUPPRESSIONS.values():
            if s.get('organization_id') != oid or not s.get('is_active'):
                continue
            exp = _parse_utc_datetime(s.get('expires_at'))
            if exp > now:
                if entity_type and s.get('entity_type') != str(entity_type).lower().strip():
                    continue
                if entity_id and s.get('entity_id') != str(entity_id).strip():
                    continue
                active.append(dict(s))

        # Also load from database
        try:
            sb = get_service_supabase()
            q = sb.table('alert_suppression_rules').select('*')\
                .eq('organization_id', oid)\
                .eq('is_active', True)\
                .gt('expires_at', now.isoformat())
            if entity_type:
                q = q.eq('entity_type', str(entity_type).lower().strip())
            if entity_id:
                q = q.eq('entity_id', str(entity_id).strip())
            res = q.execute()
            if res.data:
                existing_ids = {a['id'] for a in active}
                for row in res.data:
                    if row['id'] not in existing_ids:
                        active.append(dict(row))
        except Exception as e:
            logger.debug(f"Could not load alert_suppression_rules from db: {e}")

        return active

    @classmethod
    def check_is_suppressed(
        cls,
        org_id: str,
        entity_type: str,
        entity_id: str,
        rule_id: str
    ) -> Tuple[bool, Optional[str]]:
        """
        Checks if candidate alert matches an active, unexpired suppression rule.
        Returns: (is_suppressed, reason)
        """
        active_rules = cls.list_active_suppressions(org_id, entity_type, entity_id)
        for supp in active_rules:
            s_rule = supp.get('rule_id', '*')
            if s_rule == '*' or s_rule == rule_id:
                return True, supp.get('reason', 'Active suppression rule')
        return False, None

    # =========================================================================
    # 2. CANDIDATE ALERT PROCESSING (DEDUPE + GROUP + SUPPRESS)
    # =========================================================================

    @classmethod
    def process_candidate_alert(
        cls,
        candidate_alert: Dict[str, Any],
        org_id: Optional[str] = None,
        dedupe_window_seconds: int = DEFAULT_DEDUPE_WINDOW_SECONDS,
        grouping_window_seconds: int = DEFAULT_GROUPING_WINDOW_SECONDS
    ) -> Dict[str, Any]:
        """
        Processes a candidate alert generated by detection rules:
        1. Checks active suppression rules.
        2. Evaluates deduplication against open alerts within sliding window.
        3. Correlates entity into alert groups.
        4. Inserts new alert or updates duplicate count and peak severity.
        """
        oid = org_id or candidate_alert.get('organization_id') or get_current_organization_id() or "00000000-0000-0000-0000-000000000001"
        metrics = cls._get_tenant_metrics(oid)
        metrics['total_evaluated'] += 1

        primary_rule = candidate_alert.get('primary_rule_id') or candidate_alert.get('rule_id') or "GENERAL"
        etype = candidate_alert.get('entity_type') or "account"
        eid = candidate_alert.get('entity_id') or candidate_alert.get('account') or candidate_alert.get('source_ip') or "unknown"
        atype = candidate_alert.get('alert_type') or "high_risk"
        score = int(candidate_alert.get('risk_score', 0))
        sev = candidate_alert.get('severity', 'medium')
        now = datetime.now(timezone.utc)
        now_iso = now.isoformat()

        # Step 1: Active Suppression Check
        is_supp, supp_reason = cls.check_is_suppressed(oid, etype, eid, primary_rule)
        if is_supp:
            metrics['suppressed'] += 1
            return {
                'action': 'suppressed',
                'reason': supp_reason,
                'alert': None,
                'is_suppressed': True
            }

        # Step 2: Fingerprint calculation
        fingerprint = cls.generate_fingerprint(oid, primary_rule, etype, eid, atype)
        fp_key = f"{oid}:{fingerprint}"

        # Step 3: Deduplication check against open alert
        existing_alert = _LOCAL_OPEN_ALERTS.get(fp_key)
        
        # Check database for existing open alert with same fingerprint if not in local cache
        if not existing_alert:
            try:
                sb = get_service_supabase()
                cutoff = (now - timedelta(seconds=dedupe_window_seconds)).isoformat()
                q = sb.table('alerts').select('*')\
                    .eq('organization_id', oid)\
                    .eq('fingerprint', fingerprint)\
                    .eq('status', 'open')\
                    .gte('last_seen_at', cutoff)\
                    .order('created_at', desc=True)\
                    .limit(1)
                res = q.execute()
                if res.data and len(res.data) > 0:
                    existing_alert = res.data[0]
                    _LOCAL_OPEN_ALERTS[fp_key] = existing_alert
            except Exception as e:
                logger.debug(f"Could not query open alerts from db: {e}")

        if existing_alert:
            # Check within deduplication window
            last_seen = _parse_utc_datetime(existing_alert.get('last_seen_at') or existing_alert.get('created_at'))
            if (now - last_seen).total_seconds() <= dedupe_window_seconds and existing_alert.get('status', 'open') == 'open':
                # Absorbed as DUPLICATE
                metrics['deduplicated'] += 1
                new_count = int(existing_alert.get('duplicate_count', 1)) + 1
                existing_alert['duplicate_count'] = new_count
                existing_alert['last_seen_at'] = now_iso

                # Risk score and severity escalation if new event is higher
                old_score = int(existing_alert.get('risk_score', 0))
                if score > old_score:
                    existing_alert['risk_score'] = score
                    existing_alert['severity'] = sev
                    existing_alert['title'] = candidate_alert.get('title', existing_alert.get('title'))

                # Append trigger event id
                new_evt = candidate_alert.get('trigger_event_id')
                if new_evt:
                    rel = existing_alert.get('related_event_ids') or []
                    if new_evt not in rel:
                        rel.append(new_evt)
                    existing_alert['related_event_ids'] = rel

                # Update in DB
                try:
                    sb = get_service_supabase()
                    sb.table('alerts').update({
                        'duplicate_count': new_count,
                        'last_seen_at': now_iso,
                        'risk_score': existing_alert['risk_score'],
                        'severity': existing_alert['severity'],
                        'title': existing_alert['title']
                    }).eq('id', existing_alert['id']).execute()
                except Exception as e:
                    logger.debug(f"Alert update db fallback: {e}")

                return {
                    'action': 'deduplicated',
                    'alert': dict(existing_alert),
                    'duplicate_count': new_count,
                    'is_suppressed': False
                }

        # Step 4: Entity Alert Grouping / Correlation
        grp_key = f"{oid}:{etype}:{eid}"
        existing_grp = _LOCAL_ENTITY_GROUPS.get(grp_key)
        group_id = None

        if existing_grp:
            grp_time = _parse_utc_datetime(existing_grp.get('created_at'))
            if (now - grp_time).total_seconds() <= grouping_window_seconds:
                group_id = existing_grp.get('group_id')

        if not group_id:
            group_id = str(uuid.uuid4())
            _LOCAL_ENTITY_GROUPS[grp_key] = {
                'group_id': group_id,
                'created_at': now_iso
            }

        # Step 5: Create brand new alert record
        metrics['created'] += 1
        new_alert_id = candidate_alert.get('id') or str(uuid.uuid4())
        created_record = {
            'id': new_alert_id,
            'organization_id': oid,
            'title': candidate_alert.get('title', 'Security Alert'),
            'severity': sev,
            'status': 'open',
            'alert_type': atype,
            'risk_score': score,
            'fingerprint': fingerprint,
            'duplicate_count': 1,
            'group_id': group_id,
            'created_at': now_iso,
            'last_seen_at': now_iso,
            'entity_type': etype,
            'entity_id': eid,
            'description': candidate_alert.get('description', ''),
            'evidence': candidate_alert.get('evidence', {}),
            'target_system_id': candidate_alert.get('target_system_id'),
            'related_event_ids': [candidate_alert.get('trigger_event_id')] if candidate_alert.get('trigger_event_id') else [],
            'is_suppressed': False
        }

        _LOCAL_OPEN_ALERTS[fp_key] = created_record

        # Persist to database
        try:
            sb = get_service_supabase()
            valid_alert_types = {'account_takeover', 'suspicious_transaction', 'high_risk', 'other'}
            raw_atype = created_record.get('alert_type')
            if raw_atype not in valid_alert_types:
                clean_type = 'high_risk' if created_record.get('severity') in ('high', 'critical') else 'other'
            else:
                clean_type = raw_atype

            clean_alert = {
                'organization_id': oid or created_record.get('organization_id') or '00000000-0000-0000-0000-000000000001',
                'title': created_record.get('title', 'Security Alert'),
                'description': created_record.get('description', ''),
                'severity': created_record.get('severity', 'medium'),
                'status': created_record.get('status', 'open'),
                'alert_type': clean_type,
                'risk_score': created_record.get('risk_score', 0),
                'evidence': created_record.get('evidence', {}),
            }
            try:
                res_ins = sb.table('alerts').insert(clean_alert).execute()
            except Exception:
                legacy_alert = {
                    'title': clean_alert['title'],
                    'description': clean_alert['description'],
                    'severity': clean_alert['severity'],
                    'status': clean_alert['status'],
                    'alert_type': clean_alert['alert_type'],
                }
                res_ins = sb.table('alerts').insert(legacy_alert).execute()

            if res_ins.data and len(res_ins.data) > 0:
                created_record['id'] = res_ins.data[0]['id']
                try:
                    from app.routes.alerts import _ALERT_ORGS
                    _ALERT_ORGS[str(created_record['id'])] = oid
                except Exception:
                    pass
        except Exception as e:
            logger.error(f"Alert insertion failed: {e}")

        return {
            'action': 'created',
            'alert': dict(created_record),
            'duplicate_count': 1,
            'is_suppressed': False
        }

    # =========================================================================
    # 3. FATIGUE REDUCTION METRICS
    # =========================================================================

    @classmethod
    def get_fatigue_metrics(cls, org_id: str) -> Dict[str, Any]:
        """
        Computes alert reduction rates, duplicate ratios, and SOC fatigue health grade.
        """
        oid = str(org_id).strip()
        metrics = cls._get_tenant_metrics(oid)

        tot = metrics['total_evaluated']
        created = metrics['created']
        deduped = metrics['deduplicated']
        suppressed = metrics['suppressed']

        reduction_rate = round((deduped + suppressed) / tot, 4) if tot > 0 else 0.0

        # Mean duplicate count per open alert
        open_alerts = [a for k, a in _LOCAL_OPEN_ALERTS.items() if a.get('organization_id') == oid]
        if open_alerts:
            avg_dupes = round(sum(int(a.get('duplicate_count', 1)) for a in open_alerts) / len(open_alerts), 2)
        else:
            avg_dupes = 1.0

        # Fatigue Health Grade
        if tot == 0:
            fatigue_grade = 'Optimal'
        elif reduction_rate >= 0.70:
            fatigue_grade = 'Optimal'
        elif reduction_rate >= 0.50:
            fatigue_grade = 'Good'
        elif reduction_rate >= 0.30:
            fatigue_grade = 'Moderate'
        else:
            fatigue_grade = 'Critical Fatigue'

        return {
            'organization_id': oid,
            'total_alerts_evaluated': tot,
            'alerts_created': created,
            'alerts_deduplicated': deduped,
            'alerts_suppressed': suppressed,
            'alert_reduction_rate': reduction_rate,
            'reduction_percentage': f"{reduction_rate:.1%}",
            'average_duplicates_per_alert': avg_dupes,
            'active_suppression_windows': len(cls.list_active_suppressions(oid)),
            'fatigue_grade': fatigue_grade
        }
