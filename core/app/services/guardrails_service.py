"""
Ethio-Cyber-Shield (ECS) — Guardrails Service (Phase 4.2).

Enforces strict containment blast-radius limits and safety controls:
1. Per-tenant Emergency Kill Switch halting automated containment.
2. Allowlists protecting critical national infrastructure IPs (EthSwitch, RTGS) and VIP/staff accounts.
3. Blast Radius Rate Limits (hourly and daily action caps per tenant).
4. Entity Cooldowns preventing repeat actions on the same entity within sliding window.
5. Minimum detection confidence threshold enforcement.
6. Complete audit logging of every guardrail decision.
Multi-tenant partitioned strictly by organization_id UUID NOT NULL.
"""
import uuid
import logging
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional, Tuple

from app.services.db import get_service_supabase
from app.services.tenant_service import get_current_organization_id

logger = logging.getLogger(__name__)

CONFIDENCE_LEVELS = {'low': 1, 'medium': 2, 'high': 3}

# In-memory stores for fast lookups & test isolation
_TENANT_CONFIGS: Dict[str, Dict[str, Any]] = {}
_ALLOWLISTS: Dict[Tuple[str, str, str], Dict[str, Any]] = {}  # Key: (org_id, entity_type, entity_id)
_ACTION_TIMESTAMPS: Dict[str, List[datetime]] = {}           # Key: org_id
_ENTITY_LAST_ACTION: Dict[Tuple[str, str, str], datetime] = {} # Key: (org_id, entity_type, entity_id)
_GUARDRAIL_AUDIT_LOGS: Dict[str, List[Dict[str, Any]]] = {}   # Key: org_id


def clear_guardrail_caches():
    """Resets in-memory guardrail configs, allowlists, and rate limit counters for testing."""
    _TENANT_CONFIGS.clear()
    _ALLOWLISTS.clear()
    _ACTION_TIMESTAMPS.clear()
    _ENTITY_LAST_ACTION.clear()
    _GUARDRAIL_AUDIT_LOGS.clear()


class GuardrailsService:
    """
    Evaluates safety guardrails before any automated or playbook mitigation is dispatched.
    """

    @classmethod
    def get_guardrail_config(cls, org_id: str) -> Dict[str, Any]:
        """Returns the guardrail configuration for the tenant, or default values."""
        oid = str(org_id).strip()
        if oid in _TENANT_CONFIGS:
            return dict(_TENANT_CONFIGS[oid])

        # Load from database if available
        try:
            sb = get_service_supabase()
            res = sb.table('tenant_guardrails').select('*').eq('organization_id', oid).limit(1).execute()
            if res.data and len(res.data) > 0:
                cfg = res.data[0]
                _TENANT_CONFIGS[oid] = cfg
                return dict(cfg)
        except Exception as e:
            logger.debug(f"DB lookup fallback for tenant guardrails: {e}")

        # Default configuration
        default_cfg = {
            'organization_id': oid,
            'emergency_kill_switch': False,
            'max_actions_per_hour': 20,
            'max_actions_per_day': 100,
            'cooldown_seconds': 900,         # 15 minutes
            'min_confidence': 'high',
            'default_ttl_minutes': 60,
            'updated_at': datetime.now(timezone.utc).isoformat()
        }
        _TENANT_CONFIGS[oid] = default_cfg
        return dict(default_cfg)

    @classmethod
    def configure_guardrails(cls, org_id: str, **kwargs) -> Dict[str, Any]:
        """Updates guardrail parameters for a tenant."""
        oid = str(org_id).strip()
        cfg = cls.get_guardrail_config(oid)

        for k, v in kwargs.items():
            if k in ('emergency_kill_switch', 'max_actions_per_hour', 'max_actions_per_day', 'cooldown_seconds', 'min_confidence', 'default_ttl_minutes'):
                cfg[k] = v

        cfg['updated_at'] = datetime.now(timezone.utc).isoformat()
        _TENANT_CONFIGS[oid] = cfg

        try:
            sb = get_service_supabase()
            sb.table('tenant_guardrails').upsert(cfg, on_conflict='organization_id').execute()
        except Exception as e:
            logger.debug(f"Could not persist tenant_guardrails to db: {e}")

        return dict(cfg)

    @classmethod
    def set_kill_switch(cls, org_id: str, enabled: bool, updated_by: Optional[str] = None) -> Dict[str, Any]:
        """Toggles the tenant emergency kill switch."""
        return cls.configure_guardrails(org_id, emergency_kill_switch=bool(enabled))

    # =========================================================================
    # ALLOWLISTS & PROTECTED ENTITIES
    # =========================================================================

    @classmethod
    def add_to_allowlist(
        cls,
        org_id: str,
        entity_type: str,
        entity_id: str,
        reason: str = "Authorized Protected Entity",
        created_by: Optional[str] = None
    ) -> Dict[str, Any]:
        """Adds an entity to the tenant allowlist."""
        oid = str(org_id).strip()
        etype = str(entity_type).lower().strip()
        eid = str(entity_id).strip()
        now_iso = datetime.now(timezone.utc).isoformat()

        record = {
            'id': str(uuid.uuid4()),
            'organization_id': oid,
            'entity_type': etype,
            'entity_id': eid,
            'reason': reason,
            'created_by': created_by or "system",
            'created_at': now_iso
        }
        _ALLOWLISTS[(oid, etype, eid)] = record

        try:
            sb = get_service_supabase()
            sb.table('tenant_allowlists').insert(record).execute()
        except Exception as e:
            logger.debug(f"Allowlist db insertion fallback: {e}")

        return dict(record)

    @classmethod
    def remove_from_allowlist(cls, org_id: str, entity_type: str, entity_id: str) -> bool:
        """Removes an entity from the tenant allowlist."""
        oid = str(org_id).strip()
        etype = str(entity_type).lower().strip()
        eid = str(entity_id).strip()

        _ALLOWLISTS.pop((oid, etype, eid), None)

        try:
            sb = get_service_supabase()
            sb.table('tenant_allowlists').delete().eq('organization_id', oid).eq('entity_type', etype).eq('entity_id', eid).execute()
        except Exception as e:
            logger.debug(f"Allowlist db delete fallback: {e}")

        return True

    @classmethod
    def is_allowlisted(cls, org_id: str, entity_type: str, entity_id: str) -> bool:
        """Checks if an entity is in the tenant allowlist."""
        oid = str(org_id).strip()
        etype = str(entity_type).lower().strip()
        eid = str(entity_id).strip()

        if (oid, etype, eid) in _ALLOWLISTS:
            return True

        # Check database
        try:
            sb = get_service_supabase()
            res = sb.table('tenant_allowlists').select('id')\
                .eq('organization_id', oid)\
                .eq('entity_type', etype)\
                .eq('entity_id', eid)\
                .limit(1).execute()
            if res.data and len(res.data) > 0:
                _ALLOWLISTS[(oid, etype, eid)] = {'organization_id': oid, 'entity_type': etype, 'entity_id': eid}
                return True
        except Exception as e:
            logger.debug(f"Allowlist db lookup fallback: {e}")

        return False

    @classmethod
    def list_allowlist(cls, org_id: str, entity_type: Optional[str] = None) -> List[Dict[str, Any]]:
        """Lists allowlisted entities for the tenant."""
        oid = str(org_id).strip()
        items: List[Dict[str, Any]] = []

        for (k_org, k_etype, k_eid), rec in _ALLOWLISTS.items():
            if k_org == oid:
                if entity_type and k_etype != str(entity_type).lower().strip():
                    continue
                items.append(dict(rec))

        try:
            sb = get_service_supabase()
            q = sb.table('tenant_allowlists').select('*').eq('organization_id', oid)
            if entity_type:
                q = q.eq('entity_type', str(entity_type).lower().strip())
            res = q.execute()
            if res.data:
                existing_keys = {(i['entity_type'], i['entity_id']) for i in items}
                for r in res.data:
                    if (r['entity_type'], r['entity_id']) not in existing_keys:
                        items.append(dict(r))
        except Exception as e:
            logger.debug(f"Allowlist db list fallback: {e}")

        return items

    # =========================================================================
    # GUARDRAIL EVALUATION & RATE LIMITS
    # =========================================================================

    @classmethod
    def record_action_execution(cls, org_id: str, action_type: str, entity_type: str, entity_id: str):
        """Records an executed action timestamp for rate-limit and cooldown tracking."""
        oid = str(org_id).strip()
        etype = str(entity_type).lower().strip()
        eid = str(entity_id).strip()
        now = datetime.now(timezone.utc)

        if oid not in _ACTION_TIMESTAMPS:
            _ACTION_TIMESTAMPS[oid] = []
        _ACTION_TIMESTAMPS[oid].append(now)

        _ENTITY_LAST_ACTION[(oid, etype, eid)] = now

    @classmethod
    def evaluate_guardrails(
        cls,
        org_id: str,
        action_type: str,
        entity_type: str,
        entity_id: str,
        confidence: str = 'high'
    ) -> Dict[str, Any]:
        """
        Evaluates all safety guardrails sequentially:
        1. Emergency Kill Switch.
        2. Allowlists & Protected Entities.
        3. Confidence Threshold.
        4. Entity Cooldown Window.
        5. Blast Radius Hourly Rate Limits.
        6. Blast Radius Daily Rate Limits.
        Logs every decision to guardrail audit trail.
        """
        oid = str(org_id).strip()
        etype = str(entity_type).lower().strip()
        eid = str(entity_id).strip()
        cfg = cls.get_guardrail_config(oid)
        now = datetime.now(timezone.utc)

        decision = 'passed'
        blocked_by = None
        reason = None

        # 1. Emergency Kill Switch Check
        if cfg.get('emergency_kill_switch'):
            decision = 'blocked'
            blocked_by = 'kill_switch'
            reason = "Emergency kill switch is active for tenant; all automated mitigations halted."

        # 2. Allowlist Check
        elif cls.is_allowlisted(oid, etype, eid):
            decision = 'blocked'
            blocked_by = 'allowlist'
            reason = f"Allowlisted entity {etype}:{eid} is protected from automated containment."

        # 3. Confidence Threshold Check
        else:
            min_conf = cfg.get('min_confidence', 'high').lower()
            conf_val = CONFIDENCE_LEVELS.get(str(confidence).lower(), 1)
            min_val = CONFIDENCE_LEVELS.get(min_conf, 3)
            if conf_val < min_val:
                decision = 'blocked'
                blocked_by = 'confidence_too_low'
                reason = f"Detection confidence '{confidence}' is below minimum required posture '{min_conf}'."

        # 4. Entity Cooldown Check
        if decision == 'passed':
            cooldown_sec = cfg.get('cooldown_seconds', 900)
            last_action_time = _ENTITY_LAST_ACTION.get((oid, etype, eid))
            if last_action_time and (now - last_action_time).total_seconds() < cooldown_sec:
                decision = 'blocked'
                blocked_by = 'cooldown'
                rem = int(cooldown_sec - (now - last_action_time).total_seconds())
                reason = f"Entity {etype}:{eid} is in cooldown window ({rem}s remaining)."

        # 5. Blast Radius Hourly Rate Limits
        if decision == 'passed':
            max_hourly = cfg.get('max_actions_per_hour', 20)
            cutoff_1h = now - timedelta(hours=1)
            past_timestamps = _ACTION_TIMESTAMPS.get(oid, [])
            recent_1h = [t for t in past_timestamps if t >= cutoff_1h]
            if len(recent_1h) >= max_hourly:
                decision = 'blocked'
                blocked_by = 'rate_limit_hour'
                reason = f"Blast radius rate limit exceeded: {len(recent_1h)} actions in past hour (max: {max_hourly})."

        # 6. Blast Radius Daily Rate Limits
        if decision == 'passed':
            max_daily = cfg.get('max_actions_per_day', 100)
            cutoff_24h = now - timedelta(hours=24)
            past_timestamps = _ACTION_TIMESTAMPS.get(oid, [])
            recent_24h = [t for t in past_timestamps if t >= cutoff_24h]
            if len(recent_24h) >= max_daily:
                decision = 'blocked'
                blocked_by = 'rate_limit_day'
                reason = f"Blast radius daily limit exceeded: {len(recent_24h)} actions in past 24h (max: {max_daily})."

        # Log to Guardrail Audit Trail
        log_entry = {
            'id': str(uuid.uuid4()),
            'organization_id': oid,
            'action_type': action_type,
            'target_entity_type': etype,
            'target_entity_id': eid,
            'guardrail_type': blocked_by or 'all_passed',
            'decision': decision,
            'reason': reason or "All guardrails passed successfully",
            'confidence': confidence,
            'created_at': now.isoformat()
        }

        if oid not in _GUARDRAIL_AUDIT_LOGS:
            _GUARDRAIL_AUDIT_LOGS[oid] = []
        _GUARDRAIL_AUDIT_LOGS[oid].append(log_entry)

        try:
            sb = get_service_supabase()
            sb.table('guardrail_audit_log').insert(log_entry).execute()
        except Exception as e:
            logger.debug(f"Guardrail audit log insertion fallback: {e}")

        return {
            'passed': decision == 'passed',
            'blocked_by': blocked_by,
            'decision': decision,
            'reason': reason or "Guardrails passed",
            'organization_id': oid
        }

    @classmethod
    def list_guardrail_logs(cls, org_id: str, limit: int = 50) -> List[Dict[str, Any]]:
        """Lists recent guardrail audit evaluation entries for the tenant."""
        oid = str(org_id).strip()
        local_logs = _GUARDRAIL_AUDIT_LOGS.get(oid, [])
        items = list(local_logs[-limit:])

        try:
            sb = get_service_supabase()
            res = sb.table('guardrail_audit_log').select('*')\
                .eq('organization_id', oid)\
                .order('created_at', desc=True)\
                .limit(limit).execute()
            if res.data:
                existing_ids = {i['id'] for i in items}
                for r in res.data:
                    if r['id'] not in existing_ids:
                        items.append(dict(r))
        except Exception as e:
            logger.debug(f"Guardrail audit log list fallback: {e}")

        return sorted(items, key=lambda x: x.get('created_at', ''), reverse=True)[:limit]
