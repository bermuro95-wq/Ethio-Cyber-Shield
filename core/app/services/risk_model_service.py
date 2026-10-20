"""
Ethio-Cyber-Shield (ECS) — Explainable Risk Model v2 (Phase 3.5).
Implements an additive 0-100 risk scoring engine incorporating:
1. Rule confidence weighting (high=1.0, medium=0.85, low=0.70).
2. Entity criticality tiers (critical, high, medium, low) with multipliers and score boosts.
3. Recency decay across temporal windows (<=15m, <=60m, <=6h, <=24h, >24h).
4. Deterministic severity rationales with zero-baseline protection.
5. Explicit Non-Probability Declaration: The risk score is a deterministic operational
   priority index, NOT a statistical probability of guilt or fraud.
Multi-tenant strictly partitioned by organization_id UUID NOT NULL.
"""
import uuid
import logging
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional, Tuple

from app.services.db import get_service_supabase
from app.services.tenant_service import get_current_organization_id

logger = logging.getLogger(__name__)

# Non-probability declaration mandated by architecture and Ethiopian legal requirements
NON_PROBABILITY_DECLARATION = (
    "Deterministic operational risk priority index (0–100); "
    "NOT a statistical probability of guilt or fraud."
)

CRITICALITY_TIERS: Dict[str, Dict[str, Any]] = {
    'critical': {
        'multiplier': 1.4,
        'boost': 15,
        'description': 'Critical infrastructure, national payment rails (EthSwitch), or executive/treasury funds'
    },
    'high': {
        'multiplier': 1.2,
        'boost': 8,
        'description': 'Corporate accounts, cashier terminals, branch managers, privileged personnel'
    },
    'medium': {
        'multiplier': 1.0,
        'boost': 0,
        'description': 'Standard retail accounts, regular authenticated users, routine endpoints'
    },
    'low': {
        'multiplier': 0.9,
        'boost': 0,
        'description': 'Sandbox test environments, low-risk public/unauthenticated endpoints'
    }
}

CONFIDENCE_FACTORS: Dict[str, float] = {
    'high': 1.0,
    'medium': 0.85,
    'low': 0.70
}

RECENCY_DECAY_TIERS: List[Dict[str, Any]] = [
    {'max_seconds': 15 * 60, 'factor': 1.00, 'label': '0-15m (Acute)'},
    {'max_seconds': 60 * 60, 'factor': 0.85, 'label': '15-60m (Elevated)'},
    {'max_seconds': 6 * 3600, 'factor': 0.65, 'label': '1-6h (Residual)'},
    {'max_seconds': 24 * 3600, 'factor': 0.40, 'label': '6-24h (Dormant)'},
    {'max_seconds': float('inf'), 'factor': 0.20, 'label': '>24h (Historical Trace)'}
]

SEVERITY_RATIONALES: Dict[str, str] = {
    'critical': "Acute threat to critical infrastructure or high-value funds; immediate autonomous/assisted containment required.",
    'high': "Significant threat pattern detected; autonomous response or immediate SOC analyst triage recommended.",
    'medium': "Noticeable behavioral or policy anomaly; elevated monitoring and non-destructive inspection recommended.",
    'low': "Sub-threshold operational telemetry; baseline monitoring without escalation."
}

# In-memory caches for fast evaluation and unit-test isolation
_LOCAL_CRITICALITY: Dict[str, Dict[str, Any]] = {}
_LOCAL_ENTITY_DETECTIONS: Dict[str, List[Dict[str, Any]]] = {}


def clear_risk_model_caches():
    """Resets in-memory stores for risk model testing."""
    _LOCAL_CRITICALITY.clear()
    _LOCAL_ENTITY_DETECTIONS.clear()


def _crit_key(org_id: str, entity_type: str, entity_id: str) -> str:
    return f"{str(org_id).strip()}:{str(entity_type).lower().strip()}:{str(entity_id).strip()}"


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


class RiskModelV2Service:
    """
    Stateless Risk Model v2 calculation and entity risk profile evaluation.
    """

    @classmethod
    def calculate_recency_decay(
        cls,
        timestamp_str: str,
        reference_time: Optional[datetime] = None
    ) -> Tuple[float, float]:
        """
        Calculates the recency decay factor and time delta in seconds.
        """
        ref = reference_time or datetime.now(timezone.utc)
        if ref.tzinfo is None:
            ref = ref.replace(tzinfo=timezone.utc)

        event_time = _parse_utc_datetime(timestamp_str)
        delta_sec = max(0.0, (ref - event_time).total_seconds())

        for tier in RECENCY_DECAY_TIERS:
            if delta_sec <= tier['max_seconds']:
                return tier['factor'], delta_sec

        return 0.20, delta_sec

    @classmethod
    def infer_criticality_tier(cls, entity_type: str, entity_id: str) -> Tuple[str, bool]:
        """
        Infers default criticality tier based on Ethiopian banking and critical infrastructure keywords.
        Returns: (tier, is_inferred)
        """
        lowered = str(entity_id).lower()
        # National infrastructure and core banking
        critical_keywords = [
            'ethswitch', 'core-banking', 'core_banking', 'treasury', 'rtgs', 'swift',
            'cbe_birr', 'telebirr_switch', 'central_switch', 'interbank'
        ]
        if any(kw in lowered for kw in critical_keywords):
            return 'critical', True

        # Privileged roles, managers, cashier terminals
        high_keywords = ['admin', 'vip', 'director', 'manager', 'cashier', 'soc-admin']
        if any(kw in lowered for kw in high_keywords):
            return 'high', True

        return 'medium', False

    @classmethod
    def get_entity_criticality(
        cls,
        org_id: str,
        entity_type: str,
        entity_id: str
    ) -> Dict[str, Any]:
        """
        Retrieves entity criticality configuration, checking local cache, database, or inferring defaults.
        """
        oid = str(org_id).strip()
        etype = str(entity_type).lower().strip()
        eid = str(entity_id).strip()
        key = _crit_key(oid, etype, eid)

        if key in _LOCAL_CRITICALITY:
            return dict(_LOCAL_CRITICALITY[key])

        # Attempt to load from database
        try:
            sb = get_service_supabase()
            res = sb.table('entity_criticality').select('*')\
                .eq('organization_id', oid)\
                .eq('entity_type', etype)\
                .eq('entity_id', eid)\
                .execute()
            if res.data and len(res.data) > 0:
                row = res.data[0]
                tier_info = CRITICALITY_TIERS.get(row.get('criticality_tier', 'medium'), CRITICALITY_TIERS['medium'])
                item = {
                    'id': row.get('id'),
                    'organization_id': oid,
                    'entity_type': etype,
                    'entity_id': eid,
                    'criticality_tier': row.get('criticality_tier', 'medium'),
                    'multiplier': tier_info['multiplier'],
                    'boost': row.get('criticality_score_boost') if row.get('criticality_score_boost') is not None else tier_info['boost'],
                    'owner_unit': row.get('owner_unit'),
                    'notes': row.get('notes'),
                    'is_overridden': True
                }
                _LOCAL_CRITICALITY[key] = item
                return dict(item)
        except Exception as e:
            logger.debug(f"Could not load entity_criticality from db: {e}")

        # Fallback to inference
        tier, is_inferred = cls.infer_criticality_tier(etype, eid)
        tier_info = CRITICALITY_TIERS[tier]
        return {
            'organization_id': oid,
            'entity_type': etype,
            'entity_id': eid,
            'criticality_tier': tier,
            'multiplier': tier_info['multiplier'],
            'boost': tier_info['boost'],
            'owner_unit': None,
            'notes': 'Inferred from entity naming' if is_inferred else 'Default standard tier',
            'is_overridden': is_inferred
        }

    @classmethod
    def set_entity_criticality(
        cls,
        org_id: str,
        entity_type: str,
        entity_id: str,
        tier: str,
        boost: Optional[int] = None,
        owner_unit: Optional[str] = None,
        notes: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Creates or updates entity criticality configuration.
        """
        oid = str(org_id).strip()
        etype = str(entity_type).lower().strip()
        eid = str(entity_id).strip()
        tier = str(tier).lower().strip()
        if tier not in CRITICALITY_TIERS:
            raise ValueError(f"Invalid criticality tier: {tier}. Must be one of: {list(CRITICALITY_TIERS.keys())}")

        tier_info = CRITICALITY_TIERS[tier]
        effective_boost = boost if boost is not None else tier_info['boost']
        key = _crit_key(oid, etype, eid)

        record_id = _LOCAL_CRITICALITY.get(key, {}).get('id') or str(uuid.uuid4())
        item = {
            'id': record_id,
            'organization_id': oid,
            'entity_type': etype,
            'entity_id': eid,
            'criticality_tier': tier,
            'multiplier': tier_info['multiplier'],
            'boost': effective_boost,
            'owner_unit': owner_unit,
            'notes': notes,
            'is_overridden': True,
            'updated_at': datetime.now(timezone.utc).isoformat()
        }
        _LOCAL_CRITICALITY[key] = item

        # Persist to database if available
        try:
            sb = get_service_supabase()
            sb.table('entity_criticality').upsert({
                'id': record_id,
                'organization_id': oid,
                'entity_type': etype,
                'entity_id': eid,
                'criticality_tier': tier,
                'criticality_score_boost': effective_boost,
                'owner_unit': owner_unit,
                'notes': notes,
                'updated_at': datetime.now(timezone.utc).isoformat()
            }, on_conflict='organization_id,entity_type,entity_id').execute()
        except Exception as e:
            logger.debug(f"Entity criticality database upsert skipped: {e}")

        return dict(item)

    @classmethod
    def delete_entity_criticality(cls, org_id: str, record_id: str) -> bool:
        """
        Deletes an entity criticality record by ID, scoped by organization_id.
        """
        oid = str(org_id).strip()
        # Remove from local cache
        found_key = None
        for k, v in _LOCAL_CRITICALITY.items():
            if v.get('organization_id') == oid and (v.get('id') == record_id or v.get('entity_id') == record_id):
                found_key = k
                break
        if found_key:
            del _LOCAL_CRITICALITY[found_key]

        # Delete from database
        try:
            sb = get_service_supabase()
            sb.table('entity_criticality').delete().eq('organization_id', oid).eq('id', record_id).execute()
        except Exception as e:
            logger.debug(f"Entity criticality database delete skipped: {e}")

        return True

    @classmethod
    def list_entity_criticalities(
        cls,
        org_id: str,
        entity_type: Optional[str] = None,
        tier: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Lists all entity criticality configurations for a tenant.
        """
        oid = str(org_id).strip()
        items = [dict(v) for v in _LOCAL_CRITICALITY.values() if v.get('organization_id') == oid]

        # Also load from database
        try:
            sb = get_service_supabase()
            query = sb.table('entity_criticality').select('*').eq('organization_id', oid)
            if entity_type:
                query = query.eq('entity_type', str(entity_type).lower().strip())
            if tier:
                query = query.eq('criticality_tier', str(tier).lower().strip())
            res = query.execute()
            if res.data:
                db_items = []
                for row in res.data:
                    t_info = CRITICALITY_TIERS.get(row.get('criticality_tier', 'medium'), CRITICALITY_TIERS['medium'])
                    db_items.append({
                        'id': row.get('id'),
                        'organization_id': oid,
                        'entity_type': row.get('entity_type'),
                        'entity_id': row.get('entity_id'),
                        'criticality_tier': row.get('criticality_tier', 'medium'),
                        'multiplier': t_info['multiplier'],
                        'boost': row.get('criticality_score_boost', t_info['boost']),
                        'owner_unit': row.get('owner_unit'),
                        'notes': row.get('notes'),
                        'is_overridden': True
                    })
                # Merge with local items deduplicating by id
                existing_ids = {i['id'] for i in items if i.get('id')}
                for d in db_items:
                    if d['id'] not in existing_ids:
                        items.append(d)
        except Exception as e:
            logger.debug(f"Could not query entity_criticality from db: {e}")

        if entity_type:
            items = [i for i in items if i.get('entity_type') == str(entity_type).lower().strip()]
        if tier:
            items = [i for i in items if i.get('criticality_tier') == str(tier).lower().strip()]

        return items

    @classmethod
    def calculate_risk(
        cls,
        fired_rules: List[Dict[str, Any]],
        baseline_score: int = 0,
        entity_type: Optional[str] = None,
        entity_id: Optional[str] = None,
        org_id: Optional[str] = None,
        custom_criticality: Optional[Dict[str, Any]] = None,
        reference_time: Optional[datetime] = None
    ) -> Dict[str, Any]:
        """
        Calculates Risk Model v2 score using additive rules, confidence weighting,
        entity criticality, and recency decay.
        """
        oid = org_id or get_current_organization_id() or "00000000-0000-0000-0000-000000000001"
        etype = entity_type or 'account'
        eid = entity_id or 'unknown'

        # 1. Resolve Entity Criticality
        crit_info = custom_criticality or cls.get_entity_criticality(oid, etype, eid)
        crit_tier = crit_info.get('criticality_tier', 'medium')
        crit_mult = crit_info.get('multiplier', CRITICALITY_TIERS.get(crit_tier, CRITICALITY_TIERS['medium'])['multiplier'])
        crit_boost = crit_info.get('boost', CRITICALITY_TIERS.get(crit_tier, CRITICALITY_TIERS['medium'])['boost'])

        # 2. Rule Confidence Adjustments
        rules_breakdown = []
        confidence_adjusted_rules_score = 0
        raw_rules_sum = 0
        has_high_confidence = False

        for r in fired_rules:
            is_shadow = r.get('is_shadow', False)
            weight = r.get('weight', 0)
            raw_rules_sum += weight

            # Determine confidence factor
            conf_str = str(r.get('confidence', '')).lower()
            if conf_str not in CONFIDENCE_FACTORS:
                # Default to full confidence (1.0) so configured rule weights are preserved
                # unless explicitly calibrated to 'medium' (0.85) or 'low' (0.70)
                conf_str = 'high'

            conf_factor = CONFIDENCE_FACTORS.get(conf_str, 1.0)
            if conf_str == 'high' and not is_shadow:
                has_high_confidence = True

            effective_contrib = 0 if is_shadow else round(weight * conf_factor)
            confidence_adjusted_rules_score += effective_contrib

            rules_breakdown.append({
                'rule_id': r.get('rule_id', 'UNKNOWN'),
                'name': r.get('name', 'Rule'),
                'weight': weight,
                'confidence': conf_str,
                'confidence_factor': conf_factor,
                'effective_contribution': effective_contrib,
                'is_shadow': is_shadow,
                'summary': r.get('summary', '')
            })

        # 3. Additive Pre-Criticality Score (Rules + Baseline Anomaly)
        pre_score = confidence_adjusted_rules_score + baseline_score

        # 4. Criticality Adjustment with Zero-Baseline Protection
        # If pre_score is 0, do NOT apply boost (avoids false alarms on benign events on critical systems)
        if pre_score == 0:
            criticality_adjusted_score = 0
            applied_boost = 0
        else:
            applied_boost = crit_boost
            criticality_adjusted_score = round(pre_score * crit_mult) + applied_boost

        # 5. Clamping [0, 100]
        final_score = max(0, min(100, criticality_adjusted_score))

        # 6. Severity Mapping & Deterministic Rationale
        if final_score >= 75:
            severity = 'critical'
        elif final_score >= 50:
            severity = 'high'
        elif final_score >= 25:
            severity = 'medium'
        else:
            severity = 'low'

        rationale = SEVERITY_RATIONALES[severity]
        overall_confidence = 'high' if has_high_confidence or final_score >= 75 else ('medium' if final_score >= 25 else 'low')

        # 7. Reasons Explanation List
        reasons = []
        for rb in rules_breakdown:
            shadow_tag = " [SHADOW - NO IMPACT]" if rb['is_shadow'] else ""
            reasons.append(
                f"[{rb['rule_id']}] {rb['name']} (+{rb['effective_contribution']} pts "
                f"[conf: {rb['confidence']}={rb['confidence_factor']}]): {rb['summary']}{shadow_tag}"
            )
        if baseline_score > 0:
            reasons.append(f"[BASELINE-ANOMALY] Behavioral baseline deviation (+{baseline_score} pts)")
        if crit_mult != 1.0 or applied_boost > 0:
            reasons.append(
                f"[CRITICALITY-{crit_tier.upper()}] Entity criticality tier applied "
                f"({crit_mult}x multiplier, +{applied_boost} pts boost)"
            )

        return {
            'risk_score': final_score,
            'severity': severity,
            'severity_rationale': rationale,
            'confidence': overall_confidence,
            'is_threat': final_score >= 25,
            'non_probability_declaration': NON_PROBABILITY_DECLARATION,
            'components': {
                'raw_rules_sum': raw_rules_sum,
                'confidence_adjusted_rules_score': confidence_adjusted_rules_score,
                'baseline_anomaly_score': baseline_score,
                'pre_criticality_score': pre_score,
                'entity_criticality': {
                    'tier': crit_tier,
                    'multiplier': crit_mult,
                    'boost': crit_boost,
                    'applied_boost': applied_boost,
                    'owner_unit': crit_info.get('owner_unit'),
                    'is_overridden': crit_info.get('is_overridden', False)
                },
                'criticality_adjusted_score': criticality_adjusted_score,
                'final_score': final_score
            },
            'rules_breakdown': rules_breakdown,
            'reasons': reasons,
            'mathematical_formula': (
                "final_score = min(100, max(0, round((confidence_adjusted_rules + baseline_anomaly) * "
                f"{crit_mult}) + {applied_boost}))"
            )
        }

    @classmethod
    def record_entity_detection(
        cls,
        org_id: str,
        entity_type: str,
        entity_id: str,
        detection_id: str,
        rule_id: str,
        score: int,
        timestamp: Optional[str] = None
    ):
        """
        Records an entity detection for temporal recency decay tracking.
        """
        oid = str(org_id).strip()
        etype = str(entity_type).lower().strip()
        eid = str(entity_id).strip()
        key = _crit_key(oid, etype, eid)

        if key not in _LOCAL_ENTITY_DETECTIONS:
            _LOCAL_ENTITY_DETECTIONS[key] = []

        ts = timestamp or datetime.now(timezone.utc).isoformat()
        _LOCAL_ENTITY_DETECTIONS[key].append({
            'detection_id': detection_id,
            'rule_id': rule_id,
            'score': score,
            'timestamp': ts
        })

    @classmethod
    def get_entity_risk_profile(
        cls,
        org_id: str,
        entity_type: str,
        entity_id: str,
        reference_time: Optional[datetime] = None,
        lookback_hours: int = 24
    ) -> Dict[str, Any]:
        """
        Computes composite active entity risk posture using recency-decayed historical detections.
        """
        oid = str(org_id).strip()
        etype = str(entity_type).lower().strip()
        eid = str(entity_id).strip()
        key = _crit_key(oid, etype, eid)

        crit = cls.get_entity_criticality(oid, etype, eid)
        ref = reference_time or datetime.now(timezone.utc)

        raw_detections = list(_LOCAL_ENTITY_DETECTIONS.get(key, []))

        # Query recent detections from database if available
        try:
            sb = get_service_supabase()
            cutoff = (ref - timedelta(hours=lookback_hours)).isoformat()
            res = sb.table('detections').select('*')\
                .eq('organization_id', oid)\
                .eq('entity_id', eid)\
                .gte('created_at', cutoff)\
                .order('created_at', desc=True)\
                .execute()
            if res.data:
                existing_d_ids = {d['detection_id'] for d in raw_detections}
                for row in res.data:
                    d_id = row.get('id')
                    if d_id not in existing_d_ids:
                        raw_detections.append({
                            'detection_id': d_id,
                            'rule_id': row.get('rule_id', 'DET'),
                            'score': row.get('score_contribution', 30),
                            'timestamp': row.get('created_at')
                        })
        except Exception as e:
            logger.debug(f"Could not query detections from db: {e}")

        decayed_detections = []
        decayed_scores = []

        for d in raw_detections:
            decay_factor, delta_sec = cls.calculate_recency_decay(d['timestamp'], ref)
            decayed_contrib = round(d['score'] * decay_factor)
            decayed_scores.append(decayed_contrib)
            decayed_detections.append({
                'detection_id': d['detection_id'],
                'rule_id': d['rule_id'],
                'raw_score': d['score'],
                'timestamp': d['timestamp'],
                'recency_decay_factor': decay_factor,
                'delta_seconds': round(delta_sec, 1),
                'decayed_score': decayed_contrib
            })

        # Calculate active decayed risk (peak decayed alert + diminishing contributions of others)
        if decayed_scores:
            decayed_scores.sort(reverse=True)
            peak = decayed_scores[0]
            tail = sum(decayed_scores[1:]) * 0.25
            raw_active = peak + tail
            active_decayed_risk = min(100, round(raw_active * crit['multiplier']) if raw_active > 0 else 0)
        else:
            active_decayed_risk = 0

        severity = (
            'critical' if active_decayed_risk >= 75 else
            ('high' if active_decayed_risk >= 50 else
            ('medium' if active_decayed_risk >= 25 else 'low'))
        )

        return {
            'organization_id': oid,
            'entity_type': etype,
            'entity_id': eid,
            'criticality_tier': crit['criticality_tier'],
            'criticality_multiplier': crit['multiplier'],
            'criticality_boost': crit['boost'],
            'owner_unit': crit.get('owner_unit'),
            'detection_count': len(raw_detections),
            'active_decayed_risk': active_decayed_risk,
            'severity': severity,
            'severity_rationale': SEVERITY_RATIONALES[severity],
            'recent_detections': decayed_detections,
            'non_probability_declaration': NON_PROBABILITY_DECLARATION
        }
