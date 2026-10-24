"""
Analyst Feedback Loop & Automated Suppression Suggestions for Ethio-Cyber-Shield (ECS) v3.0 (Phase 4.6).
Provides:
1. Analyst verdict and triage feedback capture on alerts and cases (TP, FP, benign positive, test).
2. Rule performance and tuning statistics (precision, false-positive rate [FPR]).
3. Automated threshold tuning warnings when FPR >= 25%.
4. False-positive invariant pattern analysis and 1-click suppression rule generation.
Strictly partitioned by organization_id UUID NOT NULL.
"""
import uuid
import logging
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional, Tuple

from app.services.db import get_service_supabase
from app.services.tenant_service import get_current_organization_id
from app.services.alert_quality_service import AlertQualityService
from app.services.audit_service import log_action

logger = logging.getLogger(__name__)

VALID_VERDICTS = [
    'true_positive',
    'false_positive',
    'benign_positive',
    'suspicious_unconfirmed',
    'test'
]

VALID_REASONS = [
    'malicious_confirmed',
    'benign_business_activity',
    'rule_overly_broad',
    'data_quality_issue',
    'authorized_testing',
    'customer_benign_exception',
    'other'
]

# In-memory stores for unit testing and fast lookup
_LOCAL_FEEDBACK: Dict[str, Dict[str, Any]] = {}  # feedback_id -> record
_LOCAL_SUGGESTIONS: Dict[str, Dict[str, Any]] = {}  # suggestion_id -> suggestion


def clear_feedback_caches() -> None:
    """Resets feedback caches for test isolation."""
    _LOCAL_FEEDBACK.clear()
    _LOCAL_SUGGESTIONS.clear()


class AnalystFeedbackService:
    """Feedback Loop Engine, Rule Tuning Diagnostics & Automated Suppression Suggester."""

    # =========================================================================
    # 1. FEEDBACK CAPTURE
    # =========================================================================

    @classmethod
    def submit_feedback(
        cls,
        org_id: str,
        rule_id: str,
        verdict: str,
        reason_category: str = 'benign_business_activity',
        analyst_notes: Optional[str] = None,
        alert_id: Optional[str] = None,
        incident_id: Optional[str] = None,
        entity_type: Optional[str] = None,
        entity_value: Optional[str] = None,
        user_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Records analyst triage feedback for an alert or incident detection.
        """
        oid = str(org_id).strip()
        rid = str(rule_id).strip()
        v = str(verdict).lower().strip()
        rc = str(reason_category).lower().strip()

        if v not in VALID_VERDICTS:
            raise ValueError(f"Invalid feedback verdict '{verdict}'. Allowed: {VALID_VERDICTS}")

        fid = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()

        record = {
            'id': fid,
            'organization_id': oid,
            'rule_id': rid,
            'verdict': v,
            'reason_category': rc,
            'analyst_notes': analyst_notes or '',
            'alert_id': alert_id,
            'incident_id': incident_id,
            'entity_type': entity_type,
            'entity_value': entity_value,
            'created_by': user_id,
            'created_at': now
        }

        _LOCAL_FEEDBACK[fid] = record

        # Database persistence
        try:
            sb = get_service_supabase()
            db_payload = {
                'id': fid,
                'organization_id': oid,
                'rule_id': rid,
                'alert_id': alert_id,
                'verdict': v,
                'reason_category': rc,
                'analyst_notes': analyst_notes,
                'created_by': user_id,
                'created_at': now
            }
            sb.table('rule_feedback').insert(db_payload).execute()
        except Exception as e:
            logger.debug(f"DB rule_feedback insert note: {e}")

        # Audit log
        try:
            log_action(user_id, 'analyst_feedback_submitted', 'rule', rid, {
                'feedback_id': fid,
                'verdict': v,
                'reason_category': rc
            })
        except Exception as e:
            logger.debug(f"Audit log skipped for feedback: {e}")

        return record

    @classmethod
    def list_feedback(
        cls,
        org_id: str,
        rule_id: Optional[str] = None,
        verdict: Optional[str] = None,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """Lists feedback records scoped by organization_id."""
        oid = str(org_id).strip()
        records = [
            f for f in _LOCAL_FEEDBACK.values()
            if str(f.get('organization_id')) == oid
        ]

        try:
            sb = get_service_supabase()
            q = sb.table('rule_feedback').select('*').eq('organization_id', oid)
            if rule_id:
                q = q.eq('rule_id', rule_id)
            if verdict:
                q = q.eq('verdict', verdict)
            res = q.order('created_at', desc=True).limit(limit).execute()
            if res.data:
                seen_ids = {r['id'] for r in records}
                for row in res.data:
                    if row['id'] not in seen_ids:
                        records.append(dict(row))
        except Exception as e:
            logger.debug(f"DB rule_feedback list note: {e}")

        if rule_id:
            records = [r for r in records if r.get('rule_id') == rule_id]
        if verdict:
            records = [r for r in records if r.get('verdict') == verdict]

        return sorted(records, key=lambda x: str(x.get('created_at')), reverse=True)[:limit]

    # =========================================================================
    # 2. RULE PERFORMANCE & TUNING METRICS
    # =========================================================================

    @classmethod
    def get_rule_tuning_stats(cls, org_id: str, rule_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Calculates precision, false-positive rate (FPR), and automated tuning recommendations.
        Flags rules where FPR >= 25% (0.25).
        """
        oid = str(org_id).strip()
        feedbacks = cls.list_feedback(oid, rule_id=rule_id)

        # Group by rule_id
        rule_groups: Dict[str, List[Dict[str, Any]]] = {}
        for fb in feedbacks:
            rid = fb.get('rule_id') or 'UNKNOWN'
            if rid not in rule_groups:
                rule_groups[rid] = []
            rule_groups[rid].append(fb)

        stats_by_rule = {}
        for rid, items in rule_groups.items():
            tp = sum(1 for i in items if i.get('verdict') == 'true_positive')
            fp = sum(1 for i in items if i.get('verdict') == 'false_positive')
            bp = sum(1 for i in items if i.get('verdict') == 'benign_positive')
            test = sum(1 for i in items if i.get('verdict') == 'test')
            unconfirmed = sum(1 for i in items if i.get('verdict') == 'suspicious_unconfirmed')

            total_rated = tp + fp + bp
            precision = round(tp / total_rated, 4) if total_rated > 0 else 1.0
            fpr = round(fp / total_rated, 4) if total_rated > 0 else 0.0

            needs_tuning = (fpr >= 0.25 and total_rated >= 3)
            recommendation = (
                f"Rule FPR is {round(fpr * 100, 1)}% (>= 25% threshold). Consider adjusting thresholds or demoting to shadow mode."
                if needs_tuning else "Rule accuracy is healthy."
            )

            stats_by_rule[rid] = {
                'rule_id': rid,
                'total_feedback_count': len(items),
                'true_positives': tp,
                'false_positives': fp,
                'benign_positives': bp,
                'test_evaluations': test,
                'unconfirmed': unconfirmed,
                'precision': precision,
                'false_positive_rate': fpr,
                'needs_tuning': needs_tuning,
                'recommendation': recommendation
            }

        # Overall summary
        all_tp = sum(s['true_positives'] for s in stats_by_rule.values())
        all_fp = sum(s['false_positives'] for s in stats_by_rule.values())
        all_bp = sum(s['benign_positives'] for s in stats_by_rule.values())
        all_total = all_tp + all_fp + all_bp

        overall_precision = round(all_tp / all_total, 4) if all_total > 0 else 1.0
        overall_fpr = round(all_fp / all_total, 4) if all_total > 0 else 0.0

        return {
            'organization_id': oid,
            'target_rule_id': rule_id,
            'overall': {
                'total_rated': all_total,
                'true_positives': all_tp,
                'false_positives': all_fp,
                'precision': overall_precision,
                'false_positive_rate': overall_fpr,
                'rules_needing_tuning': [rid for rid, s in stats_by_rule.items() if s['needs_tuning']]
            },
            'rules': stats_by_rule if not rule_id else stats_by_rule.get(rule_id, {
                'rule_id': rule_id,
                'total_feedback_count': 0,
                'true_positives': 0,
                'false_positives': 0,
                'precision': 1.0,
                'false_positive_rate': 0.0,
                'needs_tuning': False,
                'recommendation': "No feedback submitted yet."
            })
        }

    # =========================================================================
    # 3. AUTOMATED SUPPRESSION SUGGESTIONS
    # =========================================================================

    @classmethod
    def generate_suppression_suggestions(cls, org_id: str, rule_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Analyzes false-positive feedback patterns to generate actionable suppression rule suggestions.
        When an entity (e.g. IP, account) receives >= 2 false-positive tags, suggests a suppression window.
        """
        oid = str(org_id).strip()
        fps = cls.list_feedback(oid, rule_id=rule_id, verdict='false_positive')

        # Cluster by (entity_type, entity_value, rule_id)
        entity_clusters: Dict[Tuple[str, str, str], List[Dict[str, Any]]] = {}
        for fb in fps:
            etype = fb.get('entity_type') or 'ip'
            eval_ = fb.get('entity_value')
            rid = fb.get('rule_id') or '*'

            if not eval_:
                # Try to infer from notes or alert
                continue

            key = (etype, eval_, rid)
            if key not in entity_clusters:
                entity_clusters[key] = []
            entity_clusters[key].append(fb)

        suggestions = []
        now = datetime.now(timezone.utc).isoformat()

        for (etype, eval_, rid), items in entity_clusters.items():
            if len(items) >= 2:
                sug_id = str(uuid.uuid4())
                reasons = [it.get('analyst_notes') for it in items if it.get('analyst_notes')]
                primary_reason = reasons[0] if reasons else f"Recurring False Positives ({len(items)} feedback reports)"

                suggestion = {
                    'id': sug_id,
                    'organization_id': oid,
                    'rule_id': rid,
                    'entity_type': etype,
                    'entity_id': eval_,
                    'false_positive_count': len(items),
                    'suggested_reason': f"Automated Suggestion: {primary_reason}",
                    'suggested_duration_minutes': 1440,  # 24 hours default
                    'confidence': min(0.99, 0.70 + (0.10 * len(items))),
                    'created_at': now
                }
                _LOCAL_SUGGESTIONS[sug_id] = suggestion
                suggestions.append(suggestion)

        return suggestions

    @classmethod
    def apply_suppression_suggestion(
        cls,
        org_id: str,
        suggestion_id_or_payload: Any,
        user_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Converts an automated suggestion into an active alert_suppression_rule with 1 click.
        """
        oid = str(org_id).strip()
        sug_data = None

        if isinstance(suggestion_id_or_payload, str):
            sug_id = suggestion_id_or_payload.strip()
            if sug_id in _LOCAL_SUGGESTIONS:
                candidate = _LOCAL_SUGGESTIONS[sug_id]
                if str(candidate.get('organization_id')) == oid:
                    sug_data = candidate
        elif isinstance(suggestion_id_or_payload, dict):
            sug_data = suggestion_id_or_payload

        if not sug_data:
            raise ValueError("Suppression suggestion not found")

        # Create active suppression rule via AlertQualityService
        active_rule = AlertQualityService.create_suppression_rule(
            org_id=oid,
            entity_type=sug_data.get('entity_type', 'ip'),
            entity_id=sug_data.get('entity_id', 'unknown'),
            rule_id=sug_data.get('rule_id', '*'),
            reason=sug_data.get('suggested_reason', 'Analyst feedback suppression suggestion'),
            duration_minutes=int(sug_data.get('suggested_duration_minutes', 1440)),
            created_by=user_id or "soc_analyst"
        )

        try:
            log_action(user_id, 'suppression_suggestion_applied', 'suppression_rule', active_rule['id'], {
                'entity_type': active_rule.get('entity_type'),
                'entity_id': active_rule.get('entity_id'),
                'rule_id': active_rule.get('rule_id')
            })
        except Exception as e:
            logger.debug(f"Audit log skipped for suppression apply: {e}")

        return active_rule
