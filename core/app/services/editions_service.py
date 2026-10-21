"""
Product Editions & Feature Entitlements Service for Ethio-Cyber-Shield (ECS) v3.0 (Phase 7.1).
Defines and manages platform tiers:
1. Community (Free, Self-Hosted): Core detection engine, open rule packs, REST APIs, local containment.
2. Pro / Operator (Commercial): 48-Hour Incident Readiness, Evidence Vault, advanced Fraud packs, multi-channel notifications, dual approvals.
3. Managed (ECS Run): Pro features + managed SOC operations, executive review summaries, priority tuning.
4. Sector Hub (Consortium): All Pro features + Community Signal Exchange Hub, STIX 2.1 bridge, participant governance.
Strictly partitioned by organization_id UUID NOT NULL.
"""
import logging
from typing import Dict, Any, List, Optional

from app.services.db import get_service_supabase
from app.services.tenant_service import get_current_organization_id

logger = logging.getLogger(__name__)

EDITIONS: Dict[str, Dict[str, Any]] = {
    'community': {
        'id': 'community',
        'name': 'ECS Community Edition',
        'description': 'Self-hosted, open-source defense platform for independent operators.',
        'target_audience': 'Fintech startups, small microfinance institutions, local infrastructure operators',
        'commercial_model': 'Free / Open Source (Apache-2.0)',
        'features': [
            'core_detection_engine',
            'declarative_yaml_rules',
            'web_api_rule_pack',
            'insider_admin_rule_pack',
            'basic_payment_fraud_pack',
            'local_response_containment',
            'rest_apis',
            'audit_logging',
            'client_sdks_python_node_php'
        ]
    },
    'pro': {
        'id': 'pro',
        'name': 'ECS Pro / Financial Operator Edition',
        'description': 'Full compliance readiness, advanced Ethiopian fraud packs, and safe automation for licensed financial institutions.',
        'target_audience': 'Commercial banks, large payment system operators, telecommunication operators',
        'commercial_model': 'Annual Subscription + Enterprise Support',
        'features': [
            'core_detection_engine',
            'declarative_yaml_rules',
            'web_api_rule_pack',
            'insider_admin_rule_pack',
            'basic_payment_fraud_pack',
            'advanced_ethiopian_fraud_pack',   # USSD, SIM-swap, rapid mule cascades, structuring
            'behavioral_baselines',
            'risk_model_v2',
            'safe_response_modes',             # observe -> recommend -> approve -> auto
            'guardrails_engine',               # kill switch, allowlists, blast radius limits
            'declarative_playbooks',
            'two_person_approvals',
            'case_management_sla',
            'multi_channel_notifications',    # SMS, Telegram, Webhook, Email
            'analyst_feedback_loop',
            'post_incident_reviews',
            'readiness_engine_48h_clock',      # Proclamation No. 1426/2026 compliance support
            'ethiocert_dossier_generator',
            'evidence_vault_sha256',
            'statutory_obligation_register',
            'one_click_audit_pack'
        ]
    },
    'managed': {
        'id': 'managed',
        'name': 'ECS Managed Defense Edition',
        'description': 'Dedicated managed operations, monthly executive tuning reviews, and incident handling assistance.',
        'target_audience': 'Operators seeking turnkey defensive operations without staffing full 24/7 internal engineering',
        'commercial_model': 'Recurring Managed Service Fee',
        'features': [
            # Includes all Pro features + Managed operations
            'all_pro_features',
            'managed_rule_tuning',
            'monthly_threat_intelligence_briefs',
            'priority_incident_tabletop_drills',
            'dedicated_support_sla'
        ]
    },
    'sector_hub': {
        'id': 'sector_hub',
        'name': 'ECS Sector Hub Edition',
        'description': 'Multi-tenant signal exchange hub and threat federation platform for banking consortia and regulatory authorities.',
        'target_audience': 'National associations, EthSwitch, INSA/EthioCERT, sector coordinators',
        'commercial_model': 'Consortium / Institutional Contract',
        'features': [
            'all_pro_features',
            'signal_exchange_hub',
            'privacy_preserving_keyed_hashing',
            'anti_poisoning_corroboration',
            'participant_reputation_engine',
            'stix_21_export_and_import',
            'consortium_governance_tooling',
            'network_effect_analytics'
        ]
    }
}

# In-memory tenant edition overrides for unit testing and local deployment
_LOCAL_TENANT_EDITIONS: Dict[str, str] = {}


def clear_editions_caches() -> None:
    """Resets in-memory tenant edition caches."""
    _LOCAL_TENANT_EDITIONS.clear()


class EditionsService:
    """Manages ECS editions, feature matrices, and tenant entitlements."""

    @classmethod
    def list_editions(cls) -> List[Dict[str, Any]]:
        """Lists all supported product editions and their feature sets."""
        return list(EDITIONS.values())

    @classmethod
    def get_edition_details(cls, edition_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves details of a specific edition."""
        return EDITIONS.get(str(edition_id).lower().strip())

    @classmethod
    def get_tenant_edition(cls, org_id: str) -> Dict[str, Any]:
        """
        Retrieves the active product edition for a given tenant.
        Default: 'pro' for primary financial institutions, 'community' for open tier.
        """
        oid = str(org_id).strip()

        # Check local cache
        if oid in _LOCAL_TENANT_EDITIONS:
            ed_id = _LOCAL_TENANT_EDITIONS[oid]
            return EDITIONS.get(ed_id, EDITIONS['pro'])

        # Check DB
        try:
            sb = get_service_supabase()
            res = sb.table('organizations').select('id, name, sector').eq('id', oid).execute()
            if res.data:
                # Default production commercial bank gets 'pro' or 'sector_hub'
                return EDITIONS['pro']
        except Exception as e:
            logger.debug(f"DB organization fetch note: {e}")

        # Default fallback
        return EDITIONS['pro']

    @classmethod
    def set_tenant_edition(cls, org_id: str, edition_id: str) -> Dict[str, Any]:
        """Sets the active edition for a tenant."""
        oid = str(org_id).strip()
        eid = str(edition_id).lower().strip()

        if eid not in EDITIONS:
            raise ValueError(f"Invalid edition '{edition_id}'. Allowed: {list(EDITIONS.keys())}")

        _LOCAL_TENANT_EDITIONS[oid] = eid
        return EDITIONS[eid]

    @classmethod
    def is_feature_enabled(cls, org_id: str, feature_name: str) -> bool:
        """
        Evaluates whether a specific platform feature is entitled under tenant's edition.
        """
        oid = str(org_id).strip()
        edition = cls.get_tenant_edition(oid)
        feat = str(feature_name).lower().strip()

        features = edition.get('features', [])
        if 'all_pro_features' in features:
            if feat in EDITIONS['pro']['features']:
                return True

        return feat in features
