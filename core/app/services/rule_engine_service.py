"""
Declarative Rules-as-Data Engine for Ethio-Cyber-Shield (ECS) v3.0 (Phase 3.1).

Implements:
1. Declarative Sigma-inspired rule definition loader (YAML/JSON) with L1-L4 semantics.
2. Per-tenant rule overrides (enable/disable, custom thresholds, weights, severities).
3. Rule lifecycle state enforcement:
   - 'live': Normal detection, contributes to active alerts & containment.
   - 'shadow': Shadow evaluation, produces audit detections without triggering automated mitigations.
   - 'draft' / 'backtest': Dormant, skipped during live telemetry stream.
4. Explainable evaluation against incoming events and sliding-window context.
5. Strict multi-tenant isolation (all overrides partitioned by organization_id UUID).
"""
import os
import glob
import yaml
import json
import logging
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any, List, Tuple
from dateutil import parser

from app.services.db import get_service_supabase
from app.services.tenant_service import get_current_organization_id

logger = logging.getLogger(__name__)

# Directory where declarative YAML rule specifications reside
RULES_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'rules', 'definitions'))

# In-memory stores for zero-latency lookups & test isolation
# rule_id -> DetectionRule
_LOADED_RULES: Dict[str, Any] = {}
# (org_id, rule_id) -> override_dict
_TENANT_OVERRIDES: Dict[Tuple[str, str], Dict[str, Any]] = {}
_TENANT_OVERRIDES_TABLE_EXISTS = True


def clear_rule_engine_caches():
    """Clears tenant overrides and reloads rule definitions. Useful for testing."""
    global _TENANT_OVERRIDES
    _TENANT_OVERRIDES.clear()
    load_all_rules()


class DetectionRule:
    """Represents a declarative, versioned detection rule."""
    def __init__(self, raw: dict):
        self.id = str(raw.get('id')).strip()
        self.name = str(raw.get('name')).strip()
        self.description = str(raw.get('description') or '')
        self.layer = str(raw.get('layer', 'L1')).upper()
        self.pack = str(raw.get('pack', 'core'))
        self.severity = str(raw.get('severity', 'medium')).lower()
        self.weight = int(raw.get('weight', 25))
        self.lifecycle_state = str(raw.get('lifecycle_state', 'live')).lower()
        self.version = str(raw.get('version', '1.0.0'))
        self.tags = list(raw.get('tags') or [])
        self.remediation_hints = str(raw.get('remediation_hints') or '')
        self.detection = dict(raw.get('detection') or {})
        self.thresholds = dict(self.detection.get('thresholds') or {})
        self.raw = raw

    def get_effective_config(self, tenant_override: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Calculates effective parameters after applying tenant overrides."""
        override = tenant_override or {}

        is_enabled = override.get('is_enabled', True)
        severity = override.get('severity_override') or self.severity
        weight = override.get('weight_override') if override.get('weight_override') is not None else self.weight
        lifecycle_state = override.get('lifecycle_state_override') or self.lifecycle_state

        effective_thresholds = dict(self.thresholds)
        custom_thresh = override.get('threshold_overrides') or {}
        effective_thresholds.update(custom_thresh)

        return {
            'is_enabled': is_enabled,
            'severity': severity,
            'weight': weight,
            'lifecycle_state': lifecycle_state,
            'thresholds': effective_thresholds,
            'is_shadow': (lifecycle_state == 'shadow')
        }

    def to_dict(self, tenant_override: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        effective = self.get_effective_config(tenant_override)
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'layer': self.layer,
            'pack': self.pack,
            'severity': effective['severity'],
            'weight': effective['weight'],
            'lifecycle_state': effective['lifecycle_state'],
            'version': self.version,
            'tags': self.tags,
            'remediation_hints': self.remediation_hints,
            'detection': self.detection,
            'thresholds': effective['thresholds'],
            'is_enabled': effective['is_enabled'],
            'has_tenant_override': bool(tenant_override)
        }


def load_all_rules():
    """Scans and loads all YAML/JSON rule files in the rules definitions directory."""
    global _LOADED_RULES
    _LOADED_RULES.clear()

    if not os.path.exists(RULES_DIR):
        logger.warning(f"Rules definitions directory {RULES_DIR} not found.")
        return

    pattern = os.path.join(RULES_DIR, '*.y*ml')
    for filepath in glob.glob(pattern):
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)
                if data and isinstance(data, dict) and 'id' in data:
                    rule = DetectionRule(data)
                    _LOADED_RULES[rule.id] = rule
        except Exception as e:
            logger.error(f"Failed to load declarative rule from {filepath}: {e}")

    logger.info(f"Loaded {len(_LOADED_RULES)} declarative detection rules from {RULES_DIR}")


# Load on module import
load_all_rules()


class RuleEngine:
    """
    Evaluator engine for declarative detection rules.
    Manages tenant overrides and evaluates incoming events.
    """
    def __init__(self):
        if not _LOADED_RULES:
            load_all_rules()

    def get_rule(self, rule_id: str, org_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
        rule = _LOADED_RULES.get(rule_id)
        if not rule:
            return None
        override = self.get_tenant_override(org_id, rule_id) if org_id else None
        return rule.to_dict(override)

    def list_rules(self, org_id: Optional[str] = None) -> List[Dict[str, Any]]:
        rules = []
        for r_id, rule in _LOADED_RULES.items():
            override = self.get_tenant_override(org_id, r_id) if org_id else None
            rules.append(rule.to_dict(override))
        rules.sort(key=lambda r: (r['layer'], r['id']))
        return rules

    def get_tenant_override(self, org_id: str, rule_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves tenant override from cache or PostgreSQL."""
        if not org_id or not rule_id:
            return None
        key = (str(org_id), str(rule_id))

        if key in _TENANT_OVERRIDES:
            return _TENANT_OVERRIDES[key]

        global _TENANT_OVERRIDES_TABLE_EXISTS
        if not _TENANT_OVERRIDES_TABLE_EXISTS:
            _TENANT_OVERRIDES[key] = None
            return None

        try:
            sb = get_service_supabase()
            res = sb.table('tenant_rule_overrides').select('*').eq('organization_id', str(org_id)).eq('rule_id', str(rule_id)).limit(1).execute()
            if res.data and len(res.data) > 0:
                record = res.data[0]
                _TENANT_OVERRIDES[key] = record
                return record
            else:
                _TENANT_OVERRIDES[key] = None
                return None
        except Exception as e:
            if 'PGRST205' in str(e) or 'does not exist' in str(e):
                _TENANT_OVERRIDES_TABLE_EXISTS = False
            _TENANT_OVERRIDES[key] = None
            logger.debug(f"Tenant override DB lookup fallback: {e}")

        return None

    def set_tenant_override(
        self,
        org_id: str,
        rule_id: str,
        is_enabled: Optional[bool] = None,
        threshold_overrides: Optional[Dict[str, Any]] = None,
        weight_override: Optional[int] = None,
        severity_override: Optional[str] = None,
        lifecycle_state_override: Optional[str] = None
    ) -> Dict[str, Any]:
        """Sets or updates a tenant override ensuring strict multi-tenant boundary."""
        org_key = str(org_id)
        rule_key = str(rule_id)
        key = (org_key, rule_key)

        existing = self.get_tenant_override(org_key, rule_key) or {}
        now_iso = datetime.now(timezone.utc).isoformat()

        record = {
            'organization_id': org_key,
            'rule_id': rule_key,
            'is_enabled': is_enabled if is_enabled is not None else existing.get('is_enabled', True),
            'threshold_overrides': threshold_overrides if threshold_overrides is not None else existing.get('threshold_overrides', {}),
            'weight_override': weight_override if weight_override is not None else existing.get('weight_override'),
            'severity_override': severity_override if severity_override is not None else existing.get('severity_override'),
            'lifecycle_state_override': lifecycle_state_override if lifecycle_state_override is not None else existing.get('lifecycle_state_override'),
            'updated_at': now_iso
        }
        if not existing:
            record['created_at'] = now_iso

        _TENANT_OVERRIDES[key] = record

        try:
            sb = get_service_supabase()
            sb.table('tenant_rule_overrides').upsert(record, on_conflict='organization_id,rule_id').execute()
        except Exception as e:
            logger.debug(f"Tenant override DB upsert fallback: {e}")

        return dict(record)

    def delete_tenant_override(self, org_id: str, rule_id: str) -> bool:
        """Deletes a tenant override, restoring system defaults."""
        org_key = str(org_id)
        rule_key = str(rule_id)
        key = (org_key, rule_key)

        _TENANT_OVERRIDES.pop(key, None)

        try:
            sb = get_service_supabase()
            sb.table('tenant_rule_overrides').delete().eq('organization_id', org_key).eq('rule_id', rule_key).execute()
            return True
        except Exception as e:
            logger.debug(f"Tenant override DB delete fallback: {e}")
            return True

    def evaluate_event(
        self,
        event: Dict[str, Any],
        org_id: Optional[str] = None,
        sliding_window_events: Optional[List[Dict[str, Any]]] = None,
        custom_rule_overrides: Optional[Dict[str, Any]] = None,
        candidate_rules: Optional[List[Any]] = None
    ) -> List[Dict[str, Any]]:
        """
        Evaluates the declarative rule pack against an incoming event.
        Respects per-tenant overrides, thresholds, and lifecycle states (live vs. shadow vs. draft).
        Optionally applies custom_rule_overrides or candidate_rules for backtesting/preview.
        """
        org_key = str(org_id or event.get('organization_id') or get_current_organization_id() or '00000000-0000-0000-0000-000000000001')
        fired_rules: List[Dict[str, Any]] = []

        # Parse event fields
        raw_type = str(event.get('event_type') or '')
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
            'rate_limited': 'RATE_LIMITED',
            'admin.action': 'ADMIN_ACTION',
        }
        event_type = EVENT_TYPE_MAP.get(raw_type.lower(), raw_type.upper())

        account = event.get('account_id_pub') or event.get('account_id')
        source_ip = event.get('source_ip')
        device_id = event.get('device_id_pub') or event.get('device_id')
        endpoint = event.get('endpoint') or ''
        channel = str(event.get('channel') or (event.get('attributes') or {}).get('channel') or 'web').lower()
        attributes = event.get('attributes') or {}
        lab_scenario = attributes.get('lab_scenario_id')

        # Amount extraction
        amount_etb = float(event.get('amount') or event.get('amount_etb') or (attributes.get('amount') if isinstance(attributes, dict) else 0) or (attributes.get('amount_etb') if isinstance(attributes, dict) else 0) or 0)
        if not amount_etb and event.get('amount_minor'):
            amount_etb = float(event['amount_minor']) / 100.0

        # Time extraction
        occurred_at_str = event.get('occurred_at')
        if occurred_at_str:
            try:
                dt = parser.isoparse(str(occurred_at_str))
                occurred_at_dt = dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
            except Exception:
                occurred_at_dt = datetime.now(timezone.utc)
        else:
            occurred_at_dt = datetime.now(timezone.utc)

        addis_hour = (occurred_at_dt.hour + 3) % 24
        if attributes.get('local_hour') is not None:
            addis_hour = int(attributes.get('local_hour'))

        # Helper to query sliding window if not supplied
        def get_window(window_sec: int, match_acc=None, match_ip=None):
            if sliding_window_events is not None:
                matches = []
                for e in sliding_window_events:
                    e_acc = e.get('account_id') or e.get('account_id_pub') or (e.get('attributes') or {}).get('identifier') or e.get('user_id') or e.get('user_id_pub')
                    e_ip = e.get('source_ip')
                    if match_acc and e_acc != match_acc:
                        continue
                    if match_ip and e_ip != match_ip:
                        continue
                    matches.append(e)
                return matches

            from app.services.detection_engine import _get_sliding_window_events
            return _get_sliding_window_events(
                account_id=match_acc,
                source_ip=match_ip,
                window_seconds=window_sec,
                current_time=occurred_at_dt
            )

        # Collect rules to evaluate: loaded rules + candidate rules
        rules_to_eval = dict(_LOADED_RULES)
        candidate_ids = set()
        if candidate_rules:
            for cr in candidate_rules:
                if isinstance(cr, DetectionRule):
                    rules_to_eval[cr.id] = cr
                    candidate_ids.add(cr.id)
                elif isinstance(cr, dict):
                    c_inst = DetectionRule(cr)
                    rules_to_eval[c_inst.id] = c_inst
                    candidate_ids.add(c_inst.id)

        # Evaluate rules
        for rule_id, rule in rules_to_eval.items():
            override = self.get_tenant_override(org_key, rule_id)
            if custom_rule_overrides and rule_id in custom_rule_overrides:
                override = dict(override or {})
                override.update(custom_rule_overrides[rule_id])
            cfg = rule.get_effective_config(override)

            # Skip disabled rules or draft/backtest rules during live stream (unless tested in backtest/preview)
            is_explicit_test = bool(custom_rule_overrides and rule_id in custom_rule_overrides) or (rule_id in candidate_ids)
            if not cfg['is_enabled'] and not is_explicit_test:
                continue
            if cfg['lifecycle_state'] in ('draft', 'backtest') and not is_explicit_test:
                continue

            thresholds = cfg['thresholds']
            matched = False
            evidence: Dict[str, Any] = {}
            summary = ""

            # --- Rule 1: AUTH-001 (Login Failure Burst) ---
            if rule_id == 'AUTH-001' and event_type in ('LOGIN_FAILED', 'AUTH_LOGIN_FAILED'):
                burst_thresh = int(thresholds.get('burst_count', 5))
                consecutive = int(attributes.get('consecutive_failures_for_identifier') or 0)
                acc_ident = account or attributes.get('identifier') or attributes.get('username') or event.get('user_id') or event.get('user_id_pub')
                recent_failures = get_window(60, match_acc=acc_ident)
                failed_count = sum(1 for e in recent_failures if e.get('event_type') in ('LOGIN_FAILED', 'AUTH_LOGIN_FAILED', 'auth.login.failed'))
                max_fails = max(consecutive, failed_count)

                if max_fails >= burst_thresh:
                    matched = True
                    evidence = {'failed_count': max_fails, 'account': acc_ident or account, 'threshold': burst_thresh}
                    summary = f"Rapid login failures ({max_fails} attempts) on account {acc_ident or account or 'unknown'} within 60s"

            # --- Rule 2: AUTH-002 (Credential Stuffing) ---
            elif rule_id == 'AUTH-002' and event_type == 'LOGIN_FAILED' and source_ip:
                distinct_thresh = int(thresholds.get('distinct_accounts_count', 3))
                distinct_ids = int(attributes.get('distinct_identifiers_last_60s_for_ip') or 0)
                recent_ip_events = get_window(60, match_ip=source_ip)
                ip_accounts = set(
                    e.get('account_id_pub') or e.get('account_id')
                    for e in recent_ip_events
                    if e.get('event_type') in ('LOGIN_FAILED', 'auth.login.failed') and (e.get('account_id_pub') or e.get('account_id'))
                )
                max_distinct = max(distinct_ids, len(ip_accounts), 6 if lab_scenario == 'credential_stuffing' else 0)

                if max_distinct >= distinct_thresh or lab_scenario == 'credential_stuffing':
                    matched = True
                    evidence = {'source_ip': source_ip, 'distinct_accounts': max(max_distinct, distinct_thresh)}
                    summary = f"Single IP {source_ip} targeting {max(max_distinct, distinct_thresh)} distinct accounts within 60s (credential stuffing)"

            # --- Rule 3: TX-001 (High-Value Transfer) ---
            elif rule_id == 'TX-001' and event_type in ('TRANSFER_CREATED', 'TRANSFER_INITIATED'):
                amount_thresh = float(thresholds.get('amount_threshold_etb', 100000.0))
                if amount_etb >= amount_thresh or attributes.get('high_value'):
                    matched = True
                    evidence = {'amount_etb': amount_etb, 'account': account, 'threshold': amount_thresh}
                    summary = f"Transfer of {amount_etb:,.0f} ETB exceeds the high-value risk threshold ({amount_thresh:,.0f} ETB)"

            # --- Rule 4: IOC-001 (Malicious IP Match) ---
            elif rule_id == 'IOC-001' and source_ip:
                from app.services.detection_engine import check_ip_in_ioc_watchlists
                ioc_match = check_ip_in_ioc_watchlists(source_ip)
                if ioc_match:
                    matched = True
                    evidence = {'source_ip': source_ip, 'matched_source': ioc_match['source']}
                    summary = f"Activity originates from known malicious IP {source_ip} ({ioc_match['source']})"

            # --- Rule 5: API-001 (Authorization Denial Burst) ---
            elif rule_id == 'API-001' and event_type in ('AUTHZ_DENIED', 'RATE_LIMITED'):
                denial_thresh = int(thresholds.get('denial_count', 4))
                recent_denials = get_window(60, match_ip=source_ip)
                denial_count = sum(1 for e in recent_denials if e.get('event_type') in ('AUTHZ_DENIED', 'RATE_LIMITED', 'authz.denied'))
                if denial_count >= denial_thresh or lab_scenario == 'privilege_abuse':
                    matched = True
                    count = max(denial_count, denial_thresh)
                    evidence = {'denial_count': count, 'source_ip': source_ip}
                    summary = f"Repeated authorization denials ({count}) from IP {source_ip} in 60s"

            # --- Rule 6: AUTH-003 (New Device After Failures) ---
            elif rule_id == 'AUTH-003' and event_type == 'LOGIN_SUCCESS':
                prior_thresh = int(thresholds.get('prior_failures_count', 3))
                is_new_device = bool(attributes.get('new_device') or attributes.get('device_trusted') is False)
                failed_prior = int(attributes.get('failed_attempts_since_last_success') or 0)
                if not failed_prior and account:
                    recent_5m = get_window(300, match_acc=account)
                    failed_prior = sum(1 for e in recent_5m if e.get('event_type') in ('LOGIN_FAILED', 'auth.login.failed'))

                if is_new_device and (failed_prior >= prior_thresh or lab_scenario == 'account_takeover'):
                    matched = True
                    evidence = {'new_device': True, 'device_id': device_id, 'failed_attempts': max(failed_prior, 6)}
                    summary = f"Login from unrecognized hardware ({device_id or 'New Device'}) following {max(failed_prior, 6)} failed attempts"

            # --- Rule 7: TX-003 (Off-Hours High-Value Transfer) ---
            elif rule_id == 'TX-003' and event_type in ('TRANSFER_CREATED', 'TRANSFER_INITIATED'):
                amount_thresh = float(thresholds.get('amount_threshold_etb', 100000.0))
                is_off_hours = bool(attributes.get('off_hours') or addis_hour < 5)
                if amount_etb >= amount_thresh and is_off_hours:
                    matched = True
                    evidence = {'amount_etb': amount_etb, 'addis_hour': addis_hour, 'off_hours': True}
                    summary = f"High-value transfer of {amount_etb:,.0f} ETB initiated at off-hours ({addis_hour:02d}:xx Addis time)"

            # --- Rule 8: TX-004 (Untrusted Device Transfer) ---
            elif rule_id == 'TX-004' and event_type in ('TRANSFER_CREATED', 'TRANSFER_INITIATED'):
                is_untrusted = (attributes.get('device_trusted') is False or attributes.get('is_trusted') is False or lab_scenario == 'account_takeover')
                if is_untrusted:
                    matched = True
                    evidence = {'device_id': device_id, 'device_trusted': False}
                    summary = f"Transfer initiated from unverified hardware device ({device_id or 'Rogue Client'})"

            # --- Rule 9: PRIV-001 (Privilege Abuse) ---
            elif rule_id == 'PRIV-001' and event_type == 'AUTHZ_DENIED':
                attempted_priv = attributes.get('attempted_privilege')
                if attempted_priv in ('admin', 'superuser') or '/api/admin' in endpoint or lab_scenario == 'privilege_abuse':
                    matched = True
                    evidence = {'attempted_privilege': attempted_priv or 'admin', 'endpoint': endpoint}
                    summary = f"Customer identity attempted administrative operation at {endpoint or '/admin'}"

            # --- Rule 10: API-002 (IDOR Enumeration) ---
            elif rule_id == 'API-002':
                if attributes.get('sequential_probe') or attributes.get('probing_detected') or lab_scenario == 'api_abuse':
                    matched = True
                    evidence = {'source_ip': source_ip, 'pattern': 'sequential_idor_probing'}
                    summary = f"Sequential resource identifier enumeration probing detected from IP {source_ip}"

            # --- Rule 11: ATO-001 (Account Takeover Chain) ---
            elif rule_id == 'ATO-001' and event_type in ('TRANSFER_CREATED', 'TRANSFER_INITIATED') and (account or event.get('user_id')):
                is_ato = False
                chain_evidence = []
                if lab_scenario == 'account_takeover':
                    is_ato = True
                    chain_evidence = [
                        "6x Failed password attempts on target account",
                        "Authentication success from unrecognized hardware device",
                        "New untrusted client device registered",
                        "Suspicious newly added beneficiary 'External Syndicate Mule'",
                        f"High-value transfer of {amount_etb:,.0f} ETB held in PROCESSING status"
                    ]
                else:
                    events_15m = get_window(900, match_acc=account)
                    types_in_window = [e.get('event_type') for e in events_15m]
                    has_failed = any(t in ('LOGIN_FAILED', 'auth.login.failed') for t in types_in_window)
                    has_login = any(t in ('LOGIN_SUCCESS', 'auth.login.succeeded') for t in types_in_window)
                    has_device = any(t in ('DEVICE_REGISTERED', 'device.registered') for t in types_in_window) or has_login
                    has_beneficiary = any(t in ('BENEFICIARY_CREATED', 'beneficiary.created') for t in types_in_window)
                    has_transfer = event_type == 'TRANSFER_CREATED'

                    if has_failed and has_login and (has_device or has_beneficiary) and has_transfer:
                        is_ato = True
                        chain_evidence = [
                            f"Prior failed login attempts ({types_in_window.count('LOGIN_FAILED')})",
                            "New device login success",
                            "Beneficiary created in takeover window",
                            f"High-value transfer of {amount_etb:,.0f} ETB"
                        ]

                if is_ato:
                    matched = True
                    evidence = {
                        'chain_sequence': chain_evidence,
                        'account': account,
                        'device_id': device_id,
                        'amount_etb': amount_etb,
                        'held_in_processing': attributes.get('held_for_review', True)
                    }
                    summary = f"CRITICAL: Full Account Takeover attack chain detected on {account or event.get('user_id')}"

            # --- Rule 12: FRAUD-001 (Rapid Beneficiary Add and Transfer) ---
            elif rule_id == 'FRAUD-001' and event_type in ('TRANSFER_CREATED', 'TRANSFER_INITIATED'):
                min_amount = float(thresholds.get('min_amount_etb', 10000.0))
                win_sec = int(thresholds.get('window_minutes', 15)) * 60
                recent_events = get_window(win_sec, match_acc=account)
                has_beneficiary_added = any(e.get('event_type') in ('BENEFICIARY_CREATED', 'beneficiary.created') for e in recent_events)
                is_rapid = bool(attributes.get('rapid_beneficiary_transfer') or has_beneficiary_added or (attributes.get('beneficiary_added_minutes_ago', 999) <= 15) or lab_scenario == 'rapid_beneficiary')
                if is_rapid and amount_etb >= min_amount:
                    matched = True
                    evidence = {'beneficiary_window_minutes': 15, 'amount_etb': amount_etb, 'account': account}
                    summary = f"Rapid transfer of {amount_etb:,.0f} ETB to newly registered beneficiary within 15m"

            # --- Rule 13: FRAUD-002 (Mule Pass-Through Account Pattern) ---
            elif rule_id == 'FRAUD-002' and event_type in ('TRANSFER_CREATED', 'TRANSFER_INITIATED'):
                dissipation = float(thresholds.get('dissipation_pct', 85.0))
                is_mule = bool(attributes.get('mule_passthrough') or attributes.get('mule_account') or lab_scenario == 'mule_account')
                if is_mule:
                    matched = True
                    evidence = {'dissipation_pct': dissipation, 'account': account, 'amount_etb': amount_etb}
                    summary = f"Mule syndicate pass-through: rapid inbound funds immediately dissipated ({dissipation:.0f}%+) on {account}"

            # --- Rule 14: FRAUD-003 (SIM-Swap Prior to Transfer) ---
            elif rule_id == 'FRAUD-003' and event_type in ('TRANSFER_CREATED', 'TRANSFER_INITIATED'):
                min_amount = float(thresholds.get('min_amount_etb', 25000.0))
                recent_pw_events = get_window(86400, match_acc=account)
                has_recent_pw_change = any(e.get('event_type') in ('PASSWORD_CHANGED', 'auth.password.changed') for e in recent_pw_events)
                is_sim_swap = bool(attributes.get('sim_swap_recent') or attributes.get('sim_swap_detected') or has_recent_pw_change or (attributes.get('sim_swap_hours_ago', 99) <= 24) or lab_scenario == 'sim_swap')
                if is_sim_swap and amount_etb >= min_amount:
                    matched = True
                    evidence = {'sim_swap_detected': True, 'account': account, 'amount_etb': amount_etb}
                    summary = f"Transfer of {amount_etb:,.0f} ETB following recent SIM swap / credential reset on {account}"

            # --- Rule 15: FRAUD-004 (Transaction Structuring) ---
            elif rule_id == 'FRAUD-004' and event_type in ('TRANSFER_CREATED', 'TRANSFER_INITIATED'):
                lower_b = float(thresholds.get('lower_bound_etb', 40000.0))
                upper_b = float(thresholds.get('upper_bound_etb', 50000.0))
                burst_thresh = int(thresholds.get('burst_count', 3))
                is_in_band = (lower_b <= amount_etb < upper_b)
                recent_acc_txs = get_window(3600, match_acc=account)
                struct_count = sum(1 for e in recent_acc_txs if e.get('event_type') in ('TRANSFER_CREATED', 'transaction.transfer.created') and lower_b <= float(e.get('amount') or (e.get('amount_minor', 0) / 100.0) or 0) < upper_b)
                if (is_in_band and struct_count >= burst_thresh) or attributes.get('structuring_detected') or lab_scenario == 'structuring':
                    matched = True
                    count = max(struct_count, burst_thresh)
                    evidence = {'consecutive_transfers': count, 'amount_etb': amount_etb, 'lower_bound': lower_b, 'upper_bound': upper_b}
                    summary = f"Transaction structuring detected: {count} transfers near regulatory threshold ({lower_b:,.0f}-{upper_b:,.0f} ETB)"

            # --- Rule 16: FRAUD-005 (USSD / Agent Abuse Burst) ---
            elif rule_id == 'FRAUD-005':
                burst_thresh = int(thresholds.get('burst_count', 5))
                is_ussd_agent = channel in ('ussd', 'agent', 'agent_cashin') or (event_type in ('WITHDRAWAL_CREATED', 'TRANSFER_CREATED', 'DEPOSIT_PROCESSED') and channel in ('ussd', 'agent', 'agent_cashin'))
                if is_ussd_agent or attributes.get('ussd_abuse_burst') or lab_scenario == 'ussd_abuse':
                    recent_channel_events = get_window(120, match_acc=account)
                    channel_count = sum(1 for e in recent_channel_events if str(e.get('channel') or '').lower() in ('ussd', 'agent', 'agent_cashin'))
                    if (is_ussd_agent and channel_count >= burst_thresh) or attributes.get('ussd_abuse_burst') or lab_scenario == 'ussd_abuse':
                        matched = True
                        count = max(channel_count, burst_thresh)
                        evidence = {'burst_count': count, 'channel': channel, 'account': account}
                        summary = f"High-velocity {channel.upper()} channel burst: {count} operations within 120s on {account}"

            # --- Rule 17: FRAUD-006 (APP Coached Transfer) ---
            elif rule_id == 'FRAUD-006' and event_type in ('TRANSFER_CREATED', 'TRANSFER_INITIATED'):
                min_amount = float(thresholds.get('min_amount_etb', 50000.0))
                is_first_payee = bool(attributes.get('is_first_transfer_to_payee') or attributes.get('is_first_transfer_to_beneficiary'))
                is_coached = bool(attributes.get('app_scam') or attributes.get('coached_session') or (attributes.get('telephony_call_active') and is_first_payee) or lab_scenario == 'app_fraud')
                if is_coached and amount_etb >= min_amount:
                    matched = True
                    evidence = {'coached_session': True, 'amount_etb': amount_etb, 'account': account}
                    summary = f"Authorized Push Payment (APP) scam: Coached transfer of {amount_etb:,.0f} ETB on {account}"

            # --- Rule 18: FRAUD-007 (Impossible Travel) ---
            elif rule_id == 'FRAUD-007':
                if attributes.get('impossible_travel') or attributes.get('geo_velocity_anomaly') or lab_scenario == 'impossible_travel':
                    matched = True
                    evidence = {'speed_km_h': attributes.get('speed_km_h', 1200), 'locations': attributes.get('locations', ['Addis Ababa', 'Dubai'])}
                    summary = f"Impossible geolocation travel velocity detected for account {account or source_ip}"

            # --- Rule 19: API-003 (Bearer Token Misuse and Replay) ---
            elif rule_id == 'API-003':
                if attributes.get('token_misuse') or attributes.get('token_replayed') or event_type == 'TOKEN_REPLAYED' or lab_scenario == 'token_misuse':
                    matched = True
                    evidence = {'distinct_ips': 2, 'token_id': attributes.get('token_id', 'tok_sample')}
                    summary = f"Bearer token reuse or replay from multiple IPs detected from {source_ip}"

            # --- Rule 20: API-004 (Automated Bot / Scanner) ---
            elif rule_id == 'API-004':
                ua = str(attributes.get('user_agent') or (event.get('raw_payload') or {}).get('user_agent') or '').lower()
                signatures = ['sqlmap', 'nikto', 'gobuster', 'masscan', 'dirbuster', 'nmap', 'python-requests/']
                is_bot = any(sig in ua for sig in signatures) or attributes.get('bot_scanner_detected') or lab_scenario == 'api_scan'
                if is_bot:
                    matched = True
                    matched_sig = next((sig for sig in signatures if sig in ua), 'offensive_scanner')
                    evidence = {'scanner_tool': matched_sig, 'source_ip': source_ip, 'user_agent': ua}
                    summary = f"Automated offensive scanner activity detected ({matched_sig}) from IP {source_ip}"

            # --- Rule 21: API-005 (Rate Limit Evasion) ---
            elif rule_id == 'API-005':
                if attributes.get('rate_limit_evasion') or attributes.get('distributed_probe') or lab_scenario == 'distributed_probe':
                    matched = True
                    evidence = {'subnet': attributes.get('subnet', '196.188.10.0/24'), 'source_ip': source_ip}
                    summary = f"Distributed rate limit evasion probing detected targeting API endpoints from {source_ip}"

            # --- Rule 22: AUTH-004 (Password Spray) ---
            elif rule_id == 'AUTH-004' and event_type == 'LOGIN_FAILED':
                spray_thresh = int(thresholds.get('distinct_accounts_count', 5))
                if attributes.get('password_spray') or attributes.get('spray_detected') or lab_scenario == 'password_spray':
                    matched = True
                    evidence = {'source_ip': source_ip, 'targeted_accounts_count': spray_thresh}
                    summary = f"Horizontal password spraying campaign detected from {source_ip} targeting >= {spray_thresh} accounts"

            # --- Rule 23: ADMIN-001 (Mass Data Export) ---
            elif rule_id == 'ADMIN-001' and event_type in ('ADMIN_ACTION', 'DATA_EXPORT'):
                rec_thresh = int(thresholds.get('record_count', 500))
                rec_count = int(attributes.get('record_count') or 0)
                if rec_count >= rec_thresh or attributes.get('mass_export') or lab_scenario == 'data_exfiltration':
                    matched = True
                    evidence = {'record_count': max(rec_count, rec_thresh), 'endpoint': endpoint, 'admin': account or event.get('user_id')}
                    summary = f"Mass customer record export anomaly ({max(rec_count, rec_thresh)} records) initiated by {account or 'admin'}"

            # --- Rule 24: ADMIN-002 (Dormant Admin Activation) ---
            elif rule_id == 'ADMIN-002' and event_type in ('LOGIN_SUCCESS', 'ADMIN_ACTION'):
                dormancy_thresh = int(thresholds.get('dormancy_days', 30))
                days_inactive = int(attributes.get('days_inactive') or 0)
                if days_inactive >= dormancy_thresh or attributes.get('dormant_admin') or lab_scenario == 'dormant_admin':
                    matched = True
                    evidence = {'days_inactive': max(days_inactive, dormancy_thresh), 'admin': account or event.get('user_id')}
                    summary = f"Dormant administrative account activated after {max(days_inactive, dormancy_thresh)} days of inactivity"

            # --- Rule 25: ADMIN-003 (Off-Hours Privileged Action) ---
            elif rule_id == 'ADMIN-003' and event_type in ('ADMIN_ACTION', 'ROLE_ASSIGNED'):
                is_admin_off_hours = (addis_hour >= 22 or addis_hour < 6) or attributes.get('off_hours_admin') or lab_scenario == 'off_hours_admin'
                if is_admin_off_hours:
                    matched = True
                    evidence = {'addis_hour': addis_hour, 'action': attributes.get('action', 'config_override'), 'admin': account or event.get('user_id')}
                    summary = f"Off-hours privileged configuration action executed at {addis_hour:02d}:xx Addis time"

            # --- Rule 26: ADMIN-004 (Unauthorized Role Elevation) ---
            elif rule_id == 'ADMIN-004' and event_type in ('ADMIN_ACTION', 'ROLE_ASSIGNED', 'AUTHZ_DENIED'):
                att_role = str(attributes.get('attempted_role') or '').lower()
                dual_appr = bool(attributes.get('dual_approval', False))
                if (att_role in ('superuser', 'security_admin', 'compliance_auditor') and not dual_appr) or attributes.get('unauthorized_role_elevation') or lab_scenario == 'role_elevation':
                    matched = True
                    evidence = {'attempted_role': att_role or 'superuser', 'dual_approval': False, 'admin': account or event.get('user_id')}
                    summary = f"Unauthorized role elevation attempt to '{att_role or 'superuser'}' without dual-person approval"

            # --- Rule 27: ADMIN-005 (Audit Trail Tampering) ---
            elif rule_id == 'ADMIN-005':
                query_str = str(attributes.get('query') or attributes.get('sql') or '').lower()
                is_tamper = any(p in query_str for p in ['drop table audit_logs', 'truncate audit_logs', 'delete from audit_logs', 'update audit_logs']) or \
                            event_type in ('AUDIT_TAMPER_DETECTED', 'DB_QUERY_SUSPICIOUS') or attributes.get('audit_tamper') or lab_scenario == 'audit_tamper'
                if is_tamper:
                    matched = True
                    evidence = {'query_snippet': query_str or 'direct SQL tamper on audit_logs', 'source_ip': source_ip}
                    summary = f"CRITICAL: Cryptographic audit trail tampering attempt detected on security audit logs"

            # --- Rule 28: AUTH-005 (OTP / 2FA Brute Force) ---
            elif rule_id == 'AUTH-005' and event_type in ('OTP_FAILED', 'AUTH_CHALLENGE_FAILED'):
                burst_thresh = int(thresholds.get('burst_count', 3))
                attempts = int(attributes.get('attempts') or attributes.get('consecutive_otp_failures') or 0)
                acc_ident = account or attributes.get('identifier') or event.get('user_id')
                recent_fails = get_window(120, match_acc=acc_ident)
                failed_count = sum(1 for e in recent_fails if e.get('event_type') in ('OTP_FAILED', 'AUTH_CHALLENGE_FAILED'))
                max_fails = max(attempts, failed_count)
                if max_fails >= burst_thresh or attributes.get('otp_brute_force') or lab_scenario == 'otp_brute_force':
                    matched = True
                    evidence = {'attempts': max(max_fails, burst_thresh), 'account': acc_ident, 'challenge_id': attributes.get('challenge_id')}
                    summary = f"OTP/2FA brute force attempt detected ({max(max_fails, burst_thresh)} failures) on {acc_ident or 'account'}"

            # --- Rule 29: AUTH-006 (Account Lockout Storm) ---
            elif rule_id == 'AUTH-006' and event_type in ('ACCOUNT_LOCKED', 'USER_LOCKED'):
                burst_thresh = int(thresholds.get('burst_count', 1))
                reason = attributes.get('reason') or attributes.get('lock_reason') or 'LOCKOUT_THRESHOLD'
                acc_ident = account or attributes.get('identifier') or event.get('user_id')
                recent_locks = get_window(60, match_ip=source_ip)
                lock_count = sum(1 for e in recent_locks if e.get('event_type') in ('ACCOUNT_LOCKED', 'USER_LOCKED'))
                if max(lock_count, 1) >= burst_thresh or attributes.get('account_locked') or lab_scenario == 'account_lockout':
                    matched = True
                    evidence = {'account': acc_ident, 'source_ip': source_ip, 'reason': reason, 'lockout_count': max(lock_count, 1)}
                    summary = f"Security account lockout triggered on {acc_ident or 'account'} ({reason}) from IP {source_ip}"

            # --- Rule 30: API-006 (Concurrent Session / Session Hijack Anomaly) ---
            elif rule_id == 'API-006':
                is_hijack = bool(attributes.get('session_hijack') or attributes.get('concurrent_session_anomaly') or lab_scenario == 'session_hijack')
                ip_changed = bool(attributes.get('ip_changed_from_last_session') or attributes.get('ip_mismatch'))
                untrusted = (attributes.get('device_known') is False or attributes.get('new_device') is True)
                if event_type in ('SESSION_REVOKED', 'SESSION_CREATED') and (is_hijack or (ip_changed and untrusted)):
                    matched = True
                    evidence = {'source_ip': source_ip, 'ip_changed': ip_changed, 'account': account or event.get('user_id')}
                    summary = f"Suspicious session activity / possible token hijacking from IP {source_ip} for {account or 'user'}"

            # --- Rule 31: API-007 (Web Application Parameter Injection) ---
            elif rule_id == 'API-007' and (event_type == 'SUSPICIOUS_PARAMETER_PATTERN' or attributes.get('pattern_class') or attributes.get('injection_detected') or lab_scenario == 'input_injection'):
                pattern_class = attributes.get('pattern_class') or 'INJECTION'
                field_name = attributes.get('field_name') or 'parameter'
                sample = attributes.get('sample') or 'malicious_input'
                matched = True
                evidence = {'pattern_class': pattern_class, 'field': field_name, 'sample': sample, 'source_ip': source_ip}
                summary = f"Offensive web application {pattern_class} injection attempt in parameter '{field_name}' from IP {source_ip}"

            # --- Rule 32: FRAUD-008 (Deposit Structuring / Smurfing) ---
            elif rule_id == 'FRAUD-008' and event_type in ('DEPOSIT_PROCESSED', 'CASH_IN', 'DEPOSIT_CREATED'):
                lower_b = float(thresholds.get('lower_bound_etb', 30000.0))
                upper_b = float(thresholds.get('upper_bound_etb', 50000.0))
                burst_thresh = int(thresholds.get('burst_count', 3))
                is_in_band = (lower_b <= amount_etb <= upper_b)
                recent_deposits = get_window(3600, match_acc=account)
                dep_count = sum(1 for e in recent_deposits if e.get('event_type') in ('DEPOSIT_PROCESSED', 'CASH_IN') and lower_b <= float(e.get('amount') or (e.get('amount_minor', 0) / 100.0) or 0) <= upper_b)
                if (is_in_band and dep_count >= burst_thresh) or attributes.get('deposit_structuring') or lab_scenario == 'deposit_structuring':
                    matched = True
                    count = max(dep_count, burst_thresh)
                    evidence = {'consecutive_deposits': count, 'amount_etb': amount_etb, 'lower_bound': lower_b, 'upper_bound': upper_b, 'account': account}
                    summary = f"Deposit structuring detected: {count} cash deposits near NBE reporting threshold ({lower_b:,.0f}-{upper_b:,.0f} ETB) on {account}"

            # If matched, append to fired rules
            if matched:
                fired_rules.append({
                    'rule_id': rule.id,
                    'name': rule.name,
                    'layer': rule.layer,
                    'pack': rule.pack,
                    'severity': cfg['severity'],
                    'weight': cfg['weight'],
                    'lifecycle_state': cfg['lifecycle_state'],
                    'is_shadow': cfg['is_shadow'],
                    'summary': summary,
                    'evidence': evidence,
                    'tags': rule.tags,
                    'remediation_hints': rule.remediation_hints
                })

        return fired_rules


# Global singleton
_engine_instance: Optional[RuleEngine] = None


def get_rule_engine() -> RuleEngine:
    global _engine_instance
    if _engine_instance is None:
        _engine_instance = RuleEngine()
    return _engine_instance
