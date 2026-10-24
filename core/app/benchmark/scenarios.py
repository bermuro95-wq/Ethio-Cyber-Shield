"""
Ethio-Cyber-Shield (ECS) — Attack Lab Scenario Library (Phase 3.6).
Provides >= 12 distinct attack scenarios across Fraud & Payments, Web/API, and Insider/Admin packs,
plus realistic benign baseline scenarios for false-positive validation.
All events adhere to ECS Event Contract v1.1.
"""
import uuid
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional


def _now_iso(offset_seconds: int = 0) -> str:
    dt = datetime.now(timezone.utc) + timedelta(seconds=offset_seconds)
    return dt.isoformat()


# =========================================================================
# 1. SCENARIO EVENT GENERATORS
# =========================================================================

def _gen_ato_chain(org_id: str) -> List[Dict[str, Any]]:
    """Multi-stage Account Takeover (ATO-001)."""
    acc = f"ACC_VICTIM_{uuid.uuid4().hex[:6]}"
    usr = f"USR_VICTIM_{uuid.uuid4().hex[:6]}"
    ip = "197.156.100.88"
    new_dev = f"DEV_ROGUE_{uuid.uuid4().hex[:6]}"
    ben = f"BEN_MULE_{uuid.uuid4().hex[:6]}"
    events = []

    # 1. Brute force password failures (5 attempts)
    for i in range(5):
        events.append({
            'event_id': str(uuid.uuid4()),
            'organization_id': org_id,
            'event_type': 'LOGIN_FAILED',
            'account_id': acc,
            'user_id': usr,
            'source_ip': ip,
            'timestamp': _now_iso(-120 + i * 2),
            'attributes': {
                'consecutive_failures_for_identifier': i + 1,
                'lab_scenario_id': 'account_takeover'
            }
        })

    # 2. Login success from unrecognized new device
    events.append({
        'event_id': str(uuid.uuid4()),
        'organization_id': org_id,
        'event_type': 'LOGIN_SUCCESS',
        'account_id': acc,
        'user_id': usr,
        'device_id': new_dev,
        'source_ip': ip,
        'timestamp': _now_iso(-90),
        'attributes': {
            'new_device': True,
            'failed_attempts_since_last_success': 5,
            'lab_scenario_id': 'account_takeover'
        }
    })

    # 3. New untrusted client device registration
    events.append({
        'event_id': str(uuid.uuid4()),
        'organization_id': org_id,
        'event_type': 'DEVICE_REGISTERED',
        'account_id': acc,
        'user_id': usr,
        'device_id': new_dev,
        'source_ip': ip,
        'timestamp': _now_iso(-60),
        'attributes': {'is_trusted': False, 'lab_scenario_id': 'account_takeover'}
    })

    # 4. Rapid beneficiary creation
    events.append({
        'event_id': str(uuid.uuid4()),
        'organization_id': org_id,
        'event_type': 'BENEFICIARY_CREATED',
        'account_id': acc,
        'user_id': usr,
        'device_id': new_dev,
        'beneficiary_id': ben,
        'source_ip': ip,
        'timestamp': _now_iso(-30),
        'attributes': {'beneficiary_name': 'External Syndicate Mule', 'lab_scenario_id': 'account_takeover'}
    })

    # 5. High-value transfer
    events.append({
        'event_id': str(uuid.uuid4()),
        'organization_id': org_id,
        'event_type': 'TRANSFER_CREATED',
        'account_id': acc,
        'user_id': usr,
        'device_id': new_dev,
        'beneficiary_id': ben,
        'amount': 150000.0,
        'currency': 'ETB',
        'source_ip': ip,
        'timestamp': _now_iso(0),
        'attributes': {
            'amount': 150000.0,
            'device_trusted': False,
            'rapid_beneficiary_transfer': True,
            'lab_scenario_id': 'account_takeover'
        }
    })
    return events


def _gen_mule_transfer(org_id: str) -> List[Dict[str, Any]]:
    """Mule Pass-Through Account Syndicate (FRAUD-002, TX-001)."""
    mule_acc = f"ACC_MULE_{uuid.uuid4().hex[:6]}"
    ip = "196.188.45.12"
    return [
        {
            'event_id': str(uuid.uuid4()),
            'organization_id': org_id,
            'event_type': 'TRANSFER_CREATED',
            'account_id': mule_acc,
            'amount': 180000.0,
            'currency': 'ETB',
            'source_ip': ip,
            'channel': 'mobile',
            'timestamp': _now_iso(0),
            'attributes': {
                'amount': 180000.0,
                'mule_passthrough': True,
                'mule_account': True,
                'dissipation_pct': 92.0,
                'lab_scenario_id': 'mule_account'
            }
        }
    ]


def _gen_sim_swap(org_id: str) -> List[Dict[str, Any]]:
    """SIM-Swap Credential Reset & Instant Cashout (FRAUD-003, TX-001)."""
    acc = f"ACC_SIMSWAP_{uuid.uuid4().hex[:6]}"
    ip = "197.156.70.33"
    return [
        {
            'event_id': str(uuid.uuid4()),
            'organization_id': org_id,
            'event_type': 'TRANSFER_CREATED',
            'account_id': acc,
            'amount': 120000.0,
            'currency': 'ETB',
            'source_ip': ip,
            'timestamp': _now_iso(0),
            'attributes': {
                'amount': 120000.0,
                'sim_swap_recent': True,
                'sim_swap_hours_ago': 2,
                'lab_scenario_id': 'sim_swap'
            }
        }
    ]


def _gen_structuring(org_id: str) -> List[Dict[str, Any]]:
    """Transaction Structuring Under Thresholds (FRAUD-004)."""
    acc = f"ACC_STRUCT_{uuid.uuid4().hex[:6]}"
    ip = "196.188.10.99"
    events = []
    # 4 transactions of 48,000 ETB (just below 50,000 reporting threshold)
    for i in range(4):
        events.append({
            'event_id': str(uuid.uuid4()),
            'organization_id': org_id,
            'event_type': 'TRANSFER_CREATED',
            'account_id': acc,
            'amount': 48000.0,
            'currency': 'ETB',
            'source_ip': ip,
            'timestamp': _now_iso(-600 + i * 120),
            'attributes': {
                'amount': 48000.0,
                'structuring_detected': True,
                'burst_count': 4,
                'lab_scenario_id': 'structuring'
            }
        })
    return events


def _gen_ussd_cash_out(org_id: str) -> List[Dict[str, Any]]:
    """USSD Session Burst & Agent Cashout (FRAUD-005)."""
    acc = f"ACC_USSD_{uuid.uuid4().hex[:6]}"
    events = []
    for i in range(6):
        events.append({
            'event_id': str(uuid.uuid4()),
            'organization_id': org_id,
            'event_type': 'WITHDRAWAL_CREATED',
            'account_id': acc,
            'channel': 'ussd',
            'amount': 5000.0,
            'currency': 'ETB',
            'timestamp': _now_iso(-100 + i * 15),
            'attributes': {
                'channel': 'ussd',
                'ussd_abuse_burst': True,
                'agent_code': f'AGT_ADDIS_{i}',
                'lab_scenario_id': 'ussd_abuse'
            }
        })
    return events


def _gen_app_coached(org_id: str) -> List[Dict[str, Any]]:
    """Coached Authorized Push Payment (APP) Fraud (FRAUD-006, TX-001)."""
    acc = f"ACC_COACHED_{uuid.uuid4().hex[:6]}"
    return [
        {
            'event_id': str(uuid.uuid4()),
            'organization_id': org_id,
            'event_type': 'TRANSFER_CREATED',
            'account_id': acc,
            'amount': 75000.0,
            'currency': 'ETB',
            'timestamp': _now_iso(0),
            'attributes': {
                'amount': 75000.0,
                'app_scam': True,
                'coached_session': True,
                'telephony_call_active': True,
                'is_first_transfer_to_payee': True,
                'lab_scenario_id': 'app_fraud'
            }
        }
    ]


def _gen_cred_stuffing(org_id: str) -> List[Dict[str, Any]]:
    """Credential Stuffing Attack across 10 Accounts (AUTH-002, API-001)."""
    bot_ip = "185.220.101.55"
    events = []
    for i in range(8):
        events.append({
            'event_id': str(uuid.uuid4()),
            'organization_id': org_id,
            'event_type': 'LOGIN_FAILED',
            'account_id': f"ACC_TARGET_{i:03d}",
            'source_ip': bot_ip,
            'timestamp': _now_iso(-40 + i * 5),
            'attributes': {
                'distinct_identifiers_last_60s_for_ip': 8,
                'lab_scenario_id': 'credential_stuffing'
            }
        })
    return events


def _gen_idor_probe(org_id: str) -> List[Dict[str, Any]]:
    """Insecure Direct Object Reference (IDOR) Enumeration (API-002)."""
    attacker_ip = "196.188.200.12"
    return [
        {
            'event_id': str(uuid.uuid4()),
            'organization_id': org_id,
            'event_type': 'API_REQUEST',
            'source_ip': attacker_ip,
            'endpoint': '/api/v1/accounts/1000199/statement',
            'timestamp': _now_iso(0),
            'attributes': {
                'sequential_probe': True,
                'probing_detected': True,
                'probed_resources_count': 15,
                'lab_scenario_id': 'api_abuse'
            }
        }
    ]


def _gen_bot_scanner(org_id: str) -> List[Dict[str, Any]]:
    """Automated Bot & Security Scanner Recon (API-004)."""
    scanner_ip = "45.154.255.88"
    return [
        {
            'event_id': str(uuid.uuid4()),
            'organization_id': org_id,
            'event_type': 'API_REQUEST',
            'source_ip': scanner_ip,
            'endpoint': '/api/v1/transfer?id=1%20UNION%20SELECT%20null,schema_name',
            'timestamp': _now_iso(0),
            'attributes': {
                'user_agent': 'sqlmap/1.7#stable (http://sqlmap.org)',
                'scanner_detected': True,
                'lab_scenario_id': 'scanner_recon'
            }
        }
    ]


def _gen_token_replay(org_id: str) -> List[Dict[str, Any]]:
    """Bearer Token Misuse and Replay (API-003)."""
    return [
        {
            'event_id': str(uuid.uuid4()),
            'organization_id': org_id,
            'event_type': 'API_REQUEST',
            'source_ip': '197.156.12.99',
            'endpoint': '/api/v1/cards/view',
            'timestamp': _now_iso(0),
            'attributes': {
                'token_misuse': True,
                'token_replayed': True,
                'token_id': 'tok_stolen_sess_9988',
                'lab_scenario_id': 'token_misuse'
            }
        }
    ]


def _gen_mass_exfil(org_id: str) -> List[Dict[str, Any]]:
    """Insider Threat: Mass Customer Data Exfiltration (ADMIN-001, PRIV-001)."""
    admin_usr = f"USR_ADMIN_{uuid.uuid4().hex[:6]}"
    return [
        {
            'event_id': str(uuid.uuid4()),
            'organization_id': org_id,
            'event_type': 'ADMIN_ACTION',
            'user_id': admin_usr,
            'endpoint': '/api/admin/customers/export',
            'timestamp': _now_iso(0),
            'attributes': {
                'record_count': 5000,
                'records_exported': 5000,
                'mass_export': True,
                'export_format': 'csv',
                'table': 'customers_pii',
                'lab_scenario_id': 'data_exfiltration'
            }
        }
    ]


def _gen_dormant_admin(org_id: str) -> List[Dict[str, Any]]:
    """Insider Threat: Dormant Admin Account Activation (ADMIN-002, ADMIN-003)."""
    admin_usr = f"USR_DORMANT_{uuid.uuid4().hex[:6]}"
    return [
        {
            'event_id': str(uuid.uuid4()),
            'organization_id': org_id,
            'event_type': 'ADMIN_ACTION',
            'user_id': admin_usr,
            'endpoint': '/api/admin/roles/grant',
            'timestamp': _now_iso(0),
            'attributes': {
                'days_inactive': 45,
                'dormant_admin': True,
                'off_hours_admin': True,
                'local_hour': 23,
                'lab_scenario_id': 'dormant_admin'
            }
        }
    ]


def _gen_audit_tamper(org_id: str) -> List[Dict[str, Any]]:
    """Insider Threat: Security Audit Log Tampering (ADMIN-005, ADMIN-004)."""
    rogue_admin = f"USR_ROGUE_{uuid.uuid4().hex[:6]}"
    return [
        {
            'event_id': str(uuid.uuid4()),
            'organization_id': org_id,
            'event_type': 'ADMIN_ACTION',
            'user_id': rogue_admin,
            'endpoint': '/api/admin/db/execute',
            'timestamp': _now_iso(0),
            'attributes': {
                'query': 'TRUNCATE TABLE audit_logs; DELETE FROM security_events;',
                'audit_tamper': True,
                'affected_table': 'audit_logs',
                'lab_scenario_id': 'audit_tamper'
            }
        }
    ]


# =========================================================================
# 2. BENIGN BASELINE TRAFFIC GENERATORS
# =========================================================================

def _gen_benign_retail(org_id: str) -> List[Dict[str, Any]]:
    """Routine Daytime Peer-to-Peer Transfer (Benign Baseline)."""
    acc = f"ACC_RETAIL_{uuid.uuid4().hex[:6]}"
    return [
        {
            'event_id': str(uuid.uuid4()),
            'organization_id': org_id,
            'event_type': 'TRANSFER_CREATED',
            'account_id': acc,
            'amount': 1500.0,
            'currency': 'ETB',
            'source_ip': '196.188.1.50',
            'channel': 'mobile',
            'timestamp': _now_iso(-30),
            'attributes': {
                'amount': 1500.0,
                'device_trusted': True,
                'local_hour': 14,
                'channel': 'mobile'
            }
        },
        {
            'event_id': str(uuid.uuid4()),
            'organization_id': org_id,
            'event_type': 'TRANSFER_CREATED',
            'account_id': acc,
            'amount': 2200.0,
            'currency': 'ETB',
            'source_ip': '196.188.1.50',
            'channel': 'mobile',
            'timestamp': _now_iso(0),
            'attributes': {
                'amount': 2200.0,
                'device_trusted': True,
                'local_hour': 15,
                'channel': 'mobile'
            }
        }
    ]


def _gen_benign_merchant(org_id: str) -> List[Dict[str, Any]]:
    """Routine Merchant QR Payment in Addis Ababa (Benign Baseline)."""
    acc = f"ACC_MERCHANT_{uuid.uuid4().hex[:6]}"
    return [
        {
            'event_id': str(uuid.uuid4()),
            'organization_id': org_id,
            'event_type': 'TRANSFER_CREATED',
            'account_id': acc,
            'amount': 450.0,
            'currency': 'ETB',
            'source_ip': '197.156.3.22',
            'channel': 'qr',
            'timestamp': _now_iso(-20),
            'attributes': {
                'amount': 450.0,
                'device_trusted': True,
                'local_hour': 12,
                'merchant_category': 'cafe_restaurant'
            }
        },
        {
            'event_id': str(uuid.uuid4()),
            'organization_id': org_id,
            'event_type': 'TRANSFER_CREATED',
            'account_id': acc,
            'amount': 600.0,
            'currency': 'ETB',
            'source_ip': '197.156.3.22',
            'channel': 'qr',
            'timestamp': _now_iso(0),
            'attributes': {
                'amount': 600.0,
                'device_trusted': True,
                'local_hour': 13,
                'merchant_category': 'groceries'
            }
        }
    ]


def _gen_benign_salary(org_id: str) -> List[Dict[str, Any]]:
    """Corporate Payroll Salary Credit (Benign Baseline)."""
    acc = f"ACC_EMPLOYEE_{uuid.uuid4().hex[:6]}"
    return [
        {
            'event_id': str(uuid.uuid4()),
            'organization_id': org_id,
            'event_type': 'TRANSFER_CREATED',
            'account_id': acc,
            'amount': 25000.0,
            'currency': 'ETB',
            'source_ip': '10.0.12.5',
            'channel': 'internal_batch',
            'timestamp': _now_iso(-10),
            'attributes': {
                'amount': 25000.0,
                'batch_type': 'payroll',
                'device_trusted': True,
                'local_hour': 10
            }
        },
        {
            'event_id': str(uuid.uuid4()),
            'organization_id': org_id,
            'event_type': 'TRANSFER_CREATED',
            'account_id': f"ACC_EMP2_{uuid.uuid4().hex[:6]}",
            'amount': 28000.0,
            'currency': 'ETB',
            'source_ip': '10.0.12.5',
            'channel': 'internal_batch',
            'timestamp': _now_iso(0),
            'attributes': {
                'amount': 28000.0,
                'batch_type': 'payroll',
                'device_trusted': True,
                'local_hour': 10
            }
        }
    ]


# =========================================================================
# 3. SCENARIO CATALOG DEFINITION
# =========================================================================

SCENARIO_CATALOG: Dict[str, Dict[str, Any]] = {
    # --- Fraud & Payments Pack (5 Scenarios) ---
    'SCEN-01-ATO-CHAIN': {
        'scenario_id': 'SCEN-01-ATO-CHAIN',
        'name': 'Account Takeover Multi-Stage Chain',
        'category': 'fraud_payments',
        'is_attack': True,
        'target_rule_ids': ['ATO-001', 'AUTH-001', 'AUTH-003', 'FRAUD-001', 'TX-001'],
        'description': 'Multi-stage ATO: Brute force login failures followed by success on unrecognized hardware, rapid beneficiary add, and high-value cash-out.',
        'generate_events': _gen_ato_chain
    },
    'SCEN-02-MULE-TRANSFER': {
        'scenario_id': 'SCEN-02-MULE-TRANSFER',
        'name': 'Mule Pass-Through Account Funnel',
        'category': 'fraud_payments',
        'is_attack': True,
        'target_rule_ids': ['FRAUD-002', 'TX-001'],
        'description': 'Inbound high-value transfer immediately dissipated (>85%) to split beneficiaries in short window.',
        'generate_events': _gen_mule_transfer
    },
    'SCEN-03-SIM-SWAP': {
        'scenario_id': 'SCEN-03-SIM-SWAP',
        'name': 'SIM-Swap Credential Reset with Transfer',
        'category': 'fraud_payments',
        'is_attack': True,
        'target_rule_ids': ['FRAUD-003', 'TX-001'],
        'description': 'Transfer initiated immediately following telecom SIM swap and password reset within 24 hours.',
        'generate_events': _gen_sim_swap
    },
    'SCEN-04-STRUCTURING': {
        'scenario_id': 'SCEN-04-STRUCTURING',
        'name': 'Transaction Structuring Under Limits',
        'category': 'fraud_payments',
        'is_attack': True,
        'target_rule_ids': ['FRAUD-004'],
        'description': 'Multiple high-frequency transfers calibrated just below the 50,000 ETB regulatory reporting threshold.',
        'generate_events': _gen_structuring
    },
    'SCEN-05-USSD-CASH-OUT': {
        'scenario_id': 'SCEN-05-USSD-CASH-OUT',
        'name': 'USSD Session Burst & Agent Abuse',
        'category': 'fraud_payments',
        'is_attack': True,
        'target_rule_ids': ['FRAUD-005'],
        'description': 'High-velocity USSD channel withdrawals across multiple mobile money agent terminals.',
        'generate_events': _gen_ussd_cash_out
    },
    'SCEN-06-APP-COACHED': {
        'scenario_id': 'SCEN-06-APP-COACHED',
        'name': 'Authorized Push Payment Coached Transfer',
        'category': 'fraud_payments',
        'is_attack': True,
        'target_rule_ids': ['FRAUD-006', 'TX-001'],
        'description': 'Coached social engineering transfer during active voice call to unfamiliar recipient.',
        'generate_events': _gen_app_coached
    },

    # --- Web & API Abuse Pack (4 Scenarios) ---
    'SCEN-07-CRED-STUFFING': {
        'scenario_id': 'SCEN-07-CRED-STUFFING',
        'name': 'Credential Stuffing Bot Attack',
        'category': 'web_api',
        'is_attack': True,
        'target_rule_ids': ['AUTH-002', 'API-001'],
        'description': 'Single attacker IP spraying stolen credentials across multiple distinct customer accounts within 60 seconds.',
        'generate_events': _gen_cred_stuffing
    },
    'SCEN-08-IDOR-PROBE': {
        'scenario_id': 'SCEN-08-IDOR-PROBE',
        'name': 'IDOR Sequential Resource Enumeration',
        'category': 'web_api',
        'is_attack': True,
        'target_rule_ids': ['API-002'],
        'description': 'Automated crawler traversing sequential customer account/statement IDs.',
        'generate_events': _gen_idor_probe
    },
    'SCEN-09-BOT-SCANNER': {
        'scenario_id': 'SCEN-09-BOT-SCANNER',
        'name': 'Automated Security Scanner Reconnaissance',
        'category': 'web_api',
        'is_attack': True,
        'target_rule_ids': ['API-004'],
        'description': 'Automated tool probing (sqlmap/nikto) with SQL injection signatures in query parameters.',
        'generate_events': _gen_bot_scanner
    },
    'SCEN-10-TOKEN-REPLAY': {
        'scenario_id': 'SCEN-10-TOKEN-REPLAY',
        'name': 'Bearer Token Replay and Session Hijack',
        'category': 'web_api',
        'is_attack': True,
        'target_rule_ids': ['API-003'],
        'description': 'Stolen session bearer token replayed simultaneously from differing IP and device fingerprint.',
        'generate_events': _gen_token_replay
    },

    # --- Insider & Admin Pack (3 Scenarios) ---
    'SCEN-11-MASS-EXFIL': {
        'scenario_id': 'SCEN-11-MASS-EXFIL',
        'name': 'Mass Customer Data Export Exfiltration',
        'category': 'insider_admin',
        'is_attack': True,
        'target_rule_ids': ['ADMIN-001', 'PRIV-001'],
        'description': 'Privileged administrator exfiltrating 5,000 customer PII and balance records via bulk export.',
        'generate_events': _gen_mass_exfil
    },
    'SCEN-12-AUDIT-TAMPER': {
        'scenario_id': 'SCEN-12-AUDIT-TAMPER',
        'name': 'Security Audit Trail Tampering Attempt',
        'category': 'insider_admin',
        'is_attack': True,
        'target_rule_ids': ['ADMIN-005', 'ADMIN-004'],
        'description': 'Rogue insider attempting TRUNCATE/DELETE commands against security audit logs.',
        'generate_events': _gen_audit_tamper
    },
    'SCEN-16-DORMANT-ADMIN': {
        'scenario_id': 'SCEN-16-DORMANT-ADMIN',
        'name': 'Dormant Admin Account Activation',
        'category': 'insider_admin',
        'is_attack': True,
        'target_rule_ids': ['ADMIN-002', 'ADMIN-003'],
        'description': 'Long-dormant administrator account (>30 days) suddenly active off-hours granting elevated privileges.',
        'generate_events': _gen_dormant_admin
    },

    # --- Benign Traffic Baseline (3 Scenarios) ---
    'SCEN-13-BENIGN-RETAIL': {
        'scenario_id': 'SCEN-13-BENIGN-RETAIL',
        'name': 'Routine Peer-to-Peer Retail Transfer',
        'category': 'benign',
        'is_attack': False,
        'target_rule_ids': [],
        'description': 'Daytime routine mobile banking transfer of 1,500 ETB from familiar device.',
        'generate_events': _gen_benign_retail
    },
    'SCEN-14-BENIGN-MERCHANT': {
        'scenario_id': 'SCEN-14-BENIGN-MERCHANT',
        'name': 'Routine In-Store Merchant QR Payment',
        'category': 'benign',
        'is_attack': False,
        'target_rule_ids': [],
        'description': 'Normal QR code point-of-sale payment of 450 ETB during business hours in Addis Ababa.',
        'generate_events': _gen_benign_merchant
    },
    'SCEN-15-BENIGN-SALARY': {
        'scenario_id': 'SCEN-15-BENIGN-SALARY',
        'name': 'Corporate Monthly Payroll Credit',
        'category': 'benign',
        'is_attack': False,
        'target_rule_ids': [],
        'description': 'Regular scheduled payroll credit of 25,000 ETB via internal banking batch.',
        'generate_events': _gen_benign_salary
    }
}


def list_scenarios(category: Optional[str] = None) -> List[Dict[str, Any]]:
    """Returns scenario catalog metadata."""
    res = []
    for s_id, s in SCENARIO_CATALOG.items():
        if category and s['category'] != category:
            continue
        res.append({
            'scenario_id': s['scenario_id'],
            'name': s['name'],
            'category': s['category'],
            'is_attack': s['is_attack'],
            'target_rule_ids': s['target_rule_ids'],
            'description': s['description']
        })
    return res


def get_scenario(scenario_id: str) -> Optional[Dict[str, Any]]:
    """Retrieves single scenario definition by ID."""
    return SCENARIO_CATALOG.get(scenario_id)
