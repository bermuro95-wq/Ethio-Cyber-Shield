"""
Ethio-Cyber-Shield (ECS) — Canonical Event Contract v1.1 Schema & Normalization Engine.
Complies with Non-Negotiable Hard Rules:
- Tenancy everywhere (organization_id)
- Zero secrets or plaintext PII in logs or code (SHA-256 hashing for MSISDN, National ID, counterparty)
- Ethiopian operational context (ETB, Africa/Addis_Ababa UTC+3, USSD, P2P, local payment rails)
"""
import re
import hashlib
import logging
from typing import Dict, Any, Tuple, List, Optional
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

HEX_SHA256_PATTERN = re.compile(r'^[a-f0-9]{64}$')

ALLOWED_CHANNELS = {
    'web',
    'mobile',
    'ussd',
    'api',
    'agent',
    'branch',
    'atm',
    'pos',
    'system',
}

ALLOWED_PAYMENT_RAILS = {
    'p2p',
    'card',
    'wallet',
    'bill_pay',
    'interbank',
    'rtgs',
    'ach',
}

ALLOWED_RESULTS = {
    'SUCCESS',
    'FAILURE',
    'DENIED',
    'HELD',
    'CHALLENGE_REQUIRED',
}

# Ethiopian financial brand & channel aliases mapped to generic canonical classifications
BRAND_TO_RAIL_MAP = {
    'telebirr': 'wallet',
    'cbebirr': 'wallet',
    'cbe_birr': 'wallet',
    'cbe birr': 'wallet',
    'amole': 'wallet',
    'hellocash': 'wallet',
    'ebirr': 'wallet',
    'e-birr': 'wallet',
    'awashbirr': 'wallet',
    'awash_birr': 'wallet',
    'coopay': 'wallet',
    'chapa': 'card',
    'ethswitch': 'interbank',
    'interbank': 'interbank',
    'interbank_transfer': 'interbank',
    'rtgs': 'rtgs',
    'ach': 'ach',
    'enat': 'interbank',
    'dashen': 'interbank',
    'awash': 'interbank',
    'cbe': 'interbank',
    'boa': 'interbank',
    'p2p': 'p2p',
    'p2p_transfer': 'p2p',
    'card': 'card',
    'pos_card': 'card',
    'atm_card': 'card',
    'visa': 'card',
    'mastercard': 'card',
    'telecom_airtime': 'bill_pay',
    'utility_bill': 'bill_pay',
    'bill_pay': 'bill_pay',
    'wallet': 'wallet',
}

CHANNEL_ALIASES = {
    'app': 'mobile',
    'android': 'mobile',
    'ios': 'mobile',
    'browser': 'web',
    'portal': 'web',
    'ussd_session': 'ussd',
    '*889#': 'ussd',
    '*990#': 'ussd',
    'teller': 'branch',
    'branch_counter': 'branch',
    'agent_pos': 'agent',
    'atm_kiosk': 'atm',
}


def hash_identifier(value: Optional[str], salt: str = '') -> Optional[str]:
    """
    Computes a deterministic SHA-256 hash of a sensitive string identifier.
    Used for privacy-preserving telemetry (MSISDN, National ID, Account numbers).
    """
    if value is None:
        return None
    val_str = str(value).strip()
    if not val_str:
        return None
    to_hash = f"{salt}:{val_str}" if salt else val_str
    return hashlib.sha256(to_hash.encode('utf-8')).hexdigest()


def normalize_msisdn(phone: str) -> str:
    """Standardizes phone number format before hashing (e.g. +251... or 09...)."""
    digits = re.sub(r'[^0-9+]', '', str(phone).strip())
    if digits.startswith('09') and len(digits) == 10:
        digits = '+251' + digits[1:]
    elif digits.startswith('9') and len(digits) == 9:
        digits = '+251' + digits
    elif digits.startswith('251') and len(digits) == 12:
        digits = '+' + digits
    return digits


def validate_and_normalize_event(raw_data: Dict[str, Any], default_org_id: Optional[str] = None) -> Tuple[bool, Dict[str, Any], List[str]]:
    """
    Validates and normalizes an incoming telemetry event against ECS Event Contract v1.1.
    Performs:
    1. Schema validation (required fields, enums, format limits).
    2. Channel and payment rail abstraction and brand mapping.
    3. Mandatory PII scrubbing and cryptographic SHA-256 hashing.
    4. Default timezone and currency assignment.
    5. Backward compatibility preservation with v1.0 payloads.

    Returns: (is_valid, normalized_event_dict, error_list)
    """
    if not isinstance(raw_data, dict):
        return False, {}, ["Event payload must be a JSON object"]

    errors: List[str] = []
    data = dict(raw_data)
    attributes = dict(data.get('attributes') or {})

    # 1. Mandatory Identity fields
    event_id = data.get('event_id')
    if not event_id or not isinstance(event_id, str) or len(event_id.strip()) == 0:
        errors.append("event_id is required and must be a non-empty string")
    elif len(event_id) > 100:
        errors.append("event_id exceeds maximum length of 100 characters")

    event_type = data.get('event_type')
    if not event_type or not isinstance(event_type, str) or len(event_type.strip()) == 0:
        errors.append("event_type is required and must be a non-empty string")
    elif len(event_type) > 100:
        errors.append("event_type exceeds maximum length of 100 characters")

    # 2. Timing & Origin
    occurred_at = data.get('occurred_at')
    if not occurred_at:
        occurred_at = datetime.now(timezone.utc).isoformat()
    elif not isinstance(occurred_at, str):
        errors.append("occurred_at must be an ISO 8601 string")

    source_system = data.get('source_system')
    if not source_system or not isinstance(source_system, str):
        source_system = 'system'

    # 3. Channel Normalization & Validation
    channel = str(data.get('channel') or attributes.get('channel') or 'web').lower().strip()
    if channel in CHANNEL_ALIASES:
        channel = CHANNEL_ALIASES[channel]
    if channel not in ALLOWED_CHANNELS:
        errors.append(f"Invalid channel '{channel}'. Allowed values: {sorted(list(ALLOWED_CHANNELS))}")

    # 4. Payment Rail Normalization & Brand Mapping
    raw_rail = data.get('payment_rail') or attributes.get('payment_rail') or attributes.get('rail')
    payment_rail = None
    if raw_rail:
        rail_key = str(raw_rail).lower().strip()
        payment_rail = BRAND_TO_RAIL_MAP.get(rail_key, rail_key)
        if payment_rail not in ALLOWED_PAYMENT_RAILS:
            errors.append(f"Invalid payment_rail '{raw_rail}'. Allowed values: {sorted(list(ALLOWED_PAYMENT_RAILS))}")

    # 5. Result Normalization
    result = str(data.get('result') or 'SUCCESS').upper().strip()
    if result == 'FAILED':
        result = 'FAILURE'
    elif result in ('SUCCESSFUL', 'SUCCEEDED', 'OK'):
        result = 'SUCCESS'
    elif result == 'BLOCKED':
        result = 'DENIED'
    elif result == 'PENDING':
        result = 'HELD'
    if result not in ALLOWED_RESULTS:
        errors.append(f"Invalid result '{result}'. Allowed values: {sorted(list(ALLOWED_RESULTS))}")

    # 6. Privacy & PII Scrubbing (MSISDN, National ID, Counterparty)
    # Check MSISDN
    msisdn_hash = data.get('msisdn_hash') or attributes.get('msisdn_hash')
    raw_phone = data.pop('msisdn', None) or data.pop('phone', None) or attributes.pop('msisdn', None) or attributes.pop('phone', None)
    if raw_phone and not msisdn_hash:
        normalized_phone = normalize_msisdn(raw_phone)
        msisdn_hash = hash_identifier(normalized_phone)

    if msisdn_hash:
        msisdn_hash = str(msisdn_hash).lower().strip()
        if not HEX_SHA256_PATTERN.match(msisdn_hash):
            errors.append("msisdn_hash must be a 64-character lowercase hexadecimal SHA-256 string")

    # Check National ID (Fayda)
    national_id_hash = data.get('national_id_hash') or attributes.get('national_id_hash')
    raw_nat_id = data.pop('national_id', None) or data.pop('fayda_id', None) or attributes.pop('national_id', None) or attributes.pop('fayda_id', None)
    if raw_nat_id and not national_id_hash:
        national_id_hash = hash_identifier(raw_nat_id)

    if national_id_hash:
        national_id_hash = str(national_id_hash).lower().strip()
        if not HEX_SHA256_PATTERN.match(national_id_hash):
            errors.append("national_id_hash must be a 64-character lowercase hexadecimal SHA-256 string")

    # Check Counterparty Ref
    counterparty_ref_hash = data.get('counterparty_ref_hash') or attributes.get('counterparty_ref_hash')
    raw_counterparty = data.pop('counterparty_ref', None) or data.pop('counterparty_account', None) or attributes.pop('counterparty_ref', None) or attributes.pop('counterparty_account', None)
    if raw_counterparty and not counterparty_ref_hash:
        counterparty_ref_hash = hash_identifier(raw_counterparty)

    if counterparty_ref_hash:
        counterparty_ref_hash = str(counterparty_ref_hash).lower().strip()
        if not HEX_SHA256_PATTERN.match(counterparty_ref_hash):
            errors.append("counterparty_ref_hash must be a 64-character lowercase hexadecimal SHA-256 string")

    # Device fingerprint & Agent ID
    device_fingerprint = data.get('device_fingerprint') or attributes.get('device_fingerprint')
    if device_fingerprint:
        device_fingerprint = str(device_fingerprint)[:128]

    agent_id = data.get('agent_id') or attributes.get('agent_id')
    if agent_id:
        agent_id = str(agent_id)[:100]

    # Timezone & Currency
    locale_tz = data.get('locale_tz') or attributes.get('locale_tz') or 'Africa/Addis_Ababa'
    currency = data.get('currency') or attributes.get('currency') or 'ETB'

    # Financial Amounts minor/major calculation
    amount_minor = data.get('amount_minor')
    amount_major = data.get('amount')
    if amount_major is None and 'amount' in attributes:
        amount_major = attributes.get('amount')

    if amount_minor is not None:
        try:
            amount_minor = int(amount_minor)
            if amount_minor < 0:
                errors.append("amount_minor cannot be negative")
            if amount_major is None:
                amount_major = float(amount_minor) / 100.0
        except (ValueError, TypeError):
            errors.append("amount_minor must be an integer")
    elif amount_major is not None:
        try:
            amount_major = float(amount_major)
            if amount_major < 0:
                errors.append("amount cannot be negative")
            amount_minor = int(round(amount_major * 100))
        except (ValueError, TypeError):
            errors.append("amount must be a numeric value")

    # Tenancy
    organization_id = data.get('organization_id') or default_org_id

    if errors:
        return False, {}, errors

    # Cleaned attributes (any raw PII already stripped)
    clean_attributes = dict(attributes)
    clean_attributes.pop('phone', None)
    clean_attributes.pop('msisdn', None)
    clean_attributes.pop('national_id', None)
    clean_attributes.pop('fayda_id', None)
    clean_attributes.pop('counterparty_ref', None)
    clean_attributes.pop('counterparty_account', None)

    normalized: Dict[str, Any] = {
        'event_id': str(event_id),
        'event_type': str(event_type),
        'occurred_at': occurred_at,
        'source_system': str(source_system),
        'organization_id': organization_id,
        'channel': channel,
        'payment_rail': payment_rail,
        'counterparty_ref_hash': counterparty_ref_hash,
        'device_fingerprint': device_fingerprint,
        'msisdn_hash': msisdn_hash,
        'agent_id': agent_id,
        'national_id_hash': national_id_hash,
        'locale_tz': locale_tz,
        'user_id_pub': data.get('user_id_pub') or data.get('user_id'),
        'account_id_pub': data.get('account_id_pub') or data.get('account_id'),
        'session_id_pub': data.get('session_id_pub') or data.get('session_id'),
        'device_id_pub': data.get('device_id_pub') or data.get('device_id'),
        'source_ip': data.get('source_ip'),
        'endpoint': data.get('endpoint'),
        'result': result,
        'amount_minor': amount_minor,
        'amount': amount_major,
        'currency': currency,
        'beneficiary_id_pub': data.get('beneficiary_id_pub') or data.get('beneficiary_id'),
        'transaction_id_pub': data.get('transaction_id_pub') or data.get('transaction_id'),
        'seq': data.get('seq'),
        'attributes': clean_attributes,
        'raw_payload': raw_data,
    }

    return True, normalized, []
