"""
Ethio-Cyber-Shield (ECS) — Generic Webhook Field Mapping & Transformation Engine.
Provides declarative JSONPath extraction, type conversions, value mapping, and
safe normalization into ECS Event Contract v1.1.
"""
import re
import uuid
import logging
from typing import Dict, Any, Tuple, List, Optional
from datetime import datetime, timezone
from dateutil import parser

from app.schemas.event_contract import (
    validate_and_normalize_event,
    normalize_msisdn,
    hash_identifier
)

logger = logging.getLogger(__name__)


def _tokenize_path(path: str) -> List[Any]:
    """
    Tokenizes a JSONPath expression into a list of keys and integer indices.
    Supports:
      - '$.data.customer.phone' -> ['data', 'customer', 'phone']
      - '$.items[0].code' -> ['items', 0, 'code']
      - 'data[1].price' -> ['data', 1, 'price']
    """
    p = str(path).strip()
    if p.startswith('$.'):
        p = p[2:]
    elif p.startswith('$'):
        p = p[1:]
    if not p:
        return []

    # Replace bracket notation with dot index: items[0] -> items.0
    p = re.sub(r'\[(\d+)\]', r'.\1', p)
    tokens: List[Any] = []
    for part in p.split('.'):
        part = part.strip()
        if not part:
            continue
        if part.isdigit():
            tokens.append(int(part))
        else:
            tokens.append(part)
    return tokens


def extract_jsonpath(payload: Any, path: str, default: Any = None) -> Any:
    """
    Extracts a value from a nested dictionary/list structure using JSONPath notation.
    Returns `default` if the path cannot be resolved or evaluates to None.
    """
    if payload is None or not path:
        return default

    tokens = _tokenize_path(path)
    if not tokens:
        return payload

    curr = payload
    for token in tokens:
        if isinstance(token, int):
            if isinstance(curr, (list, tuple)) and 0 <= token < len(curr):
                curr = curr[token]
            else:
                return default
        elif isinstance(token, str):
            if isinstance(curr, dict) and token in curr:
                curr = curr[token]
            else:
                return default
        else:
            return default

    return curr if curr is not None else default


def apply_transforms(
    val: Any,
    transform: Optional[str] = None,
    value_map: Optional[Dict[str, Any]] = None,
    default: Any = None
) -> Any:
    """
    Applies transformations, dictionary value mapping, and type casting to an extracted value.
    """
    # 1. Apply value_map if provided
    if value_map and isinstance(value_map, dict) and val is not None:
        str_val = str(val)
        if val in value_map:
            val = value_map[val]
        elif str_val in value_map:
            val = value_map[str_val]
        elif str_val.lower() in value_map:
            val = value_map[str_val.lower()]
        elif default is not None:
            val = default

    # 2. If val is None, return default
    if val is None:
        return default

    # 3. Apply specific named transform
    if transform:
        tf = str(transform).lower().strip()
        try:
            if tf == 'amount_to_minor':
                # e.g., 250.50 -> 25050
                num = float(val)
                return int(round(num * 100))
            elif tf == 'minor_to_amount':
                # e.g., 25050 -> 250.50
                return float(val) / 100.0
            elif tf in ('to_float', 'float'):
                return float(val)
            elif tf in ('to_int', 'int'):
                return int(val)
            elif tf in ('to_str', 'str', 'string'):
                return str(val)
            elif tf == 'to_upper':
                return str(val).upper()
            elif tf == 'to_lower':
                return str(val).lower()
            elif tf == 'timestamp_iso':
                if isinstance(val, (int, float)) or (isinstance(val, str) and val.isdigit()):
                    num = float(val)
                    if num > 1e11:  # Milliseconds
                        num /= 1000.0
                    return datetime.fromtimestamp(num, timezone.utc).isoformat()
                elif isinstance(val, str):
                    dt = parser.isoparse(val)
                    if dt.tzinfo is None:
                        dt = dt.replace(tzinfo=timezone.utc)
                    return dt.isoformat()
            elif tf == 'normalize_phone_hash':
                norm_phone = normalize_msisdn(str(val))
                return hash_identifier(norm_phone)
            elif tf in ('hash_sha256', 'sha256'):
                return hash_identifier(str(val))
        except Exception as e:
            logger.debug(f"Transform '{transform}' failed on value {val}: {e}")
            return default

    return val


def _resolve_rule(payload: Dict[str, Any], rule_spec: Any) -> Any:
    """Resolves a single field from payload according to rule configuration."""
    if rule_spec is None:
        return None
    if isinstance(rule_spec, str):
        if rule_spec.startswith('$.') or rule_spec.startswith('$'):
            return extract_jsonpath(payload, rule_spec)
        return rule_spec
    if not isinstance(rule_spec, dict):
        return rule_spec

    path = rule_spec.get('path')
    transform = rule_spec.get('transform')
    value_map = rule_spec.get('value_map')
    default = rule_spec.get('default')
    fallback = rule_spec.get('fallback')

    raw_val = None
    if path:
        raw_val = extract_jsonpath(payload, path)

    if raw_val is None:
        if fallback == 'uuid':
            raw_val = f"evt_{uuid.uuid4().hex[:16]}"
        elif default is not None:
            raw_val = default

    if raw_val is not None:
        return apply_transforms(raw_val, transform=transform, value_map=value_map, default=default)

    return default


def apply_mapping(
    payload: Dict[str, Any],
    mapping_rules: Dict[str, Any],
    default_org_id: str,
    source_name: str = 'webhook'
) -> Tuple[bool, Dict[str, Any], List[str]]:
    """
    Applies declarative mapping rules to transform an inbound webhook payload
    into a canonical ECS Event Contract v1.1 event.

    Returns: (is_valid, normalized_event, errors)
    """
    if not isinstance(payload, dict):
        return False, {}, ["Webhook payload must be a JSON object"]
    if not isinstance(mapping_rules, dict):
        mapping_rules = {}

    # 1. Identity & Routing
    event_id = _resolve_rule(payload, mapping_rules.get('event_id'))
    if not event_id:
        event_id = f"wh_{uuid.uuid4().hex[:16]}"

    event_type = _resolve_rule(payload, mapping_rules.get('event_type')) or 'TRANSACTION'
    source_system = _resolve_rule(payload, mapping_rules.get('source_system')) or source_name
    occurred_at = _resolve_rule(payload, mapping_rules.get('occurred_at')) or datetime.now(timezone.utc).isoformat()
    channel = _resolve_rule(payload, mapping_rules.get('channel')) or 'web'
    payment_rail = _resolve_rule(payload, mapping_rules.get('payment_rail'))
    action = _resolve_rule(payload, mapping_rules.get('action')) or 'transfer'
    result = _resolve_rule(payload, mapping_rules.get('result')) or 'SUCCESS'

    # 2. Financials
    amount = _resolve_rule(payload, mapping_rules.get('amount'))
    amount_minor = _resolve_rule(payload, mapping_rules.get('amount_minor'))
    currency = _resolve_rule(payload, mapping_rules.get('currency')) or 'ETB'

    # 3. Actor (Payer / Initiator)
    actor_rules = mapping_rules.get('actor', {}) if isinstance(mapping_rules.get('actor'), dict) else {}
    actor_id = _resolve_rule(payload, actor_rules.get('actor_id') or mapping_rules.get('actor_id'))
    actor_type = _resolve_rule(payload, actor_rules.get('actor_type') or mapping_rules.get('actor_type')) or 'customer'
    account_number = _resolve_rule(payload, actor_rules.get('account_number') or mapping_rules.get('account_number'))
    phone = _resolve_rule(payload, actor_rules.get('phone') or mapping_rules.get('phone') or mapping_rules.get('msisdn'))
    ip = _resolve_rule(payload, actor_rules.get('ip') or mapping_rules.get('ip') or mapping_rules.get('source_ip'))
    device_fingerprint = _resolve_rule(payload, actor_rules.get('device_fingerprint') or mapping_rules.get('device_fingerprint'))
    national_id = _resolve_rule(payload, actor_rules.get('national_id') or mapping_rules.get('national_id'))

    # 4. Target (Counterparty / Recipient)
    target_rules = mapping_rules.get('target', {}) if isinstance(mapping_rules.get('target'), dict) else {}
    target_id = _resolve_rule(payload, target_rules.get('target_id') or mapping_rules.get('target_id'))
    target_type = _resolve_rule(payload, target_rules.get('target_type') or mapping_rules.get('target_type')) or 'account'
    counterparty_ref = _resolve_rule(payload, target_rules.get('counterparty_ref') or mapping_rules.get('counterparty_ref'))
    counterparty_name = _resolve_rule(payload, target_rules.get('counterparty_name') or mapping_rules.get('counterparty_name'))
    bank_code = _resolve_rule(payload, target_rules.get('bank_code') or mapping_rules.get('bank_code'))

    # 5. Metadata / Extra Details
    attributes: Dict[str, Any] = {
        'mapped_via': 'ecs_webhook_receiver',
        'raw_source': source_name
    }
    if counterparty_name:
        attributes['counterparty_name'] = str(counterparty_name)
    if bank_code:
        attributes['bank_code'] = str(bank_code)

    details_rules = mapping_rules.get('details', {})
    if isinstance(details_rules, dict):
        paths_spec = details_rules.get('paths', {})
        if isinstance(paths_spec, dict):
            for k, p in paths_spec.items():
                val = extract_jsonpath(payload, p)
                if val is not None:
                    attributes[k] = val

    # Build canonical raw candidate
    raw_event: Dict[str, Any] = {
        'event_id': str(event_id),
        'organization_id': default_org_id,
        'event_type': str(event_type),
        'source_system': str(source_system),
        'occurred_at': occurred_at,
        'channel': channel,
        'result': result,
        'currency': currency,
        'attributes': attributes
    }

    if payment_rail:
        raw_event['payment_rail'] = payment_rail
    if amount is not None:
        raw_event['amount'] = amount
    if amount_minor is not None:
        raw_event['amount_minor'] = amount_minor
    if actor_id:
        raw_event['user_id_pub'] = str(actor_id)
    if account_number:
        raw_event['account_id_pub'] = str(account_number)
    if target_id or counterparty_ref:
        raw_event['beneficiary_id_pub'] = str(counterparty_ref or target_id)
    if ip:
        raw_event['source_ip'] = str(ip)
    if device_fingerprint:
        raw_event['device_fingerprint'] = str(device_fingerprint)
    if phone:
        raw_event['phone'] = str(phone)
    if national_id:
        raw_event['national_id'] = str(national_id)
    if counterparty_ref:
        raw_event['counterparty_ref_hash'] = hash_identifier(str(counterparty_ref))

    # Pass through canonical schema validation & normalization
    return validate_and_normalize_event(raw_event, default_org_id=default_org_id)


def test_mapping(
    sample_payload: Dict[str, Any],
    mapping_rules: Dict[str, Any],
    default_org_id: str = "00000000-0000-0000-0000-000000000001"
) -> Dict[str, Any]:
    """
    Test-with-sample dry-run runner. Evaluates mapping against sample payload without
    persisting or queueing events. Returns detailed diagnostics.
    """
    is_valid, normalized_event, errors = apply_mapping(
        sample_payload,
        mapping_rules,
        default_org_id=default_org_id,
        source_name="Sample Test"
    )

    fields_count = sum(1 for k, v in normalized_event.items() if v is not None and v != "")

    return {
        "success": is_valid,
        "is_valid": is_valid,
        "normalized_event": normalized_event,
        "errors": errors,
        "fields_mapped_count": fields_count,
        "sample_summary": list(sample_payload.keys()) if isinstance(sample_payload, dict) else []
    }
