"""
Ethio-Cyber-Shield (ECS) — Log Agent Parsing Engine.
Specialized parsers for:
- Nginx / Apache Combined and Common Access logs
- Nginx / Apache Error logs
- Syslog (RFC 3164 and RFC 5424)
- Common Event Format (CEF)
Parses raw lines into ECS Canonical Event Contract v1.1 with SHA-256 evidence sealing.
"""
import re
import uuid
import hashlib
import logging
from typing import Dict, Any, Optional, Tuple
from datetime import datetime, timezone
from dateutil import parser as date_parser

from app.schemas.event_contract import (
    validate_and_normalize_event,
    hash_identifier,
    normalize_msisdn
)

logger = logging.getLogger(__name__)

# =========================================================================
# REGEX DEFINITIONS
# =========================================================================

# Nginx / Apache Combined Access:
# IP - User [Date] "Method URL HTTP/Version" Status Bytes "Referer" "User-Agent"
NGINX_COMBINED_REGEX = re.compile(
    r'^(\S+)\s+\S+\s+(\S+)\s+\[([^\]]+)\]\s+"([A-Z]+)\s+([^\s"]+)(?:\s+HTTP/[\d\.]+)?(?:")\s+(\d{3})\s+(\d+|-)(?:\s+"([^"]*)")?(?:\s+"([^"]*)")?'
)

# Nginx Error:
# 2026/10/18 10:15:30 [error] 1234#0: *5678 message, client: IP, server: URL, request: "METHOD URL HTTP/1.1", host: "HOST"
NGINX_ERROR_REGEX = re.compile(
    r'^(\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})\s+\[(\w+)\]\s+\d+#\d+:\s+(?:\*\d+\s+)?(.+?)(?:,\s+client:\s+(\S+))?(?:,\s+server:\s+(\S+))?(?:,\s+request:\s+"([A-Z]+)\s+([^\s"]+)(?:\s+HTTP/[\d\.]+)?")?(?:,\s+host:\s+"([^"]+)")?$'
)

# Syslog RFC 3164:
# <PRI>Mmm dd hh:mm:ss HOST APP[PID]: MSG
SYSLOG_RFC3164_REGEX = re.compile(
    r'^(?:<(\d+)>)?([A-Za-z]{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+([\w\.\-]+)(?:\[(\d+)\])?:\s+(.*)$'
)

# Syslog RFC 5424:
# <PRI>VERSION TIMESTAMP HOST APP PID MSGID [STRUCTURED-DATA] MSG
SYSLOG_RFC5424_REGEX = re.compile(
    r'^<(\d+)>(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)(?:\s+(\[.*?\]))?\s+(.*)$'
)

# CEF (Common Event Format):
# CEF:Version|Device Vendor|Device Product|Device Version|Device Event Class ID|Name|Severity|Extension
CEF_HEADER_REGEX = re.compile(
    r'^CEF:(\d+)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|(.*)$'
)

IP_EXTRACT_REGEX = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')


def _compute_line_hash(line: str) -> str:
    """Computes SHA-256 hash of the exact raw log line for evidentiary seal."""
    return hashlib.sha256(line.encode('utf-8')).hexdigest()


def _parse_access_timestamp(ts_str: str) -> str:
    """Parses access log timestamp (e.g. 18/Oct/2026:10:15:30 +0300) to ISO 8601 UTC."""
    try:
        dt = datetime.strptime(ts_str.strip(), "%d/%b/%Y:%H:%M:%S %z")
        return dt.astimezone(timezone.utc).isoformat()
    except Exception:
        try:
            dt = date_parser.parse(ts_str)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.isoformat()
        except Exception:
            return datetime.now(timezone.utc).isoformat()


def _detect_channel_from_ua(ua: str) -> str:
    """Infers access channel from User-Agent string."""
    if not ua:
        return 'web'
    ua_lower = ua.lower()
    if any(k in ua_lower for k in ('android', 'iphone', 'mobile', 'ipad')):
        return 'mobile'
    if any(k in ua_lower for k in ('curl', 'postman', 'python', 'go-http', 'wget', 'httpclient')):
        return 'api'
    return 'web'


# =========================================================================
# 1. NGINX / APACHE ACCESS LOG PARSER
# =========================================================================

def parse_nginx_apache_access(
    line: str,
    organization_id: str,
    source_system: str = "nginx-access"
) -> Optional[Dict[str, Any]]:
    """
    Parses a Combined or Common Nginx/Apache access log line into a canonical ECS event.
    """
    clean_line = line.strip()
    if not clean_line:
        return None

    match = NGINX_COMBINED_REGEX.match(clean_line)
    if not match:
        return None

    ip, user, ts_raw, method, url, status_str, bytes_str, referer, ua = match.groups()

    occurred_at = _parse_access_timestamp(ts_raw)
    status_code = int(status_code_str) if (status_code_str := status_str) and status_str.isdigit() else 200
    bytes_sent = int(bytes_str) if bytes_str and bytes_str.isdigit() else 0

    # Determine result
    if status_code in (401, 403):
        result = 'DENIED'
    elif status_code >= 400:
        result = 'FAILURE'
    else:
        result = 'SUCCESS'

    # Determine event type
    url_lower = url.lower()
    if status_code in (401, 403):
        event_type = 'AUTHZ_DENIED'
    elif any(k in url_lower for k in ('/login', '/auth', '/signin', '/token')):
        event_type = 'LOGIN_SUCCESS' if result == 'SUCCESS' else 'LOGIN_FAILED'
    elif any(k in url_lower for k in ('/transfer', '/pay', '/checkout', '/charge')):
        event_type = 'TRANSACTION'
    else:
        event_type = 'HTTP_REQUEST'

    channel = _detect_channel_from_ua(ua or "")

    attributes = {
        'http_method': method,
        'status_code': status_code,
        'bytes_sent': bytes_sent,
        'user_agent': ua or '',
        'referer': referer or '',
        'raw_log_hash': _compute_line_hash(clean_line)
    }

    user_id_pub = None if user in ('-', '', None) else user

    raw_event = {
        'event_id': f"log_{uuid.uuid4().hex[:16]}",
        'organization_id': organization_id,
        'event_type': event_type,
        'occurred_at': occurred_at,
        'source_system': source_system,
        'source_ip': ip,
        'endpoint': url,
        'channel': channel,
        'result': result,
        'attributes': attributes
    }

    if user_id_pub:
        raw_event['user_id_pub'] = user_id_pub

    is_valid, norm_event, _ = validate_and_normalize_event(raw_event, default_org_id=organization_id)
    return norm_event if is_valid else None


# =========================================================================
# 2. NGINX / APACHE ERROR LOG PARSER
# =========================================================================

def parse_nginx_apache_error(
    line: str,
    organization_id: str,
    source_system: str = "nginx-error"
) -> Optional[Dict[str, Any]]:
    """
    Parses an Nginx/Apache error log line into a canonical ECS security event.
    """
    clean_line = line.strip()
    if not clean_line:
        return None

    match = NGINX_ERROR_REGEX.match(clean_line)
    if not match:
        return None

    ts_raw, log_level, message, client_ip, server, method, endpoint, host = match.groups()

    try:
        dt = datetime.strptime(ts_raw.strip(), "%Y/%m/%d %H:%M:%S")
        # Assume Africa/Addis_Ababa (+03:00) by default for Ethiopian installations
        dt = dt.replace(tzinfo=timezone.utc)
        occurred_at = dt.isoformat()
    except Exception:
        occurred_at = datetime.now(timezone.utc).isoformat()

    msg_lower = (message or "").lower()
    if any(k in msg_lower for k in ('forbidden', 'access denied', 'unauthorized', 'permission denied')):
        event_type = 'AUTHZ_DENIED'
        result = 'DENIED'
    elif any(k in msg_lower for k in ('failed', 'error', 'upstream timed out', '502', '504')):
        event_type = 'SYSTEM_ERROR'
        result = 'FAILURE'
    else:
        event_type = 'SECURITY_ALERT'
        result = 'FAILURE'

    attributes = {
        'log_level': log_level,
        'message': message,
        'server': server or '',
        'host': host or '',
        'http_method': method or '',
        'raw_log_hash': _compute_line_hash(clean_line)
    }

    raw_event = {
        'event_id': f"err_{uuid.uuid4().hex[:16]}",
        'organization_id': organization_id,
        'event_type': event_type,
        'occurred_at': occurred_at,
        'source_system': source_system,
        'channel': 'web',
        'result': result,
        'attributes': attributes
    }

    if client_ip:
        raw_event['source_ip'] = client_ip
    if endpoint:
        clean_endpoint = endpoint.split()[0].strip()
        raw_event['endpoint'] = clean_endpoint

    is_valid, norm_event, _ = validate_and_normalize_event(raw_event, default_org_id=organization_id)
    return norm_event if is_valid else None


# =========================================================================
# 3. SYSLOG PARSER (RFC 3164 & RFC 5424)
# =========================================================================

def parse_syslog(
    line: str,
    organization_id: str,
    source_system: Optional[str] = None
) -> Optional[Dict[str, Any]]:
    """
    Parses RFC 3164 or RFC 5424 syslog lines into canonical ECS events.
    """
    clean_line = line.strip()
    if not clean_line:
        return None

    occurred_at = None
    app_name = None
    message = None
    source_ip = None

    # Try RFC 5424 first
    match_5424 = SYSLOG_RFC5424_REGEX.match(clean_line)
    if match_5424:
        pri, ver, ts_str, host, app, pid, msgid, sd, msg = match_5424.groups()
        app_name = app
        message = msg
        try:
            occurred_at = date_parser.isoparse(ts_str).astimezone(timezone.utc).isoformat()
        except Exception:
            occurred_at = datetime.now(timezone.utc).isoformat()
    else:
        # Try RFC 3164
        match_3164 = SYSLOG_RFC3164_REGEX.match(clean_line)
        if match_3164:
            pri, ts_str, host, app, pid, msg = match_3164.groups()
            app_name = app
            message = msg
            try:
                curr_year = datetime.now(timezone.utc).year
                dt = datetime.strptime(f"{curr_year} {ts_str}", "%Y %b %d %H:%M:%S")
                dt = dt.replace(tzinfo=timezone.utc)
                occurred_at = dt.isoformat()
            except Exception:
                occurred_at = datetime.now(timezone.utc).isoformat()
        else:
            message = clean_line
            occurred_at = datetime.now(timezone.utc).isoformat()

    if not occurred_at:
        occurred_at = datetime.now(timezone.utc).isoformat()

    # Extract source IP from message if present
    ip_match = IP_EXTRACT_REGEX.search(message or "")
    if ip_match:
        source_ip = ip_match.group(0)

    # Classify event
    msg_lower = (message or "").lower()
    user_id = None

    if 'failed password' in msg_lower or 'invalid user' in msg_lower or 'authentication failure' in msg_lower:
        event_type = 'LOGIN_FAILED'
        result = 'FAILURE'
        # Extract user
        u_match = re.search(r'for (?:invalid user )?([^\s]+)', message or "")
        if u_match:
            user_id = u_match.group(1)
    elif 'accepted password' in msg_lower or 'session opened' in msg_lower:
        event_type = 'LOGIN_SUCCESS'
        result = 'SUCCESS'
        u_match = re.search(r'for ([^\s]+)', message or "")
        if u_match:
            user_id = u_match.group(1)
    elif any(k in msg_lower for k in ('blocked', 'denied', 'drop', 'reject')):
        event_type = 'CONNECTION_DENIED'
        result = 'DENIED'
    else:
        event_type = 'SYSTEM_EVENT'
        result = 'SUCCESS'

    attributes = {
        'syslog_app': app_name or 'syslog',
        'raw_message': message,
        'raw_log_hash': _compute_line_hash(clean_line)
    }

    raw_event = {
        'event_id': f"sys_{uuid.uuid4().hex[:16]}",
        'organization_id': organization_id,
        'event_type': event_type,
        'occurred_at': occurred_at,
        'source_system': source_system or app_name or 'syslog',
        'channel': 'system',
        'result': result,
        'attributes': attributes
    }

    if source_ip:
        raw_event['source_ip'] = source_ip
    if user_id:
        raw_event['user_id_pub'] = user_id

    is_valid, norm_event, _ = validate_and_normalize_event(raw_event, default_org_id=organization_id)
    return norm_event if is_valid else None


# =========================================================================
# 4. COMMON EVENT FORMAT (CEF) PARSER
# =========================================================================

def _parse_cef_extension(ext_str: str) -> Dict[str, str]:
    """Parses CEF extension key=value pairs handling escaped characters."""
    result: Dict[str, str] = {}
    tokens = re.split(r'(\w+)=', ext_str)
    if len(tokens) > 1:
        for i in range(1, len(tokens), 2):
            k = tokens[i].strip()
            v = tokens[i + 1].strip() if i + 1 < len(tokens) else ""
            result[k] = v
    return result


def parse_cef(
    line: str,
    organization_id: str,
    source_system: Optional[str] = None
) -> Optional[Dict[str, Any]]:
    """
    Parses ArcSight Common Event Format (CEF) log line into a canonical ECS event.
    """
    clean_line = line.strip()
    if not clean_line or not clean_line.startswith('CEF:'):
        return None

    match = CEF_HEADER_REGEX.match(clean_line)
    if not match:
        return None

    ver, vendor, product, dev_ver, class_id, name, sev, ext_raw = match.groups()
    ext = _parse_cef_extension(ext_raw)

    # Resolve action & result
    act = (ext.get('act') or '').lower()
    if act in ('block', 'deny', 'drop', 'reject'):
        result = 'DENIED'
    elif act in ('fail', 'failure'):
        result = 'FAILURE'
    else:
        result = 'SUCCESS'

    # Financial / payment details
    amount_minor = None
    currency = 'ETB'
    payment_rail = None

    if 'cn1' in ext and ('amount' in (ext.get('cn1Label') or '').lower() or ext.get('cn1').isdigit()):
        try:
            amount_minor = int(ext['cn1'])
        except Exception:
            pass

    if 'cs1' in ext and 'currency' in (ext.get('cs1Label') or '').lower():
        currency = ext['cs1'].upper()

    if 'cs2' in ext:
        payment_rail = ext['cs2'].lower()

    attributes = {
        'cef_vendor': vendor,
        'cef_product': product,
        'cef_version': dev_ver,
        'cef_class_id': class_id,
        'cef_name': name,
        'cef_severity': sev,
        'raw_log_hash': _compute_line_hash(clean_line)
    }

    if 'msg' in ext:
        attributes['message'] = ext['msg']

    raw_event = {
        'event_id': f"cef_{uuid.uuid4().hex[:16]}",
        'organization_id': organization_id,
        'event_type': class_id or 'SECURITY_ALERT',
        'occurred_at': datetime.now(timezone.utc).isoformat(),
        'source_system': source_system or product or vendor or 'cef-device',
        'channel': 'system',
        'result': result,
        'currency': currency,
        'attributes': attributes
    }

    if 'src' in ext:
        raw_event['source_ip'] = ext['src']
    if 'suser' in ext:
        raw_event['user_id_pub'] = ext['suser']
    if 'duser' in ext:
        raw_event['beneficiary_id_pub'] = ext['duser']
    if 'request' in ext:
        raw_event['endpoint'] = ext['request']
    if amount_minor is not None:
        raw_event['amount_minor'] = amount_minor
        raw_event['amount'] = round(amount_minor / 100.0, 2)
    if payment_rail:
        raw_event['payment_rail'] = payment_rail

    is_valid, norm_event, _ = validate_and_normalize_event(raw_event, default_org_id=organization_id)
    return norm_event if is_valid else None


# =========================================================================
# 5. DISPATCHER
# =========================================================================

def parse_log_line(
    line: str,
    format_type: str,
    organization_id: str,
    source_system: Optional[str] = None
) -> Optional[Dict[str, Any]]:
    """
    Dispatches parsing to the appropriate format parser:
    - 'nginx_access', 'apache_access', 'combined'
    - 'nginx_error', 'apache_error'
    - 'syslog'
    - 'cef'
    - 'auto'
    """
    clean_format = (format_type or 'auto').lower().strip()

    if clean_format in ('nginx_access', 'apache_access', 'combined', 'access'):
        return parse_nginx_apache_access(line, organization_id=organization_id, source_system=source_system or "access-log")

    if clean_format in ('nginx_error', 'apache_error', 'error'):
        return parse_nginx_apache_error(line, organization_id=organization_id, source_system=source_system or "error-log")

    if clean_format == 'syslog':
        return parse_syslog(line, organization_id=organization_id, source_system=source_system)

    if clean_format == 'cef':
        return parse_cef(line, organization_id=organization_id, source_system=source_system)

    # Auto-detect format
    clean_line = line.strip()
    if clean_line.startswith('CEF:'):
        return parse_cef(clean_line, organization_id=organization_id, source_system=source_system)
    if NGINX_COMBINED_REGEX.match(clean_line):
        return parse_nginx_apache_access(clean_line, organization_id=organization_id, source_system=source_system or "access-log")
    if NGINX_ERROR_REGEX.match(clean_line):
        return parse_nginx_apache_error(clean_line, organization_id=organization_id, source_system=source_system or "error-log")
    if clean_line.startswith('<') or SYSLOG_RFC3164_REGEX.match(clean_line):
        return parse_syslog(clean_line, organization_id=organization_id, source_system=source_system)

    return None
