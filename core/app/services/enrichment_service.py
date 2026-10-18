"""
Ethio-Cyber-Shield (ECS) — Telemetry Enrichment & Context Synthesis Engine.
Provides:
1. Low-bandwidth offline GeoIP and ASN lookup with special awareness for Ethiopian critical infrastructure.
2. Tor exit node, VPN, proxy, and cloud datacenter / hosting provider detection.
3. High-speed Threat Intelligence (TI) indicator cache layer.
4. Internal device reputation scoring from historical organization telemetry.
5. Canonical event enrichment hooks.
"""
import ipaddress
import logging
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime, timedelta, timezone

logger = logging.getLogger(__name__)

# =========================================================================
# 1. OFFLINE PRE-SEEDED IP & ASN NETWORK REGISTRY
# =========================================================================

# Pre-compiled IP network definitions for zero-latency in-memory matching
_OFFLINE_NETWORKS: List[Tuple[Any, Dict[str, Any]]] = []

_NETWORK_DEFINITIONS = [
    # -------------------------------------------------------------------------
    # Ethiopian Telecom & Critical Infrastructure Networks
    # -------------------------------------------------------------------------
    ("196.188.0.0/14", {
        "country": "ET", "country_name": "Ethiopia", "city": "Addis Ababa", "region": "Addis Ababa",
        "asn": "AS24757", "as_org": "Ethio Telecom", "is_local_ethiopian": True, "is_hosting": False
    }),
    ("197.156.0.0/16", {
        "country": "ET", "country_name": "Ethiopia", "city": "Addis Ababa", "region": "Addis Ababa",
        "asn": "AS24757", "as_org": "Ethio Telecom", "is_local_ethiopian": True, "is_hosting": False
    }),
    ("213.55.64.0/18", {
        "country": "ET", "country_name": "Ethiopia", "city": "Addis Ababa", "region": "Addis Ababa",
        "asn": "AS24757", "as_org": "Ethio Telecom", "is_local_ethiopian": True, "is_hosting": False
    }),
    ("196.189.0.0/16", {
        "country": "ET", "country_name": "Ethiopia", "city": "Addis Ababa", "region": "Addis Ababa",
        "asn": "AS24757", "as_org": "Ethio Telecom", "is_local_ethiopian": True, "is_hosting": False
    }),
    ("196.190.0.0/16", {
        "country": "ET", "country_name": "Ethiopia", "city": "Addis Ababa", "region": "Addis Ababa",
        "asn": "AS24757", "as_org": "Ethio Telecom", "is_local_ethiopian": True, "is_hosting": False
    }),
    ("196.191.0.0/16", {
        "country": "ET", "country_name": "Ethiopia", "city": "Addis Ababa", "region": "Addis Ababa",
        "asn": "AS24757", "as_org": "Ethio Telecom", "is_local_ethiopian": True, "is_hosting": False
    }),
    ("102.218.40.0/22", {
        "country": "ET", "country_name": "Ethiopia", "city": "Addis Ababa", "region": "Addis Ababa",
        "asn": "AS329340", "as_org": "Safaricom Telecommunications Ethiopia", "is_local_ethiopian": True, "is_hosting": False
    }),
    ("102.216.96.0/20", {
        "country": "ET", "country_name": "Ethiopia", "city": "Addis Ababa", "region": "Addis Ababa",
        "asn": "AS329340", "as_org": "Safaricom Telecommunications Ethiopia", "is_local_ethiopian": True, "is_hosting": False
    }),
    ("213.55.100.0/22", {
        "country": "ET", "country_name": "Ethiopia", "city": "Addis Ababa", "region": "Addis Ababa",
        "asn": "AS37108", "as_org": "EthERNet / Ministry of Innovation", "is_local_ethiopian": True, "is_hosting": False
    }),

    # -------------------------------------------------------------------------
    # Private RFC1918 & Loopback Networks
    # -------------------------------------------------------------------------
    ("10.0.0.0/8", {
        "country": "INTERNAL", "country_name": "Internal Network", "city": "Private LAN", "region": "LAN",
        "asn": "AS0", "as_org": "RFC1918 Private", "is_local_ethiopian": True, "is_hosting": False, "is_private": True
    }),
    ("172.16.0.0/12", {
        "country": "INTERNAL", "country_name": "Internal Network", "city": "Private LAN", "region": "LAN",
        "asn": "AS0", "as_org": "RFC1918 Private", "is_local_ethiopian": True, "is_hosting": False, "is_private": True
    }),
    ("192.168.0.0/16", {
        "country": "INTERNAL", "country_name": "Internal Network", "city": "Private LAN", "region": "LAN",
        "asn": "AS0", "as_org": "RFC1918 Private", "is_local_ethiopian": True, "is_hosting": False, "is_private": True
    }),
    ("127.0.0.0/8", {
        "country": "INTERNAL", "country_name": "Loopback", "city": "Localhost", "region": "Host",
        "asn": "AS0", "as_org": "Loopback", "is_local_ethiopian": True, "is_hosting": False, "is_private": True
    }),

    # -------------------------------------------------------------------------
    # Cloud Datacenter & Hosting Providers (AWS, DigitalOcean, Hetzner, GCP, Azure)
    # -------------------------------------------------------------------------
    ("3.0.0.0/9", {
        "country": "US", "country_name": "United States", "city": "Ashburn", "region": "Virginia",
        "asn": "AS16509", "as_org": "Amazon AWS", "is_local_ethiopian": False, "is_hosting": True
    }),
    ("13.32.0.0/15", {
        "country": "US", "country_name": "United States", "city": "Seattle", "region": "Washington",
        "asn": "AS16509", "as_org": "Amazon AWS", "is_local_ethiopian": False, "is_hosting": True
    }),
    ("52.0.0.0/11", {
        "country": "US", "country_name": "United States", "city": "Ashburn", "region": "Virginia",
        "asn": "AS16509", "as_org": "Amazon AWS", "is_local_ethiopian": False, "is_hosting": True
    }),
    ("167.99.0.0/16", {
        "country": "US", "country_name": "United States", "city": "New York", "region": "New York",
        "asn": "AS14061", "as_org": "DigitalOcean", "is_local_ethiopian": False, "is_hosting": True
    }),
    ("159.65.0.0/16", {
        "country": "US", "country_name": "United States", "city": "San Francisco", "region": "California",
        "asn": "AS14061", "as_org": "DigitalOcean", "is_local_ethiopian": False, "is_hosting": True
    }),
    ("88.198.0.0/16", {
        "country": "DE", "country_name": "Germany", "city": "Nuremberg", "region": "Bavaria",
        "asn": "AS24940", "as_org": "Hetzner Online", "is_local_ethiopian": False, "is_hosting": True
    }),
    ("138.201.0.0/16", {
        "country": "DE", "country_name": "Germany", "city": "Falkenstein", "region": "Saxony",
        "asn": "AS24940", "as_org": "Hetzner Online", "is_local_ethiopian": False, "is_hosting": True
    }),
    ("34.64.0.0/11", {
        "country": "US", "country_name": "United States", "city": "Mountain View", "region": "California",
        "asn": "AS15169", "as_org": "Google Cloud", "is_local_ethiopian": False, "is_hosting": True
    }),
    ("20.0.0.0/11", {
        "country": "US", "country_name": "United States", "city": "Redmond", "region": "Washington",
        "asn": "AS8075", "as_org": "Microsoft Azure", "is_local_ethiopian": False, "is_hosting": True
    }),

    # -------------------------------------------------------------------------
    # Tor Exit Nodes & Anonymizing Proxies
    # -------------------------------------------------------------------------
    ("185.220.101.0/24", {
        "country": "DE", "country_name": "Germany", "city": "Frankfurt", "region": "Hesse",
        "asn": "AS208294", "as_org": "Tor Exit Relay", "is_local_ethiopian": False, "is_hosting": True,
        "is_tor": True, "is_vpn": True, "is_proxy": True
    }),
    ("185.220.102.0/24", {
        "country": "DE", "country_name": "Germany", "city": "Frankfurt", "region": "Hesse",
        "asn": "AS208294", "as_org": "Tor Exit Relay", "is_local_ethiopian": False, "is_hosting": True,
        "is_tor": True, "is_vpn": True, "is_proxy": True
    }),
    ("171.25.193.0/24", {
        "country": "CH", "country_name": "Switzerland", "city": "Zurich", "region": "Zurich",
        "asn": "AS51852", "as_org": "Privacy Relay", "is_local_ethiopian": False, "is_hosting": True,
        "is_tor": True, "is_vpn": True, "is_proxy": True
    }),
]

for cidr, data in _NETWORK_DEFINITIONS:
    try:
        _OFFLINE_NETWORKS.append((ipaddress.ip_network(cidr), data))
    except Exception as e:
        logger.warning(f"Could not load CIDR {cidr}: {e}")

# In-memory LRU-like caches
_IP_ENRICHMENT_CACHE: Dict[str, Dict[str, Any]] = {}
_THREAT_INDICATORS_CACHE: Dict[str, Dict[str, Any]] = {}


def clear_enrichment_caches():
    """Resets all runtime caches (used primarily in test suites)."""
    _IP_ENRICHMENT_CACHE.clear()
    _THREAT_INDICATORS_CACHE.clear()


def add_threat_indicator(
    indicator_type: str,
    value: str,
    severity: str = "high",
    confidence: int = 80,
    category: str = "suspicious",
    description: str = ""
):
    """Adds a threat intelligence indicator to the local cache and detection engine."""
    val_norm = value.strip().lower()
    score_map = {'critical': 90, 'high': 75, 'medium': 50, 'low': 25, 'benign': 0}
    score = score_map.get(severity.lower(), 50)
    status = 'malicious' if score >= 75 else ('suspicious' if score >= 40 else 'benign')

    _THREAT_INDICATORS_CACHE[val_norm] = {
        'indicator_type': indicator_type,
        'value': value,
        'severity': severity,
        'confidence': confidence,
        'category': category,
        'score': score,
        'status': status,
        'description': description,
        'created_at': datetime.now(timezone.utc).isoformat()
    }


def lookup_ip_enrichment(ip_str: str) -> Dict[str, Any]:
    """
    Resolves Geolocation, ASN, Carrier, Hosting, and Threat flags for an IP address.
    Fully offline-first with zero external network dependencies.
    """
    clean_ip = (ip_str or "").strip()
    if not clean_ip:
        return _default_ip_info("0.0.0.0")

    if clean_ip in _IP_ENRICHMENT_CACHE:
        return dict(_IP_ENRICHMENT_CACHE[clean_ip])

    info = _default_ip_info(clean_ip)

    try:
        ip_obj = ipaddress.ip_address(clean_ip)

        # Check for private or loopback
        if ip_obj.is_private or ip_obj.is_loopback:
            info.update({
                "country": "INTERNAL",
                "country_name": "Internal Network",
                "city": "Private LAN",
                "region": "LAN",
                "asn": "AS0",
                "as_org": "Private RFC1918",
                "is_local_ethiopian": True,
                "is_hosting": False,
                "is_private": True
            })
        else:
            # Check pre-seeded offline CIDRs
            for net, data in _OFFLINE_NETWORKS:
                if ip_obj in net:
                    info.update(data)
                    break

        # Check threat intelligence cache
        ti_record = _THREAT_INDICATORS_CACHE.get(clean_ip.lower())
        if ti_record:
            info["threat_intel"] = {
                "status": ti_record["status"],
                "category": ti_record["category"],
                "score": ti_record["score"],
                "confidence": ti_record["confidence"],
                "description": ti_record["description"]
            }
            if ti_record["status"] == "malicious":
                info["is_tor"] = info.get("is_tor") or ("tor" in ti_record["category"].lower())
                info["is_vpn"] = info.get("is_vpn") or ("vpn" in ti_record["category"].lower())

    except Exception as e:
        logger.debug(f"IP parse error for {clean_ip}: {e}")

    _IP_ENRICHMENT_CACHE[clean_ip] = info
    return dict(info)


def _default_ip_info(ip: str) -> Dict[str, Any]:
    """Default fallback payload for unclassified IPs."""
    return {
        "ip": ip,
        "country": "UNKNOWN",
        "country_name": "Unknown",
        "city": "Unknown",
        "region": "Unknown",
        "asn": "AS0",
        "as_org": "Unknown",
        "is_local_ethiopian": False,
        "is_hosting": False,
        "is_tor": False,
        "is_vpn": False,
        "is_proxy": False,
        "is_private": False,
        "threat_intel": {
            "status": "benign",
            "category": "none",
            "score": 0,
            "confidence": 0,
            "description": "No active threat indicators"
        }
    }


# =========================================================================
# 2. DEVICE REPUTATION ENGINE (FROM INTERNAL TELEMETRY HISTORY)
# =========================================================================

def calculate_device_reputation(
    device_fingerprint: str,
    organization_id: str
) -> Dict[str, Any]:
    """
    Computes an explainable device reputation score (0–100) based on historical
    behavior observed across the tenant's authentication and transaction streams.
    Strictly isolated by organization_id.
    """
    dfp = (device_fingerprint or "").strip()
    if not dfp:
        return {
            "device_fingerprint": "",
            "risk_score": 0,
            "reputation": "trusted",
            "accounts_seen_24h": 0,
            "failed_logins_24h": 0,
            "reasons": ["Empty device fingerprint"]
        }

    now = datetime.now(timezone.utc)
    since_24h = now - timedelta(hours=24)

    # 1. Fetch matching events from in-memory sliding buffer or database
    recent_events = []

    # Stream sliding buffer check
    try:
        from app.services.event_service import get_recent_in_memory_events
        buffer = get_recent_in_memory_events()
        for ev in buffer:
            if str(ev.get('organization_id')) == str(organization_id):
                ev_dev = ev.get('device_fingerprint') or ev.get('device_id') or ev.get('device_id_pub')
                if ev_dev == dfp:
                    recent_events.append(ev)
    except Exception as e:
        logger.debug(f"Device reputation buffer lookup error: {e}")

    # Database query fallback
    if len(recent_events) < 10:
        try:
            from app.services.db import get_service_supabase
            sb = get_service_supabase()
            res = sb.table('security_events').select('*')\
                .eq('organization_id', organization_id)\
                .eq('device_fingerprint', dfp)\
                .gte('occurred_at', since_24h.isoformat())\
                .limit(200).execute()
            if res.data:
                # Merge deduplicated
                seen_ids = {e.get('event_id') for e in recent_events}
                for r in res.data:
                    if r.get('event_id') not in seen_ids:
                        recent_events.append(r)
        except Exception as e:
            logger.debug(f"Device reputation DB query fallback: {e}")

    # 2. Behavioral synthesis
    distinct_accounts = set()
    failed_logins = 0
    total_events = len(recent_events)

    for ev in recent_events:
        acc = ev.get('account_id') or ev.get('account_id_pub') or ev.get('user_id') or ev.get('user_id_pub')
        if acc:
            distinct_accounts.add(acc)

        res = str(ev.get('result') or '').upper()
        ev_type = str(ev.get('event_type') or '').upper()
        if res in ('FAILURE', 'DENIED') or 'FAIL' in ev_type:
            failed_logins += 1

    accounts_count = len(distinct_accounts)

    # 3. Calculate Risk Score (0-100)
    score = 0
    reasons = []

    if accounts_count >= 5:
        score += 45
        reasons.append(f"Device accessed {accounts_count} distinct accounts within 24h (credential stuffing / mule indicator)")
    elif accounts_count >= 3:
        score += 25
        reasons.append(f"Device shared across {accounts_count} distinct user accounts within 24h")

    if failed_logins >= 5:
        score += 40
        reasons.append(f"High failure frequency: {failed_logins} failed authentication/transaction attempts within 24h")
    elif failed_logins >= 2:
        score += 20
        reasons.append(f"{failed_logins} failed operations from this device in the last 24h")

    # Cap score
    score = min(score, 100)

    # Determine classification
    if score >= 70:
        reputation = "high_risk"
    elif score >= 35:
        reputation = "suspicious"
    else:
        reputation = "trusted"
        if not reasons:
            reasons.append("Device behavior within normal baseline limits")

    return {
        "device_fingerprint": dfp,
        "organization_id": organization_id,
        "risk_score": score,
        "reputation": reputation,
        "total_events_24h": total_events,
        "accounts_seen_24h": accounts_count,
        "failed_logins_24h": failed_logins,
        "reasons": reasons
    }


# =========================================================================
# 3. CANONICAL EVENT ENRICHMENT HOOK
# =========================================================================

def enrich_canonical_event(event: Dict[str, Any]) -> Dict[str, Any]:
    """
    Enriches a canonical ECS event dictionary with GeoIP, ASN, Threat Intelligence,
    and Device Reputation context before downstream correlation and storage.
    """
    enriched = dict(event)
    attributes = dict(enriched.get('attributes') or {})
    org_id = enriched.get('organization_id')

    source_ip = enriched.get('source_ip')
    device_fp = enriched.get('device_fingerprint')

    enrichment_payload: Dict[str, Any] = {}

    if source_ip:
        ip_info = lookup_ip_enrichment(source_ip)
        enrichment_payload["geo"] = {
            "country": ip_info.get("country"),
            "country_name": ip_info.get("country_name"),
            "city": ip_info.get("city"),
            "region": ip_info.get("region"),
            "asn": ip_info.get("asn"),
            "as_org": ip_info.get("as_org"),
            "is_local_ethiopian": ip_info.get("is_local_ethiopian", False),
            "is_hosting": ip_info.get("is_hosting", False),
            "is_tor": ip_info.get("is_tor", False),
            "is_vpn": ip_info.get("is_vpn", False)
        }
        enrichment_payload["threat_intel"] = ip_info.get("threat_intel")

    if device_fp and org_id:
        dev_info = calculate_device_reputation(device_fp, org_id)
        enrichment_payload["device"] = {
            "risk_score": dev_info.get("risk_score", 0),
            "reputation": dev_info.get("reputation", "trusted"),
            "accounts_seen_24h": dev_info.get("accounts_seen_24h", 0),
            "reasons": dev_info.get("reasons", [])
        }

    attributes["enrichment"] = enrichment_payload
    enriched["attributes"] = attributes
    return enriched
