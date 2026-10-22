"""
Ethio-Cyber-Shield (ECS) — Unified Entity Graph & Linkage Engine.
Maintains a real-time graph of accounts, devices, IPs, sessions, beneficiaries,
and hashed identity attributes (phone, national ID) with first/last seen tracking,
link counting, graph traversal, and transitive fraud ring detection.
"""
import uuid
import logging
from typing import Dict, Any, List, Optional, Set, Tuple
from datetime import datetime, timezone

from app.services.db import get_service_supabase

logger = logging.getLogger(__name__)

# In-memory stores for ultra-low latency graph traversal and unit test isolation
_LOCAL_ENTITIES: Dict[str, Dict[str, Any]] = {}
_LOCAL_LINKS: Dict[str, Dict[str, Any]] = {}
_ENTITIES_TABLE_EXISTS = True
_ENTITY_LINKS_TABLE_EXISTS = True


def clear_entity_graph_stores():
    """Resets all in-memory graph stores (used primarily in test suites)."""
    _LOCAL_ENTITIES.clear()
    _LOCAL_LINKS.clear()


def _entity_key(org_id: str, entity_type: str, entity_value: str) -> str:
    return f"{org_id}:{entity_type.lower().strip()}:{entity_value.strip()}"


def _link_key(org_id: str, st: str, sv: str, tt: str, tv: str, lt: str) -> str:
    return f"{org_id}:{st.lower().strip()}:{sv.strip()}:{tt.lower().strip()}:{tv.strip()}:{lt.lower().strip()}"


# =========================================================================
# 1. ENTITY AND LINK UPSERTION
# =========================================================================

def upsert_entity(
    org_id: str,
    entity_type: str,
    entity_value: str,
    occurred_at: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Upserts an entity node in the graph, updating event_count and advancing last_seen_at.
    """
    val = str(entity_value).strip()
    etype = str(entity_type).lower().strip()
    key = _entity_key(org_id, etype, val)
    now_iso = occurred_at or datetime.now(timezone.utc).isoformat()

    existing = _LOCAL_ENTITIES.get(key)
    if existing:
        existing['event_count'] = int(existing.get('event_count') or 1) + 1
        # Update last_seen_at to the latest timestamp
        if now_iso > existing.get('last_seen_at', ''):
            existing['last_seen_at'] = now_iso
        if metadata:
            existing.setdefault('metadata', {}).update(metadata)
        record = existing
    else:
        record = {
            'id': str(uuid.uuid4()),
            'organization_id': org_id,
            'entity_type': etype,
            'entity_value': val,
            'first_seen_at': now_iso,
            'last_seen_at': now_iso,
            'event_count': 1,
            'risk_score': 0,
            'risk_level': 'low',
            'tags': [],
            'metadata': metadata or {},
            'created_at': now_iso,
            'updated_at': now_iso
        }
        _LOCAL_ENTITIES[key] = record

    # Sync to database if available
    global _ENTITIES_TABLE_EXISTS
    if _ENTITIES_TABLE_EXISTS:
        try:
            sb = get_service_supabase()
            sb.table('entities').upsert(record, on_conflict='organization_id,entity_type,entity_value').execute()
        except Exception as e:
            if 'PGRST205' in str(e) or 'does not exist' in str(e):
                _ENTITIES_TABLE_EXISTS = False
            logger.debug(f"Entity upsert DB fallback: {e}")

    return record


def upsert_entity_link(
    org_id: str,
    source_type: str,
    source_value: str,
    target_type: str,
    target_value: str,
    link_type: str,
    occurred_at: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Upserts a relationship link (edge) between two entities in the graph.
    """
    st = str(source_type).lower().strip()
    sv = str(source_value).strip()
    tt = str(target_type).lower().strip()
    tv = str(target_value).strip()
    lt = str(link_type).lower().strip()
    key = _link_key(org_id, st, sv, tt, tv, lt)
    now_iso = occurred_at or datetime.now(timezone.utc).isoformat()

    existing = _LOCAL_LINKS.get(key)
    if existing:
        existing['link_count'] = int(existing.get('link_count') or 1) + 1
        if now_iso > existing.get('last_linked_at', ''):
            existing['last_linked_at'] = now_iso
        if metadata:
            existing.setdefault('metadata', {}).update(metadata)
        record = existing
    else:
        record = {
            'id': str(uuid.uuid4()),
            'organization_id': org_id,
            'source_type': st,
            'source_value': sv,
            'target_type': tt,
            'target_value': tv,
            'link_type': lt,
            'first_linked_at': now_iso,
            'last_linked_at': now_iso,
            'link_count': 1,
            'metadata': metadata or {},
            'created_at': now_iso,
            'updated_at': now_iso
        }
        _LOCAL_LINKS[key] = record

    # Sync to database if available
    global _ENTITY_LINKS_TABLE_EXISTS
    if _ENTITY_LINKS_TABLE_EXISTS:
        try:
            sb = get_service_supabase()
            sb.table('entity_links').upsert(record, on_conflict='organization_id,source_type,source_value,target_type,target_value,link_type').execute()
        except Exception as e:
            if 'PGRST205' in str(e) or 'does not exist' in str(e):
                _ENTITY_LINKS_TABLE_EXISTS = False
            logger.debug(f"Entity link upsert DB fallback: {e}")

    return record


def record_event_entities(event: Dict[str, Any]) -> None:
    """
    Analyzes an incoming canonical event, extracts all participating entities,
    and establishes bidirectional relationship links in the entity graph.
    """
    org_id = event.get('organization_id')
    if not org_id:
        return

    occurred_at = event.get('occurred_at') or datetime.now(timezone.utc).isoformat()

    # Extract entity values
    acc_id = event.get('account_id_pub') or event.get('account_id')
    dev_id = event.get('device_fingerprint') or event.get('device_id_pub') or event.get('device_id')
    ip_addr = event.get('source_ip')
    sess_id = event.get('session_id_pub') or event.get('session_id')
    dest_ref = event.get('counterparty_ref_hash') or event.get('beneficiary_id_pub')
    phone_hash = event.get('msisdn_hash')
    nat_id_hash = event.get('national_id_hash')

    # Upsert entity nodes
    if acc_id:
        upsert_entity(org_id, 'account', acc_id, occurred_at)
    if dev_id:
        upsert_entity(org_id, 'device', dev_id, occurred_at)
    if ip_addr:
        upsert_entity(org_id, 'ip', ip_addr, occurred_at)
    if sess_id:
        upsert_entity(org_id, 'session', sess_id, occurred_at)
    if dest_ref:
        upsert_entity(org_id, 'beneficiary', dest_ref, occurred_at)
    if phone_hash:
        upsert_entity(org_id, 'phone_hash', phone_hash, occurred_at)
    if nat_id_hash:
        upsert_entity(org_id, 'national_id_hash', nat_id_hash, occurred_at)

    # Establish semantic links
    if acc_id and dev_id:
        upsert_entity_link(org_id, 'account', acc_id, 'device', dev_id, 'used_device', occurred_at)
        upsert_entity_link(org_id, 'device', dev_id, 'account', acc_id, 'used_by_account', occurred_at)

    if acc_id and ip_addr:
        upsert_entity_link(org_id, 'account', acc_id, 'ip', ip_addr, 'connected_from_ip', occurred_at)
        upsert_entity_link(org_id, 'ip', ip_addr, 'account', acc_id, 'accessed_account', occurred_at)

    if dev_id and ip_addr:
        upsert_entity_link(org_id, 'device', dev_id, 'ip', ip_addr, 'routed_through_ip', occurred_at)
        upsert_entity_link(org_id, 'ip', ip_addr, 'device', dev_id, 'associated_device', occurred_at)

    if acc_id and sess_id:
        upsert_entity_link(org_id, 'account', acc_id, 'session', sess_id, 'active_session', occurred_at)

    if acc_id and dest_ref:
        upsert_entity_link(org_id, 'account', acc_id, 'beneficiary', dest_ref, 'transferred_to', occurred_at)
        upsert_entity_link(org_id, 'beneficiary', dest_ref, 'account', acc_id, 'received_transfer_from', occurred_at)

    if acc_id and phone_hash:
        upsert_entity_link(org_id, 'account', acc_id, 'phone_hash', phone_hash, 'registered_phone', occurred_at)

    if acc_id and nat_id_hash:
        upsert_entity_link(org_id, 'account', acc_id, 'national_id_hash', nat_id_hash, 'verified_identity', occurred_at)


# =========================================================================
# 2. GRAPH RETRIEVAL & TRAVERSAL
# =========================================================================

def get_entity(entity_type: str, entity_value: str, org_id: str) -> Optional[Dict[str, Any]]:
    """Retrieves an entity node scoped to organization."""
    key = _entity_key(org_id, entity_type, entity_value)
    if key in _LOCAL_ENTITIES:
        return dict(_LOCAL_ENTITIES[key])

    try:
        sb = get_service_supabase()
        res = sb.table('entities').select('*')\
            .eq('organization_id', org_id)\
            .eq('entity_type', entity_type.lower())\
            .eq('entity_value', str(entity_value))\
            .limit(1).execute()
        if res.data:
            node = res.data[0]
            _LOCAL_ENTITIES[key] = node
            return node
    except Exception as e:
        logger.debug(f"Entity DB lookup error: {e}")

    return None


def get_entity_links(
    entity_type: str,
    entity_value: str,
    org_id: str,
    link_type: Optional[str] = None
) -> List[Dict[str, Any]]:
    """Retrieves all links (inbound & outbound) for an entity node scoped to organization."""
    etype = entity_type.lower().strip()
    eval_str = str(entity_value).strip()

    links: List[Dict[str, Any]] = []

    # Local in-memory store scan
    prefix = f"{org_id}:"
    for k, v in _LOCAL_LINKS.items():
        if k.startswith(prefix):
            st = v.get('source_type')
            sv = v.get('source_value')
            tt = v.get('target_type')
            tv = v.get('target_value')
            lt = v.get('link_type')

            if link_type and lt != link_type.lower().strip():
                continue

            if (st == etype and sv == eval_str) or (tt == etype and tv == eval_str):
                links.append(dict(v))

    return links


def get_entity_graph(
    entity_type: str,
    entity_value: str,
    org_id: str,
    depth: int = 1
) -> Dict[str, Any]:
    """
    Performs breadth-first traversal up to `depth` levels (default 1, max 2).
    Generates a Cytoscape/D3 network graph structure with nodes and edges.
    """
    root_type = entity_type.lower().strip()
    root_val = str(entity_value).strip()

    visited_nodes: Dict[str, Dict[str, Any]] = {}
    edges: List[Dict[str, Any]] = []
    seen_edge_keys: Set[str] = set()

    queue: List[Tuple[str, str, int]] = [(root_type, root_val, 0)]

    while queue:
        curr_type, curr_val, curr_depth = queue.pop(0)
        curr_node_id = f"{curr_type}:{curr_val}"

        if curr_node_id not in visited_nodes:
            node_record = get_entity(curr_type, curr_val, org_id) or {
                'entity_type': curr_type,
                'entity_value': curr_val,
                'risk_score': 0,
                'risk_level': 'low',
                'tags': [],
                'event_count': 1
            }
            visited_nodes[curr_node_id] = {
                'id': curr_node_id,
                'type': curr_type,
                'value': curr_val,
                'risk_score': node_record.get('risk_score', 0),
                'risk_level': node_record.get('risk_level', 'low'),
                'tags': node_record.get('tags', []),
                'event_count': node_record.get('event_count', 1),
                'first_seen': node_record.get('first_seen_at'),
                'last_seen': node_record.get('last_seen_at')
            }

        if curr_depth >= depth:
            continue

        # Find connected links
        links = get_entity_links(curr_type, curr_val, org_id)
        for link in links:
            st = link['source_type']
            sv = link['source_value']
            tt = link['target_type']
            tv = link['target_value']
            lt = link['link_type']

            edge_key = f"{st}:{sv}->{tt}:{tv}:{lt}"
            if edge_key not in seen_edge_keys:
                seen_edge_keys.add(edge_key)
                edges.append({
                    'source': f"{st}:{sv}",
                    'target': f"{tt}:{tv}",
                    'link_type': lt,
                    'link_count': link.get('link_count', 1),
                    'last_linked': link.get('last_linked_at')
                })

            # Queue adjacent node
            if st == curr_type and sv == curr_val:
                next_node = (tt, tv, curr_depth + 1)
            else:
                next_node = (st, sv, curr_depth + 1)

            if f"{next_node[0]}:{next_node[1]}" not in visited_nodes:
                queue.append(next_node)

    max_risk = max((n['risk_score'] for n in visited_nodes.values()), default=0)

    return {
        'root_entity': f"{root_type}:{root_val}",
        'nodes': list(visited_nodes.values()),
        'edges': edges,
        'summary': {
            'total_nodes': len(visited_nodes),
            'total_edges': len(edges),
            'max_risk_score': max_risk
        }
    }


# =========================================================================
# 3. FRAUD RING & SHARED ENTITY ANALYSIS
# =========================================================================

def find_shared_entities(
    entity_type: str,
    entity_value: str,
    org_id: str
) -> Dict[str, Any]:
    """
    Identifies multi-account device sharing (credential stuffing / account takeover)
    and multi-sender beneficiary concentration (mule account aggregators).
    """
    etype = entity_type.lower().strip()
    eval_str = str(entity_value).strip()

    links = get_entity_links(etype, eval_str, org_id)

    if etype == 'device':
        # Find all accounts connected to this device
        accounts = set()
        for l in links:
            if l['link_type'] in ('used_by_account', 'used_device'):
                if l['source_type'] == 'account':
                    accounts.add(l['source_value'])
                elif l['target_type'] == 'account':
                    accounts.add(l['target_value'])

        accounts_list = sorted(list(accounts))
        return {
            'entity_type': 'device',
            'entity_value': eval_str,
            'is_shared': len(accounts_list) > 1,
            'shared_count': len(accounts_list),
            'connected_accounts': accounts_list
        }

    elif etype == 'beneficiary':
        # Find all accounts that sent funds to this beneficiary
        senders = set()
        for l in links:
            if l['link_type'] in ('transferred_to', 'received_transfer_from'):
                if l['source_type'] == 'account':
                    senders.add(l['source_value'])
                elif l['target_type'] == 'account':
                    senders.add(l['target_value'])

        senders_list = sorted(list(senders))
        return {
            'entity_type': 'beneficiary',
            'entity_value': eval_str,
            'is_shared': len(senders_list) > 1,
            'shared_count': len(senders_list),
            'sending_accounts': senders_list
        }

    elif etype == 'account':
        # Find all devices and IPs used by this account
        devices = set()
        ips = set()
        for l in links:
            if l['source_type'] == 'device':
                devices.add(l['source_value'])
            elif l['target_type'] == 'device':
                devices.add(l['target_value'])
            if l['source_type'] == 'ip':
                ips.add(l['source_value'])
            elif l['target_type'] == 'ip':
                ips.add(l['target_value'])

        return {
            'entity_type': 'account',
            'entity_value': eval_str,
            'devices': sorted(list(devices)),
            'ips': sorted(list(ips))
        }

    return {
        'entity_type': etype,
        'entity_value': eval_str,
        'is_shared': False,
        'shared_count': 0
    }


def calculate_graph_risk(
    entity_type: str,
    entity_value: str,
    org_id: str
) -> Dict[str, Any]:
    """
    Computes explainable transitive risk by analyzing connected neighbor nodes.
    """
    etype = entity_type.lower().strip()
    eval_str = str(entity_value).strip()

    node = get_entity(etype, eval_str, org_id) or {}
    tags = node.get('tags') or []

    score = 0
    reasons: List[str] = []

    # 1. Direct node tags
    if 'compromised' in tags:
        score += 80
        reasons.append("Entity explicitly flagged as compromised")
    if 'mule' in tags or 'fraud' in tags:
        score += 75
        reasons.append("Entity tagged as participating in fraudulent transactions")

    # 2. Transitive neighborhood checks (depth 1)
    links = get_entity_links(etype, eval_str, org_id)

    connected_compromised = []
    connected_accounts = set()

    for l in links:
        other_t = l['target_type'] if l['source_type'] == etype else l['source_type']
        other_v = l['target_value'] if l['source_value'] == eval_str else l['source_value']

        neighbor = get_entity(other_t, other_v, org_id) or {}
        n_tags = neighbor.get('tags') or []

        if 'compromised' in n_tags:
            connected_compromised.append(f"{other_t}:{other_v}")

        if other_t == 'account':
            connected_accounts.add(other_v)

    if connected_compromised:
        score += 50
        reasons.append(f"Connected to compromised entities: {', '.join(connected_compromised)}")

    if etype == 'device' and len(connected_accounts) >= 3:
        score += 35
        reasons.append(f"Device shared across {len(connected_accounts)} distinct accounts within tenant")

    score = min(score, 100)
    risk_level = 'critical' if score >= 80 else ('high' if score >= 60 else ('medium' if score >= 30 else 'low'))

    return {
        'entity_type': etype,
        'entity_value': eval_str,
        'organization_id': org_id,
        'risk_score': score,
        'risk_level': risk_level,
        'reasons': reasons
    }


def tag_entity(
    entity_type: str,
    entity_value: str,
    tag: str,
    org_id: str
) -> Optional[Dict[str, Any]]:
    """Tags an entity node and updates risk level."""
    node = get_entity(entity_type, entity_value, org_id)
    if not node:
        node = upsert_entity(org_id, entity_type, entity_value)

    tags = list(node.get('tags') or [])
    tag_clean = tag.strip().lower()
    if tag_clean not in tags:
        tags.append(tag_clean)
        node['tags'] = tags

    key = _entity_key(org_id, entity_type, entity_value)
    _LOCAL_ENTITIES[key] = node

    try:
        sb = get_service_supabase()
        sb.table('entities').update({'tags': tags, 'updated_at': datetime.now(timezone.utc).isoformat()})\
            .eq('organization_id', org_id)\
            .eq('entity_type', entity_type.lower())\
            .eq('entity_value', str(entity_value)).execute()
    except Exception as e:
        logger.debug(f"Entity tag DB update error: {e}")

    return node
