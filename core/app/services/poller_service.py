"""
Outbound Target Synchronization Poller & Health Heartbeat Daemon for ECS.
Periodically pulls security events from connected target systems (Direction B)
and maintains live connection health statistics.
"""
import time
import threading
import logging
from datetime import datetime, timezone
from app.services.db import get_service_supabase
from app.services.target_system_service import (
    call_target,
    check_target_health,
    get_target_by_id,
    list_active_targets,
)
from app.services.event_service import ingest_batch

logger = logging.getLogger(__name__)


def poll_target_once(target_id: str) -> dict:
    """
    Executes a single pull synchronization cycle against a target application.
    Queries GET /api/public/security/events?since_seq={last_seq}&limit=100
    and advances the target's high-water mark sequence.
    """
    target = get_target_by_id(target_id)
    if not target:
        return {'target_id': target_id, 'status': 'skipped', 'error': 'Target not found', 'events_synced': 0}

    base_url = target.get('base_url')
    key_id = target.get('key_id')
    secret = target.get('secret_key')
    last_seq = int(target.get('last_synced_seq') or 0)

    endpoint_path = f"/api/public/security/events?since_seq={last_seq}&limit=100"

    try:
        resp = call_target(
            method="GET",
            path=endpoint_path,
            base_url=base_url,
            key_id=key_id,
            secret=secret
        )

        if not resp.ok:
            logger.warning(f"Target {target_id} returned status {resp.status_code} during poll: {resp.text}")
            return {
                'target_id': target_id,
                'status': 'error',
                'status_code': resp.status_code,
                'events_synced': 0,
                'error': resp.text,
            }

        try:
            body = resp.json() if resp.text else {}
        except Exception:
            body = {}
        events = body.get('events', [])
        next_seq = body.get('next_seq')

        # Ingest events batch into security_events and entity cache
        synced_count = ingest_batch(events, target=target)

        # Update high-water mark sequence if advanced
        new_seq = next_seq if (next_seq is not None and next_seq > last_seq) else last_seq
        if events and new_seq > last_seq:
            from app.services.target_system_service import _LOCAL_TARGETS
            if target_id in _LOCAL_TARGETS:
                _LOCAL_TARGETS[target_id]['last_synced_seq'] = new_seq
            try:
                sb = get_service_supabase()
                sb.table('target_systems').update({
                    'last_synced_seq': new_seq,
                    'updated_at': datetime.now(timezone.utc).isoformat()
                }).eq('id', target_id).execute()
            except Exception as e:
                logger.debug(f"Could not update target_systems sequence: {e}")

        return {
            'target_id': target_id,
            'events_synced': synced_count,
            'previous_seq': last_seq,
            'new_seq': new_seq,
            'status': 'success'
        }

    except Exception as e:
        err_str = str(e)
        if "Connection refused" in err_str or "Max retries exceeded" in err_str:
            logger.debug(f"Target {target_id} offline or connection refused: {e}")
            return {
                'target_id': target_id,
                'events_synced': 0,
                'error': 'Target offline (connection refused)',
                'status': 'offline'
            }
        logger.warning(f"Error during polling of target {target_id}: {e}")
        return {
            'target_id': target_id,
            'events_synced': 0,
            'error': str(e),
            'status': 'error'
        }


def poll_all_active_targets() -> list[dict]:
    """
    Polls all active target systems configured with pull or bidirectional mode.
    """
    targets = list_active_targets()
    results = []
    for t in targets:
        if t.get('sync_mode') in ('pull', 'bidirectional'):
            res = poll_target_once(t['id'])
            results.append(res)
    return results


def check_and_update_all_targets_health() -> list[dict]:
    """
    Checks the health endpoint of all active targets and updates target_systems table.
    """
    targets = list_active_targets()
    sb = get_service_supabase()
    results = []

    for t in targets:
        base_url = t.get('base_url')
        health = check_target_health(base_url)
        is_healthy = health.get('status') == 'healthy'
        status_label = 'healthy' if is_healthy else 'down'

        from app.services.target_system_service import _LOCAL_TARGETS
        if t['id'] in _LOCAL_TARGETS:
            _LOCAL_TARGETS[t['id']]['health_status'] = status_label
            _LOCAL_TARGETS[t['id']]['last_health_check'] = datetime.now(timezone.utc).isoformat()

        try:
            sb = get_service_supabase()
            sb.table('target_systems').update({
                'health_status': status_label,
                'last_health_check': datetime.now(timezone.utc).isoformat()
            }).eq('id', t['id']).execute()
        except Exception as e:
            logger.debug(f"Could not update target health in database: {e}")

        results.append({
            'target_id': t['id'],
            'name': t.get('name'),
            'status': status_label,
            'details': health
        })

    return results


class TargetPollerDaemon:
    """
    Background daemon thread that periodically synchronizes events from target systems
    and performs continuous health checking.
    """
    def __init__(self, poll_interval_seconds: int = 5, health_interval_seconds: int = 60):
        self.poll_interval = poll_interval_seconds
        self.health_interval = health_interval_seconds
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._last_health_time = 0

    def _run_loop(self):
        from app.services.connector_scheduler_service import get_connector_scheduler_manager
        mgr = get_connector_scheduler_manager()
        logger.info(f"TargetPollerDaemon started with per-connector schedulers (health_interval={self.health_interval}s)")
        self._last_health_time = time.time()
        while not self._stop_event.is_set():
            try:
                # 1. Synchronize active targets with per-connector schedulers
                mgr.sync_with_target_systems()

                # 2. Trigger due connectors concurrently
                mgr.trigger_all_due()

                # 3. Check health if health interval elapsed
                now = time.time()
                if now - self._last_health_time >= self.health_interval:
                    check_and_update_all_targets_health()
                    self._last_health_time = now

            except Exception as e:
                logger.error(f"Error in poller daemon loop: {e}")

            # Responsive sleep interval (2 seconds per cycle)
            for _ in range(4):
                if self._stop_event.is_set():
                    break
                time.sleep(0.5)

        logger.info("TargetPollerDaemon stopped.")


    def start(self):
        if self._thread and self._thread.is_alive():
            logger.info("TargetPollerDaemon is already running.")
            return

        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run_loop, daemon=True, name="TargetPollerDaemon")
        self._thread.start()

    def stop(self):
        if self._thread and self._thread.is_alive():
            self._stop_event.set()
            self._thread.join(timeout=3)
            self._thread = None

    def is_running(self) -> bool:
        return bool(self._thread and self._thread.is_alive())


# Global singleton instance
_daemon_instance: TargetPollerDaemon | None = None


def get_poller_daemon() -> TargetPollerDaemon:
    global _daemon_instance
    if _daemon_instance is None:
        _daemon_instance = TargetPollerDaemon()
    return _daemon_instance
