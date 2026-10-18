"""
Multi-Target Connector Scheduler Service for Ethio-Cyber-Shield (ECS) v3.0 (Phase 2.8).

Replaces single-target monolithic poller with:
1. Per-connector independent scheduling with custom intervals and state tracking.
2. Concurrent non-blocking polling via ThreadPoolExecutor.
3. Exponential backoff with jitter on target/network failures.
4. Rapid recovery upon successful polling (resetting backoff to base interval).
5. Comprehensive lifecycle controls (trigger, pause, resume, reconfigure).
6. Strict multi-tenant isolation (scoped by organization_id UUID).
"""
import time
import random
import logging
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any, List, Callable, Tuple
from concurrent.futures import ThreadPoolExecutor, Future

from app.services.tenant_service import get_current_organization_id

logger = logging.getLogger(__name__)


class ConnectorScheduler:
    """
    Independent scheduling state machine for a specific target/connector.
    Implements per-connector intervals, exponential backoff with jitter, and execution metrics.
    """
    def __init__(
        self,
        connector_id: str,
        name: str,
        organization_id: str,
        connector_type: str = 'poller',
        interval_seconds: int = 5,
        backoff_multiplier: float = 2.0,
        max_backoff_seconds: int = 300,
        jitter_ratio: float = 0.2
    ):
        self.connector_id = str(connector_id)
        self.name = str(name or connector_id)
        self.organization_id = str(organization_id)
        self.connector_type = str(connector_type)
        self.interval_seconds = max(1, int(interval_seconds))
        self.backoff_multiplier = max(1.1, float(backoff_multiplier))
        self.max_backoff_seconds = max(self.interval_seconds, int(max_backoff_seconds))
        self.jitter_ratio = min(0.5, max(0.0, float(jitter_ratio)))

        now = datetime.now(timezone.utc)
        self.status = 'idle'  # 'idle', 'running', 'backoff', 'paused', 'stopped'
        self.consecutive_failures = 0
        self.total_runs = 0
        self.total_events_synced = 0
        self.total_errors = 0
        self.last_run_at: Optional[datetime] = None
        self.last_run_duration_ms: float = 0.0
        self.last_status: Optional[str] = None
        self.last_error: Optional[str] = None
        self.next_run_at = now

    def is_due(self, now: Optional[datetime] = None) -> bool:
        """Returns True if the connector is ready for its next execution cycle."""
        if self.status == 'paused' or self.status == 'stopped':
            return False
        if now is None:
            now = datetime.now(timezone.utc)
        elif now.tzinfo is None:
            now = now.replace(tzinfo=timezone.utc)
        return now >= self.next_run_at

    def record_poll_result(
        self,
        success: bool,
        events_synced: int = 0,
        error_message: Optional[str] = None,
        duration_ms: float = 0.0,
        now: Optional[datetime] = None
    ):
        """
        Updates scheduler state after an execution cycle:
        - If success: resets consecutive failures and schedules next run at base interval.
        - If failure: increments consecutive failures, applies exponential backoff with jitter.
        """
        if now is None:
            now = datetime.now(timezone.utc)
        elif now.tzinfo is None:
            now = now.replace(tzinfo=timezone.utc)

        self.total_runs += 1
        self.last_run_at = now
        self.last_run_duration_ms = round(float(duration_ms), 2)

        if success:
            self.consecutive_failures = 0
            self.status = 'idle'
            self.last_status = 'success'
            self.last_error = None
            self.total_events_synced += int(events_synced or 0)
            self.next_run_at = now + timedelta(seconds=self.interval_seconds)
        else:
            self.consecutive_failures += 1
            self.total_errors += 1
            self.status = 'backoff'
            self.last_status = 'error'
            self.last_error = str(error_message) if error_message else "Unknown poll error"

            # Exponential backoff calculation: interval * (multiplier ** failures)
            exp_delay = self.interval_seconds * (self.backoff_multiplier ** self.consecutive_failures)
            capped_delay = min(exp_delay, self.max_backoff_seconds)

            # Apply ±jitter
            jitter_factor = random.uniform(1.0 - self.jitter_ratio, 1.0 + self.jitter_ratio)
            backoff_delay = max(1.0, capped_delay * jitter_factor)

            self.next_run_at = now + timedelta(seconds=backoff_delay)

    def pause(self):
        self.status = 'paused'

    def resume(self, now: Optional[datetime] = None):
        if now is None:
            now = datetime.now(timezone.utc)
        elif now.tzinfo is None:
            now = now.replace(tzinfo=timezone.utc)
        self.status = 'idle'
        self.next_run_at = now

    def configure(
        self,
        interval_seconds: Optional[int] = None,
        backoff_multiplier: Optional[float] = None,
        max_backoff_seconds: Optional[int] = None
    ):
        if interval_seconds is not None:
            self.interval_seconds = max(1, int(interval_seconds))
        if backoff_multiplier is not None:
            self.backoff_multiplier = max(1.1, float(backoff_multiplier))
        if max_backoff_seconds is not None:
            self.max_backoff_seconds = max(self.interval_seconds, int(max_backoff_seconds))

    def to_dict(self) -> Dict[str, Any]:
        return {
            'connector_id': self.connector_id,
            'name': self.name,
            'organization_id': self.organization_id,
            'connector_type': self.connector_type,
            'interval_seconds': self.interval_seconds,
            'backoff_multiplier': self.backoff_multiplier,
            'max_backoff_seconds': self.max_backoff_seconds,
            'status': self.status,
            'consecutive_failures': self.consecutive_failures,
            'total_runs': self.total_runs,
            'total_events_synced': self.total_events_synced,
            'total_errors': self.total_errors,
            'last_run_at': self.last_run_at.isoformat() if self.last_run_at else None,
            'last_run_duration_ms': self.last_run_duration_ms,
            'last_status': self.last_status,
            'last_error': self.last_error,
            'next_run_at': self.next_run_at.isoformat() if self.next_run_at else None
        }


class ConnectorSchedulerManager:
    """
    Coordinates and schedules all connectors concurrently using a worker pool.
    Guarantees strict multi-tenancy and non-blocking isolation.
    """
    def __init__(self, max_workers: int = 10):
        self.max_workers = max_workers
        self._executor = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="ECS-Connector")
        # Keyed by (organization_id, connector_id)
        self._schedulers: Dict[Tuple[str, str], ConnectorScheduler] = {}

    def register_connector(
        self,
        connector_id: str,
        name: str,
        org_id: str,
        connector_type: str = 'poller',
        interval_seconds: int = 5,
        backoff_multiplier: float = 2.0,
        max_backoff_seconds: int = 300
    ) -> ConnectorScheduler:
        """Registers or updates a connector scheduler configuration."""
        key = (str(org_id), str(connector_id))
        sched = self._schedulers.get(key)
        if sched:
            sched.name = name or sched.name
            sched.connector_type = connector_type or sched.connector_type
            sched.configure(interval_seconds, backoff_multiplier, max_backoff_seconds)
        else:
            sched = ConnectorScheduler(
                connector_id=connector_id,
                name=name,
                organization_id=org_id,
                connector_type=connector_type,
                interval_seconds=interval_seconds,
                backoff_multiplier=backoff_multiplier,
                max_backoff_seconds=max_backoff_seconds
            )
            self._schedulers[key] = sched
        return sched

    def get_scheduler(self, connector_id: str, org_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves scheduler details enforcing tenant boundary."""
        key = (str(org_id), str(connector_id))
        sched = self._schedulers.get(key)
        return sched.to_dict() if sched else None

    def list_schedulers(self, org_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Lists all connector schedulers, optionally scoped to an organization."""
        results = []
        for (o_id, _), sched in self._schedulers.items():
            if org_id is None or o_id == str(org_id):
                results.append(sched.to_dict())
        results.sort(key=lambda s: s.get('name', ''))
        return results

    def pause_connector(self, connector_id: str, org_id: str) -> bool:
        """Pauses a connector scheduler."""
        key = (str(org_id), str(connector_id))
        sched = self._schedulers.get(key)
        if sched:
            sched.pause()
            return True
        return False

    def resume_connector(self, connector_id: str, org_id: str) -> bool:
        """Resumes a paused connector scheduler."""
        key = (str(org_id), str(connector_id))
        sched = self._schedulers.get(key)
        if sched:
            sched.resume()
            return True
        return False

    def configure_connector(
        self,
        connector_id: str,
        org_id: str,
        interval_seconds: Optional[int] = None,
        backoff_multiplier: Optional[float] = None,
        max_backoff_seconds: Optional[int] = None
    ) -> bool:
        """Reconfigures scheduler parameters for a specific connector."""
        key = (str(org_id), str(connector_id))
        sched = self._schedulers.get(key)
        if sched:
            sched.configure(interval_seconds, backoff_multiplier, max_backoff_seconds)
            return True
        return False

    def _execute_poll(self, sched: ConnectorScheduler, poll_func: Callable[[str], dict]) -> dict:
        """Worker task executing a poll cycle and updating scheduler state."""
        start_time = time.time()
        try:
            res = poll_func(sched.connector_id)
            duration_ms = (time.time() - start_time) * 1000.0

            success = res.get('status') == 'success' or (res.get('events_synced', 0) >= 0 and not res.get('error'))
            events_synced = res.get('events_synced', 0)
            err = res.get('error')

            sched.record_poll_result(
                success=success,
                events_synced=events_synced,
                error_message=err,
                duration_ms=duration_ms
            )
            return res
        except Exception as e:
            duration_ms = (time.time() - start_time) * 1000.0
            sched.record_poll_result(
                success=False,
                error_message=str(e),
                duration_ms=duration_ms
            )
            return {'status': 'error', 'error': str(e), 'events_synced': 0}

    def trigger_connector(
        self,
        connector_id: str,
        org_id: str,
        poll_func: Optional[Callable[[str], dict]] = None
    ) -> Optional[Future]:
        """Dispatches an immediate poll task for the specified connector."""
        key = (str(org_id), str(connector_id))
        sched = self._schedulers.get(key)
        if not sched:
            return None

        if poll_func is None:
            from app.services.poller_service import poll_target_once
            poll_func = poll_target_once

        return self._executor.submit(self._execute_poll, sched, poll_func)

    def trigger_all_due(
        self,
        poll_funcs: Optional[List[Callable[[str], dict]]] = None,
        now: Optional[datetime] = None
    ) -> List[Future]:
        """
        Inspects all registered schedulers and submits asynchronous poll tasks
        for any connectors that are due. Returns list of running Futures.
        """
        if now is None:
            now = datetime.now(timezone.utc)
        elif now.tzinfo is None:
            now = now.replace(tzinfo=timezone.utc)

        futures: List[Future] = []
        default_func = poll_funcs[0] if (poll_funcs and len(poll_funcs) > 0) else None

        if default_func is None:
            from app.services.poller_service import poll_target_once
            default_func = poll_target_once

        for sched in list(self._schedulers.values()):
            if sched.is_due(now=now):
                f = self._executor.submit(self._execute_poll, sched, default_func)
                futures.append(f)

        return futures

    def sync_with_target_systems(self, org_id: Optional[str] = None):
        """Discovers active targets from database and registers per-connector schedulers."""
        try:
            from app.services.target_system_service import list_active_targets
            targets = list_active_targets()
            for t in targets:
                t_org = t.get('organization_id')
                if org_id and str(t_org) != str(org_id):
                    continue
                if t.get('sync_mode') in ('pull', 'bidirectional'):
                    self.register_connector(
                        connector_id=t['id'],
                        name=t.get('name', t['id']),
                        org_id=t_org or org_id or '00000000-0000-0000-0000-000000000001',
                        connector_type='poller',
                        interval_seconds=int(t.get('poll_interval_seconds') or 5)
                    )
        except Exception as e:
            logger.debug(f"Target sync error in scheduler manager: {e}")


# Singleton instance
_manager_instance: Optional[ConnectorSchedulerManager] = None


def get_connector_scheduler_manager() -> ConnectorSchedulerManager:
    global _manager_instance
    if _manager_instance is None:
        _manager_instance = ConnectorSchedulerManager()
    return _manager_instance


def clear_connector_schedulers():
    """Clears all registered schedulers. Useful for test teardown."""
    mgr = get_connector_scheduler_manager()
    mgr._schedulers.clear()
