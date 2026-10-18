"""
Ethio-Cyber-Shield (ECS) — Python Transactional Outbox.
Guarantees resilient, at-least-once telemetry delivery with exponential backoff,
dead-letter escalation, local durability (SQLite/In-Memory), and non-blocking background dispatch.
Generalizes ShieldBank's outbox.server.ts into an independent enterprise client pattern.
"""
import sqlite3
import json
import time
import uuid
import logging
import threading
from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


class OutboxItem:
    """Represents a telemetry record stored in the local outbox queue."""

    def __init__(
        self,
        event_id: str,
        payload: Dict[str, Any],
        status: str = "PENDING",
        attempts: int = 0,
        last_error: Optional[str] = None,
        created_at: Optional[float] = None,
        updated_at: Optional[float] = None,
        next_retry_at: Optional[float] = None,
        delivered_at: Optional[float] = None,
    ):
        now = time.time()
        self.event_id = event_id
        self.payload = payload
        self.status = status
        self.attempts = attempts
        self.last_error = last_error
        self.created_at = created_at or now
        self.updated_at = updated_at or now
        self.next_retry_at = next_retry_at or 0.0
        self.delivered_at = delivered_at

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "payload": self.payload,
            "status": self.status,
            "attempts": self.attempts,
            "last_error": self.last_error,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "next_retry_at": self.next_retry_at,
            "delivered_at": self.delivered_at,
        }


class BaseOutboxStorage(ABC):
    """Abstract interface for local transactional outbox storage engines."""

    @abstractmethod
    def save(self, event_id: str, payload: Dict[str, Any]) -> None:
        """Stores a new event with status PENDING."""
        pass

    @abstractmethod
    def get_by_id(self, event_id: str) -> Optional[OutboxItem]:
        """Retrieves a single outbox record by event ID."""
        pass

    @abstractmethod
    def get_pending_and_retryable(self, limit: int, now: float) -> List[OutboxItem]:
        """Retrieves events that are PENDING or FAILED with next_retry_at <= now."""
        pass

    @abstractmethod
    def mark_delivered(self, event_id: str) -> None:
        """Transitions status to DELIVERED and records timestamp."""
        pass

    @abstractmethod
    def mark_failed(self, event_id: str, attempts: int, error: str, next_retry_at: Optional[float] = None) -> None:
        """Transitions status to FAILED, increments attempts, and schedules next retry."""
        pass

    @abstractmethod
    def mark_dead_letter(self, event_id: str, attempts: int, error: str) -> None:
        """Transitions status to DEAD_LETTER after exceeding max attempts."""
        pass

    @abstractmethod
    def get_stats(self) -> Dict[str, int]:
        """Returns counts by status."""
        pass


class SQLiteOutboxStorage(BaseOutboxStorage):
    """
    Thread-safe, zero-dependency persistent outbox engine using SQLite in WAL mode.
    Ensures telemetry is durable on disk before network transmission.
    """

    def __init__(self, db_path: str = "ecs_outbox.db"):
        self.db_path = db_path
        self._lock = threading.Lock()
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, check_same_thread=False, timeout=30.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA busy_timeout = 5000;")
        return conn

    def _init_db(self) -> None:
        with self._lock:
            with self._get_connection() as conn:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS ecs_outbox (
                        event_id TEXT PRIMARY KEY,
                        payload TEXT NOT NULL,
                        status TEXT NOT NULL DEFAULT 'PENDING',
                        attempts INTEGER NOT NULL DEFAULT 0,
                        last_error TEXT,
                        created_at REAL NOT NULL,
                        updated_at REAL NOT NULL,
                        next_retry_at REAL NOT NULL DEFAULT 0.0,
                        delivered_at REAL
                    );
                """)
                conn.execute("""
                    CREATE INDEX IF NOT EXISTS idx_ecs_outbox_retry 
                    ON ecs_outbox(status, next_retry_at, updated_at);
                """)
                conn.commit()

    def save(self, event_id: str, payload: Dict[str, Any]) -> None:
        now = time.time()
        payload_json = json.dumps(payload)
        with self._lock:
            with self._get_connection() as conn:
                conn.execute("""
                    INSERT INTO ecs_outbox (event_id, payload, status, attempts, created_at, updated_at, next_retry_at)
                    VALUES (?, ?, 'PENDING', 0, ?, ?, 0.0)
                    ON CONFLICT(event_id) DO UPDATE SET
                        payload = excluded.payload,
                        updated_at = excluded.updated_at;
                """, (event_id, payload_json, now, now))
                conn.commit()

    def get_by_id(self, event_id: str) -> Optional[OutboxItem]:
        with self._lock:
            with self._get_connection() as conn:
                cur = conn.execute("SELECT * FROM ecs_outbox WHERE event_id = ?", (event_id,))
                row = cur.fetchone()
                if not row:
                    return None
                return self._row_to_item(row)

    def get_pending_and_retryable(self, limit: int, now: float) -> List[OutboxItem]:
        with self._lock:
            with self._get_connection() as conn:
                cur = conn.execute("""
                    SELECT * FROM ecs_outbox
                    WHERE status IN ('PENDING', 'FAILED')
                      AND next_retry_at <= ?
                    ORDER BY updated_at ASC
                    LIMIT ?
                """, (now, limit))
                return [self._row_to_item(row) for row in cur.fetchall()]

    def mark_delivered(self, event_id: str) -> None:
        now = time.time()
        with self._lock:
            with self._get_connection() as conn:
                conn.execute("""
                    UPDATE ecs_outbox
                    SET status = 'DELIVERED',
                        delivered_at = ?,
                        updated_at = ?,
                        last_error = NULL
                    WHERE event_id = ?
                """, (now, now, event_id))
                conn.commit()

    def mark_failed(self, event_id: str, attempts: int, error: str, next_retry_at: Optional[float] = None) -> None:
        now = time.time()
        retry_time = next_retry_at if next_retry_at is not None else (now + 10.0)
        with self._lock:
            with self._get_connection() as conn:
                conn.execute("""
                    UPDATE ecs_outbox
                    SET status = 'FAILED',
                        attempts = ?,
                        last_error = ?,
                        next_retry_at = ?,
                        updated_at = ?
                    WHERE event_id = ?
                """, (attempts, str(error)[:500], retry_time, now, event_id))
                conn.commit()

    def mark_dead_letter(self, event_id: str, attempts: int, error: str) -> None:
        now = time.time()
        with self._lock:
            with self._get_connection() as conn:
                conn.execute("""
                    UPDATE ecs_outbox
                    SET status = 'DEAD_LETTER',
                        attempts = ?,
                        last_error = ?,
                        updated_at = ?
                    WHERE event_id = ?
                """, (attempts, str(error)[:500], now, event_id))
                conn.commit()

    def _update_item(self, item: OutboxItem) -> None:
        with self._lock:
            with self._get_connection() as conn:
                conn.execute("""
                    UPDATE ecs_outbox
                    SET status = ?, attempts = ?, last_error = ?, next_retry_at = ?, delivered_at = ?, updated_at = ?
                    WHERE event_id = ?
                """, (item.status, item.attempts, item.last_error, item.next_retry_at, item.delivered_at, item.updated_at, item.event_id))
                conn.commit()

    def get_stats(self) -> Dict[str, int]:
        stats = {"PENDING": 0, "DELIVERED": 0, "FAILED": 0, "DEAD_LETTER": 0}
        with self._lock:
            with self._get_connection() as conn:
                cur = conn.execute("SELECT status, COUNT(*) as cnt FROM ecs_outbox GROUP BY status")
                for row in cur.fetchall():
                    stats[row["status"]] = row["cnt"]
        return stats

    def _row_to_item(self, row: sqlite3.Row) -> OutboxItem:
        return OutboxItem(
            event_id=row["event_id"],
            payload=json.loads(row["payload"]),
            status=row["status"],
            attempts=row["attempts"],
            last_error=row["last_error"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
            next_retry_at=row["next_retry_at"],
            delivered_at=row["delivered_at"],
        )


class InMemoryOutboxStorage(BaseOutboxStorage):
    """In-memory outbox storage for ephemeral testing and high-speed benchmarks."""

    def __init__(self):
        self._items: Dict[str, OutboxItem] = {}
        self._lock = threading.Lock()

    def save(self, event_id: str, payload: Dict[str, Any]) -> None:
        with self._lock:
            self._items[event_id] = OutboxItem(event_id=event_id, payload=payload)

    def get_by_id(self, event_id: str) -> Optional[OutboxItem]:
        with self._lock:
            return self._items.get(event_id)

    def get_pending_and_retryable(self, limit: int, now: float) -> List[OutboxItem]:
        with self._lock:
            candidates = [
                item for item in self._items.values()
                if item.status in ("PENDING", "FAILED") and item.next_retry_at <= now
            ]
            candidates.sort(key=lambda x: x.updated_at)
            return candidates[:limit]

    def mark_delivered(self, event_id: str) -> None:
        with self._lock:
            if event_id in self._items:
                self._items[event_id].status = "DELIVERED"
                self._items[event_id].delivered_at = time.time()
                self._items[event_id].last_error = None

    def mark_failed(self, event_id: str, attempts: int, error: str, next_retry_at: Optional[float] = None) -> None:
        now = time.time()
        retry_time = next_retry_at if next_retry_at is not None else (now + 10.0)
        with self._lock:
            if event_id in self._items:
                item = self._items[event_id]
                item.status = "FAILED"
                item.attempts = attempts
                item.last_error = error
                item.next_retry_at = retry_time
                item.updated_at = now

    def mark_dead_letter(self, event_id: str, attempts: int, error: str) -> None:
        with self._lock:
            if event_id in self._items:
                item = self._items[event_id]
                item.status = "DEAD_LETTER"
                item.attempts = attempts
                item.last_error = error
                item.updated_at = time.time()

    def get_stats(self) -> Dict[str, int]:
        stats = {"PENDING": 0, "DELIVERED": 0, "FAILED": 0, "DEAD_LETTER": 0}
        with self._lock:
            for item in self._items.values():
                stats[item.status] = stats.get(item.status, 0) + 1
        return stats


class TransactionalOutbox:
    """
    Manages transactional telemetry dispatching from client applications to ECS.
    Guarantees:
    - Zero data loss during network disruptions
    - Exponential backoff retry: min(max_backoff, initial_interval * 2^(attempts-1))
    - Escalation to DEAD_LETTER after max_attempts
    - Clean background daemon worker
    """

    def __init__(
        self,
        client: Any,
        storage: Optional[BaseOutboxStorage] = None,
        initial_backoff: float = 2.0,
        max_backoff: float = 300.0,
        max_attempts: int = 8,
        batch_size: int = 50,
    ):
        self.client = client
        self.storage = storage or SQLiteOutboxStorage()
        self.initial_backoff = initial_backoff
        self.max_backoff = max_backoff
        self.max_attempts = max_attempts
        self.batch_size = batch_size

        self._worker_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._flush_lock = threading.Lock()

    def enqueue(self, event_payload: Dict[str, Any]) -> str:
        """
        Enqueues an event into local outbox storage.
        Assigns a unique event_id if not present.
        """
        payload = dict(event_payload)
        event_id = payload.get("event_id") or f"evt-{uuid.uuid4().hex[:12]}"
        payload["event_id"] = event_id
        if "occurred_at" not in payload:
            payload["occurred_at"] = datetime.now(timezone.utc).isoformat()

        self.storage.save(event_id, payload)
        return event_id

    def flush(self) -> Dict[str, int]:
        """
        Pulls ready items from the outbox and attempts signed batch delivery to ECS.
        Thread-safe; executes atomically.
        """
        with self._flush_lock:
            now = time.time()
            batch = self.storage.get_pending_and_retryable(limit=self.batch_size, now=now)
            if not batch:
                return {"processed": 0, "delivered": 0, "failed": 0}

            events = [item.payload for item in batch]
            delivered_count = 0
            failed_count = 0

            try:
                # Deliver batch to ECS endpoint
                resp = self.client.send_batch(events)
                is_success = resp.get("status") in ("ok", "received") or resp.get("code") in (200, 201)

                if is_success:
                    for item in batch:
                        self.storage.mark_delivered(item.event_id)
                        delivered_count += 1
                else:
                    err_msg = resp.get("message") or resp.get("error") or "Non-200 response"
                    self._handle_batch_failure(batch, err_msg, now)
                    failed_count += len(batch)

            except Exception as exc:
                err_msg = str(exc)
                logger.warning(f"Outbox delivery exception: {err_msg}")
                self._handle_batch_failure(batch, err_msg, now)
                failed_count += len(batch)

            return {
                "processed": len(batch),
                "delivered": delivered_count,
                "failed": failed_count,
            }

    def _handle_batch_failure(self, batch: List[OutboxItem], error_msg: str, now: float) -> None:
        """Computes exponential backoff and updates storage state for each item."""
        for item in batch:
            new_attempts = item.attempts + 1
            if new_attempts >= self.max_attempts:
                logger.error(
                    f"Outbox event {item.event_id} reached max attempts ({self.max_attempts}). Escalating to DEAD_LETTER."
                )
                self.storage.mark_dead_letter(item.event_id, new_attempts, error_msg)
            else:
                backoff_sec = min(
                    self.max_backoff,
                    self.initial_backoff * (2 ** (new_attempts - 1))
                )
                next_retry = now + backoff_sec
                self.storage.mark_failed(item.event_id, new_attempts, error_msg, next_retry)

    def start_worker(self, interval_seconds: float = 5.0) -> None:
        """Starts a background daemon thread that periodically flushes the outbox."""
        if self.is_worker_running():
            return

        self._stop_event.clear()

        def _worker_loop():
            while not self._stop_event.is_set():
                try:
                    self.flush()
                except Exception as e:
                    logger.debug(f"Outbox worker flush error: {e}")
                self._stop_event.wait(interval_seconds)

        self._worker_thread = threading.Thread(
            target=_worker_loop,
            name="ecs-outbox-worker",
            daemon=True
        )
        self._worker_thread.start()
        logger.info("ECS Transactional Outbox worker started.")

    def stop_worker(self, timeout: float = 2.0) -> None:
        """Gracefully halts the background daemon worker."""
        if not self.is_worker_running():
            return

        self._stop_event.set()
        if self._worker_thread:
            self._worker_thread.join(timeout=timeout)
            self._worker_thread = None
        logger.info("ECS Transactional Outbox worker stopped.")

    def is_worker_running(self) -> bool:
        return self._worker_thread is not None and self._worker_thread.is_alive()

    def get_stats(self) -> Dict[str, int]:
        return self.storage.get_stats()

    def __enter__(self):
        self.start_worker()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop_worker()
