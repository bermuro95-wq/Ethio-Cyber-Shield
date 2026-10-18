"""
Ethio-Cyber-Shield (ECS) — Lightweight Log Agent Collector Engine.
Provides continuous log file tailing, byte-offset state checkpointing, and
bounded CPU and RAM processing constraints to avoid resource exhaustion.
"""
import os
import json
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone

from connectors.log_agent.parser import parse_log_line

logger = logging.getLogger(__name__)


class CollectorCheckpoint:
    """Manages file read position across restarts using atomic file replacement."""
    def __init__(self, offset: int = 0, inode: int = 0, last_updated: Optional[str] = None):
        self.offset = offset
        self.inode = inode
        self.last_updated = last_updated or datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> Dict[str, Any]:
        return {
            'offset': self.offset,
            'inode': self.inode,
            'last_updated': self.last_updated
        }

    def save(self, path: str):
        if not path:
            return
        tmp_path = f"{path}.tmp"
        try:
            self.last_updated = datetime.now(timezone.utc).isoformat()
            with open(tmp_path, 'w', encoding='utf-8') as f:
                json.dump(self.to_dict(), f, indent=2)
            os.replace(tmp_path, path)
        except Exception as e:
            logger.error(f"Failed to save collector checkpoint {path}: {e}")

    @classmethod
    def load(cls, path: str) -> "CollectorCheckpoint":
        if not path or not os.path.exists(path):
            return cls(offset=0, inode=0)
        try:
            with open(path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            return cls(
                offset=data.get('offset', 0),
                inode=data.get('inode', 0),
                last_updated=data.get('last_updated')
            )
        except Exception as e:
            logger.warning(f"Could not load checkpoint {path}, resetting offset: {e}")
            return cls(offset=0, inode=0)


class LogAgentCollector:
    """
    Lightweight, memory-bounded log collector.
    Tails log files, checkpoints read byte offsets, and converts entries into canonical events.
    """

    def __init__(
        self,
        log_file: str,
        organization_id: str,
        log_format: str = "auto",
        source_system: Optional[str] = None,
        state_file: Optional[str] = None,
        batch_size: int = 100,
        max_queue_size: int = 5000,
        poll_interval_seconds: float = 1.0
    ):
        self.log_file = log_file
        self.organization_id = organization_id
        self.log_format = log_format
        self.source_system = source_system or f"{log_format}-collector"
        self.state_file = state_file
        self.batch_size = max(1, batch_size)
        self.max_queue_size = max(10, max_queue_size)
        self.poll_interval_seconds = poll_interval_seconds

        # Metrics
        self._processed_lines = 0
        self._dropped_lines = 0
        self._error_lines = 0

        # State initialization
        self.checkpoint = CollectorCheckpoint.load(self.state_file) if self.state_file else CollectorCheckpoint()

    def get_metrics(self) -> Dict[str, Any]:
        """Returns runtime performance and resource health metrics."""
        return {
            'log_file': self.log_file,
            'log_format': self.log_format,
            'offset': self.checkpoint.offset,
            'processed_lines': self._processed_lines,
            'dropped_lines': self._dropped_lines,
            'error_lines': self._error_lines,
            'max_queue_size': self.max_queue_size,
            'batch_size': self.batch_size
        }

    def poll_once(self) -> List[Dict[str, Any]]:
        """
        Polls the log file for new entries starting from the saved checkpoint offset.
        Enforces batch size limits and queue bounds to guarantee predictable memory usage.
        """
        if not os.path.exists(self.log_file):
            return []

        try:
            stat_info = os.stat(self.log_file)
            file_size = stat_info.st_size
            curr_inode = stat_info.st_ino

            # Detect log rotation or truncation
            if file_size < self.checkpoint.offset or (self.checkpoint.inode != 0 and self.checkpoint.inode != curr_inode):
                logger.info(f"Log rotation detected on {self.log_file}. Resetting offset from {self.checkpoint.offset} to 0")
                self.checkpoint.offset = 0
            self.checkpoint.inode = curr_inode

            # Nothing new to read
            if file_size == self.checkpoint.offset:
                return []

            events: List[Dict[str, Any]] = []

            with open(self.log_file, 'r', encoding='utf-8', errors='replace') as f:
                f.seek(self.checkpoint.offset)

                while len(events) < self.batch_size:
                    line = f.readline()
                    if not line:
                        break  # EOF reached

                    # Guard against memory exhaustion: enforce max_queue_size
                    if len(events) >= self.max_queue_size:
                        self._dropped_lines += 1
                        logger.warning(f"Collector queue capacity ({self.max_queue_size}) exceeded; dropping line to bound RAM.")
                        continue

                    clean_line = line.strip()
                    if not clean_line:
                        self.checkpoint.offset = f.tell()
                        continue

                    try:
                        parsed = parse_log_line(
                            line=clean_line,
                            format_type=self.log_format,
                            organization_id=self.organization_id,
                            source_system=self.source_system
                        )
                        if parsed:
                            events.append(parsed)
                        self._processed_lines += 1
                    except Exception as e:
                        self._error_lines += 1
                        logger.debug(f"Log line parse error: {e}")

                    self.checkpoint.offset = f.tell()

            # Persist checkpoint after processing batch
            if self.state_file:
                self.checkpoint.save(self.state_file)

            return events

        except Exception as e:
            logger.error(f"Error reading log file {self.log_file}: {e}")
            return []
