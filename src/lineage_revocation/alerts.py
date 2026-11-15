from __future__ import annotations

import logging
import threading
from collections import Counter

_logger = logging.getLogger("lineage_revocation.alerts")
_counters: Counter[str] = Counter()
_lock = threading.Lock()


def emit_alert(kind: str, **fields) -> None:
    """Structured alert: one log record (attributes `alert_kind`, `alert_fields`) and a monotonic counter."""
    with _lock:
        _counters[kind] += 1
    _logger.warning("alert %s %r", kind, fields, extra={"alert_kind": kind, "alert_fields": dict(fields)})


def alert_count(kind: str) -> int:
    """Monotonic: only ever incremented, never reset."""
    with _lock:
        return _counters[kind]
