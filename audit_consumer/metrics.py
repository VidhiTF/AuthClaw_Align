"""Small in-process metrics registry for the audit consumer.

The consumer intentionally has no web framework dependency. Metrics are kept as
plain counters/gauges and can be rendered as Prometheus text from the optional
HTTP endpoint started by ``consumer.py``.
"""

from __future__ import annotations

import threading
from collections import defaultdict
from typing import DefaultDict


class MetricsRegistry:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._counters: DefaultDict[str, int] = defaultdict(int)
        self._gauges: dict[str, int] = {}

    def increment(self, name: str, value: int = 1) -> None:
        with self._lock:
            self._counters[name] += value

    def set_gauge(self, name: str, value: int) -> None:
        with self._lock:
            self._gauges[name] = value

    def snapshot(self) -> dict[str, int]:
        with self._lock:
            data = dict(self._counters)
            data.update(self._gauges)
            return data

    def render_prometheus(self) -> str:
        lines = []
        for name, value in sorted(self.snapshot().items()):
            safe_name = name.replace(".", "_").replace("-", "_")
            lines.append(f"# TYPE {safe_name} gauge")
            lines.append(f"{safe_name} {value}")
        return "\n".join(lines) + "\n"


metrics = MetricsRegistry()
