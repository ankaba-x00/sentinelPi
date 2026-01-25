from __future__ import annotations

import json
from pathlib import Path
from typing import Protocol

from sentinelpi.core.events import Alert
from sentinelpi.core.output import emit


class AlertSink(Protocol):
    def send(self, alert: Alert) -> None:
        ...


class ConsoleSink:
    def send(self, alert: Alert) -> None:
        emit(alert.severity, alert.message)


class JSONLFileSink:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def send(self, alert: Alert) -> None:
        line = json.dumps({
            "timestamp": alert.timestamp,
            "severity": alert.severity,
            "message": alert.message,
            "data": alert.data,
            "event": {
                "type": alert.event.type,
                "message": alert.event.message,
                "timestamp": alert.event.timestamp,
                "severity": alert.event.severity,
                "source": alert.event.source,
            } if alert.event else None,
        }, ensure_ascii=False)

        with self.path.open("a", encoding="utf-8") as f:
            f.write(line + "\n")
