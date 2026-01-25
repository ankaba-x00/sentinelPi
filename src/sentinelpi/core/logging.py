from __future__ import annotations

import json
from pathlib import Path

from sentinelpi.core.events import Event


class JSONLLogger:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def log(self, event: Event) -> None:
        line = json.dumps({
            "timestamp": event.timestamp,
            "type": event.type,
            "message": event.message,
            "severity": event.severity,
            "source": event.source,
            "data": event.data,
        }, ensure_ascii=False)
        with self.path.open("a", encoding="utf-8") as f:
            f.write(line + "\n")
