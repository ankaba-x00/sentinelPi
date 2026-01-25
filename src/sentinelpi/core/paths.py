from __future__ import annotations

from pathlib import Path


def default_data_dir() -> Path:
    return Path.home() / ".sentinelpi"


def events_log_path(data_dir: Path) -> Path:
    return data_dir / "events.jsonl"


def alerts_log_path(data_dir: Path) -> Path:
    return data_dir / "alerts.jsonl"