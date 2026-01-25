import json
from pathlib import Path
from sentinelpi.modules.proc.models import ProcessRecord


def save_baseline(path: Path, processes: list[ProcessRecord]) -> None:
    data = [record.__dict__ for record in processes]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2))


def load_baseline(path: Path) -> list[ProcessRecord]:
    if not path.exists():
        return []

    raw = json.loads(path.read_text())
    return [
        ProcessRecord(
            pid=rec["pid"],
            ppid=rec["ppid"],
            user=rec["user"],
            exe=rec["exe"],
            cmdline=tuple(rec["cmdline"]),
        )
        for rec in raw
    ]