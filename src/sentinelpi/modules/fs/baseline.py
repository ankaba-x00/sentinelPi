import json
from pathlib import Path
from sentinelpi.modules.fs.models import FileRecord


def save_baseline(path: Path, records: list[FileRecord]) -> None:
    data = [record.__dict__ for record in records]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2))


def load_baseline(path: Path) -> list[FileRecord]:
    if not path.exists():
        return []

    raw = json.loads(path.read_text())
    return [
        FileRecord(
            path=rec["path"],
            sha256=rec["sha256"],
            size=rec["size"],
            mtime=rec["mtime"],
        )
        for rec in raw
    ]
