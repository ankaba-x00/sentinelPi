from pathlib import Path
from typing import Iterable

from sentinelpi.modules.fs.models import FileRecord
from sentinelpi.modules.fs.hasher import hash_file


def scan_paths(
    roots: Iterable[Path],
    exclude_dirs: Iterable[str] = (),
    max_file_size: int = 10 * 1024 * 1024, # 10 MB
) -> list[FileRecord]:
    records: list[FileRecord] = []

    for root in roots:
        if not root.exists():
            continue

        for path in root.rglob("*"):
            try:
                if not path.is_file():
                    continue

                if any(part in exclude_dirs for part in path.parts):
                    continue

                stat = path.stat()

                if stat.st_size > max_file_size:
                    continue

                sha256 = hash_file(path)

                records.append(
                    FileRecord(
                        path=str(path),
                        sha256=sha256,
                        size=stat.st_size,
                        mtime=stat.st_mtime,
                    )
                )

            except (PermissionError, FileNotFoundError):
                # expected on system paths
                continue

    return records
