from __future__ import annotations

from typing import Iterable
import os
import stat

from sentinelpi.analyzers.base import Analyzer
from sentinelpi.core.events import Event
from sentinelpi.modules.fs.models import FileRecord


def is_executable(path: str) -> bool:
    try:
        st = os.stat(path)
        return bool(st.st_mode & stat.S_IXUSR)
    except (FileNotFoundError, PermissionError):
        return False


def suspicious_dirs_for(platform: str) -> tuple[str, ...]:
    if platform == "darwin":
        # On macOS, home executables are common for devs
        return (
            "/tmp/",
            "/var/tmp/",
        )
    # Linux / Pi
    return (
        "/tmp/",
        "/var/tmp/",
        "/home/",
    )


class NewExecutableFileAnalyzer(Analyzer):
    """
    Detects newly created executable files.
    """

    def analyze(self, *, context: dict) -> Iterable[Event]:
        diff: dict = context.get("fs.diff", {})
        platform: str = context.get("platform", "unknown")

        new_files: list[FileRecord] = diff.get("new", [])
        suspicious_dirs = suspicious_dirs_for(platform)

        for f in new_files:
            path = f.path

            if not path.startswith(suspicious_dirs):
                continue

            if not is_executable(path):
                continue

            yield Event(
                type="warn.fs.anomaly.new_executable",
                message=f"New executable file created: {path}",
                severity="warn",
                data={
                    "path": path,
                    "size": f.size,
                    "mtime": f.mtime,
                },
            )
