from __future__ import annotations

from pathlib import Path
from typing import Iterable

from sentinelpi.analyzers.base import Analyzer
from sentinelpi.core.events import Event

# TODO: add explicit type checking later via context class
# from sentinelpi.modules.fs.models import FileRecord
# class FsContext(TypedDict):
#     baseline: list[FileRecord]
#     current: list[FileRecord]
#     diff: dict[str, list[FileRecord]]

def critical_paths_for(platform: str) -> tuple[str, ...]:
    if platform == "darwin":
        return (
            "/etc/",
        )
    return (
        "/etc/",
        "/usr/bin/",
        "/usr/sbin/",
        "/bin/",
        "/sbin/",
    )

def autostart_paths_for(platform: str) -> tuple[str, ...]:
    if platform == "darwin":
        home = str(Path.home())
        return (
            f"{home}/Library/LaunchAgents",
            "/Library/LaunchAgents/",
            "/Library/LaunchDaemons/",
            "/System/Library/LaunchAgents/",
            "/System/Library/LaunchDaemons/",
        )
    return (
        "/etc/cron",
        "/etc/init.d/",
        "/etc/systemd/",
        "/lib/systemd/",
    )


class FsCriticalAndAutostartAnalyzer(Analyzer):
    """
    Detects modification of critical system files and autostart locations.
    """

    def analyze(self, *, context: dict) -> Iterable[Event]:
        diff: dict = context.get("fs.diff", {})
        platform: str = context.get("platform", "unknown")

        critical_prefixes = critical_paths_for(platform)
        autostart_prefixes = autostart_paths_for(platform)

        for f in diff.get("modified", []):
            path = f.path

            if path.startswith(critical_prefixes):
                yield Event(
                    type="warn.fs.anomaly.critical_modified",
                    message=f"Critical system file modified: {path}",
                    severity="warn",
                    data={
                        "path": path,
                        "size": f.size,
                        "mtime": f.mtime,
                    },
                )

            if path.startswith(autostart_prefixes):
                yield Event(
                    type="warn.fs.anomaly.autostart_modified",
                    message=f"Autostart file modified: {path}",
                    severity="warn",
                    data={
                        "path": path,
                        "size": f.size,
                        "mtime": f.mtime,
                    },
                )

        for f in diff.get("new", []):
            path = f.path

            if path.startswith(autostart_prefixes):
                yield Event(
                    type="warn.fs.anomaly.autostart_created",
                    message=f"New autostart file created: {path}",
                    severity="warn",
                    data={
                        "path": path,
                        "size": f.size,
                        "mtime": f.mtime,
                    },
                )