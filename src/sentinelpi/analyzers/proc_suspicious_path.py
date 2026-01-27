from __future__ import annotations

from typing import Iterable

from sentinelpi.analyzers.base import Analyzer
from sentinelpi.core.events import Event
from sentinelpi.modules.proc.models import ProcessRecord


# TODO: ADD 
# 1) baseline-known root services and user-launced processes
# 2) monitoring suppression rules later 
# 3) severity downgrades

def suspicious_prefixes_for(platform: str) -> tuple[str, ...]:
    if platform == "darwin":
        return (
            "/tmp/",
            "/var/tmp/",
            "/dev/shm/",
        )
    return (
        "/tmp/",
        "/var/tmp/",
        "/dev/shm/",
        "/home/",
    )

def safe_executables_for(platform: str) -> set[str]:
    if platform == "darwin":
        return {
            "python",
            "python3",
            "node",
            "npm",
            "ruby",
            "java",
        }
    return set()


class SuspiciousExecutablePathAnalyzer(Analyzer):
    """
    Detects processes executing from suspicious, writable locations.
    """

    def analyze(self, *, context: dict) -> Iterable[Event]:
        baseline: list[ProcessRecord] = context.get("proc.baseline", [])
        diff: dict = context.get("proc.diff", {})

        baseline_ids = {p.identity for p in baseline}
        new_processes: list[ProcessRecord] = diff.get("new", [])

        for proc in new_processes:
            # Skip if process identity was already known (defensive)
            if proc.identity in baseline_ids:
                continue
            
            platform = str(context.get("platform"))
            prefixes = suspicious_prefixes_for(platform)
            safe_execs = safe_executables_for(platform)

            # Skip if process labelled non-suspicious
            exe = proc.exe or ""
            if not exe.startswith(prefixes):
                continue

            # Skip if process labelled as safe executable needed for macOS
            exe_name = exe.split("/")[-1]
            if exe_name in safe_execs:
                continue

            yield Event(
                type="warn.proc.anomaly.suspicious_path",
                message=f"Process running from suspicious path: exe={exe}",
                severity="warn",
                data={
                    "pid": proc.pid,
                    "user": proc.user,
                    "exe": exe,
                    "cmdline": list(proc.cmdline),
                },
            )
