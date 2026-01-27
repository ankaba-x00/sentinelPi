from __future__ import annotations

from typing import Iterable

from sentinelpi.analyzers.base import Analyzer
from sentinelpi.core.events import Event
from sentinelpi.modules.proc.models import ProcessRecord


class RootNewProcessAnalyzer(Analyzer):
    """
    Detects root-owned processes that were not present in the baseline.
    """

    def analyze(self, *, context: dict) -> Iterable[Event]:
        baseline: list[ProcessRecord] = context.get("proc.baseline", [])
        diff: dict = context.get("proc.diff", {})

        new_processes: list[ProcessRecord] = diff.get("new", [])

        for proc in new_processes:
            if proc.user != "root":
                continue

            yield Event(
                type="warn.proc.anomaly.root_new",
                message=f"New root process detected: exe={proc.exe}",
                severity="warn",
                data={
                    "pid": proc.pid,
                    "exe": proc.exe,
                    "cmdline": list(proc.cmdline),
                },
            )