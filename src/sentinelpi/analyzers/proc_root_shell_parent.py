from __future__ import annotations

from typing import Iterable

from sentinelpi.analyzers.base import Analyzer
from sentinelpi.core.events import Event
from sentinelpi.modules.proc.models import ProcessRecord


SHELL_NAMES = {
    "sh",
    "bash",
    "zsh",
    "dash",
}

SAFE_PARENT_NAMES = {
    "init",
    "systemd",
    "launchd",
    "sh",
    "bash",
    "zsh",
    "sudo",
    "su",
}


class RootShellUnexpectedParentAnalyzer(Analyzer):
    """
    Detects root shells spawned by unexpected parent processes.
    """

    def analyze(self, *, context: dict) -> Iterable[Event]:
        current: list[ProcessRecord] = context.get("proc.current", [])
        diff: dict = context.get("proc.diff", {})

        proc_by_pid = {p.pid: p for p in current}

        new_processes: list[ProcessRecord] = diff.get("new", [])

        for proc in new_processes:
            if proc.user != "root":
                continue

            exe = proc.exe or ""
            exe_name = exe.split("/")[-1]

            if exe_name not in SHELL_NAMES:
                continue

            parent = proc_by_pid.get(proc.ppid)
            parent_name = None

            if parent and parent.exe:
                parent_name = parent.exe.split("/")[-1]

            # Skip if parent is unknown
            if not parent_name:
                continue

            if parent_name in SAFE_PARENT_NAMES:
                continue

            yield Event(
                type="warn.proc.anomaly.root_shell_parent",
                message=(
                    "Root shell spawned by unexpected parent "
                    f"(parent={parent_name}, exe={exe})"
                ),
                severity="warn",
                data={
                    "pid": proc.pid,
                    "ppid": proc.ppid,
                    "exe": exe,
                    "parent_exe": parent.exe if parent else None,
                    "cmdline": list(proc.cmdline),
                },
            )
