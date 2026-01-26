from __future__ import annotations

from sentinelpi.core.event_factory import EventFactory


class ProcEventFactory:
    """
    Process-monitoring specific events.
    """

    def __init__(self, factory: EventFactory) -> None:
        self._f = factory

    # ---- lifecycle ----

    def list_summary(self, count: int) -> None:
        self._f.emit(
            kind="list",
            message=f"Detected {count} running processes",
            severity="info",
            data={"count": count},
        )

    def list_item(self, *, pid: int, user: str, exe: str) -> None:
        self._f.emit(
            kind="list_item",
            message=f"pid={pid} user={user} exe={exe}",
            severity="info",
            data={"pid": pid, "user": user, "exe": exe},
        )

    def baseline_saved(self, count: int) -> None:
        self._f.emit(
            kind="baseline_saved",
            message=f"Process baseline saved ({count} entries)",
            severity="done",
            data={"count": count},
        )

    def no_baseline(self) -> None:
        self._f.emit(
            kind="no_baseline",
            message="No process baseline found. Run 'sentinelpi proc baseline' first.",
            severity="error",
        )

    def clean(self) -> None:
        self._f.emit(
            kind="clean",
            message="No unexpected processes detected",
            severity="ok",
        )

    # ---- findings ----

    def new_processes(self, count: int) -> None:
        self._f.emit(
            kind="new_processes",
            message=f"New processes detected: {count}",
            severity="warn",
            data={"count": count},
        )

    def new_process(self, *, pid: int, user: str, exe: str) -> None:
        self._f.emit(
            kind="new_process",
            message=f"NEW pid={pid} user={user} exe={exe}",
            severity="info",
            data={"pid": pid, "user": user, "exe": exe},
        )

    def root_processes(self, count: int) -> None:
        self._f.emit(
            kind="root_processes",
            message=f"Root-owned processes detected: {count}",
            severity="warn",
            data={"count": count},
        )

    def root_process(self, *, pid: int, exe: str) -> None:
        self._f.emit(
            kind="root_process",
            message=f"ROOT pid={pid} exe={exe}",
            severity="info",
            data={"pid": pid, "exe": exe},
        )

    def root_processes_truncated(self, omitted: int) -> None:
        self._f.emit(
            kind="root_processes_truncated",
            message=f"{omitted} additional root processes not shown",
            severity="info",
            data={"omitted": omitted},
        )
