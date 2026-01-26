from __future__ import annotations

from sentinelpi.core.event_factory import EventFactory


class FsEventFactory:
    """
    Filesystem integrity specific events.
    """

    def __init__(self, factory: EventFactory) -> None:
        self._f = factory

    # ---- lifecycle ----

    def baseline_saved(self, count: int) -> None:
        self._f.emit(
            kind="baseline_saved",
            message=f"Filesystem baseline saved ({count} files)",
            severity="done",
            data={"count": count},
        )

    def no_baseline(self) -> None:
        self._f.emit(
            kind="no_baseline",
            message="No filesystem baseline found. Run 'sentinelpi fs baseline' first.",
            severity="error",
        )

    def clean(self) -> None:
        self._f.emit(
            kind="clean",
            message="No filesystem integrity violations detected",
            severity="ok",
        )

    # ---- findings ----

    def modified_files(self, count: int) -> None:
        self._f.emit(
            kind="modified",
            message=f"Modified files detected: {count}",
            severity="warn",
            data={"count": count},
        )

    def modified_file(self, path: str) -> None:
        self._f.emit(
            kind="modified.file",
            message=f"Modified: {path}",
            severity="info",
            data={"path": path},
        )

    def new_files(self, count: int) -> None:
        self._f.emit(
            kind="new",
            message=f"New files detected: {count}",
            severity="warn",
            data={"count": count},
        )

    def new_file(self, path: str) -> None:
        self._f.emit(
            kind="new.file",
            message=f"New: {path}",
            severity="info",
            data={"path": path},
        )

    def deleted_files(self, count: int) -> None:
        self._f.emit(
            kind="deleted",
            message=f"Deleted files detected: {count}",
            severity="warn",
            data={"count": count},
        )

    def deleted_file(self, path: str) -> None:
        self._f.emit(
            kind="deleted.file",
            message=f"Deleted: {path}",
            severity="info",
            data={"path": path},
        )
