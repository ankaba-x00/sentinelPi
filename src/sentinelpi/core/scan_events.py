from __future__ import annotations

from sentinelpi.core.event_factory import EventFactory


class ScanEventFactory:
    def __init__(self, factory: EventFactory) -> None:
        self._f = factory

    def start(self) -> None:
        self._f.emit(
            kind="start",
            message="Starting SentinelPi scan",
            severity="info",
        )

    def summary_ok(self) -> None:
        self._f.emit(
            kind="summary",
            message="Scan completed: no issues detected",
            severity="ok",
        )

    def summary_warn(self, findings: int) -> None:
        self._f.emit(
            kind="summary",
            message=f"Scan completed: {findings} findings detected",
            severity="warn",
            data={"findings": findings},
        )

    def summary_error(self, reason: str) -> None:
        self._f.emit(
            kind="summary",
            message=f"Scan failed: {reason}",
            severity="error",
        )
