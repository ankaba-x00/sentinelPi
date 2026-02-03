from sentinelpi.core.event_factory import EventFactory


class CorrelationEventFactory:
    def __init__(self, factory: EventFactory) -> None:
        self._f = factory

    def fs_proc_execution(self, *, path: str) -> None:
        self._f.emit(
            kind="fs_proc_execution",
            message=(
                "Executable created and executed within same scan: "
                f"{path}"
            ),
            severity="error",
            data={"path": path},
        )