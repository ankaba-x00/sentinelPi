from __future__ import annotations

from sentinelpi.core.events import Event
from sentinelpi.alerting.dispatcher import Dispatcher


class EventFactory:
    """
    Helper to reduce Event boilerplate.
    """

    def __init__(self, dispatcher: Dispatcher, namespace: str) -> None:
        self.dispatcher = dispatcher
        self.namespace = namespace

    def emit(
        self,
        *,
        kind: str,
        message: str,
        severity: str,
        data: dict | None = None,
    ) -> None:
        event = Event(
            type=f"{severity}.{self.namespace}.{kind}",
            message=message,
            severity=severity,
            data=data or {},
        )
        self.dispatcher.handle(event)
