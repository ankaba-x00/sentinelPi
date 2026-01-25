from __future__ import annotations

from sentinelpi.core.events import Event, Alert


class Policy:
    """
    v1: simple mapping.
    v2+: configurable rules per event type, thresholds, correlation, etc.
    """

    def decide(self, event: Event) -> Alert:
        if event.severity:
            severity = event.severity
        else:
            if event.type.startswith("error."):
                severity = "error"
            elif event.type.startswith("warn."):
                severity = "warn"
            else:
                severity = "info"

        return Alert(severity=severity, message=event.message, event=event, data=event.data)
