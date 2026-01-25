from __future__ import annotations

from typing import Iterable, List

from sentinelpi.core.events import Event
from sentinelpi.core.logging import JSONLLogger
from sentinelpi.alerting.policy import Policy
from sentinelpi.alerting.sinks import AlertSink


class Dispatcher:
    def __init__(
        self,
        logger: JSONLLogger,
        policy: Policy,
        sinks: Iterable[AlertSink],
        verbose: bool = False,
    ) -> None:
        self.logger = logger
        self.policy = policy
        self.sinks: List[AlertSink] = list(sinks)
        self.verbose = verbose

    def handle(self, event: Event) -> None:
        # always log raw event
        self.logger.log(event)

        # conversion to alert and dispatch
        alert = self.policy.decide(event)
        for sink in self.sinks:
            sink.send(alert)