from dataclasses import dataclass

from sentinelpi.platform.base import Platform
from sentinelpi.alerting.dispatcher import Dispatcher
from sentinelpi.core.event_factory import EventFactory


@dataclass
class CLIContext:
    platform: Platform
    dispatcher: Dispatcher
    events: EventFactory
    verbose: bool = False