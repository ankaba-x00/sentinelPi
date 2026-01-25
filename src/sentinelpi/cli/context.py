from dataclasses import dataclass

from sentinelpi.platform.base import Platform
from sentinelpi.alerting.dispatcher import Dispatcher


@dataclass
class CLIContext:
    platform: Platform
    dispatcher: Dispatcher
    verbose: bool = False