from dataclasses import dataclass
from sentinelpi.platform.base import Platform

@dataclass
class CLIContext:
    platform: Platform
    verbose: bool = False