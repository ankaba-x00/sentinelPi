"""
Common context keys:

Process analyzers:
- proc.baseline
- proc.current
- proc.diff

Filesystem analyzers:
- fs.baseline
- fs.current
- fs.diff

Future:
- scan.time
- scan.hostname
- config
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Iterable

from sentinelpi.core.events import Event


class Analyzer(ABC):
    """
    Analyzer inspects collected facts and emits Events describing
    suspicious or noteworthy conditions.
    """

    @abstractmethod
    def analyze(self, *, context: dict) -> Iterable[Event]:
        """
        Analyze a scan context and return zero or more Events.

        The context dict is intentionally generic to allow reuse across proc, fs, net, usb analyzers.

        Expected keys depend on analyzer type.
        """
        raise NotImplementedError