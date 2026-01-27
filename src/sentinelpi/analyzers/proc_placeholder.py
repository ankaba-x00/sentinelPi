from __future__ import annotations

from typing import Iterable

from sentinelpi.analyzers.base import Analyzer
from sentinelpi.core.events import Event


class ProcPlaceholderAnalyzer(Analyzer):
    """
    Placeholder analyzer for process monitoring.
    Emits nothing.
    """

    def analyze(self, *, context: dict) -> Iterable[Event]:
        return []
