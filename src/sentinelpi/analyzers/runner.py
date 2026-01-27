from __future__ import annotations

from typing import Iterable, Sequence

from sentinelpi.analyzers.base import Analyzer
from sentinelpi.core.events import Event


class AnalyzerRunner:
    """
    Runs a set of analyzers against a shared context.
    """

    def __init__(self, analyzers: Sequence[Analyzer]) -> None:
        self.analyzers = analyzers

    def run(self, *, context: dict) -> Iterable[Event]:
        for analyzer in self.analyzers:
            yield from analyzer.analyze(context=context)
