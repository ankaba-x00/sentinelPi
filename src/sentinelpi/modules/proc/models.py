from dataclasses import dataclass
from typing import Tuple


@dataclass(frozen=True)
class ProcessRecord:
    pid: int
    ppid: int
    user: str
    exe: str
    cmdline: Tuple[str, ...]

    @property
    def identity(self) -> str:
        """
        Stable identifier for baseline comparison.
        PID is intentionally excluded.
        """
        return f"{self.user}:{self.exe}:{' '.join(self.cmdline)}"