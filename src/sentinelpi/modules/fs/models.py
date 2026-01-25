from dataclasses import dataclass


@dataclass(frozen=True)
class FileRecord:
    path: str
    sha256: str
    size: int
    mtime: float

    @property
    def identity(self) -> str:
        """
        Stable identity for diffing.
        """
        return self.path
