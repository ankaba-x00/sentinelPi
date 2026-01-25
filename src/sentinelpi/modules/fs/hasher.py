import hashlib
from pathlib import Path


def hash_file(path: Path, block_size: int = 65536) -> str:
    h = hashlib.sha256()

    with path.open("rb") as f:
        for block in iter(lambda: f.read(block_size), b""):
            h.update(block)

    return h.hexdigest()
