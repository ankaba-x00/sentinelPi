from __future__ import annotations

import platform as _platform

from .base import Platform

def detect_platform() -> Platform:
    system = _platform.system().lower()

    if system == "linux":
        from .linux import LinuxPlatform
        return LinuxPlatform()

    if system == "darwin":
        from .darwin import DarwinPlatform
        return DarwinPlatform()

    raise RuntimeError(f"Unsupported operating system: {system}")