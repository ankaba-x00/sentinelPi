from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional, Sequence


class PlatformUnsupportedError(RuntimeError):
    """Raised when a platform cannot support a requested operation."""


@dataclass(frozen=True)
class USBDevice:
    vendor_id: str          # e.g. "046d"
    product_id: str         # e.g. "c534"
    description: str = ""   # human-friendly, if available


@dataclass(frozen=True)
class NetNeighbor:
    ip: str                 # e.g. "192.168.1.10"
    mac: str                # e.g. "aa:bb:cc:dd:ee:ff"
    interface: str = ""     # e.g. "wlan0"
    state: str = ""         # e.g. "REACHABLE", "STALE"


@dataclass(frozen=True)
class ProcessInfo:
    pid: int
    user: str               # best-effort (root / pi / etc.)
    exe: str                # absolute path if available, else process name
    cmdline: Sequence[str]  # argv tokens (best-effort)
    ppid: Optional[int] = None


class Platform(ABC):
    """
    OS abstraction layer.

    Modules must call these methods rather than shelling out directly.
    Implementations can degrade gracefully on non-Linux platforms.
    """

    name: str               # "linux" or "darwin"
    pretty_name: str        # "Linux" or "macOS"

    # ---- Capability flags ----
    supports_usb_monitoring: bool = False
    supports_network_discovery: bool = False
    supports_proc_introspection: bool = True
    supports_fs_integrity: bool = True

    @abstractmethod
    def list_usb_devices(self) -> list[USBDevice]:
        """Return connected USB devices. Raise PlatformUnsupportedError if not supported."""
        raise NotImplementedError

    @abstractmethod
    def list_network_neighbors(self) -> list[NetNeighbor]:
        """Return LAN neighbors (ARP/ND). Raise PlatformUnsupportedError if not supported."""
        raise NotImplementedError

    @abstractmethod
    def list_processes(self) -> list[ProcessInfo]:
        """Return current process inventory."""
        raise NotImplementedError

    @abstractmethod
    def run_command(self, argv: Sequence[str], timeout_s: int = 5) -> str:
        """
        Execute a command and return stdout text.
        Centralized here so you can standardize logging, timeouts, and error handling.
        """
        raise NotImplementedError

    def require(self, feature: str) -> None:
        """
        Small helper used by modules/CLI to produce consistent errors.
        feature examples: "usb", "net"
        """
        if feature == "usb" and not self.supports_usb_monitoring:
            raise PlatformUnsupportedError(f"[ERROR] USB monitoring is not supported on {self.pretty_name}.")
        if feature == "net" and not self.supports_network_discovery:
            raise PlatformUnsupportedError(f"[ERROR] Network discovery is not supported on {self.pretty_name}.")