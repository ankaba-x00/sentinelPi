from __future__ import annotations

import subprocess
from typing import Sequence

from .base import (
    Platform,
    PlatformUnsupportedError,
    USBDevice,
    NetNeighbor,
    ProcessInfo,
)

class DarwinPlatform(Platform):
    name = "darwin"
    pretty_name = "macOS"
    supports_usb_monitoring = False
    supports_network_discovery = False
    supports_proc_introspection = True
    supports_fs_integrity = True

    def run_command(self, argv: Sequence[str], timeout_s: int = 5) -> str:
        try:
            cp = subprocess.run(
                list(argv),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=timeout_s,
                check=False,
            )
        except subprocess.TimeoutExpired as e:
            raise RuntimeError(f"[ERROR] Command timed out: {argv}") from e

        if cp.returncode != 0:
            raise RuntimeError(f"[ERROR] Command failed ({cp.returncode}): {argv}\n{cp.stderr.strip()}")

        return cp.stdout

    def list_usb_devices(self) -> list[USBDevice]:
        raise PlatformUnsupportedError("[ERROR] USB monitoring is not supported on macOS in v1.")

    def list_network_neighbors(self) -> list[NetNeighbor]:
        raise PlatformUnsupportedError("[ERROR] Network discovery is not supported on macOS in v1.")

    def list_processes(self) -> list[ProcessInfo]:
        # macOS `ps`: `ps -Ao pid,ppid,user,comm,args`
        out = self.run_command(["ps", "-Ao", "pid,ppid,user,comm,args"])
        procs: list[ProcessInfo] = []
        lines = out.splitlines()
        for line in lines[1:]:
            line = line.strip()
            if not line:
                continue
            parts = line.split(maxsplit=4)
            if len(parts) < 4:
                continue
            pid = int(parts[0])
            ppid = int(parts[1])
            user = parts[2]
            comm = parts[3]
            args = parts[4] if len(parts) >= 5 else comm
            cmdline = args.split()
            exe = comm
            procs.append(ProcessInfo(pid=pid, ppid=ppid, user=user, exe=exe, cmdline=cmdline))
        return procs