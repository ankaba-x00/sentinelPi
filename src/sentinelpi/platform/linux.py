from __future__ import annotations

import subprocess
from typing import Sequence

from .base import (
    Platform,
    USBDevice,
    NetNeighbor,
    ProcessInfo,
)

class LinuxPlatform(Platform):
    name = "linux"
    pretty_name = "Linux"
    supports_usb_monitoring = True
    supports_network_discovery = True
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
        # expect: "Bus 001 Device 004: ID 046d:c534 Logitech, Inc. Unifying Receiver"
        out = self.run_command(["lsusb"])
        devices: list[USBDevice] = []
        for line in out.splitlines():
            line = line.strip()
            if " ID " not in line:
                continue
            try:
                after_id = line.split(" ID ", 1)[1]
                id_part, desc = after_id.split(" ", 1)
                vendor_id, product_id = id_part.split(":")
                devices.append(USBDevice(vendor_id=vendor_id, product_id=product_id, description=desc.strip()))
            except Exception:
                # skip malformed lines
                continue
        return devices

    def list_network_neighbors(self) -> list[NetNeighbor]:
        # `ip neigh` example:
        # "192.168.1.1 dev wlan0 lladdr aa:bb:cc:dd:ee:ff REACHABLE"
        out = self.run_command(["ip", "neigh"])
        neighbors: list[NetNeighbor] = []
        for line in out.splitlines():
            parts = line.split()
            if len(parts) < 1:
                continue

            ip = parts[0]
            mac = ""
            iface = ""
            state = parts[-1] if parts else ""

            # parse "dev <iface>"
            if "dev" in parts:
                try:
                    iface = parts[parts.index("dev") + 1]
                except Exception:
                    iface = ""

            # parse "lladdr <mac>"
            if "lladdr" in parts:
                try:
                    mac = parts[parts.index("lladdr") + 1].lower()
                except Exception:
                    mac = ""

            if mac:
                neighbors.append(NetNeighbor(ip=ip, mac=mac, interface=iface, state=state))
        return neighbors

    def list_processes(self) -> list[ProcessInfo]:
        # `ps` for v1 portability; TODO: later switch to proc for richer data
        # `ps -eo pid,ppid,user,comm,args`
        out = self.run_command(["ps", "-eo", "pid,ppid,user,comm,args"])
        procs: list[ProcessInfo] = []
        lines = out.splitlines()
        for line in lines[1:]:  # skip header
            line = line.strip()
            if not line:
                continue
            # crude split: first 4 fields fixed, rest is args
            parts = line.split(maxsplit=4)
            if len(parts) < 4:
                continue
            pid = int(parts[0])
            ppid = int(parts[1])
            user = parts[2]
            comm = parts[3]
            args = parts[4] if len(parts) >= 5 else comm
            cmdline = args.split()
            exe = comm  # v1; TODO: later resolve full path via /proc/<pid>/exe
            procs.append(ProcessInfo(pid=pid, ppid=ppid, user=user, exe=exe, cmdline=cmdline))
        return procs