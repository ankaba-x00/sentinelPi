from sentinelpi.modules.proc.models import ProcessRecord
from sentinelpi.platform.base import Platform


def scan_processes(platform: Platform) -> list[ProcessRecord]:
    processes = []

    for proc in platform.list_processes():
        record = ProcessRecord(
            pid=proc.pid,
            ppid=proc.ppid or 0,
            user=proc.user,
            exe=proc.exe,
            cmdline=tuple(proc.cmdline),
        )
        processes.append(record)

    return processes