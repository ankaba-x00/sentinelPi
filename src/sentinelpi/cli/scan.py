import click
from pathlib import Path

from sentinelpi.cli.context import CLIContext
from sentinelpi.core.event_factory import EventFactory
from sentinelpi.core.scan_events import ScanEventFactory

from sentinelpi.modules.proc.scanner import scan_processes
from sentinelpi.modules.proc.baseline import load_baseline as load_proc_baseline
from sentinelpi.modules.proc.diff import diff_processes, count_findings as count_proc

from sentinelpi.modules.fs.scanner import scan_paths
from sentinelpi.modules.fs.baseline import load_baseline as load_fs_baseline
from sentinelpi.modules.fs.diff import diff_files, count_findings as count_fs


PROC_BASELINE = Path.home() / ".sentinelpi" / "proc_baseline.json"
FS_BASELINE = Path.home() / ".sentinelpi" / "fs_baseline.json"


@click.command()
@click.pass_obj
def scan(ctx: CLIContext) -> None:
    scan_events = ScanEventFactory(
        EventFactory(ctx.dispatcher, namespace="scan")
    )

    scan_events.start()

    total_findings = 0

    # ---- process check ----
    proc_baseline = load_proc_baseline(PROC_BASELINE)
    if proc_baseline:
        current = scan_processes(ctx.platform)
        diff = diff_processes(proc_baseline, current)
        total_findings += count_proc(diff)

    # ---- filesystem check ----
    fs_baseline = load_fs_baseline(FS_BASELINE)
    if fs_baseline:
        current = scan_paths([Path.home() / ".ssh"])
        diff = diff_files(fs_baseline, current)
        total_findings += count_fs(diff)

    # ---- summary ----
    if total_findings == 0:
        scan_events.summary_ok()
    else:
        scan_events.summary_warn(total_findings)