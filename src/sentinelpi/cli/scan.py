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

from sentinelpi.analyzers.runner import AnalyzerRunner

from sentinelpi.analyzers.proc_root_new import RootNewProcessAnalyzer
from sentinelpi.analyzers.proc_suspicious_path import SuspiciousExecutablePathAnalyzer
from sentinelpi.analyzers.proc_root_shell_parent import RootShellUnexpectedParentAnalyzer

from sentinelpi.analyzers.fs_new_executable import NewExecutableFileAnalyzer
from sentinelpi.analyzers.fs_critical_and_autostart import FsCriticalAndAutostartAnalyzer

from sentinelpi.core.correlation_events import CorrelationEventFactory


PROC_BASELINE = Path.home() / ".sentinelpi" / "proc_baseline.json"
FS_BASELINE = Path.home() / ".sentinelpi" / "fs_baseline.json"


def fs_new_executable_paths(events: list) -> set[str]:
    paths = set()
    for e in events:
        if e.type == "warn.fs.anomaly.new_executable":
            path = e.data.get("path")
            if path:
                paths.add(path)
    return paths


def proc_executed_paths(events: list) -> set[str]:
    paths = set()
    for e in events:
        exe = e.data.get("exe")
        if exe:
            paths.add(exe)
    return paths


@click.command()
@click.pass_obj
def scan(ctx: CLIContext) -> None:
    scan_events = ScanEventFactory(
        EventFactory(ctx.dispatcher, namespace="scan")
    )

    scan_events.start()

    total_findings = 0

    # ---- process check ----
    proc_events = []

    proc_baseline = load_proc_baseline(PROC_BASELINE)
    if proc_baseline:
        proc_current = scan_processes(ctx.platform)
        proc_diff = diff_processes(proc_baseline, proc_current)
        total_findings += count_proc(proc_diff)

        proc_runner = AnalyzerRunner([
            RootNewProcessAnalyzer(),
            SuspiciousExecutablePathAnalyzer(),
            RootShellUnexpectedParentAnalyzer(),
        ])

        proc_context = {
            "proc.baseline": proc_baseline,
            "proc.current": proc_current,
            "proc.diff": proc_diff,
            "platform": ctx.platform.name,
        }

        for event in proc_runner.run(context=proc_context):
            proc_events.append(event)
            ctx.dispatcher.handle(event)

    # ---- filesystem check ----
    fs_events = []

    fs_baseline = load_fs_baseline(FS_BASELINE)
    if fs_baseline:
        fs_current = scan_paths([Path.home() / ".ssh"])
        fs_diff = diff_files(fs_baseline, fs_current)
        total_findings += count_fs(fs_diff)

        fs_runner = AnalyzerRunner([
            NewExecutableFileAnalyzer(),
            FsCriticalAndAutostartAnalyzer(),
        ])

        fs_context = {
            "fs.baseline": fs_baseline,
            "fs.current": fs_current,
            "fs.diff": fs_diff,
            "platform": ctx.platform.name,
        }

        for event in fs_runner.run(context=fs_context):
            fs_events.append(event)
            ctx.dispatcher.handle(event)
    
    # ---- corelation: fs and proc ----
    corr_factory = CorrelationEventFactory(
        EventFactory(ctx.dispatcher, namespace="correlation")
    )

    fs_paths = fs_new_executable_paths(fs_events)
    proc_paths = proc_executed_paths(proc_events)

    for path in fs_paths & proc_paths:
        corr_factory.fs_proc_execution(path=path)

    # ---- summary ----
    if total_findings == 0:
        scan_events.summary_ok()
    else:
        scan_events.summary_warn(total_findings)