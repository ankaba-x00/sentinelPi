import click
from pathlib import Path

from sentinelpi.cli.context import CLIContext
from sentinelpi.modules.proc.scanner import scan_processes
from sentinelpi.modules.proc.baseline import save_baseline, load_baseline
from sentinelpi.modules.proc.events import ProcEventFactory
from sentinelpi.modules.proc.diff import diff_processes
from sentinelpi.core.event_factory import EventFactory
from sentinelpi.analyzers.runner import AnalyzerRunner
from sentinelpi.analyzers.proc_root_new import RootNewProcessAnalyzer
from sentinelpi.analyzers.proc_suspicious_path import SuspiciousExecutablePathAnalyzer


BASELINE_PATH = Path.home() / ".sentinelpi" / "proc_baseline.json"

def _shorten_path(path: str, max_len: int = 60) -> str:
    if len(path) <= max_len:
        return path
    return "..." + path[-(max_len - 3):]


@click.group()
@click.pass_obj
def proc(ctx: CLIContext) -> None:
    """Process monitoring commands."""
    pass


@proc.command()
@click.pass_obj
def list(ctx: CLIContext) -> None:
    proc_events = ProcEventFactory(
        EventFactory(ctx.dispatcher, namespace="proc")
    )

    processes = scan_processes(ctx.platform)
    proc_events.list_summary(len(processes))

    for p in processes[:10]:
        proc_events.list_item(
            pid=p.pid,
            user=p.user,
            exe=_shorten_path(p.exe),
        )


@proc.command()
@click.pass_obj
def baseline(ctx: CLIContext) -> None:
    proc_events = ProcEventFactory(
        EventFactory(ctx.dispatcher, namespace="proc")
    )

    processes = scan_processes(ctx.platform)
    save_baseline(BASELINE_PATH, processes)
    proc_events.baseline_saved(len(processes))


@proc.command()
@click.pass_obj
def check(ctx: CLIContext) -> None:
    proc_events = ProcEventFactory(
        EventFactory(ctx.dispatcher, namespace="proc")
    )

    baseline = load_baseline(BASELINE_PATH)
    current = scan_processes(ctx.platform)

    if not baseline:
        proc_events.no_baseline()
        return

    result = diff_processes(baseline, current)

    runner = AnalyzerRunner([
        RootNewProcessAnalyzer(),
        SuspiciousExecutablePathAnalyzer(),
    ])

    context = {
        "proc.baseline": baseline,
        "proc.current": current,
        "proc.diff": result,
        "platform": ctx.platform.name,
    }

    for event in runner.run(context=context):
        ctx.dispatcher.handle(event)

    if not result["new"] and not result["root"]:
        proc_events.clean()
        return

    if result["new"]:
        proc_events.new_processes(len(result["new"]))
        for p in result["new"]:
            proc_events.new_process(
                pid=p.pid,
                user=p.user,
                exe=_shorten_path(p.exe),
            )

    if result["root"]:
        proc_events.root_processes(len(result["root"]))

        for p in result["root"][:10]:
            proc_events.root_process(
                pid=p.pid,
                exe=_shorten_path(p.exe),
            )

        if len(result["root"]) > 10:
            proc_events.root_processes_truncated(
                len(result["root"]) - 10
            )

