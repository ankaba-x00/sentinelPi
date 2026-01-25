import click
from pathlib import Path

from sentinelpi.cli.context import CLIContext
from sentinelpi.modules.proc.scanner import scan_processes
from sentinelpi.modules.proc.baseline import save_baseline, load_baseline
from sentinelpi.modules.proc.diff import diff_processes
from sentinelpi.core.events import Event


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
    processes = scan_processes(ctx.platform)
    ctx.dispatcher.handle(Event(
        type="info.proc.list",
        message=f"Detected {len(processes)} running processes",
        data={"count": len(processes)},
        severity="info",
    ))

    for p in processes[:10]:
        exe = _shorten_path(p.exe)
        ctx.dispatcher.handle(Event(
            type="info.proc.list.item",
            message=f"pid={p.pid} user={p.user} exe={exe}",
            data={"pid": p.pid, "user": p.user, "exe": p.exe},
            severity="info",
        ))


@proc.command()
@click.pass_obj
def baseline(ctx: CLIContext) -> None:
    processes = scan_processes(ctx.platform)
    save_baseline(BASELINE_PATH, processes)
    ctx.dispatcher.handle(Event(
        type="done.proc.baseline_saved",
        message=f"Process baseline saved ({len(processes)} entries)",
        data={"count": len(processes)},
        severity="done",
    ))


@proc.command()
@click.pass_obj
def check(ctx: CLIContext) -> None:
    baseline = load_baseline(BASELINE_PATH)
    current = scan_processes(ctx.platform)

    if not baseline:
        ctx.dispatcher.handle(Event(
            type="error.proc.no_baseline",
            message="No process baseline found. Run 'sentinelpi proc baseline' first.",
            severity="error",
        ))
        return

    result = diff_processes(baseline, current)

    if not result["new"] and not result["root"]:
        ctx.dispatcher.handle(Event(
            type="ok.proc.no_unexpected",
            message="No unexpected processes detected",
            severity="ok",
        ))
        return

    if result["new"]:
        ctx.dispatcher.handle(Event(
            type="warn.proc.new_processes",
            message=f"New processes detected: {len(result['new'])}",
            data={"count": len(result["new"])},
            severity="warn",
        ))
        for p in result["new"]:
            exe = _shorten_path(p.exe)
            ctx.dispatcher.handle(Event(
                type="info.proc.new_process",
                message=f"NEW pid={p.pid} user={p.user} exe={exe}",
                data={
                    "pid": p.pid,
                    "user": p.user,
                    "exe": p.exe,
                },
                severity="info",
            ))

    if result["root"]:
        ctx.dispatcher.handle(Event(
            type="warn.proc.root_processes",
            message=f"Root-owned processes detected: {len(result['root'])}",
            data={"count": len(result["root"])},
            severity="warn",
        ))

        for p in result["root"][:10]:
            exe = _shorten_path(p.exe)
            ctx.dispatcher.handle(Event(
                type="info.proc.root_process",
                message=f"ROOT pid={p.pid} exe={exe}",
                data={"pid": p.pid, "exe": p.exe},
                severity="info",
            ))

        if len(result["root"]) > 10:
            ctx.dispatcher.handle(Event(
                type="info.proc.root_processes.truncated",
                message=f"{len(result['root']) - 10} additional root processes not shown",
                data={"omitted": len(result["root"]) - 10},
                severity="info",
            ))

