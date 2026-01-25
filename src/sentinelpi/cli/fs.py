import click
from pathlib import Path

from sentinelpi.cli.context import CLIContext
from sentinelpi.modules.fs.scanner import scan_paths
from sentinelpi.modules.fs.baseline import save_baseline, load_baseline
from sentinelpi.modules.fs.diff import diff_files
from sentinelpi.core.events import Event


BASELINE_PATH = Path.home() / ".sentinelpi" / "fs_baseline.json"


def _default_paths() -> list[Path]:
    return [
        Path.home() / ".ssh",
    ]


@click.group()
@click.pass_obj
def fs(ctx: CLIContext) -> None:
    """Filesystem integrity commands."""
    pass


@fs.command()
@click.pass_obj
def baseline(ctx: CLIContext) -> None:
    paths = _default_paths()
    records = scan_paths(paths)

    save_baseline(BASELINE_PATH, records)
    ctx.dispatcher.handle(Event(
        type="done.fs.baseline_saved",
        message=f"Filesystem baseline saved ({len(records)} files)",
        data={"files": len(records)},
        severity="done",
    ))


@fs.command()
@click.pass_obj
def check(ctx: CLIContext) -> None:
    baseline = load_baseline(BASELINE_PATH)

    if not baseline:
        ctx.dispatcher.handle(Event(
            type="error.fs.no_baseline",
            message="No filesystem baseline found. Run 'sentinelpi fs baseline' first.",
            severity="error",
        ))
        return

    current = scan_paths(_default_paths())
    diff = diff_files(baseline, current)

    if not any(diff.values()):
        ctx.dispatcher.handle(Event(
            type="ok.fs.clean",
            message="No filesystem integrity violations detected",
            severity="ok",
        ))
        return

    if diff["modified"]:
        ctx.dispatcher.handle(Event(
            type="warn.fs.modified",
            message=f"Modified files detected: {len(diff['modified'])}",
            data={"count": len(diff["modified"])},
            severity="warn",
        ))
        for f in diff["modified"][:5]:
            ctx.dispatcher.handle(Event(
                type="info.fs.modified.file",
                message=f"Modified: {f.path}",
                data={"path": f.path},
                severity="info",
            ))

    if diff["new"]:
        ctx.dispatcher.handle(Event(
            type="warn.fs.new",
            message=f"New files detected: {len(diff['new'])}",
            data={"count": len(diff["new"])},
            severity="warn",
        ))
        for f in diff["new"][:5]:
            ctx.dispatcher.handle(Event(
                type="info.fs.new.file",
                message=f"New: {f.path}",
                data={"path": f.path},
                severity="info",
            ))

    if diff["deleted"]:
        ctx.dispatcher.handle(Event(
            type="warn.fs.deleted",
            message=f"Deleted files detected: {len(diff['deleted'])}",
            data={"count": len(diff["deleted"])},
            severity="warn",
        ))
        for f in diff["deleted"][:5]:
            ctx.dispatcher.handle(Event(
                type="info.fs.deleted.file",
                message=f"Deleted: {f.path}",
                data={"path": f.path},
                severity="info",
            ))
