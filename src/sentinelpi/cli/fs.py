import click
from pathlib import Path

from sentinelpi.cli.context import CLIContext
from sentinelpi.modules.fs.scanner import scan_paths
from sentinelpi.modules.fs.baseline import save_baseline, load_baseline
from sentinelpi.modules.fs.diff import diff_files
from sentinelpi.modules.fs.events import FsEventFactory
from sentinelpi.core.event_factory import EventFactory
from sentinelpi.analyzers.runner import AnalyzerRunner
from sentinelpi.analyzers.fs_new_executable import NewExecutableFileAnalyzer


BASELINE_PATH = Path.home() / ".sentinelpi" / "fs_baseline.json"


def _default_paths() -> list[Path]:
    return [
        Path.home() / ".ssh",
        Path("/tmp"),
        Path("/etc"),
    ]


@click.group()
@click.pass_obj
def fs(ctx: CLIContext) -> None:
    """Filesystem integrity commands."""
    pass


@fs.command()
@click.pass_obj
def baseline(ctx: CLIContext) -> None:
    fs_events = FsEventFactory(
        EventFactory(ctx.dispatcher, namespace="fs")
    )

    paths = _default_paths()
    records = scan_paths(paths)

    save_baseline(BASELINE_PATH, records)
    fs_events.baseline_saved(len(records))


@fs.command()
@click.pass_obj
def check(ctx: CLIContext) -> None:
    fs_events = FsEventFactory(
        EventFactory(ctx.dispatcher, namespace="fs")
    )

    baseline = load_baseline(BASELINE_PATH)

    if not baseline:
        fs_events.no_baseline()
        return

    current = scan_paths(_default_paths())
    diff = diff_files(baseline, current)

    if not any(diff.values()):
        fs_events.clean()
        return
    
    runner = AnalyzerRunner([
        NewExecutableFileAnalyzer(),
    ])

    context = {
        "fs.baseline": baseline,
        "fs.current": current,
        "fs.diff": diff,
        "platform": ctx.platform.name,
    }

    for event in runner.run(context=context):
        ctx.dispatcher.handle(event)

    if diff["modified"]:
        fs_events.modified_files(len(diff["modified"]))
        for f in diff["modified"][:5]:
            fs_events.modified_file(f.path)

    if diff["new"]:
        fs_events.new_files(len(diff["new"]))
        for f in diff["new"][:5]:
            fs_events.new_file(f.path)

    if diff["deleted"]:
        fs_events.deleted_files(len(diff["deleted"]))
        for f in diff["deleted"][:5]:
            fs_events.deleted_file(f.path)
