import click
from pathlib import Path

from sentinelpi.cli.context import CLIContext
from sentinelpi.modules.fs.scanner import scan_paths
from sentinelpi.modules.fs.baseline import save_baseline, load_baseline
from sentinelpi.modules.fs.diff import diff_files


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
    click.echo(f"[DONE] Filesystem baseline saved ({len(records)} files)")


@fs.command()
@click.pass_obj
def check(ctx: CLIContext) -> None:
    baseline = load_baseline(BASELINE_PATH)

    if not baseline:
        click.echo("[ERROR] No filesystem baseline found. Run 'sentinelpi fs baseline' first.")
        return

    current = scan_paths(_default_paths())
    diff = diff_files(baseline, current)

    if not any(diff.values()):
        click.echo("[OK] No filesystem integrity violations detected")
        return

    if diff["modified"]:
        click.echo(f"[WARN] Modified files detected: {len(diff['modified'])}")
        for f in diff["modified"][:5]:
            click.echo(f"  MOD {f.path}")

    if diff["new"]:
        click.echo(f"[WARN] New files detected: {len(diff['new'])}")
        for f in diff["new"][:5]:
            click.echo(f"  NEW {f.path}")

    if diff["deleted"]:
        click.echo(f"[WARN] Deleted files detected: {len(diff['deleted'])}")
        for f in diff["deleted"][:5]:
            click.echo(f"  DEL {f.path}")
