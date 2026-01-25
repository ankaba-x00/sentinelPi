import click
from pathlib import Path

from sentinelpi.cli.context import CLIContext
from sentinelpi.modules.proc.scanner import scan_processes
from sentinelpi.modules.proc.baseline import save_baseline, load_baseline
from sentinelpi.modules.proc.diff import diff_processes


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
    click.echo(f"[INFO] Detected {len(processes)} running processes")

    for p in processes[:10]:
        click.echo(f"{p.pid:>6} {p.user:<8} {p.exe}")


@proc.command()
@click.pass_obj
def baseline(ctx: CLIContext) -> None:
    processes = scan_processes(ctx.platform)
    save_baseline(BASELINE_PATH, processes)
    click.echo(f"[DONE] Process baseline saved ({len(processes)} entries)")


@proc.command()
@click.pass_obj
def check(ctx: CLIContext) -> None:
    baseline = load_baseline(BASELINE_PATH)
    current = scan_processes(ctx.platform)

    if not baseline:
        click.echo("[ERROR] No process baseline found. Run 'sentinelpi proc baseline' first.")
        return

    result = diff_processes(baseline, current)

    if not result["new"] and not result["root"]:
        click.echo("[OK] No unexpected processes detected")
        return

    if result["new"]:
        click.echo(f"[WARN] New processes detected: {len(result['new'])}")
        for p in result["new"]:
            exe = _shorten_path(p.exe)
            click.echo(
                f"  NEW pid={p.pid:<6} user={p.user:<8} exe={exe}"
            )

    if result["root"]:
        click.echo(f"[WARN] Root-owned processes detected: {len(result['root'])}")

        for p in result["root"][:10]:
            exe = _shorten_path(p.exe)
            click.echo(
                f"  ROOT pid={p.pid:<6} exe={exe}"
            )

        if len(result["root"]) > 10:
            click.echo(
                f"[INFO] {len(result['root']) - 10} additional root processes not shown"
            )
