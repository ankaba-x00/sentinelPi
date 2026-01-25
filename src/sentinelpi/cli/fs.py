import click
from sentinelpi.cli.context import CLIContext

@click.group()
@click.pass_obj
def fs(ctx: CLIContext) -> None:
    """Filesystem integrity commands."""
    pass