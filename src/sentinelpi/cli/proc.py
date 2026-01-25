import click
from sentinelpi.cli.context import CLIContext

@click.group()
@click.pass_obj
def proc(ctx: CLIContext) -> None:
    """Process monitoring commands."""
    pass