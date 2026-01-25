import click
from sentinelpi.cli.context import CLIContext

@click.group()
@click.pass_obj
def net(ctx: CLIContext) -> None:
    """Network discovery commands."""
    pass