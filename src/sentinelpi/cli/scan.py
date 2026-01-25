import click
from sentinelpi.cli.context import CLIContext

@click.command()
@click.pass_obj
def scan(ctx: CLIContext) -> None:
    """Run all enabled checks."""
    click.echo("Scan not implemented yet.")