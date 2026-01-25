import click
from sentinelpi.cli.context import CLIContext
from sentinelpi.platform.base import PlatformUnsupportedError


@click.group()
@click.pass_obj
def usb(ctx: CLIContext) -> None:
    """USB device monitoring commands."""
    pass


@usb.command()
@click.pass_obj
def list(ctx: CLIContext) -> None:
    """List currently connected USB devices."""
    platform = ctx.platform

    try:
        platform.require("usb")
        devices = platform.list_usb_devices()
    except PlatformUnsupportedError as e:
        click.echo(f"{e}")
        return

    if not devices:
        click.echo("No USB devices found.")
        return

    for dev in devices:
        click.echo(f"{dev.vendor_id}:{dev.product_id}  {dev.description}")