import click

from sentinelpi.platform import detect_platform
from sentinelpi.cli.context import CLIContext

from sentinelpi.cli.usb import usb
from sentinelpi.cli.net import net
from sentinelpi.cli.fs import fs
from sentinelpi.cli.proc import proc
from sentinelpi.cli.scan import scan


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.option(
    "-v", "--verbose",
    is_flag=True,
    help="Enable verbose output"
)
@click.pass_context
def main(ctx: click.Context, verbose: bool) -> None:
    """
    SentinelPi: Raspberry Pi security monitoring platform.
    Linux-first, Pi-optimized. macOS supported for development and demos.
    """
    platform = detect_platform()
    # print(platform.pretty_name, platform.supports_usb_monitoring)

    ctx.obj = CLIContext(
        platform=platform,
        verbose=verbose,
    )

    if verbose:
        click.echo(f"[DEBUG] Platform detected: {platform.pretty_name}")


# ---- Subcommands ----
main.add_command(usb)
main.add_command(net)
main.add_command(fs)
main.add_command(proc)
main.add_command(scan)


if __name__ == "__main__":
    main()