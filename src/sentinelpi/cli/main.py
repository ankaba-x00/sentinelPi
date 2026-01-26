import click

from sentinelpi.platform import detect_platform
from sentinelpi.cli.context import CLIContext

from sentinelpi.core.paths import default_data_dir, events_log_path, alerts_log_path
from sentinelpi.core.logging import JSONLLogger
from sentinelpi.core.output import emit
from sentinelpi.core.event_factory import EventFactory
from sentinelpi.alerting.policy import Policy
from sentinelpi.alerting.dispatcher import Dispatcher
from sentinelpi.alerting.sinks import ConsoleSink, JSONLFileSink

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

    data_dir = default_data_dir()
    logger = JSONLLogger(events_log_path(data_dir))

    sinks = [ConsoleSink(), JSONLFileSink(alerts_log_path(data_dir))]
    
    dispatcher = Dispatcher(
        logger=logger,
        policy=Policy(),
        sinks=sinks,
        verbose=verbose
    )

    event_factory = EventFactory(dispatcher, namespace="cli")

    ctx.obj = CLIContext(
        platform=platform,
        dispatcher=dispatcher,
        events=event_factory,
        verbose=verbose,
    )

    if verbose:
        emit("debug", f"Platform detected: {platform.pretty_name}")
        emit("debug", f"Data dir: {str(data_dir)}")
    
    if ctx.invoked_subcommand is None:
        emit("info", "SentinelPi initialized")
        emit("info", "Use --help to see available commands")
        

# ---- Subcommands ----
main.add_command(usb)
main.add_command(net)
main.add_command(fs)
main.add_command(proc)
main.add_command(scan)


if __name__ == "__main__":
    main()