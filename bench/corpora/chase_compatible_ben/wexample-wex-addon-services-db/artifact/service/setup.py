from __future__ import annotations

from typing import TYPE_CHECKING

from wexample_cli.decorator.command import command
from wexample_wex_core.const.globals import COMMAND_TYPE_SERVICE

if TYPE_CHECKING:
    from wexample_cli.context.execution_context import ExecutionContext
    from wexample_wex_addon_app.service.app_service import AppService


@command(
    type=COMMAND_TYPE_SERVICE,
    description="Initialize mongo service filesystem requirements",
)
def mongo__service__setup(
    context: ExecutionContext,
    service: AppService,
) -> None:
    import subprocess

    keyfile_path = service.app_workdir.get_path() / "mongo-keyfile"
    if not keyfile_path.exists() or keyfile_path.stat().st_size == 0:
        key = subprocess.check_output(["openssl", "rand", "-base64", "756"])
        keyfile_path.write_bytes(key.replace(b"\n", b""))
        context.io.log("Generated mongo-keyfile")
