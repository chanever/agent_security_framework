from __future__ import annotations

from typing import TYPE_CHECKING

from wexample_cli.decorator.command import command
from wexample_wex_core.const.globals import COMMAND_TYPE_SERVICE

if TYPE_CHECKING:
    from wexample_cli.context.execution_context import ExecutionContext
    from wexample_wex_addon_app.service.app_service import AppService


@command(
    type=COMMAND_TYPE_SERVICE,
    description="Configure openclaw service in app config",
)
def openclaw__service__install(
    context: ExecutionContext,
    service: AppService,
) -> None:
    from wexample_helpers.helpers.string import string_random_token

    config_file = service.app_workdir.get_config_file()
    config = config_file.read_config()

    config.set_by_path(f"service.{service.name}.skip_onboarding", True)
    config.set_by_path(f"service.{service.name}.sandbox", False)
    config.set_by_path(
        f"service.{service.name}.init_token",
        string_random_token(),
    )

    config_file.write_config(config)
    service.app_workdir.get_runtime_config(rebuild=True)

    context.io.log("Configured openclaw service defaults")
