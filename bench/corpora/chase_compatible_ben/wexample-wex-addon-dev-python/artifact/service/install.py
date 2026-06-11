from __future__ import annotations

from typing import TYPE_CHECKING

from wexample_cli.decorator.command import command
from wexample_wex_core.const.globals import COMMAND_TYPE_SERVICE

if TYPE_CHECKING:
    from wexample_cli.context.execution_context import ExecutionContext
    from wexample_wex_addon_app.service.app_service import AppService


@command(
    type=COMMAND_TYPE_SERVICE,
    description="Register docker image build config for the python service",
)
def python__service__install(
    context: ExecutionContext,
    service: AppService,
) -> None:
    project_name = service.app_workdir.get_project_name()

    config_file = service.app_workdir.get_config_file()
    config = config_file.read_config()

    from wexample_app.const.globals import WORKDIR_SETUP_DIR

    if config.search("docker.images").is_none():
        config.set_by_path(
            "docker.images",
            {
                "base": {
                    "dockerfile": str(
                        WORKDIR_SETUP_DIR / "docker" / "images" / "Dockerfile.base"
                    ),
                    "tag": f"{project_name}:local",
                },
                "develop": {
                    "dockerfile": str(
                        WORKDIR_SETUP_DIR / "docker" / "images" / "Dockerfile.develop"
                    ),
                    "tag": f"{project_name}-dev:local",
                    "depends_on": "base",
                },
            },
        )
        config_file.write_config(config)
        context.io.log(f"Registered docker images for '{project_name}'")
