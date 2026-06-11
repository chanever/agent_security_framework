from __future__ import annotations

from typing import TYPE_CHECKING

from wexample_cli.decorator.command import command
from wexample_wex_core.const.globals import COMMAND_TYPE_SERVICE

if TYPE_CHECKING:
    from wexample_app.response.boolean_response import BooleanResponse
    from wexample_cli.context.execution_context import ExecutionContext
    from wexample_wex_addon_app.service.app_service import AppService


@command(type=COMMAND_TYPE_SERVICE, description="Check if mongo service is ready")
def mongo__service__ready(
    context: ExecutionContext,
    service: AppService,
) -> BooleanResponse:
    import subprocess

    from wexample_app.response.boolean_response import BooleanResponse

    runtime = service.app_workdir.get_runtime_config()
    app_project_name = runtime.search("app.project_name").get_str()
    container_name = f"{app_project_name}_{service.name}"

    result = subprocess.run(
        [
            "docker",
            "exec",
            container_name,
            "mongosh",
            "--quiet",
            "--eval",
            "db.runCommand({ ping: 1 }).ok",
        ],
        capture_output=True,
        text=True,
    )

    return BooleanResponse(
        kernel=context.kernel,
        content=result.returncode == 0 and result.stdout.strip() == "1",
    )
