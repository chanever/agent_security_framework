from __future__ import annotations

from typing import TYPE_CHECKING

from wexample_cli.decorator.command import command
from wexample_wex_core.const.globals import COMMAND_TYPE_SERVICE

if TYPE_CHECKING:
    from wexample_app.response.boolean_response import BooleanResponse
    from wexample_cli.context.execution_context import ExecutionContext
    from wexample_wex_addon_app.service.app_service import AppService


@command(type=COMMAND_TYPE_SERVICE, description="Check if openclaw service is ready")
def openclaw__service__ready(
    context: ExecutionContext,
    service: AppService,
) -> BooleanResponse:
    import subprocess

    from wexample_app.response.boolean_response import BooleanResponse

    runtime = service.app_workdir.get_runtime_config()
    app_project_name = runtime.search("app.project_name").get_str()
    container_name = f"{app_project_name}_{service.name}"

    # OpenClaw gateway answers on 18789. Endpoint to refine after first install
    # — fallback to root probe accepting any HTTP response.
    result = subprocess.run(
        [
            "docker",
            "exec",
            container_name,
            "curl",
            "-sf",
            "-o",
            "/dev/null",
            "http://localhost:18789/",
        ],
        capture_output=True,
    )

    return BooleanResponse(kernel=context.kernel, content=result.returncode == 0)
