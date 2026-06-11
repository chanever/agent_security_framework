from __future__ import annotations

from typing import TYPE_CHECKING

from wexample_cli.decorator.command import command
from wexample_cli.decorator.middleware import middleware
from wexample_cli.decorator.option import option
from wexample_helpers.validator.regex_validator import RegexValidator
from wexample_wex_core.const.globals import COMMAND_PATTERNS, COMMAND_TYPE_ADDON

from wexample_wex_addon_master.middleware.master_middleware import MasterMiddleware

if TYPE_CHECKING:
    from wexample_cli.context.execution_context import ExecutionContext

    from wexample_wex_addon_master.workdir.master_workdir import MasterWorkdir


@option(
    name="command",
    short_name="c",
    type=str,
    required=True,
    description="The full command to execute on each app, e.g. app::info/show",
    validators=[RegexValidator(pattern=COMMAND_PATTERNS)],
)
@option(
    name="arguments",
    type=str,
    description='The arguments string, e.g. "-a arg -v --yes"',
)
@option(
    name="continue_on_error",
    short_name="coe",
    is_flag=True,
    type=bool,
    description="Continue execution on all apps even if one fails. Reports failures at the end.",
)
@option(
    name="async_mode",
    short_name="a",
    is_flag=True,
    type=bool,
    description="Run all apps in parallel; outputs are captured and printed grouped at the end.",
)
@option(
    name="stack",
    short_name="s",
    type=str,
    description="Restrict execution to apps belonging to the given stack.",
)
@middleware(middleware=MasterMiddleware)
@command(
    type=COMMAND_TYPE_ADDON,
    description="Execute a command on each app resolved by the master project.",
)
def master__apps__run(
    context: ExecutionContext,
    command: str,
    app_workdir: MasterWorkdir,
    arguments: str = None,
    continue_on_error: bool = False,
    async_mode: bool = False,
    stack: str = None,
) -> None:
    from wexample_helpers.helpers.shell import shell_split_cmd

    app_workdir.apps_execute_manager(
        command=command,
        arguments=shell_split_cmd(arguments) if arguments else None,
        fail_fast=not continue_on_error,
        async_mode=async_mode,
        stack=stack,
    )
