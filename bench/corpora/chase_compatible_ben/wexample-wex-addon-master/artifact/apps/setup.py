from __future__ import annotations

from typing import TYPE_CHECKING

from wexample_cli.decorator.command import command
from wexample_cli.decorator.middleware import middleware
from wexample_wex_core.const.globals import COMMAND_TYPE_ADDON

from wexample_wex_addon_master.middleware.master_middleware import MasterMiddleware

if TYPE_CHECKING:
    from wexample_cli.context.execution_context import ExecutionContext

    from wexample_wex_addon_master.workdir.master_workdir import MasterWorkdir


@middleware(middleware=MasterMiddleware)
@command(
    type=COMMAND_TYPE_ADDON,
    description="Ensure each resolved app has a working .wex/bin/app-manager. "
    "Replaces broken symlinks or stale content; sets the executable bit.",
)
def master__apps__setup(
    context: ExecutionContext,
    app_workdir: MasterWorkdir,
) -> None:
    written, ok = app_workdir.apps_ensure_manager_bin()

    for p in written:
        context.io.success(f"Wrote {p.name}/.wex/bin/app-manager")
    for p in ok:
        context.io.log(f"OK    {p.name}")

    context.io.log(f"Setup complete — {len(written)} written, {len(ok)} already ok.")
