from __future__ import annotations

from typing import TYPE_CHECKING

from wexample_cli.decorator.command import command
from wexample_wex_core.const.globals import COMMAND_TYPE_SERVICE

if TYPE_CHECKING:
    from wexample_cli.context.execution_context import ExecutionContext
    from wexample_wex_addon_app.service.app_service import AppService


@command(
    type=COMMAND_TYPE_SERVICE,
    description="Build python docker images if not already built (idempotent via lock)",
)
def python__service__setup(
    context: ExecutionContext,
    service: AppService,
) -> None:
    import subprocess

    from wexample_app.const.globals import WORKDIR_LOCAL_DIR_NAME, WORKDIR_SETUP_DIR
    from wexample_helpers.helpers.file import file_mkdir_as_real_user
    from wexample_wex_addon_app.helpers.image_builds import (
        load_builds,
        resolve_build_order,
    )

    app_path = service.app_workdir.get_path()
    lock_dir = app_path / WORKDIR_SETUP_DIR / WORKDIR_LOCAL_DIR_NAME / "setup"
    lock_file = lock_dir / "python.done"

    if lock_file.exists():
        return

    try:
        builds = load_builds(app_path)
    except (FileNotFoundError, KeyError):
        context.io.log("No docker.images in config.yml, skipping image build")
        return

    ordered = resolve_build_order(builds)

    for build_name in ordered:
        build = builds[build_name]
        dockerfile = str(app_path / build["dockerfile"])
        tag = build["tag"]
        cmd = ["docker", "build", "-f", dockerfile, "-t", tag]
        if "depends_on" in build:
            parent_tag = builds[build["depends_on"]]["tag"]
            cmd += ["--build-arg", f"BASE_IMAGE={parent_tag}"]
        cmd.append(str(app_path))
        context.io.log(f"Building image '{build_name}' → {tag}")
        subprocess.run(cmd, check=True)

    file_mkdir_as_real_user(lock_dir)
    lock_file.write_text("done\n")
    context.io.log("Python setup complete.")
