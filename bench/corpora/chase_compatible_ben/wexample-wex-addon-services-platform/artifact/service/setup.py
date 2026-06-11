from __future__ import annotations

import json
from typing import TYPE_CHECKING

from wexample_cli.decorator.command import command
from wexample_wex_core.const.globals import COMMAND_TYPE_SERVICE

if TYPE_CHECKING:
    from wexample_cli.context.execution_context import ExecutionContext
    from wexample_wex_addon_app.service.app_service import AppService


@command(
    type=COMMAND_TYPE_SERVICE,
    description="Seed openclaw.json with gateway config",
)
def openclaw__service__setup(
    context: ExecutionContext,
    service: AppService,
) -> None:
    # openclaw.json is not versioned (data dir holds tokens, paired devices,
    # last-good snapshots — owned by the running container after first start).
    # Seed it on each start if missing, typically right after a fresh prod
    # clone. Subsequent runs are no-op.
    json_path = service.app_workdir.get_path() / "openclaw" / "data" / "openclaw.json"
    if json_path.exists():
        return

    domain = service.app_workdir.get_config().search("domain").get_str_or_none()
    allowed_origins = [
        "http://localhost:18789",
        "http://127.0.0.1:18789",
    ]
    if domain:
        allowed_origins += [f"http://{domain}", f"https://{domain}"]

    payload = {
        "gateway": {
            "mode": "local",
            "controlUi": {"allowedOrigins": allowed_origins},
            # RFC1918 — covers any docker bridge the wex-proxy sidecar lands on
            # without hard-coding a CIDR.
            "trustedProxies": [
                "10.0.0.0/8",
                "172.16.0.0/12",
                "192.168.0.0/16",
            ],
        }
    }

    json_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.write_text(json.dumps(payload, indent=2) + "\n")

    context.io.log(f"Seeded {json_path.name}")
