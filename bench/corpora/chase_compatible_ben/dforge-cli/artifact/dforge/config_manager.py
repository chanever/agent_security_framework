import json
from pathlib import Path

CONFIG_DIR = Path.home() / ".dforge"
CONFIG_FILE = CONFIG_DIR / "config.json"


def load_config():
    if not CONFIG_FILE.exists():
        return {}

    try:
        with open(CONFIG_FILE, "r") as f:
            return json.load(f)
    except Exception:
        return {}


def save_config(config: dict):
    CONFIG_DIR.mkdir(exist_ok=True)

    with open(CONFIG_FILE, "w") as f:
        json.dump(config, f, indent=4)


def get_tool_path(tool: str):
    return load_config().get(tool)


def set_tool_path(tool: str, path: str):
    config = load_config()
    config[tool] = path
    save_config(config)