import os
from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class PruneConfig:
    api_key: Optional[str] = None
    base_url: str = "https://api.prune.so"
    enable_analytics: bool = True
    cache_enabled: bool = True
    fallback_on_error: bool = True
    request_timeout: float = 120.0


_config: Optional[PruneConfig] = None


def get_prune_config() -> PruneConfig:
    global _config
    if _config is None:
        _config = PruneConfig(
            api_key=os.getenv("PRUNE_API_KEY"),
            base_url=os.getenv("PRUNE_BASE_URL", "https://api.prune.so").rstrip("/"),
            fallback_on_error=os.getenv("PRUNE_FALLBACK", "true").lower()
            not in ("0", "false", "no"),
        )
    return _config


def configure(
    api_key: Optional[str] = None,
    base_url: Optional[str] = None,
    **kwargs: Any,
) -> PruneConfig:
    """
    Configure Prune globally.

    Example:
        import prune
        prune.configure(api_key="prune_xxx")
    """
    global _config
    current = get_prune_config()
    _config = PruneConfig(
        api_key=api_key if api_key is not None else current.api_key,
        base_url=(base_url or current.base_url).rstrip("/"),
        enable_analytics=kwargs.get("enable_analytics", current.enable_analytics),
        cache_enabled=kwargs.get("cache_enabled", current.cache_enabled),
        fallback_on_error=kwargs.get("fallback_on_error", current.fallback_on_error),
        request_timeout=kwargs.get("request_timeout", current.request_timeout),
    )
    return _config
