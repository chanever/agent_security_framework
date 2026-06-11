"""Shared HTTP helpers for routing through the Prune proxy."""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional, Tuple

import httpx

from prune.config import get_prune_config
from prune.exceptions import PruneProxyError

logger = logging.getLogger("prune")

# Fields accepted by the Prune Anthropic proxy (see prune-backend ProxyRequest)
ANTHROPIC_PROXY_FIELDS = frozenset(
    {"messages", "model", "max_tokens", "temperature", "system"}
)

OPENAI_PROXY_FIELDS = frozenset(
    {
        "messages",
        "model",
        "max_tokens",
        "temperature",
        "top_p",
        "response_format",
        "n",
        "stop",
        "presence_penalty",
        "frequency_penalty",
    }
)


def build_anthropic_proxy_body(kwargs: Dict[str, Any], user_api_key: str) -> Dict[str, Any]:
    body: Dict[str, Any] = {
        "messages": kwargs["messages"],
        "model": kwargs["model"],
        "max_tokens": kwargs["max_tokens"],
        "user_api_key": user_api_key,
    }
    if "temperature" in kwargs and kwargs["temperature"] is not None:
        body["temperature"] = kwargs["temperature"]
    if "system" in kwargs and kwargs["system"] is not None:
        body["system"] = kwargs["system"]
    return body


def build_openai_proxy_body(kwargs: Dict[str, Any], user_api_key: str) -> Dict[str, Any]:
    body: Dict[str, Any] = {
        "messages": kwargs["messages"],
        "model": kwargs["model"],
        "user_api_key": user_api_key,
    }
    for key in OPENAI_PROXY_FIELDS:
        if key in kwargs and key not in body:
            body[key] = kwargs[key]
    if "max_tokens" not in body and kwargs.get("max_completion_tokens"):
        body["max_tokens"] = kwargs["max_completion_tokens"]
    return body


def post_proxy(
    path: str,
    *,
    prune_api_key: str,
    json_body: Dict[str, Any],
    base_url: Optional[str] = None,
    timeout: Optional[float] = None,
) -> Tuple[Dict[str, Any], Optional[Dict[str, Any]]]:
    config = get_prune_config()
    url = f"{(base_url or config.base_url).rstrip('/')}{path}"
    timeout = timeout or config.request_timeout

    with httpx.Client(timeout=timeout) as client:
        response = client.post(
            url,
            headers={
                "X-Prune-Key": prune_api_key,
                "Content-Type": "application/json",
            },
            json=json_body,
        )

    if response.status_code >= 400:
        detail = response.text[:500]
        raise PruneProxyError(
            f"Prune proxy error ({response.status_code}): {detail}",
            status_code=response.status_code,
        )

    data = response.json()
    metadata = data.pop("prune_metadata", None)
    return data, metadata


async def apost_proxy(
    path: str,
    *,
    prune_api_key: str,
    json_body: Dict[str, Any],
    base_url: Optional[str] = None,
    timeout: Optional[float] = None,
) -> Tuple[Dict[str, Any], Optional[Dict[str, Any]]]:
    config = get_prune_config()
    url = f"{(base_url or config.base_url).rstrip('/')}{path}"
    timeout = timeout or config.request_timeout

    async with httpx.AsyncClient(timeout=timeout) as client:
        response = await client.post(
            url,
            headers={
                "X-Prune-Key": prune_api_key,
                "Content-Type": "application/json",
            },
            json=json_body,
        )

    if response.status_code >= 400:
        detail = response.text[:500]
        raise PruneProxyError(
            f"Prune proxy error ({response.status_code}): {detail}",
            status_code=response.status_code,
        )

    data = response.json()
    metadata = data.pop("prune_metadata", None)
    return data, metadata


def should_fallback(exc: BaseException) -> bool:
    config = get_prune_config()
    if not config.fallback_on_error:
        return False
    if isinstance(exc, (httpx.TimeoutException, httpx.ConnectError, httpx.NetworkError)):
        return True
    if isinstance(exc, PruneProxyError):
        code = exc.status_code
        return code is None or code >= 500 or code == 404
    return False
