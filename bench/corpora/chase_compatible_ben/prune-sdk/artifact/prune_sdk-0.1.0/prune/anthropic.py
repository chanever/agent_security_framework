"""
Drop-in Anthropic client that routes through the Prune proxy.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

from anthropic import Anthropic as _AnthropicSDK
from anthropic import AsyncAnthropic as _AsyncAnthropicSDK
from anthropic.types import Message

from prune._proxy import (
    apost_proxy,
    build_anthropic_proxy_body,
    post_proxy,
    should_fallback,
)
from prune.config import get_prune_config
from prune.exceptions import PruneConfigError, PruneProxyError

logger = logging.getLogger("prune")

ANTHROPIC_PROXY_PATH = "/v1/proxy/anthropic/messages"


def _to_message(data: dict[str, Any]) -> Message:
    return Message.model_validate(data)


class Anthropic:
    """
    Drop-in replacement for ``anthropic.Anthropic`` that routes through Prune.

    Example::

        from prune import Anthropic

        client = Anthropic(
            api_key="sk-ant-...",
            prune_api_key="prune_...",
        )
        message = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=1024,
            messages=[{"role": "user", "content": "Hello"}],
        )
    """

    def __init__(
        self,
        api_key: str,
        *,
        prune_api_key: Optional[str] = None,
        prune_base_url: Optional[str] = None,
        enable_prune: bool = True,
        **anthropic_kwargs: Any,
    ) -> None:
        self.api_key = api_key
        config = get_prune_config()
        self.prune_api_key = prune_api_key or config.api_key
        self.prune_base_url = (prune_base_url or config.base_url).rstrip("/")
        self.enable_prune = enable_prune
        self._anthropic_kwargs = anthropic_kwargs
        self._direct = _AnthropicSDK(api_key=api_key, **anthropic_kwargs)

        if enable_prune and not self.prune_api_key:
            raise PruneConfigError(
                "Prune API key required. Pass prune_api_key=..., call prune.configure(), "
                "or set PRUNE_API_KEY. Get a key at https://prune.so"
            )

        self.messages = _Messages(self)
        self.last_prune_metadata: Optional[dict[str, Any]] = None

    def _use_proxy(self, kwargs: dict[str, Any]) -> bool:
        if not self.enable_prune or not self.prune_api_key:
            return False
        if kwargs.get("stream"):
            logger.debug("Streaming requests bypass Prune proxy")
            return False
        return True


class _Messages:
    def __init__(self, client: Anthropic) -> None:
        self._client = client

    def create(self, **kwargs: Any) -> Message:
        client = self._client
        if not client._use_proxy(kwargs):
            return client._direct.messages.create(**kwargs)

        try:
            body = build_anthropic_proxy_body(kwargs, client.api_key)
            data, metadata = post_proxy(
                ANTHROPIC_PROXY_PATH,
                prune_api_key=client.prune_api_key,
                json_body=body,
                base_url=client.prune_base_url,
            )
            client.last_prune_metadata = metadata
            return _to_message(data)
        except Exception as exc:
            if should_fallback(exc):
                logger.warning("Prune proxy unavailable, falling back to Anthropic: %s", exc)
                return client._direct.messages.create(**kwargs)
            if isinstance(exc, PruneProxyError):
                raise
            raise PruneProxyError(str(exc)) from exc


class AsyncAnthropic:
    """Async drop-in replacement for ``anthropic.AsyncAnthropic``."""

    def __init__(
        self,
        api_key: str,
        *,
        prune_api_key: Optional[str] = None,
        prune_base_url: Optional[str] = None,
        enable_prune: bool = True,
        **anthropic_kwargs: Any,
    ) -> None:
        self.api_key = api_key
        config = get_prune_config()
        self.prune_api_key = prune_api_key or config.api_key
        self.prune_base_url = (prune_base_url or config.base_url).rstrip("/")
        self.enable_prune = enable_prune
        self._direct = _AsyncAnthropicSDK(api_key=api_key, **anthropic_kwargs)

        if enable_prune and not self.prune_api_key:
            raise PruneConfigError(
                "Prune API key required. Pass prune_api_key=..., call prune.configure(), "
                "or set PRUNE_API_KEY."
            )

        self.messages = _AsyncMessages(self)
        self.last_prune_metadata: Optional[dict[str, Any]] = None

    def _use_proxy(self, kwargs: dict[str, Any]) -> bool:
        if not self.enable_prune or not self.prune_api_key:
            return False
        if kwargs.get("stream"):
            return False
        return True


class _AsyncMessages:
    def __init__(self, client: AsyncAnthropic) -> None:
        self._client = client

    async def create(self, **kwargs: Any) -> Message:
        client = self._client
        if not client._use_proxy(kwargs):
            return await client._direct.messages.create(**kwargs)

        try:
            body = build_anthropic_proxy_body(kwargs, client.api_key)
            data, metadata = await apost_proxy(
                ANTHROPIC_PROXY_PATH,
                prune_api_key=client.prune_api_key,
                json_body=body,
                base_url=client.prune_base_url,
            )
            client.last_prune_metadata = metadata
            return _to_message(data)
        except Exception as exc:
            if should_fallback(exc):
                logger.warning("Prune proxy unavailable, falling back to Anthropic: %s", exc)
                return await client._direct.messages.create(**kwargs)
            if isinstance(exc, PruneProxyError):
                raise
            raise PruneProxyError(str(exc)) from exc
