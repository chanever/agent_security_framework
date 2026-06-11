"""
Drop-in OpenAI client that routes through the Prune proxy when available.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

from openai import AsyncOpenAI as _AsyncOpenAISDK
from openai import OpenAI as _OpenAISDK
from openai.types.chat import ChatCompletion

from prune._proxy import (
    apost_proxy,
    build_openai_proxy_body,
    post_proxy,
    should_fallback,
)
from prune.config import get_prune_config
from prune.exceptions import PruneConfigError, PruneProxyError

logger = logging.getLogger("prune")

OPENAI_PROXY_PATH = "/v1/proxy/openai/chat/completions"


def _to_chat_completion(data: dict[str, Any]) -> ChatCompletion:
    return ChatCompletion.model_validate(data)


class OpenAI:
    """
    Drop-in replacement for ``openai.OpenAI`` that routes through Prune.

    Routes chat completions through the Prune OpenAI proxy when available.
    Falls back to the official OpenAI API on proxy outage (5xx / network).
    """

    def __init__(
        self,
        api_key: str,
        *,
        prune_api_key: Optional[str] = None,
        prune_base_url: Optional[str] = None,
        enable_prune: bool = True,
        **openai_kwargs: Any,
    ) -> None:
        self.api_key = api_key
        config = get_prune_config()
        self.prune_api_key = prune_api_key or config.api_key
        self.prune_base_url = (prune_base_url or config.base_url).rstrip("/")
        self.enable_prune = enable_prune
        self._direct = _OpenAISDK(api_key=api_key, **openai_kwargs)

        if enable_prune and not self.prune_api_key:
            raise PruneConfigError(
                "Prune API key required. Pass prune_api_key=..., call prune.configure(), "
                "or set PRUNE_API_KEY."
            )

        self.chat = _Chat(self)
        self.last_prune_metadata: Optional[dict[str, Any]] = None

    def _use_proxy(self, kwargs: dict[str, Any]) -> bool:
        if not self.enable_prune or not self.prune_api_key:
            return False
        if kwargs.get("stream"):
            return False
        return True


class _Chat:
    def __init__(self, client: OpenAI) -> None:
        self.completions = _Completions(client)


class _Completions:
    def __init__(self, client: OpenAI) -> None:
        self._client = client

    def create(self, **kwargs: Any) -> ChatCompletion:
        client = self._client
        if not client._use_proxy(kwargs):
            return client._direct.chat.completions.create(**kwargs)

        try:
            body = build_openai_proxy_body(kwargs, client.api_key)
            if "max_tokens" not in body:
                body["max_tokens"] = kwargs.get("max_tokens", 1024)
            data, metadata = post_proxy(
                OPENAI_PROXY_PATH,
                prune_api_key=client.prune_api_key,
                json_body=body,
                base_url=client.prune_base_url,
            )
            client.last_prune_metadata = metadata
            return _to_chat_completion(data)
        except Exception as exc:
            if should_fallback(exc):
                logger.warning("Prune OpenAI proxy unavailable, falling back to OpenAI: %s", exc)
                return client._direct.chat.completions.create(**kwargs)
            if isinstance(exc, PruneProxyError):
                raise
            raise PruneProxyError(str(exc)) from exc


class AsyncOpenAI:
    """Async OpenAI client with Prune routing."""

    def __init__(
        self,
        api_key: str,
        *,
        prune_api_key: Optional[str] = None,
        prune_base_url: Optional[str] = None,
        enable_prune: bool = True,
        **openai_kwargs: Any,
    ) -> None:
        self.api_key = api_key
        config = get_prune_config()
        self.prune_api_key = prune_api_key or config.api_key
        self.prune_base_url = (prune_base_url or config.base_url).rstrip("/")
        self.enable_prune = enable_prune
        self._direct = _AsyncOpenAISDK(api_key=api_key, **openai_kwargs)

        if enable_prune and not self.prune_api_key:
            raise PruneConfigError("Prune API key required.")

        self.chat = _AsyncChat(self)
        self.last_prune_metadata: Optional[dict[str, Any]] = None

    def _use_proxy(self, kwargs: dict[str, Any]) -> bool:
        if not self.enable_prune or not self.prune_api_key:
            return False
        return not kwargs.get("stream")


class _AsyncChat:
    def __init__(self, client: AsyncOpenAI) -> None:
        self.completions = _AsyncCompletions(client)


class _AsyncCompletions:
    def __init__(self, client: AsyncOpenAI) -> None:
        self._client = client

    async def create(self, **kwargs: Any) -> ChatCompletion:
        client = self._client
        if not client._use_proxy(kwargs):
            return await client._direct.chat.completions.create(**kwargs)

        try:
            body = build_openai_proxy_body(kwargs, client.api_key)
            if "max_tokens" not in body:
                body["max_tokens"] = kwargs.get("max_tokens", 1024)
            data, metadata = await apost_proxy(
                OPENAI_PROXY_PATH,
                prune_api_key=client.prune_api_key,
                json_body=body,
                base_url=client.prune_base_url,
            )
            client.last_prune_metadata = metadata
            return _to_chat_completion(data)
        except Exception as exc:
            if should_fallback(exc):
                logger.warning("Prune OpenAI proxy unavailable, falling back to OpenAI: %s", exc)
                return await client._direct.chat.completions.create(**kwargs)
            if isinstance(exc, PruneProxyError):
                raise
            raise PruneProxyError(str(exc)) from exc
