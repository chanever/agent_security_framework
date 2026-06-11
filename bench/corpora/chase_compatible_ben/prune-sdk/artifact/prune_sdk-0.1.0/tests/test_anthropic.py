"""Tests for Prune Anthropic client."""

from unittest.mock import MagicMock, patch

import httpx
import pytest
import respx
from anthropic.types import Message

from prune import Anthropic, configure
from prune.exceptions import PruneConfigError


@pytest.fixture(autouse=True)
def reset_config():
    import prune.config as cfg

    cfg._config = None
    yield
    cfg._config = None


def test_anthropic_client_initialization():
    client = Anthropic(api_key="sk-ant-test", prune_api_key="prune_test")
    assert client.api_key == "sk-ant-test"
    assert client.prune_api_key == "prune_test"


def test_missing_prune_key_raises_error():
    with pytest.raises(PruneConfigError, match="Prune API key required"):
        Anthropic(api_key="sk-ant-test")


def test_configure_sets_global_key():
    configure(api_key="prune_global", base_url="http://localhost:8000")
    client = Anthropic(api_key="sk-ant-test")
    assert client.prune_api_key == "prune_global"


@respx.mock
def test_proxy_messages_create():
    configure(api_key="prune_test", base_url="http://localhost:8000")

    mock_body = {
        "id": "msg_test",
        "type": "message",
        "role": "assistant",
        "content": [{"type": "text", "text": "Hello!"}],
        "model": "claude-3-5-haiku-20241022",
        "stop_reason": "end_turn",
        "usage": {"input_tokens": 10, "output_tokens": 5},
        "prune_metadata": {
            "cache_hit": True,
            "cache_type": "exact",
            "tokens_saved": 10,
            "cost_saved": 0.00003,
            "original_tokens": 10,
            "optimized_tokens": 0,
        },
    }

    route = respx.post("http://localhost:8000/v1/proxy/anthropic/messages").mock(
        return_value=httpx.Response(200, json=mock_body)
    )

    client = Anthropic(api_key="sk-ant-test", prune_api_key="prune_test")
    message = client.messages.create(
        model="claude-3-5-haiku-20241022",
        max_tokens=50,
        messages=[{"role": "user", "content": "Hi"}],
    )

    assert route.called
    assert isinstance(message, Message)
    assert message.content[0].text == "Hello!"
    assert client.last_prune_metadata["cache_hit"] is True


@respx.mock
def test_fallback_on_proxy_failure():
    configure(api_key="prune_test", base_url="http://localhost:8000", fallback_on_error=True)

    respx.post("http://localhost:8000/v1/proxy/anthropic/messages").mock(
        return_value=httpx.Response(503, text="unavailable")
    )

    client = Anthropic(api_key="sk-ant-test", prune_api_key="prune_test")

    fake_message = Message(
        id="msg_direct",
        content=[{"type": "text", "text": "direct"}],
        model="claude-3-5-haiku-20241022",
        role="assistant",
        stop_reason="end_turn",
        type="message",
        usage={"input_tokens": 1, "output_tokens": 1},
    )

    with patch.object(
        client._direct.messages, "create", return_value=fake_message
    ) as direct_create:
        message = client.messages.create(
            model="claude-3-5-haiku-20241022",
            max_tokens=50,
            messages=[{"role": "user", "content": "Hi"}],
        )

    direct_create.assert_called_once()
    assert message.content[0].text == "direct"


def test_streaming_uses_direct_client():
    configure(api_key="prune_test")
    client = Anthropic(api_key="sk-ant-test", prune_api_key="prune_test")

    with patch.object(client._direct.messages, "create") as direct_create:
        direct_create.return_value = MagicMock()
        client.messages.create(
            model="claude-3-5-haiku-20241022",
            max_tokens=50,
            messages=[{"role": "user", "content": "Hi"}],
            stream=True,
        )
        direct_create.assert_called_once()


@pytest.mark.integration
def test_real_api_call():
    import os

    if not os.getenv("ANTHROPIC_API_KEY") or not os.getenv("PRUNE_API_KEY"):
        pytest.skip("ANTHROPIC_API_KEY and PRUNE_API_KEY required")

    configure(base_url=os.getenv("PRUNE_BASE_URL", "http://localhost:8000"))

    client = Anthropic(
        api_key=os.environ["ANTHROPIC_API_KEY"],
        prune_api_key=os.environ["PRUNE_API_KEY"],
    )

    message = client.messages.create(
        model="claude-3-5-haiku-20241022",
        max_tokens=50,
        messages=[{"role": "user", "content": "Reply with the word ok."}],
    )

    assert message.content
    assert len(message.content) > 0
