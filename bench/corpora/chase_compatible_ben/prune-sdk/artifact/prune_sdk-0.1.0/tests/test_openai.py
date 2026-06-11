"""Tests for Prune OpenAI client."""

import httpx
import pytest
import respx
from openai.types.chat import ChatCompletion

from prune import OpenAI, configure
from prune.exceptions import PruneConfigError


@pytest.fixture(autouse=True)
def reset_config():
    import prune.config as cfg

    cfg._config = None
    yield
    cfg._config = None


def test_openai_client_initialization():
    client = OpenAI(api_key="sk-test", prune_api_key="prune_test")
    assert client.api_key == "sk-test"
    assert client.prune_api_key == "prune_test"


def test_missing_prune_key_raises_error():
    with pytest.raises(PruneConfigError, match="Prune API key required"):
        OpenAI(api_key="sk-test")


@respx.mock
def test_openai_fallback_on_404():
    configure(api_key="prune_test", base_url="http://localhost:8000")

    respx.post("http://localhost:8000/v1/proxy/openai/chat/completions").mock(
        return_value=httpx.Response(404, text="not found")
    )

    client = OpenAI(api_key="sk-test", prune_api_key="prune_test")

    fake = ChatCompletion.model_validate(
        {
            "id": "chatcmpl-test",
            "object": "chat.completion",
            "created": 0,
            "model": "gpt-4o-mini",
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": "hi"},
                    "finish_reason": "stop",
                }
            ],
            "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
        }
    )

    from unittest.mock import patch

    with patch.object(
        client._direct.chat.completions, "create", return_value=fake
    ) as direct:
        result = client.chat.completions.create(
            model="gpt-4o-mini",
            max_tokens=10,
            messages=[{"role": "user", "content": "Hi"}],
        )

    direct.assert_called_once()
    assert result.choices[0].message.content == "hi"
