"""
Prune SDK — reduce LLM API costs with a one-line import change.

Example::

    from prune import Anthropic

    client = Anthropic(api_key="sk-ant-...", prune_api_key="prune_...")
    message = client.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=1024,
        messages=[{"role": "user", "content": "Hello"}],
    )
"""

__version__ = "0.1.0"

from prune.anthropic import Anthropic, AsyncAnthropic
from prune.config import configure, get_prune_config
from prune.exceptions import PruneConfigError, PruneError, PruneProxyError
from prune.openai import AsyncOpenAI, OpenAI

__all__ = [
    "Anthropic",
    "AsyncAnthropic",
    "OpenAI",
    "AsyncOpenAI",
    "configure",
    "get_prune_config",
    "PruneError",
    "PruneConfigError",
    "PruneProxyError",
    "__version__",
]
