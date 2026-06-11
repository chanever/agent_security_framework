# Prune SDK

Reduce your LLM API costs by 40–70% (blended over repeat & similar traffic) with a one-line import change — **no prompt edits**, same responses on cache miss.

```python
# Before
from anthropic import Anthropic

# After
from prune import Anthropic
```

## Supported providers

| Provider | Status |
|----------|--------|
| **Anthropic** (Claude Opus, Sonnet, Haiku) | Live via proxy |
| **OpenAI** (GPT-4o, GPT-4o-mini, o-series) | Live via proxy |
| **Google Gemini** | Planned |

## Installation

```bash
pip install prune-sdk
```

For local backend development:

```bash
export PRUNE_BASE_URL="http://127.0.0.1:8000"
```

Install from source (contributors):

```bash
pip install -e "./prune-sdk[dev]"
```

## Quick start

### Anthropic (Claude)

```python
from prune import Anthropic

client = Anthropic(
    api_key="sk-ant-your-key",
    prune_api_key="prune_your_key",
)

message = client.messages.create(
    model="claude-sonnet-4-20250514",
    max_tokens=1024,
    messages=[{"role": "user", "content": "Hello, Claude!"}],
)

print(message.content[0].text)
print(client.last_prune_metadata)  # cache hit, tokens saved, etc.
```

### OpenAI (GPT)

```python
from prune import OpenAI

client = OpenAI(
    api_key="sk-your-openai-key",
    prune_api_key="prune_your_key",
)

completion = client.chat.completions.create(
    model="gpt-4o-mini",
    max_tokens=256,
    messages=[{"role": "user", "content": "Hello!"}],
)

print(completion.choices[0].message.content)
```

### Async

```python
from prune import AsyncAnthropic

client = AsyncAnthropic(
    api_key="sk-ant-...",
    prune_api_key="prune_...",
)

message = await client.messages.create(
    model="claude-3-5-haiku-20241022",
    max_tokens=100,
    messages=[{"role": "user", "content": "Hi"}],
)
```

## Configuration

**Environment variables:**

```bash
export PRUNE_API_KEY="prune_your_key"
export PRUNE_BASE_URL="https://api.prune.so"   # or http://127.0.0.1:8000 for local backend
export PRUNE_FALLBACK="true"                     # fallback to direct API if proxy fails
```

**Programmatic:**

```python
import prune

prune.configure(api_key="prune_your_key", base_url="https://api.prune.so")

client = prune.Anthropic(api_key="sk-ant-...")
```

## Behavior

| Feature | Details |
|---------|---------|
| **Proxy routing** | Anthropic → `/v1/proxy/anthropic/messages` · OpenAI → `/v1/proxy/openai/chat/completions` |
| **Quality** | Cache miss = same payload to the provider as without Prune. Cache hit = identical prior response. |
| **Savings** | Exact + semantic cache; Claude system prompt caching. See `docs/SAVINGS_MODEL.md`. |
| **Response type** | Real `anthropic.types.Message` / `ChatCompletion` objects |
| **Streaming** | Bypasses Prune; uses official SDK directly |
| **Fallback** | On proxy outage (5xx / network), calls Anthropic/OpenAI directly |
| **Disable Prune** | `Anthropic(..., enable_prune=False)` |
| **Prompt Pass** | HTTP header `X-Prune-Optimize: light` or `compact` (optional; default off) |

## Direct HTTP (no SDK)

If you only need to test the proxy, skip the SDK and POST to the backend:

```bash
curl -X POST http://127.0.0.1:8000/v1/proxy/anthropic/messages ^
  -H "X-Prune-Key: prune_your_key" ^
  -H "Content-Type: application/json" ^
  -d "{\"model\":\"claude-sonnet-4-20250514\",\"max_tokens\":64,\"messages\":[{\"role\":\"user\",\"content\":\"Hello\"}],\"user_api_key\":\"sk-ant-...\"}"
```

```python
import httpx

resp = httpx.post(
    "http://127.0.0.1:8000/v1/proxy/anthropic/messages",
    headers={"X-Prune-Key": "prune_your_key"},
    json={
        "model": "claude-sonnet-4-20250514",
        "max_tokens": 64,
        "messages": [{"role": "user", "content": "Hello"}],
        "user_api_key": "sk-ant-...",
    },
    timeout=60,
)
print(resp.json())
```

## Development

```bash
cd prune-sdk
pip install -e ".[dev]"
pytest tests/ -q
pytest tests/ -m integration  # needs ANTHROPIC_API_KEY + PRUNE_API_KEY
```

## License

MIT
