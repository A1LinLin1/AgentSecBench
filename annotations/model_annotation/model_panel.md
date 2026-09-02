# Hybrid Model Panel

Verified on 2026-08-06. The OpenRouter slug, not a first-party API ID, is the
experimental model identifier.

| Rater | Exact OpenRouter slug | Reasoning setting |
|---|---|---|
| M1 / OpenAI | `openai/gpt-5-mini` | medium, reasoning excluded from response |
| M2 / Anthropic | `anthropic/claude-sonnet-4.6` | medium, reasoning excluded |
| M3 / Google | `google/gemini-3.5-flash-lite` | medium, reasoning excluded |
| M4 / Qwen | `qwen/qwen3-max` | provider default; no dedicated thinking mode |
| M5 / DeepSeek | `deepseek-v4-pro` (official API) | thinking enabled, high; reasoning redacted locally |

M1--M4 use `https://openrouter.ai/api/v1/chat/completions` with one
`OPENROUTER_API_KEY` and the following constraints:

- `allow_fallbacks: false`
- `require_parameters: true`
- `data_collection: deny`
- `zdr: true` by default; an explicit, manifest-recorded non-ZDR mode is
  available only when separately approved
- strict JSON Schema response format
- `max_tokens: 3000`
- one fixed `session_id` per model rater
- no tools, browsing, retrieval, or code execution

M5 uses `https://api.deepseek.com/chat/completions` with a separate
`DEEPSEEK_API_KEY`, `response_format=json_object`, thinking mode `high`, and a
6000-token ceiling. DeepSeek official JSON mode does not enforce the supplied
JSON Schema, so the same schema is validated locally and invalid outputs are
audited. OpenRouter routing and data-policy flags do not apply to this direct
request; only public repository code is supplied.

The runner records the returned model, generation ID, upstream provider, token
usage, reported cost, and system fingerprint. It stops if a model is observed on
more than one upstream provider during the run.

Important: `qwen/qwen3-max` is not the same identifier as the previously planned
first-party `qwen3-max-2026-01-23`. Publications must report the OpenRouter slug.

Official references:

- https://openrouter.ai/docs/quickstart
- https://openrouter.ai/docs/guides/routing/provider-selection
- https://openrouter.ai/docs/guides/features/structured-outputs
- https://openrouter.ai/docs/guides/features/zdr
- https://openrouter.ai/openai/gpt-5-mini
- https://openrouter.ai/anthropic/claude-sonnet-4.6
- https://openrouter.ai/google/gemini-3.5-flash-lite
- https://openrouter.ai/qwen/qwen3-max
- https://openrouter.ai/deepseek/deepseek-v4-pro
- https://api-docs.deepseek.com/api/create-chat-completion
- https://api-docs.deepseek.com/guides/json_mode/
- https://api-docs.deepseek.com/quick_start/pricing
