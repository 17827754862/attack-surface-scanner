# Optional DeepSeek Analysis

The scan graph is deterministic. LLM analysis is disabled by default and never chooses tools,
changes targets, creates findings or modifies severity/confidence.

Enable it in `.env`:

```text
LLM_ENABLED=true
LLM_BASE_URL=http://host.docker.internal:11434/v1
LLM_API_KEY=local-key
LLM_MODEL=deepseek-chat
```

The node sends only compact finding metadata to the configured OpenAI-compatible endpoint.
It requests a defensive risk summary, priority and retesting narrative. API keys and credentials
are not included in the prompt. Timeouts, HTTP errors and malformed responses degrade to a
`skipped` node without affecting findings or the report.

For fully offline operation keep `LLM_ENABLED=false`; this is the default and competition-safe mode.
