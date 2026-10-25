# AI analysis module

This package owns scam and suspicious-investment text analysis. It is designed
to plug into the shared FastAPI backend without owning application routes,
authentication, database persistence, or FSCA verification.

## Module responsibilities

- `schemas.py`: validated inputs and the assessment response contract.
- `baseline.py`: simple phrase checks and baseline risk categorisation. These
  checks are clues for further review, not a final decision about fraud.
- `prompts.py`: instructions that treat submitted content as untrusted evidence.
- `openrouter_client.py`: backend-only OpenRouter API integration and configuration.
- `service.py`: combines the baseline with optional AI explanations.
- `backend/tests/services/ai_analysis/`: tests for the baseline, validation,
  prompt-injection resistance, and AI service failure behavior.

The baseline must remain usable when the OpenRouter service is unavailable. AI
output is explanatory evidence, not proof of fraud or a legal finding. API
credentials belong in an untracked local `.env` file, never in frontend code
or source control.

## OpenRouter configuration

The service reads these values from the process environment or `backend/.env`.
Set `OPENROUTER_API_KEY` to a newly created OpenRouter key; do not reuse a key
that has been posted in chat or committed to source control.

- `OPENROUTER_API_KEY` (required to enable AI explanations)
- `OPENROUTER_MODEL` (defaults to `google/gemma-4-31b-it`)
- `OPENROUTER_BASE_URL` (optional; defaults to `https://openrouter.ai/api/v1`)
- `OPENROUTER_TIMEOUT_SECONDS` (optional; defaults to 30)

For migration, the client accepts `NVIDIA_API_KEY` and `NVIDIA_MODEL` as
fallbacks, but always uses the OpenRouter endpoint unless
`OPENROUTER_BASE_URL` is configured.

Use `await analyze_text(text)` from `service.py`. The deterministic rules
always determine the risk category and indicators; OpenRouter only supplies the
explanation, next steps, and limitations. If the AI provider fails or returns
invalid content, the service logs the failure and returns the deterministic
assessment.

## HTTP API

Run the backend from the repository root with
`uvicorn backend.app.main:app --reload`. Submit a JSON `POST` to
`/api/v1/analysis`:

```json
{"text": "Message or offer text to check"}
```

The response contains the risk category, indicators, explanation, next steps,
limitations, and a `source` value indicating whether AI provided the
explanation (`openrouter_ai_explanation` for OpenRouter, otherwise
`deterministic_rules`). Input text must contain 1-5000 characters.
