"""Orchestrates deterministic assessment and optional AI explanations.

Contract (§5 - honest AI behaviour):
- The deterministic baseline always decides category, risk_score and
  indicators (evidence). The AI can only improve the WORDING of the
  explanation, next steps and limitations - never the verdict.
- If the provider fails, times out, or returns output that does not match
  the strict schema, the baseline is returned unchanged. We never fabricate
  a successful analysis: the response's `source` field says which engine
  produced the text ("deterministic_rules" vs "openrouter_ai_explanation").
- `verification` guidance is deterministic and survives every path.
"""

import logging

from pydantic import ValidationError

from .baseline import analyze_text as analyze_baseline
from .openrouter_client import (
    OpenRouterClient,
    OpenRouterClientError,
    OpenRouterConfig,
)
from .prompts import build_analysis_messages
from .schemas import AIAnalysisExplanation, RiskCategory, ScamAssessment
from ..repeat_scam import RepeatSignal, apply_repeat_signal


logger = logging.getLogger(__name__)


def parse_explanation(content: str) -> AIAnalysisExplanation:
    """Validate model JSON, allowing a surrounding Markdown JSON fence."""
    response = content.strip()
    if response.startswith("```") and response.endswith("```"):
        first_line, separator, body = response.partition("\n")
        if separator and first_line[3:].strip().casefold() in {"", "json"}:
            response = body[:-3].strip()
    return AIAnalysisExplanation.model_validate_json(response)


async def analyze_text(
    text: str, repeat: RepeatSignal | None = None
) -> ScamAssessment:
    """Assess text deterministically and optionally enrich it with OpenRouter AI.

    `repeat` carries the caller's report-history lookup (same contact or
    provider reported before). It is applied to the deterministic assessment
    BEFORE the AI is consulted, so the escalation is rule-based and the AI
    only explains it.
    """
    baseline = analyze_baseline(text)
    if repeat is not None:
        baseline = apply_repeat_signal(baseline, repeat)
    if baseline.category == RiskCategory.INCONCLUSIVE:
        return baseline

    config = OpenRouterConfig.from_env()
    if not config.is_configured:
        if config.api_key and not config.model:
            logger.warning(
                "OPENROUTER_API_KEY is set but OPENROUTER_MODEL is missing; "
                "using deterministic analysis."
            )
        return baseline

    try:
        content = await OpenRouterClient(config).complete(
            build_analysis_messages(text, baseline, repeat=repeat)
        )
        explanation = parse_explanation(content)
    except OpenRouterClientError:
        logger.warning(
            "OpenRouter AI analysis failed; using deterministic analysis.",
            exc_info=True,
        )
        return baseline
    except (ValueError, ValidationError):
        logger.warning(
            "OpenRouter AI analysis returned invalid structured content; "
            "using deterministic analysis."
        )
        return baseline

    return baseline.model_copy(
        update={
            "explanation": explanation.explanation,
            "next_steps": explanation.next_steps,
            "limitations": explanation.limitations,
            "source": "openrouter_ai_explanation",
        }
    )
