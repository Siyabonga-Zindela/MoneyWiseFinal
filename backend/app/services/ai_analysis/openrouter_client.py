"""Backend-only client for OpenRouter's OpenAI-compatible API."""

import math
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

import httpx
from dotenv import load_dotenv


DEFAULT_BASE_URL = "https://openrouter.ai/api/v1"
DEFAULT_MODEL = "google/gemma-4-31b-it"
DEFAULT_TIMEOUT_SECONDS = 30.0
DOTENV_PATH = Path(__file__).resolve().parents[3] / ".env"


class OpenRouterClientError(RuntimeError):
    """Raised when OpenRouter cannot provide a usable response."""


@dataclass(frozen=True)
class OpenRouterConfig:
    api_key: str
    model: str
    base_url: str = DEFAULT_BASE_URL
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS

    @classmethod
    def from_env(
        cls, environ: Mapping[str, str] | None = None
    ) -> "OpenRouterConfig":
        """Load OpenRouter settings from the process environment and backend/.env."""
        if environ is None:
            load_dotenv(DOTENV_PATH)
            environ = os.environ

        api_key = (
            environ.get("OPENROUTER_API_KEY", "").strip()
            or environ.get("NVIDIA_API_KEY", "").strip()
        )
        model = (
            environ.get("OPENROUTER_MODEL", "").strip()
            or environ.get("NVIDIA_MODEL", "").strip()
            or DEFAULT_MODEL
        )
        base_url = environ.get("OPENROUTER_BASE_URL", DEFAULT_BASE_URL).strip()
        timeout_value = environ.get(
            "OPENROUTER_TIMEOUT_SECONDS",
            environ.get("NVIDIA_TIMEOUT_SECONDS", str(DEFAULT_TIMEOUT_SECONDS)),
        ).strip()

        try:
            timeout_seconds = float(timeout_value)
        except ValueError as exc:
            raise ValueError("OPENROUTER_TIMEOUT_SECONDS must be a number.") from exc

        if not math.isfinite(timeout_seconds) or timeout_seconds <= 0:
            raise ValueError("OPENROUTER_TIMEOUT_SECONDS must be greater than zero.")
        if not base_url:
            raise ValueError("OPENROUTER_BASE_URL must not be empty.")

        return cls(
            api_key=api_key,
            model=model,
            base_url=base_url.rstrip("/"),
            timeout_seconds=timeout_seconds,
        )

    @property
    def is_configured(self) -> bool:
        return bool(self.api_key and self.model)


class OpenRouterClient:
    """Small async client for OpenRouter chat completions."""

    def __init__(
        self,
        config: OpenRouterConfig,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._config = config
        self._transport = transport

    async def complete(self, messages: list[dict[str, str]]) -> str:
        """Return the assistant message content or raise a safe client error."""
        headers = {
            "Authorization": f"Bearer {self._config.api_key}",
            "Accept": "application/json",
            "Content-Type": "application/json",
            "HTTP-Referer": "https://moneywise.app",
            "X-Title": "MoneyWise",
        }
        payload = {
            "model": self._config.model,
            "messages": messages,
            "temperature": 0.2,
        }
        try:
            async with httpx.AsyncClient(
                timeout=self._config.timeout_seconds,
                transport=self._transport,
            ) as client:
                response = await client.post(
                    f"{self._config.base_url}/chat/completions",
                    headers=headers,
                    json=payload,
                )
        except httpx.TimeoutException as exc:
            raise OpenRouterClientError("The OpenRouter request timed out.") from exc
        except httpx.RequestError as exc:
            raise OpenRouterClientError("The OpenRouter request failed.") from exc

        if response.is_error:
            raise OpenRouterClientError(
                f"OpenRouter returned HTTP {response.status_code}."
            )

        try:
            response_body = response.json()
            content = response_body["choices"][0]["message"]["content"]
        except (ValueError, KeyError, IndexError, TypeError) as exc:
            raise OpenRouterClientError(
                "OpenRouter returned an invalid chat completion."
            ) from exc

        if not isinstance(content, str) or not content.strip():
            raise OpenRouterClientError(
                "OpenRouter returned an empty chat completion."
            )
        return content.strip()
