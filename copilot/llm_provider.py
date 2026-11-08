"""
LLM provider abstraction for the AI SOC Copilot.

Supported providers:
- gemini
- anthropic
- openai
- mock

Gemini is the recommended provider for this project.
"""

from __future__ import annotations

import json
import os


class LLMProvider:
    """Base interface for LLM providers."""

    def complete(self, system: str, user: str) -> str:
        raise NotImplementedError


class GeminiProvider(LLMProvider):
    """Google Gemini provider using the current Interactions API."""

    def __init__(
        self,
        model: str = "gemini-3.5-flash-lite",
    ):
        from google import genai

        api_key = os.getenv("GEMINI_API_KEY")

        if not api_key:
            raise RuntimeError(
                "GEMINI_API_KEY environment variable is not set."
            )

        self.client = genai.Client(
            api_key=api_key
        )

        self.model = model

    def complete(
        self,
        system: str,
        user: str,
    ) -> str:
        """Send a system instruction and user evidence to Gemini."""

        prompt = f"""
SYSTEM INSTRUCTIONS
{system}

USER / SECURITY EVIDENCE
{user}
""".strip()

        interaction = self.client.interactions.create(
            model=self.model,
            input=prompt,
        )

        output = interaction.output_text

        if not output:
            raise RuntimeError(
                "Gemini returned an empty response."
            )

        return output


class AnthropicProvider(LLMProvider):
    """Anthropic provider."""

    def __init__(
        self,
        model: str = "claude-haiku-4-5-20251001",
    ):
        import anthropic

        self.client = anthropic.Anthropic(
            api_key=os.getenv("ANTHROPIC_API_KEY")
        )

        self.model = model

    def complete(
        self,
        system: str,
        user: str,
    ) -> str:

        response = self.client.messages.create(
            model=self.model,
            max_tokens=800,
            system=system,
            messages=[
                {
                    "role": "user",
                    "content": user,
                }
            ],
        )

        return response.content[0].text


class OpenAIProvider(LLMProvider):
    """OpenAI provider."""

    def __init__(
        self,
        model: str = "gpt-4o-mini",
    ):
        from openai import OpenAI

        self.client = OpenAI(
            api_key=os.getenv("OPENAI_API_KEY")
        )

        self.model = model

    def complete(
        self,
        system: str,
        user: str,
    ) -> str:

        response = self.client.chat.completions.create(
            model=self.model,
            max_tokens=800,
            messages=[
                {
                    "role": "system",
                    "content": system,
                },
                {
                    "role": "user",
                    "content": user,
                },
            ],
        )

        return response.choices[0].message.content


class MockProvider(LLMProvider):
    """
    No API key required.

    Used for deterministic testing of the complete pipeline.
    This is NOT real AI analysis.
    """

    def complete(
        self,
        system: str,
        user: str,
    ) -> str:

        injection_detected = (
            "sanitization flagged" in user
        )

        return json.dumps(
            {
                "attack_technique": "T1204.002",
                "severity": "Medium",
                "confidence": 55,
                "recommended_action": (
                    "[MOCK MODE — no LLM called] "
                    "Manually review this alert; "
                    "set an API key for real analysis."
                ),
                "explanation": (
                    "This is a mock response for "
                    "demonstration purposes only — "
                    "no LLM was actually called."
                ),
                "injection_attempt_detected": (
                    injection_detected
                ),
            }
        )


def get_provider() -> LLMProvider:
    """Create the configured LLM provider."""

    provider_name = os.getenv(
        "LLM_PROVIDER",
        "mock",
    ).lower()

    if provider_name == "gemini":
        return GeminiProvider()

    if provider_name == "anthropic":
        return AnthropicProvider()

    if provider_name == "openai":
        return OpenAIProvider()

    if provider_name == "mock":
        return MockProvider()

    raise ValueError(
        f"Unknown LLM_PROVIDER: {provider_name}"
    )