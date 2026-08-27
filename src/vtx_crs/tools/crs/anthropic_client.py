"""Minimal Anthropic API client wrapper.

Reads the API key from the ANTHROPIC_API_KEY environment variable.
"""

from __future__ import annotations

import os

from anthropic import Anthropic, APIError

DEFAULT_MODEL = "claude-sonnet-4-20250514"


class AnthropicClient:
    def __init__(self, api_key: str | None = None, model: str = DEFAULT_MODEL) -> None:
        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY", "")
        if not self.api_key:
            raise ValueError("ANTHROPIC_API_KEY environment variable is not set")
        self.client = Anthropic(api_key=self.api_key)
        self.model = model

    def send_message(self, prompt: str, max_tokens: int = 1024) -> str:
        """Send a simple user message and return the assistant's text response."""
        message = self.client.messages.create(
            model=self.model,
            max_tokens=max_tokens,
            messages=[{"role": "user", "content": prompt}],
        )
        block = message.content[0]
        return getattr(block, "text", str(block))
