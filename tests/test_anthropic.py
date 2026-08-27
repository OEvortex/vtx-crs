"""Tests for the Anthropic API client wrapper."""

from __future__ import annotations

import os
from unittest.mock import MagicMock, patch

import pytest

from vtx_crs.tools.crs.anthropic_client import DEFAULT_MODEL, AnthropicClient


def test_client_requires_api_key() -> None:
    with (
        patch.dict(os.environ, {}, clear=True),
        pytest.raises(ValueError, match="ANTHROPIC_API_KEY"),
    ):
        AnthropicClient()


def test_client_uses_env_key() -> None:
    fake_key = "sk-ant-test-key"
    with patch.dict(os.environ, {"ANTHROPIC_API_KEY": fake_key}):
        client = AnthropicClient()
    assert client.api_key == fake_key
    assert client.model == DEFAULT_MODEL


def test_client_send_message() -> None:
    fake_key = "sk-ant-test-key"
    fake_response_text = "Hello from Claude!"

    with patch.dict(os.environ, {"ANTHROPIC_API_KEY": fake_key}):
        client = AnthropicClient()

    mock_message = MagicMock()
    mock_message.content = [MagicMock(text=fake_response_text)]

    with patch.object(client.client.messages, "create", return_value=mock_message) as mock_create:
        result = client.send_message("Say hello")

    assert result == fake_response_text
    mock_create.assert_called_once()
    call_kwargs = mock_create.call_args.kwargs
    assert call_kwargs["model"] == DEFAULT_MODEL
    assert call_kwargs["max_tokens"] == 1024
    assert call_kwargs["messages"] == [{"role": "user", "content": "Say hello"}]


def test_client_send_message_custom_model() -> None:
    fake_key = "sk-ant-test-key"
    custom_model = "claude-opus-4-20250514"

    with patch.dict(os.environ, {"ANTHROPIC_API_KEY": fake_key}):
        client = AnthropicClient(model=custom_model)

    assert client.model == custom_model

    mock_message = MagicMock()
    mock_message.content = [MagicMock(text="test")]

    with patch.object(client.client.messages, "create", return_value=mock_message) as mock_create:
        client.send_message("test")

    assert mock_create.call_args.kwargs["model"] == custom_model
