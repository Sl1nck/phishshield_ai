from unittest.mock import patch

import pytest

from phishshield.core.llm.factory import LLMFactory
from phishshield.core.llm.gemini_adapter import GeminiAdapter


def test_factory_creates_gemini_adapter(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "mock_key_12345")

    with patch("phishshield.core.llm.gemini_adapter.genai.Client"):
        adapter = LLMFactory.create_adapter("gemini")
        assert isinstance(adapter, GeminiAdapter)


def test_factory_raises_error_for_unsupported_provider():
    with pytest.raises(ValueError, match="Proveedor de IA 'unsupported' no soportado"):
        LLMFactory.create_adapter("unsupported")
