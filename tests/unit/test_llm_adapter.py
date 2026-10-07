from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from phishshield.core.llm.gemini_adapter import GeminiAdapter


@pytest.mark.asyncio
async def test_gemini_adapter_initialization():
    with patch("phishshield.core.llm.gemini_adapter.genai.Client"):
        adapter = GeminiAdapter(api_key="mock_key")
        assert adapter is not None


@pytest.mark.asyncio
async def test_gemini_adapter_analyze_text():
    mock_response = MagicMock()
    mock_response.text = "Sitio sospechoso de Phishing"

    with patch("phishshield.core.llm.gemini_adapter.genai.Client") as mock_client_cls:
        mock_client = MagicMock()
        mock_aio = MagicMock()
        mock_models = MagicMock()
        mock_models.generate_content = AsyncMock(return_value=mock_response)
        mock_aio.models = mock_models
        mock_client.aio = mock_aio
        mock_client_cls.return_value = mock_client

        adapter = GeminiAdapter(api_key="mock_key")
        result = await adapter.analyze_text("Analiza este dominio")
        assert result == "Sitio sospechoso de Phishing"
