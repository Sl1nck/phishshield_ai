from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from google.genai.errors import APIError, ServerError
from pydantic import BaseModel, ValidationError

from phishshield.core.llm.gemini_adapter import GeminiAdapter, _is_transient_error
from phishshield.core.llm.schemas import RiskLevel, ThreatAnalysisReport
from phishshield.scraper.parser import ParsedDOM


class DummySchema(BaseModel):
    message: str


# --- 1. Tests para _is_transient_error ---
def test_is_transient_error():
    assert _is_transient_error(ServerError("Server error", response_json={})) is True

    err_429 = APIError(429, response_json={})
    assert _is_transient_error(err_429) is True

    err_500 = APIError(500, response_json={})
    assert _is_transient_error(err_500) is True

    err_400 = APIError(400, response_json={})
    assert _is_transient_error(err_400) is False

    assert _is_transient_error(ValueError("Otro error")) is False


# --- 2. Tests de Inicialización ---
def test_gemini_adapter_init_missing_api_key():
    with patch("phishshield.core.llm.gemini_adapter.os.getenv", return_value=None), patch(
        "phishshield.core.llm.gemini_adapter.settings"
    ) as mock_settings:
        mock_settings.GEMINI_API_KEY = None
        with pytest.raises(ValueError, match="No se proporcionó una clave de API válida"):
            GeminiAdapter(api_key=None)


# --- 3. Tests de analyze_text ---
@pytest.mark.asyncio
async def test_gemini_adapter_analyze_text_success():
    mock_response = MagicMock()
    mock_response.text = "Sitio sospechoso"

    with patch("phishshield.core.llm.gemini_adapter.genai.Client") as mock_client_cls:
        mock_client = MagicMock()
        mock_client.aio.models.generate_content = AsyncMock(return_value=mock_response)
        mock_client_cls.return_value = mock_client

        adapter = GeminiAdapter(api_key="test_api_key")
        res = await adapter.analyze_text("Consulta de prueba")
        assert res == "Sitio sospechoso"


@pytest.mark.asyncio
async def test_gemini_adapter_analyze_text_empty_response():
    mock_response = MagicMock()
    mock_response.text = None

    with patch("phishshield.core.llm.gemini_adapter.genai.Client") as mock_client_cls:
        mock_client = MagicMock()
        mock_client.aio.models.generate_content = AsyncMock(return_value=mock_response)
        mock_client_cls.return_value = mock_client

        adapter = GeminiAdapter(api_key="test_api_key")
        res = await adapter.analyze_text("Consulta de prueba")
        assert res == ""


# --- 4. Tests de analyze_multimodal ---
@pytest.mark.asyncio
async def test_gemini_adapter_analyze_multimodal_success():
    mock_response = MagicMock()
    mock_response.text = "Análisis de imagen completado"

    with patch("phishshield.core.llm.gemini_adapter.genai.Client") as mock_client_cls:
        mock_client = MagicMock()
        mock_client.aio.models.generate_content = AsyncMock(return_value=mock_response)
        mock_client_cls.return_value = mock_client

        adapter = GeminiAdapter(api_key="test_api_key")
        res = await adapter.analyze_multimodal(
            prompt="Analizar captura", image_bytes=b"fake_image_bytes"
        )
        assert res == "Análisis de imagen completado"


@pytest.mark.asyncio
async def test_gemini_adapter_analyze_multimodal_empty():
    mock_response = MagicMock()
    mock_response.text = None

    with patch("phishshield.core.llm.gemini_adapter.genai.Client") as mock_client_cls:
        mock_client = MagicMock()
        mock_client.aio.models.generate_content = AsyncMock(return_value=mock_response)
        mock_client_cls.return_value = mock_client

        adapter = GeminiAdapter(api_key="test_api_key")
        res = await adapter.analyze_multimodal(
            prompt="Analizar captura", image_bytes=b"fake_image_bytes"
        )
        assert res == ""


# --- 5. Tests de analyze_structured ---
@pytest.mark.asyncio
async def test_gemini_adapter_analyze_structured_via_parsed_instance():
    dummy_obj = DummySchema(message="OK")
    mock_response = MagicMock()
    mock_response.parsed = dummy_obj

    with patch("phishshield.core.llm.gemini_adapter.genai.Client") as mock_client_cls:
        mock_client = MagicMock()
        mock_client.aio.models.generate_content = AsyncMock(return_value=mock_response)
        mock_client_cls.return_value = mock_client

        adapter = GeminiAdapter(api_key="test_api_key")
        res = await adapter.analyze_structured("Prompt", DummySchema)
        assert res.message == "OK"


@pytest.mark.asyncio
async def test_gemini_adapter_analyze_structured_via_parsed_dict():
    mock_response = MagicMock()
    mock_response.parsed = {"message": "Dict OK"}

    with patch("phishshield.core.llm.gemini_adapter.genai.Client") as mock_client_cls:
        mock_client = MagicMock()
        mock_client.aio.models.generate_content = AsyncMock(return_value=mock_response)
        mock_client_cls.return_value = mock_client

        adapter = GeminiAdapter(api_key="test_api_key")
        res = await adapter.analyze_structured("Prompt", DummySchema)
        assert res.message == "Dict OK"


@pytest.mark.asyncio
async def test_gemini_adapter_analyze_structured_via_json_string():
    mock_response = MagicMock()
    mock_response.parsed = None
    mock_response.text = '{"message": "JSON Text OK"}'

    with patch("phishshield.core.llm.gemini_adapter.genai.Client") as mock_client_cls:
        mock_client = MagicMock()
        mock_client.aio.models.generate_content = AsyncMock(return_value=mock_response)
        mock_client_cls.return_value = mock_client

        adapter = GeminiAdapter(api_key="test_api_key")
        res = await adapter.analyze_structured("Prompt", DummySchema)
        assert res.message == "JSON Text OK"


@pytest.mark.asyncio
async def test_gemini_adapter_analyze_structured_invalid_response():
    mock_response = MagicMock()
    mock_response.parsed = None
    mock_response.text = ""

    with patch("phishshield.core.llm.gemini_adapter.genai.Client") as mock_client_cls:
        mock_client = MagicMock()
        mock_client.aio.models.generate_content = AsyncMock(return_value=mock_response)
        mock_client_cls.return_value = mock_client

        adapter = GeminiAdapter(api_key="test_api_key")
        with pytest.raises(ValueError, match="Respuesta nula o inválida"):
            await adapter.analyze_structured("Prompt", DummySchema)


# --- 6. Tests de analyze_phishing_site (Casos borde, Fallback y Errores) ---
@pytest.mark.asyncio
async def test_gemini_adapter_analyze_phishing_site_mocked():
    mock_report = ThreatAnalysisReport(
        risk_score=90,
        risk_level=RiskLevel.CRITICAL,
        impersonated_brand="PayPal",
        detected_indicators=[
            "Formulario no oficial de autenticación",
            "Logo suplantado",
        ],
        reasoning="El sitio solicita credenciales de PayPal bajo una URL no oficial.",
        recommended_action="Bloquear la URL en la red corporativa",
    )

    mock_response = MagicMock()
    mock_response.parsed = mock_report

    with patch("phishshield.core.llm.gemini_adapter.genai.Client") as mock_client_cls:
        mock_client = MagicMock()
        mock_client.aio.models.generate_content = AsyncMock(return_value=mock_response)
        mock_client_cls.return_value = mock_client

        adapter = GeminiAdapter(api_key="test_api_key")

        sample_dom = ParsedDOM(
            title="Ingreso a su cuenta PayPal",
            links=["https://paypal.com"],
            form_actions=["http://attacker.com/login"],
            input_fields=[{"name": "passwd", "type": "password"}],
            clean_text="Inicie sesión en PayPal",
        )

        res = await adapter.analyze_phishing_site(
            parsed_dom=sample_dom,
            screenshot_bytes=b"fake_png_bytes",
            url="https://paypa1-login.com",
            heuristic_flags=[{"rule_id": "URL_01", "score": 20}],
        )

        assert res.risk_score == 90
        assert res.risk_level == RiskLevel.CRITICAL
        assert res.impersonated_brand == "PayPal"


@pytest.mark.asyncio
async def test_gemini_adapter_analyze_phishing_site_via_json_string():
    raw_json = """
    {
        "risk_score": 85,
        "risk_level": "HIGH",
        "impersonated_brand": "Google",
        "detected_indicators": ["Dominio sospechoso"],
        "reasoning": "Clon de pantalla de login de Google.",
        "recommended_action": "Bloquear acceso"
    }
    """
    mock_response = MagicMock()
    mock_response.parsed = None
    mock_response.text = raw_json

    with patch("phishshield.core.llm.gemini_adapter.genai.Client") as mock_client_cls:
        mock_client = MagicMock()
        mock_client.aio.models.generate_content = AsyncMock(return_value=mock_response)
        mock_client_cls.return_value = mock_client

        adapter = GeminiAdapter(api_key="test_api_key")

        class CustomDOM:
            forms = ["/login"]
            external_links = ["http://example.com"]
            iframes = ["http://iframe.com"]
            text_content = "Texto de la página"
            has_password_field = True
            title = "Login Google"

        res = await adapter.analyze_phishing_site(
            parsed_dom=CustomDOM(),
            screenshot_bytes=None,
            url="http://fake-google.com",
        )

        assert res.risk_score == 85
        assert res.impersonated_brand == "Google"


@pytest.mark.asyncio
async def test_gemini_adapter_analyze_phishing_site_fallback_model_success():
    mock_report = ThreatAnalysisReport(
        risk_score=95,
        risk_level=RiskLevel.CRITICAL,
        impersonated_brand="Banco",
        detected_indicators=["Suplantación"],
        reasoning="Análisis con modelo de respaldo.",
        recommended_action="Bloquear inmediatamente",
    )

    mock_response_success = MagicMock()
    mock_response_success.parsed = mock_report

    with patch("phishshield.core.llm.gemini_adapter.genai.Client") as mock_client_cls:
        mock_client = MagicMock()
        mock_client.aio.models.generate_content = AsyncMock(
            side_effect=[
                ServerError("Límite o error de servidor", response_json={}),
                mock_response_success,
            ]
        )
        mock_client_cls.return_value = mock_client

        adapter = GeminiAdapter(
            api_key="test_api_key",
            primary_model="gemini-2.0-flash",
            fallback_model="gemini-1.5-pro",
        )

        sample_dom = ParsedDOM(title="Banco Login")
        res = await adapter.analyze_phishing_site(
            parsed_dom=sample_dom,
            url="http://banco-phish.com",
        )

        assert res.risk_score == 95
        assert mock_client.aio.models.generate_content.call_count == 2


@pytest.mark.asyncio
async def test_gemini_adapter_analyze_phishing_site_all_models_fail():
    with patch("phishshield.core.llm.gemini_adapter.genai.Client") as mock_client_cls:
        mock_client = MagicMock()
        mock_client.aio.models.generate_content = AsyncMock(
            side_effect=ServerError("Error persistente de API", response_json={})
        )
        mock_client_cls.return_value = mock_client

        adapter = GeminiAdapter(
            api_key="test_api_key",
            primary_model="gemini-2.0-flash",
            fallback_model="gemini-1.5-pro",
        )

        sample_dom = ParsedDOM(title="Prueba")

        with pytest.raises(ServerError):
            await adapter.analyze_phishing_site(
                parsed_dom=sample_dom,
                url="http://test.com",
            )


@pytest.mark.asyncio
async def test_gemini_adapter_analyze_phishing_site_json_validation_error():
    mock_response = MagicMock()
    mock_response.parsed = None
    mock_response.text = '{"json_invalido": true}'

    with patch("phishshield.core.llm.gemini_adapter.genai.Client") as mock_client_cls:
        mock_client = MagicMock()
        mock_client.aio.models.generate_content = AsyncMock(return_value=mock_response)
        mock_client_cls.return_value = mock_client

        adapter = GeminiAdapter(api_key="test_api_key")
        sample_dom = ParsedDOM(title="Prueba")

        with pytest.raises(ValidationError):
            await adapter.analyze_phishing_site(
                parsed_dom=sample_dom,
                url="http://test.com",
            )