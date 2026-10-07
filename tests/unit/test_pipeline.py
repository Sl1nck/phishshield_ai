from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from phishshield.core.llm.schemas import RiskLevel, ThreatAnalysisReport
from phishshield.pipeline import PhishShieldPipeline
from phishshield.scraper.browser import ScraperNetworkError


@patch("phishshield.pipeline.PlaywrightScraper")
def test_pipeline_runs_heuristics_on_scraped_dom(mock_scraper_cls):
    instance = mock_scraper_cls.return_value
    mock_artifacts = MagicMock()
    mock_artifacts.html_content = (
        "<html><head><title>Verificación de Cuenta</title></head>"
        '<body><form action="http://insecure-backend.com/login">'
        '<input type="password" name="pass"></form></body></html>'
    )
    mock_artifacts.screenshot_bytes = b"fake_screenshot"
    mock_artifacts.final_url = "https://suspicious-bank-login.com"

    instance.scrape_url = AsyncMock(return_value=mock_artifacts)

    pipeline = PhishShieldPipeline()
    report = pipeline.analyze_url("https://suspicious-bank-login.com")

    assert report.url == "https://suspicious-bank-login.com"
    assert report.heuristic_result is not None


@pytest.mark.asyncio
@patch("phishshield.pipeline.PlaywrightScraper")
async def test_pipeline_triggers_gemini_when_suspicious(mock_scraper_cls):
    instance = mock_scraper_cls.return_value
    mock_artifacts = MagicMock()
    mock_artifacts.html_content = (
        "<html><head><title>Ingreso de Seguridad</title></head>"
        '<body><form action="http://bad-actor.com/steal">'
        '<input type="password" name="pass"></form></body></html>'
    )
    mock_artifacts.screenshot_bytes = b"fake_screenshot"
    mock_artifacts.final_url = "http://suspicious-login.com"

    instance.scrape_url = AsyncMock(return_value=mock_artifacts)

    mock_gemini = MagicMock()
    mock_gemini.analyze_phishing_site = AsyncMock(
        return_value=ThreatAnalysisReport(
            risk_score=85,
            risk_level=RiskLevel.HIGH,
            impersonated_brand="Desconocida",
            detected_indicators=["Envío HTTP inseguro", "Campo de contraseña"],
            reasoning="El sitio intenta capturar credenciales sobre conexión no cifrada.",
            recommended_action="Bloquear acceso.",
        )
    )

    pipeline = PhishShieldPipeline(gemini_adapter=mock_gemini)
    report = await pipeline.analyze_url_async("http://suspicious-login.com")

    assert report.ai_report is not None
    assert report.ai_report.risk_score == 85

    # Verificación de propagación de alertas heurísticas hacia GeminiAdapter
    mock_gemini.analyze_phishing_site.assert_awaited_once()
    _, kwargs = mock_gemini.analyze_phishing_site.call_args
    assert "heuristic_flags" in kwargs
    assert isinstance(kwargs["heuristic_flags"], list)


@pytest.mark.asyncio
async def test_pipeline_handles_scraper_error_gracefully():
    """Valida que un fallo de red o timeout durante el scraping no detenga el pipeline."""
    mock_scraper = AsyncMock()
    mock_scraper.scrape_url.side_effect = ScraperNetworkError(
        "Error de conexión simulado"
    )

    pipeline = PhishShieldPipeline(scraper=mock_scraper)
    report = await pipeline.analyze_url_async(
        "https://invalid-domain.local", force_ai=True
    )

    assert report.error_message == "Error de conexión simulado"
    assert report.ai_report is None  # No debe invocar IA si falla la captura web
    assert report.parsed_dom is not None


@pytest.mark.asyncio
async def test_pipeline_handles_gemini_exception_gracefully():
    """Valida que si la API de Gemini falla, el reporte retorne los hallazgos heurísticos sin lanzar excepción."""
    mock_scraper = AsyncMock()
    mock_artifacts = MagicMock()
    mock_artifacts.html_content = "<html><body><h1>Test</h1></body></html>"
    mock_artifacts.screenshot_bytes = b"bytes"
    mock_artifacts.final_url = "https://example.com"
    mock_scraper.scrape_url.return_value = mock_artifacts

    mock_gemini = AsyncMock()
    mock_gemini.analyze_phishing_site.side_effect = RuntimeError(
        "API Key agotada o cuota excedida"
    )

    pipeline = PhishShieldPipeline(
        scraper=mock_scraper, gemini_adapter=mock_gemini
    )
    report = await pipeline.analyze_url_async(
        "https://example.com", force_ai=True
    )

    assert report.ai_report is None
    assert report.error_message is None
    assert report.heuristic_result is not None


@pytest.mark.asyncio
async def test_pipeline_sync_wrapper_raises_error_in_running_event_loop():
    """Valida que analyze_url() prevenga colisiones de event loops activos."""
    pipeline = PhishShieldPipeline()
    with pytest.raises(
        RuntimeError, match="no se puede llamar desde un event loop activo"
    ):
        pipeline.analyze_url("https://example.com")


@pytest.mark.asyncio
async def test_pipeline_context_manager():
    """Valida la liberación limpia de recursos mediante 'async with'."""
    mock_scraper = AsyncMock()
    mock_scraper.close = AsyncMock()

    async with PhishShieldPipeline(scraper=mock_scraper) as pipeline:
        assert isinstance(pipeline, PhishShieldPipeline)

    mock_scraper.close.assert_awaited_once()