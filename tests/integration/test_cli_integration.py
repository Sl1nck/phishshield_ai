from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from typer.testing import CliRunner

from phishshield.cli.main import app
from phishshield.core.llm.schemas import RiskLevel, ThreatAnalysisReport

runner = CliRunner()


@pytest.fixture
def mock_scraped_artifacts():
    """Fixture que simula los artefactos devueltos por PlaywrightScraper."""
    artifacts = MagicMock()
    artifacts.url = "https://test-phishing.com"
    artifacts.final_url = "https://test-phishing.com/login"
    artifacts.status_code = 200
    artifacts.html_content = (
        "<html><head><title>Acceso Seguro Banco</title></head>"
        '<body><form action="http://insecure.com/collect">'
        '<input type="password" name="pass">'
        "</form></body></html>"
    )
    artifacts.screenshot_bytes = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR..."
    return artifacts


@pytest.fixture
def mock_ai_report():
    """Fixture que simula la respuesta estructurada de GeminiAdapter."""
    return ThreatAnalysisReport(
        risk_score=90,
        risk_level=RiskLevel.HIGH,
        impersonated_brand="Banco Test",
        detected_indicators=["Envío HTTP inseguro", "Campo de contraseña"],
        reasoning="Formulario de captura de credenciales sobre canal no cifrado.",
        recommended_action="Bloquear la URL e iniciar proceso de takedown.",
    )


@patch("phishshield.pipeline.PlaywrightScraper")
@patch("phishshield.pipeline.GeminiAdapter")
def test_cli_analyze_command_integration(
    mock_gemini_cls, mock_scraper_cls, mock_scraped_artifacts, mock_ai_report
):
    """Valida el comando 'phishshield analyze' conectando la CLI con la Pipeline."""
    scraper_instance = mock_scraper_cls.return_value
    scraper_instance.scrape_url = AsyncMock(return_value=mock_scraped_artifacts)

    gemini_instance = mock_gemini_cls.return_value
    gemini_instance.analyze_phishing_site = AsyncMock(return_value=mock_ai_report)

    result = runner.invoke(app, ["analyze", "https://test-phishing.com"])

    assert result.exit_code == 0
    assert "PhishShield AI Report" in result.stdout
    assert "Puntaje Heurístico Total" in result.stdout
    assert "Dictamen de Amenaza - PhishShield AI" in result.stdout


@patch("phishshield.cli.main.PlaywrightScraper")
@patch("phishshield.cli.main.GeminiAdapter")
def test_cli_scan_url_command_with_file_exports(
    mock_gemini_cls, mock_scraper_cls, mock_scraped_artifacts, mock_ai_report, tmp_path
):
    """Valida 'phishshield scan-url' verificando la generación de reportes JSON y capturas PNG."""
    scraper_instance = mock_scraper_cls.return_value
    scraper_instance.scrape_url = AsyncMock(return_value=mock_scraped_artifacts)

    gemini_instance = mock_gemini_cls.return_value
    gemini_instance.analyze_phishing_site = AsyncMock(return_value=mock_ai_report)

    json_output = tmp_path / "reports" / "output.json"
    png_output = tmp_path / "reports" / "screenshot.png"

    result = runner.invoke(
        app,
        [
            "scan-url",
            "-u",
            "https://test-phishing.com",
            "-o",
            str(json_output),
            "-s",
            str(png_output),
        ],
    )

    assert result.exit_code == 0
    assert json_output.exists()
    assert png_output.exists()
