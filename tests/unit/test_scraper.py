from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from playwright.async_api import Error as PlaywrightError, TimeoutError as PlaywrightTimeoutError

from phishshield.scraper.browser import (
    DEFAULT_USER_AGENTS,
    PlaywrightScraper,
    ScrapeResult,
    ScraperNetworkError,
    ScraperTimeoutError,
    get_random_user_agent,
)


@pytest.mark.asyncio
async def test_playwright_scraper_mocked():
    mock_response = AsyncMock()
    mock_response.status = 200

    mock_page = AsyncMock()
    mock_page.on = MagicMock()  # <--- Método síncrono en Playwright
    mock_page.goto.return_value = mock_response
    mock_page.url = "https://example.com/login"
    mock_page.content.return_value = "<html><body><form></form></body></html>"
    mock_page.screenshot.return_value = b"fake_png_bytes"

    mock_context = AsyncMock()
    mock_context.new_page.return_value = mock_page

    mock_browser = AsyncMock()
    mock_browser.new_context.return_value = mock_context

    mock_playwright = AsyncMock()
    mock_playwright.chromium.launch.return_value = mock_browser

    with patch("phishshield.scraper.browser.async_playwright") as mock_pw_func:
        mock_pw_func.return_value.__aenter__.return_value = mock_playwright

        scraper = PlaywrightScraper(timeout_ms=5000)
        result = await scraper.scrape_url("https://example.com")

        assert isinstance(result, ScrapeResult)
        assert result.status_code == 200
        assert result.final_url == "https://example.com/login"
        assert "form" in result.html_content
        assert result.screenshot_bytes == b"fake_png_bytes"
        assert mock_page.on.called


@pytest.mark.asyncio
async def test_playwright_scraper_fallback_on_networkidle_timeout():
    """Valida que si 'networkidle' falla por timeout, reintente con 'domcontentloaded' y tenga éxito."""
    mock_response = AsyncMock()
    mock_response.status = 200

    mock_page = AsyncMock()
    mock_page.on = MagicMock()
    # Primer goto (networkidle) lanza TimeoutError, segundo goto (domcontentloaded) es exitoso
    mock_page.goto.side_effect = [
        PlaywrightTimeoutError("networkidle timeout"),
        mock_response,
    ]
    mock_page.url = "https://example.com/slow"
    mock_page.content.return_value = "<html><body>Slow Site</body></html>"
    mock_page.screenshot.return_value = b"fake_png_bytes"

    mock_context = AsyncMock()
    mock_context.new_page.return_value = mock_page

    mock_browser = AsyncMock()
    mock_browser.new_context.return_value = mock_context

    mock_playwright = AsyncMock()
    mock_playwright.chromium.launch.return_value = mock_browser

    with patch("phishshield.scraper.browser.async_playwright") as mock_pw_func:
        mock_pw_func.return_value.__aenter__.return_value = mock_playwright

        scraper = PlaywrightScraper(timeout_ms=4000)
        result = await scraper.scrape_url("https://example.com/slow")

        assert isinstance(result, ScrapeResult)
        assert result.status_code == 200
        assert mock_page.goto.call_count == 2


@pytest.mark.asyncio
async def test_playwright_scraper_timeout_raises_custom_exception():
    mock_page = AsyncMock()
    # Ambos intentos fallan con TimeoutError
    mock_page.goto.side_effect = PlaywrightTimeoutError("Timeout exceeded")

    mock_context = AsyncMock()
    mock_page.on = MagicMock()
    mock_context.new_page.return_value = mock_page

    mock_browser = AsyncMock()
    mock_browser.new_context.return_value = mock_context

    mock_playwright = AsyncMock()
    mock_playwright.chromium.launch.return_value = mock_browser

    with patch("phishshield.scraper.browser.async_playwright") as mock_pw_func:
        mock_pw_func.return_value.__aenter__.return_value = mock_playwright

        scraper = PlaywrightScraper(timeout_ms=1000)
        with pytest.raises(ScraperTimeoutError, match="Tiempo de espera agotado"):
            await scraper.scrape_url("https://slow-unresponsive-site.com")


@pytest.mark.asyncio
async def test_playwright_scraper_network_error_raises_custom_exception():
    mock_page = AsyncMock()
    mock_page.goto.side_effect = PlaywrightError("net::ERR_NAME_NOT_RESOLVED")

    mock_context = AsyncMock()
    mock_page.on = MagicMock()
    mock_context.new_page.return_value = mock_page

    mock_browser = AsyncMock()
    mock_browser.new_context.return_value = mock_context

    mock_playwright = AsyncMock()
    mock_playwright.chromium.launch.return_value = mock_browser

    with patch("phishshield.scraper.browser.async_playwright") as mock_pw_func:
        mock_pw_func.return_value.__aenter__.return_value = mock_playwright

        scraper = PlaywrightScraper(timeout_ms=1000)
        with pytest.raises(ScraperNetworkError, match="Error de red o conexión"):
            await scraper.scrape_url("https://invalid-domain.local")


@pytest.mark.asyncio
async def test_playwright_scraper_screenshot_error_handled_gracefully():
    mock_page = AsyncMock()
    mock_response = AsyncMock()
    mock_response.status = 200
    mock_page.goto.return_value = mock_response
    mock_page.url = "https://example.com"
    mock_page.content.return_value = "<html>Content</html>"
    # Falla la captura de pantalla pero el scraping debe continuar
    mock_page.screenshot.side_effect = PlaywrightError("Screenshot failed")

    mock_context = AsyncMock()
    mock_page.on = MagicMock()
    mock_context.new_page.return_value = mock_page

    mock_browser = AsyncMock()
    mock_browser.new_context.return_value = mock_context

    mock_playwright = AsyncMock()
    mock_playwright.chromium.launch.return_value = mock_browser

    with patch("phishshield.scraper.browser.async_playwright") as mock_pw_func:
        mock_pw_func.return_value.__aenter__.return_value = mock_playwright

        scraper = PlaywrightScraper(timeout_ms=5000)
        result = await scraper.scrape_url("https://example.com")

        assert result.status_code == 200
        assert result.screenshot_bytes == b""


def test_playwright_scraper_user_agent_assignment():
    custom_ua = "CustomUserAgent/1.0"
    scraper_custom = PlaywrightScraper(user_agent=custom_ua)
    assert scraper_custom.user_agent == custom_ua

    scraper_default = PlaywrightScraper()
    assert scraper_default.user_agent in DEFAULT_USER_AGENTS


def test_get_random_user_agent():
    ua = get_random_user_agent()
    assert isinstance(ua, str)
    assert len(ua) > 0