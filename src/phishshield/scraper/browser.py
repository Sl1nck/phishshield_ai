import asyncio
import logging
import random
from dataclasses import dataclass

from playwright.async_api import Browser, Error as PlaywrightError, async_playwright
from playwright.async_api import TimeoutError as PlaywrightTimeoutError

logger = logging.getLogger(__name__)

DEFAULT_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
]


def get_random_user_agent() -> str:
    """Devuelve un User-Agent aleatorio de la lista por defecto."""
    return random.choice(DEFAULT_USER_AGENTS)


class ScraperError(Exception):
    """Excepción base para errores durante el scraping."""

    pass


class ScraperTimeoutError(ScraperError):
    """Excepción cuando el tiempo de espera de navegación se agota."""

    pass


class ScraperNetworkError(ScraperError):
    """Excepción para errores de red o DNS al acceder a la URL."""

    pass


@dataclass
class ScrapeResult:
    """Estructura de datos que contiene los artefactos extraídos del sitio web."""

    url: str
    final_url: str
    status_code: int
    html_content: str
    screenshot_bytes: bytes
    error_message: str | None = None


class PlaywrightScraper:
    """Motor de captura web asíncrono y hardening anti-ejecución."""

    def __init__(self, timeout_ms: int = 15000, user_agent: str | None = None):
        self.timeout_ms = timeout_ms
        self.user_agent = user_agent or get_random_user_agent()

    async def scrape_url(self, url: str) -> ScrapeResult:
        """Navega a la URL objetivo en un contexto aislado y extrae artefactos visuales y DOM.

        Aplica un mecanismo de fallback: si 'networkidle' falla por timeout debido a conexiones
        persistentes de la página maliciosa, reintenta esperando solo 'domcontentloaded'.
        Maneja diálogos emergentes, errores de red y fallos en screenshots de forma resiliente.
        """
        async with async_playwright() as p:
            browser: Browser = await p.chromium.launch(
                headless=True,
                args=[
                    "--no-sandbox",
                    "--disable-setuid-sandbox",
                    "--disable-dev-shm-usage",
                    "--disable-blink-features=AutomationControlled",
                ],
            )

            context = await browser.new_context(
                user_agent=self.user_agent,
                viewport={"width": 1280, "height": 720},
                accept_downloads=False,
                ignore_https_errors=True,
                extra_http_headers={
                    "Accept-Language": "en-US,en;q=0.9",
                    "DNT": "1",
                },
            )

            page = await context.new_page()

            # Desactivar diálogos (alert, confirm, prompt) que puedan congelar la navegación
            page.on("dialog", lambda dialog: asyncio.create_task(dialog.dismiss()))

            response = None
            try:
                # Intento primario: red inactiva (networkidle)
                response = await page.goto(
                    url, timeout=self.timeout_ms, wait_until="networkidle"
                )
            except PlaywrightTimeoutError:
                logger.warning(
                    "Timeout con networkidle en %s. Reintentando con domcontentloaded...",
                    url,
                )
                try:
                    # Intento de fallback: esperar únicamente a la carga del DOM inicial
                    response = await page.goto(
                        url,
                        timeout=max(5000, self.timeout_ms // 2),
                        wait_until="domcontentloaded",
                    )
                except PlaywrightTimeoutError as fallback_err:
                    raise ScraperTimeoutError(
                        f"Tiempo de espera agotado ({self.timeout_ms}ms) al acceder a: {url}"
                    ) from fallback_err
                except PlaywrightError as net_err:
                    raise ScraperNetworkError(
                        f"Error de red durante fallback en {url}: {net_err}"
                    ) from net_err
            except PlaywrightError as net_err:
                raise ScraperNetworkError(
                    f"Error de red o conexión al acceder a {url}: {net_err}"
                ) from net_err

            try:
                status_code = response.status if response else 0
                final_url = page.url

                # Breve pausa para permitir renderizado JS dinámico o desofuscación inicial
                await page.wait_for_timeout(1000)

                html_content = await page.content()

                # Captura de pantalla resiliente (si falla, conserva el HTML)
                screenshot_bytes = b""
                try:
                    screenshot_bytes = await page.screenshot(
                        type="png", full_page=False, timeout=5000
                    )
                except PlaywrightError as img_err:
                    logger.warning(
                        "No se pudo obtener captura de pantalla para %s: %s",
                        url,
                        img_err,
                    )

                return ScrapeResult(
                    url=url,
                    final_url=final_url,
                    status_code=status_code,
                    html_content=html_content,
                    screenshot_bytes=screenshot_bytes,
                )
            finally:
                await context.close()
                await browser.close()