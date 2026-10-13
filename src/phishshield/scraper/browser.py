import asyncio
import logging
import random
from dataclasses import dataclass, field

from playwright.async_api import Browser, Error as PlaywrightError, async_playwright
from playwright.async_api import TimeoutError as PlaywrightTimeoutError

logger = logging.getLogger(__name__)

DEFAULT_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
]

MOBILE_USER_AGENTS = [
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; SM-S928B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.6312.40 Mobile Safari/537.36",
]


def get_random_user_agent(is_mobile: bool = False) -> str:
    """Devuelve un User-Agent aleatorio según el tipo de dispositivo."""
    choices = MOBILE_USER_AGENTS if is_mobile else DEFAULT_USER_AGENTS
    return random.choice(choices)


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
    """Estructura de datos que contiene los artefactos extraídos de una sola sesión (Desktop o Mobile)."""

    url: str
    final_url: str
    status_code: int
    html_content: str
    screenshot_bytes: bytes
    error_message: str | None = None


@dataclass
class DualScrapeResult:
    """Contenedor de capturas paralelas (Desktop vs Mobile) para detección de User-Agent Cloaking."""

    requested_url: str
    desktop: ScrapeResult
    mobile: ScrapeResult
    is_cloaking_detected: bool = False
    cloaking_reason: str | None = None

    @property
    def final_url(self) -> str:
        """Compatibilidad con el pipeline: prioriza la URL final móvil si hay cloaking."""
        return self.mobile.final_url if self.is_cloaking_detected else self.desktop.final_url

    @property
    def html_content(self) -> str:
        """Compatibilidad con el pipeline: prioriza el HTML móvil si hay cloaking."""
        return self.mobile.html_content if self.is_cloaking_detected else self.desktop.html_content

    @property
    def status_code(self) -> int:
        return self.mobile.status_code if self.is_cloaking_detected else self.desktop.status_code

    @property
    def screenshot_bytes(self) -> bytes:
        """Compatibilidad con el pipeline: prioriza la captura móvil si hay cloaking."""
        return self.mobile.screenshot_bytes if self.is_cloaking_detected else self.desktop.screenshot_bytes


class PlaywrightScraper:
    """Motor de captura web asíncrono con inspección dual en paralelo (Anti-Cloaking / Smishing)."""

    def __init__(self, timeout_ms: int = 15000, divergence_threshold: float = 0.65):
        self.timeout_ms = timeout_ms
        self.divergence_threshold = divergence_threshold

    async def _scrape_single_context(
        self,
        url: str,
        user_agent: str,
        viewport: dict[str, int],
        is_mobile: bool = False,
    ) -> ScrapeResult:
        """Navega a la URL en un contexto aislado aplicando todas las reglas defensivas y de resiliencia."""
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
                user_agent=user_agent,
                viewport=viewport,
                is_mobile=is_mobile,
                has_touch=is_mobile,
                device_scale_factor=2 if is_mobile else 1,
                accept_downloads=False,
                ignore_https_errors=True,
                extra_http_headers={
                    "Accept-Language": "en-US,en;q=0.9",
                    "DNT": "1",
                },
            )

            page = await context.new_page()

            # Desactivar diálogos emergentes que puedan congelar la navegación
            page.on("dialog", lambda dialog: asyncio.create_task(dialog.dismiss()))

            response = None
            try:
                response = await page.goto(
                    url, timeout=self.timeout_ms, wait_until="networkidle"
                )
            except PlaywrightTimeoutError:
                logger.warning(
                    "Timeout con networkidle en modo %s para %s. Reintentando con domcontentloaded...",
                    "Móvil" if is_mobile else "Escritorio",
                    url,
                )
                try:
                    response = await page.goto(
                        url,
                        timeout=max(5000, self.timeout_ms // 2),
                        wait_until="domcontentloaded",
                    )
                except PlaywrightTimeoutError as fallback_err:
                    raise ScraperTimeoutError(
                        f"Tiempo de espera agotado ({self.timeout_ms}ms) en modo {'Móvil' if is_mobile else 'Escritorio'} para: {url}"
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

                # Breve pausa para renderizado dinámico de scripts
                await page.wait_for_timeout(1000)

                html_content = await page.content()

                screenshot_bytes = b""
                try:
                    screenshot_bytes = await page.screenshot(
                        type="png", full_page=False, timeout=5000
                    )
                except PlaywrightError as img_err:
                    logger.warning(
                        "No se pudo obtener captura de pantalla en modo %s para %s: %s",
                        "Móvil" if is_mobile else "Escritorio",
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

    def _detect_cloaking_divergence(
        self, desktop: ScrapeResult, mobile: ScrapeResult
    ) -> tuple[bool, str | None]:
        """Analiza discrepancias críticas entre las vistas de Escritorio y Móvil (User-Agent Cloaking)."""
        # 1. Divergencia en la URL final (Redirección selectiva por dispositivo)
        if desktop.final_url != mobile.final_url:
            return (
                True,
                f"Redirección divergente detectada: Escritorio finalizó en '{desktop.final_url}' pero Móvil en '{mobile.final_url}'.",
            )

        # 2. Divergencia severa en el tamaño del DOM utilizando el umbral configurable
        d_len = len(desktop.html_content)
        m_len = len(mobile.html_content)
        if d_len > 0 and abs(d_len - m_len) / max(d_len, m_len) > self.divergence_threshold:
            return (
                True,
                f"Discrepancia estructural masiva por tipo de dispositivo ({d_len} bytes en Escritorio vs {m_len} bytes en Móvil).",
            )

        return False, None

    async def scrape_url(self, url: str) -> DualScrapeResult:
        """Punto de entrada unificado: Ejecuta el escaneo dual simultáneo (Escritorio + Móvil)."""
        desktop_ua = get_random_user_agent(is_mobile=False)
        mobile_ua = get_random_user_agent(is_mobile=True)

        # Disparar ambas tareas en paralelo de forma asíncrona
        desktop_task = self._scrape_single_context(
            url=url,
            user_agent=desktop_ua,
            viewport={"width": 1280, "height": 720},
            is_mobile=False,
        )
        mobile_task = self._scrape_single_context(
            url=url,
            user_agent=mobile_ua,
            viewport={"width": 393, "height": 852},
            is_mobile=True,
        )

        try:
            desktop_result, mobile_result = await asyncio.gather(
                desktop_task, mobile_task
            )
        except Exception as e:
            if isinstance(e, ScraperError):
                raise e
            raise ScraperError(f"Fallo en la ejecución paralela del scraper dual: {e}") from e

        # Validar si existe técnica de camuflaje / cloaking usando el umbral configurable
        is_cloaking, reason = self._detect_cloaking_divergence(
            desktop_result, mobile_result
        )

        if is_cloaking:
            logger.warning("[ALERTA DE CLOAKING]: %s", reason)

        return DualScrapeResult(
            requested_url=url,
            desktop=desktop_result,
            mobile=mobile_result,
            is_cloaking_detected=is_cloaking,
            cloaking_reason=reason,
        )