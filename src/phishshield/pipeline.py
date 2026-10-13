import asyncio
from dataclasses import dataclass
from types import TracebackType
from typing import Self

from rich.console import Console

from phishshield.core.llm.gemini_adapter import GeminiAdapter
from phishshield.core.llm.schemas import ThreatAnalysisReport
from phishshield.heuristics.engine import HeuristicEngine, HeuristicResult, RuleResult
from phishshield.scraper.browser import (
    PlaywrightScraper,
    ScraperError,
    ScraperNetworkError,
    ScraperTimeoutError,
)
from phishshield.scraper.parser import DOMParser, ParsedDOM

console = Console()


@dataclass
class PipelineReport:
    """Contenedor de resultados unificados del análisis local e IA."""

    url: str
    parsed_dom: ParsedDOM
    heuristic_result: HeuristicResult
    ai_report: ThreatAnalysisReport | None = None
    error_message: str | None = None
    is_cloaking_detected: bool = False
    cloaking_reason: str | None = None


class PhishShieldPipeline:
    """Orquestador principal que conecta la extracción DOM, el motor heurístico y la inferencia por IA."""

    def __init__(
        self,
        scraper: PlaywrightScraper | None = None,
        engine: HeuristicEngine | None = None,
        gemini_adapter: GeminiAdapter | None = None,
        use_pro: bool = False,
    ) -> None:
        self.scraper = scraper or PlaywrightScraper()
        self.engine = engine or HeuristicEngine()
        self.use_pro = use_pro
        self.gemini_adapter = gemini_adapter or GeminiAdapter(use_pro=use_pro)

    async def analyze_url_async(
        self,
        url: str,
        force_ai: bool = True,
    ) -> PipelineReport:
        """Ejecuta el flujo asíncrono completo combinando extracción DOM dual, evaluación heurística y análisis por IA.

        :param url: URL del sitio a analizar.
        :param force_ai: Si es True, ejecuta Gemini independientemente del score heurístico.
        """
        error_message: str | None = None
        final_url = url
        html_content = ""
        screenshot_bytes = b""
        dual_artifacts = None

        # 1. Scraping dual en paralelo (Desktop vs Mobile) y captura de artefactos
        try:
            dual_artifacts = await self.scraper.scrape_url(url)
            final_url = dual_artifacts.final_url
            html_content = dual_artifacts.html_content
            screenshot_bytes = dual_artifacts.screenshot_bytes
        except ScraperError as err:
            console.print(
                f"[bold red][!] Error de scraping al acceder a {url}:[/] {err}"
            )
            error_message = str(err)

        # 2. Parsing de la estructura HTML/DOM (prioriza contenido móvil si se detecta cloaking)
        parser = DOMParser(html_content)
        parsed_dom = parser.parse()

        # 3. Evaluación heurística local
        heuristic_result = self.engine.analyze(parsed_dom, final_url)

        # 💡 3.1. Inyección automática de regla heurística si se detecta Cloaking / Smishing evasivo
        if dual_artifacts and dual_artifacts.is_cloaking_detected:
            cloaking_rule = RuleResult(
                rule_id="HEUR-CLOAKING",
                name="User-Agent Cloaking / Evasión de Dispositivo",
                triggered=True,
                description=dual_artifacts.cloaking_reason or "El sitio altera su comportamiento o redirecciones según el tipo de dispositivo.",
            )
            
            if hasattr(heuristic_result, "triggered_rules"):
                heuristic_result.triggered_rules.append(cloaking_rule)
                if hasattr(heuristic_result, "total_score"):
                    heuristic_result.total_score = min(100, heuristic_result.total_score + 40)

        # 4. Inferencia por IA multimodal (solo si el scraping fue exitoso y la IA está habilitada)
        ai_report: ThreatAnalysisReport | None = None

        should_trigger_ai = (
            force_ai or getattr(heuristic_result, "is_suspicious", True)
        ) and (error_message is None)

        if self.gemini_adapter and should_trigger_ai:
            try:
                # Extraer las reglas/alertas activadas para enviarlas a Gemini
                heuristic_flags = getattr(
                    heuristic_result,
                    "triggered_rules",
                    getattr(heuristic_result, "flags", []),
                )

                ai_report = await self.gemini_adapter.analyze_phishing_site(
                    parsed_dom=parsed_dom,
                    screenshot_bytes=screenshot_bytes,
                    url=final_url,
                    heuristic_flags=heuristic_flags,
                )
            except Exception as e:
                console.print(
                    f"[bold yellow][!] Fallo en el módulo de IA (GeminiAdapter):[/] {e}"
                )
                ai_report = None

        return PipelineReport(
            url=final_url,
            parsed_dom=parsed_dom,
            heuristic_result=heuristic_result,
            ai_report=ai_report,
            error_message=error_message,
            is_cloaking_detected=dual_artifacts.is_cloaking_detected if dual_artifacts else False,
            cloaking_reason=dual_artifacts.cloaking_reason if dual_artifacts else None,
        )

    def analyze_url(self, url: str, force_ai: bool = True) -> PipelineReport:
        """Wrapper síncrono seguro que ejecuta el pipeline completo.

        Maneja internamente la existencia de bucles de eventos activos.
        """
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None

        if loop and loop.is_running():
            raise RuntimeError(
                "PhishShieldPipeline.analyze_url() no se puede llamar desde un event loop activo. "
                "Utiliza 'await pipeline.analyze_url_async(url)' en su lugar."
            )

        return asyncio.run(self.analyze_url_async(url, force_ai=force_ai))

    async def close(self) -> None:
        """Libera de forma limpia los recursos del scraper y conexiones abiertas."""
        if hasattr(self.scraper, "close") and callable(self.scraper.close):
            if asyncio.iscoroutinefunction(self.scraper.close):
                await self.scraper.close()
            else:
                self.scraper.close()

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        await self.close()