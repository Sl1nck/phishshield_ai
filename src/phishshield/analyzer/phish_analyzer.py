from typing import Any

from phishshield.core.rules.engine import HeuristicEngine
from phishshield.core.rules.schemas import HeuristicAnalysisResult


class PhishAnalyzer:
    """Analizador principal que orquesta la detección heurística y la IA."""

    def __init__(self, heuristic_engine: HeuristicEngine | None = None):
        self.heuristic_engine = heuristic_engine or HeuristicEngine()

    def analyze_url(self, url: str, parsed_dom: Any | None = None) -> dict[str, Any]:
        """
        Ejecuta la primera fase de análisis estático (heurística)
        y prepara la estructura para la integración multimodal.
        """
        heuristic_res: HeuristicAnalysisResult = self.heuristic_engine.analyze(
            url=url, parsed_dom=parsed_dom
        )

        return {
            "target_url": url,
            "heuristic_analysis": heuristic_res.model_dump(),
            "requires_ai_escalation": heuristic_res.should_escalate_to_ai,
        }
