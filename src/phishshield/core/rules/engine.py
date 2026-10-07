from typing import Any

from phishshield.core.rules.base import BaseRule
from phishshield.core.rules.schemas import (
    HeuristicAnalysisResult,
    RuleResult,
    RuleSeverity,
)
from phishshield.core.rules.url_rules import (
    BrandTyposquattingRule,
    DomainEntropyRule,
    IPAddressURLRule,
)

# Ponderación para determinar la severidad máxima de los hallazgos
SEVERITY_WEIGHTS = {
    RuleSeverity.INFO: 0,
    RuleSeverity.LOW: 1,
    RuleSeverity.MEDIUM: 2,
    RuleSeverity.HIGH: 3,
    RuleSeverity.CRITICAL: 4,
}


class HeuristicEngine:
    """Orquestador del motor de reglas estáticas."""

    def __init__(self, rules: list[BaseRule] | None = None):
        if rules is None:
            self.rules: list[BaseRule] = [
                IPAddressURLRule(),
                DomainEntropyRule(),
                BrandTyposquattingRule(),
            ]
        else:
            self.rules = rules

    def analyze(
        self, url: str, parsed_dom: Any | None = None
    ) -> HeuristicAnalysisResult:
        """
        Ejecuta todas las reglas configuradas sobre la URL y DOM especificados.
        """
        triggered_rules: list[RuleResult] = []
        total_score = 0
        highest_severity = RuleSeverity.INFO

        for rule in self.rules:
            res = rule.evaluate(url, parsed_dom=parsed_dom)
            if res.triggered:
                triggered_rules.append(res)
                total_score += res.score_impact

                if SEVERITY_WEIGHTS[res.severity] > SEVERITY_WEIGHTS[highest_severity]:
                    highest_severity = res.severity

        # El puntaje máximo acumulado no puede exceder 100
        total_score = min(total_score, 100)

        # Se determina si requiere escalamiento a la IA si hubo hallazgos
        should_escalate = total_score > 0 or len(triggered_rules) > 0

        return HeuristicAnalysisResult(
            total_heuristic_score=total_score,
            highest_severity=highest_severity,
            triggered_rules=triggered_rules,
            executed_rules_count=len(self.rules),
            should_escalate_to_ai=should_escalate,
        )
