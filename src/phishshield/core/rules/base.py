from abc import ABC, abstractmethod
from typing import Any

from phishshield.core.rules.schemas import RuleResult


class BaseRule(ABC):
    """Clase base abstracta para todas las reglas heurísticas estáticas."""

    def __init__(self, rule_id: str, name: str):
        self.rule_id = rule_id
        self.name = name

    @abstractmethod
    def evaluate(self, url: str, parsed_dom: Any | None = None) -> RuleResult:
        """
        Evalúa el objetivo y retorna un objeto RuleResult.

        :param url: URL final a analizar.
        :param parsed_dom: Estructura parseada del DOM (opcional).
        """
        pass
