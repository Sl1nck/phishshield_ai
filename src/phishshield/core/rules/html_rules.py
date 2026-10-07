import re
from typing import Any
from urllib.parse import urlparse

from bs4 import BeautifulSoup

from phishshield.core.rules.base import BaseRule
from phishshield.core.rules.schemas import RuleResult, RuleSeverity


class ExternalFormActionRule(BaseRule):
    """Detecta formularios que envían datos a un dominio externo o IP diferente al del sitio hospedador."""

    def __init__(self):
        super().__init__(
            rule_id="RULE-HTML-001",
            name="Formulario con Acción de Envío Externa / Sospechosa",
        )

    def evaluate(self, url: str, parsed_dom: Any | None = None) -> RuleResult:
        if parsed_dom is None or not isinstance(parsed_dom, BeautifulSoup):
            return RuleResult(
                rule_id=self.rule_id,
                name=self.name,
                triggered=False,
                severity=RuleSeverity.INFO,
                score_impact=0,
                description="No se proporcionó un DOM parseado válido para evaluación.",
            )

        base_hostname = (urlparse(url).hostname or "").lower()
        forms = parsed_dom.find_all("form")

        for form in forms:
            action = form.get("action", "").strip()
            if not action or action.startswith("#") or action.startswith("javascript:"):
                continue

            action_hostname = (urlparse(action).hostname or "").lower()

            if action_hostname and action_hostname != base_hostname:
                return RuleResult(
                    rule_id=self.rule_id,
                    name=self.name,
                    triggered=True,
                    severity=RuleSeverity.HIGH,
                    score_impact=35,
                    description=f"Formulario configurado para enviar datos a un dominio externo ({action_hostname}).",
                    details={
                        "base_hostname": base_hostname,
                        "action_target": action,
                        "action_hostname": action_hostname,
                    },
                )

        return RuleResult(
            rule_id=self.rule_id,
            name=self.name,
            triggered=False,
            severity=RuleSeverity.INFO,
            score_impact=0,
            description="Todos los formularios envían datos a sus propios endpoints o rutas relativas.",
        )


class CredentialFormPresenceRule(BaseRule):
    """Detecta presencia de campos para contraseñas o datos financieros sensibles."""

    def __init__(self):
        super().__init__(
            rule_id="RULE-HTML-002",
            name="Captura de Credenciales o Datos Financieros en HTML",
        )

    def evaluate(self, url: str, parsed_dom: Any | None = None) -> RuleResult:
        if parsed_dom is None or not isinstance(parsed_dom, BeautifulSoup):
            return RuleResult(
                rule_id=self.rule_id,
                name=self.name,
                triggered=False,
                severity=RuleSeverity.INFO,
                score_impact=0,
                description="No se proporcionó un DOM parseado válido para evaluación.",
            )

        password_inputs = parsed_dom.find_all("input", {"type": "password"})
        sensitive_keywords = ["cvv", "creditcard", "cardnumber", "ssn", "pin", "expdate"]
        
        found_sensitive_attrs = []
        for inp in parsed_dom.find_all("input"):
            attr_val = f"{inp.get('name', '')} {inp.get('id', '')} {inp.get('placeholder', '')}".lower()
            if any(kw in attr_val for kw in sensitive_keywords):
                found_sensitive_attrs.append(attr_val.strip())

        if len(password_inputs) > 0 or len(found_sensitive_attrs) > 0:
            impact = 30 if len(found_sensitive_attrs) > 0 else 20
            severity = RuleSeverity.HIGH if len(found_sensitive_attrs) > 0 else RuleSeverity.MEDIUM
            return RuleResult(
                rule_id=self.rule_id,
                name=self.name,
                triggered=True,
                severity=severity,
                score_impact=impact,
                description="Se detectaron campos de entrada orientados a captura de credenciales o datos de pago.",
                details={
                    "password_fields_count": len(password_inputs),
                    "sensitive_fields_detected": found_sensitive_attrs,
                },
            )

        return RuleResult(
            rule_id=self.rule_id,
            name=self.name,
            triggered=False,
            severity=RuleSeverity.INFO,
            score_impact=0,
            description="No se detectaron formularios de solicitud de contraseñas o tarjetas de crédito.",
        )


class ObfuscatedScriptRule(BaseRule):
    """Detecta JavaScript sospechoso u ofuscado en etiquetas <script> (eval, unescape, hex encoding)."""

    def __init__(self):
        super().__init__(
            rule_id="RULE-HTML-003",
            name="Detección de JavaScript Ofuscado / Sospechoso",
        )

    def evaluate(self, url: str, parsed_dom: Any | None = None) -> RuleResult:
        if parsed_dom is None or not isinstance(parsed_dom, BeautifulSoup):
            return RuleResult(
                rule_id=self.rule_id,
                name=self.name,
                triggered=False,
                severity=RuleSeverity.INFO,
                score_impact=0,
                description="No se proporcionó un DOM parseado válido para evaluación.",
            )

        scripts = parsed_dom.find_all("script")
        obfuscation_patterns = [
            r"eval\s*\(\s*function\s*\(",
            r"document\.write\s*\(\s*unescape\s*\(",
            r"String\.fromCharCode\s*\(",
            r"\\x[0-9a-fA-F]{2}(\\x[0-9a-fA-F]{2}){5,}",
            r"window\[['\"]\\x",
        ]

        detected_patterns = []
        for script in scripts:
            content = script.string or ""
            for pattern in obfuscation_patterns:
                if re.search(pattern, content):
                    detected_patterns.append(pattern)

        if detected_patterns:
            return RuleResult(
                rule_id=self.rule_id,
                name=self.name,
                triggered=True,
                severity=RuleSeverity.HIGH,
                score_impact=30,
                description="Se identificaron patrones de JavaScript ofuscado en el documento.",
                details={"matched_patterns": list(set(detected_patterns))},
            )

        return RuleResult(
            rule_id=self.rule_id,
            name=self.name,
            triggered=False,
            severity=RuleSeverity.INFO,
            score_impact=0,
            description="No se detectaron secuencias de script sospechosas u ofuscadas.",
        )