import math
import re
import ipaddress
import unicodedata
from typing import Any
from urllib.parse import urlparse

from phishshield.core.rules.base import BaseRule
from phishshield.core.rules.schemas import RuleResult, RuleSeverity


def calculate_shannon_entropy(text: str) -> float:
    """Calcula la entropía de Shannon para medir el grado de aleatoriedad en un texto."""
    if not text:
        return 0.0
    entropy = 0.0
    length = len(text)
    for char in set(text):
        p_x = text.count(char) / length
        entropy -= p_x * math.log2(p_x)
    return round(entropy, 3)


def levenshtein_distance(s1: str, s2: str) -> int:
    """Calcula la distancia de Levenshtein entre dos cadenas."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    previous_row: list[int] = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        current_row: list[int] = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row

    return previous_row[-1]


class IPAddressURLRule(BaseRule):
    """Detecta el uso directo de direcciones IP (IPv4/IPv6) en lugar de nombres de dominio."""

    def __init__(self):
        super().__init__(
            rule_id="RULE-URL-001", name="Uso directo de dirección IP en URL"
        )

    def evaluate(self, url: str, parsed_dom: Any | None = None) -> RuleResult:
        hostname = urlparse(url).hostname or ""
        
        is_ip = False
        if hostname:
            try:
                # ipaddress.ip_address valida tanto IPv4 como IPv6
                ipaddress.ip_address(hostname)
                is_ip = True
            except ValueError:
                is_ip = False

        if is_ip:
            return RuleResult(
                rule_id=self.rule_id,
                name=self.name,
                triggered=True,
                severity=RuleSeverity.HIGH,
                score_impact=40,
                description="La URL utiliza una dirección IP directa en lugar de un nombre de dominio.",
                details={"hostname": hostname}
            )

        return RuleResult(
            rule_id=self.rule_id,
            name=self.name,
            triggered=False,
            severity=RuleSeverity.INFO,
            score_impact=0,
            description="La URL utiliza un nombre de dominio resolver adecuado.",
            details=None
        )


class DomainEntropyRule(BaseRule):
    """Detecta dominios aleatorios o generados por algoritmos (DGA) mediante Entropía de Shannon."""

    def __init__(self, entropy_threshold: float = 3.8):
        super().__init__(
            rule_id="RULE-URL-002", name="Alta Entropía de Dominio (DGA/Aleatorio)"
        )
        self.entropy_threshold = entropy_threshold

    def evaluate(self, url: str, parsed_dom: Any | None = None) -> RuleResult:
        hostname = urlparse(url).hostname or ""
        domain_parts = hostname.split(".")
        sld = domain_parts[-2] if len(domain_parts) >= 2 else hostname
        entropy = calculate_shannon_entropy(sld)

        if entropy > self.entropy_threshold and len(sld) > 8:
            return RuleResult(
                rule_id=self.rule_id,
                name=self.name,
                triggered=True,
                severity=RuleSeverity.MEDIUM,
                score_impact=25,
                description=f"El dominio '{sld}' presenta una entropía inusual ({entropy}).",
                details={
                    "sld": sld,
                    "entropy": entropy,
                    "threshold": self.entropy_threshold,
                },
            )

        return RuleResult(
            rule_id=self.rule_id,
            name=self.name,
            triggered=False,
            severity=RuleSeverity.INFO,
            score_impact=0,
            description="Entropía de dominio dentro de rangos normales.",
        )


class BrandTyposquattingRule(BaseRule):
    """Detecta suplantación de marcas populares mediante Typosquatting."""

    TARGET_BRANDS: list[str] = [
        "paypal",
        "google",
        "microsoft",
        "apple",
        "netflix",
        "amazon",
        "facebook",
        "instagram",
        "binance",
        "chase",
        "bankofamerica",
    ]

    def __init__(self, max_distance: int = 2):
        super().__init__(
            rule_id="RULE-URL-003", name="Suplantación de Marca por Typosquatting"
        )
        self.max_distance = max_distance

    def evaluate(self, url: str, parsed_dom: Any | None = None) -> RuleResult:
        hostname = (urlparse(url).hostname or "").lower()
        domain_parts = hostname.split(".")
        sld = domain_parts[-2] if len(domain_parts) >= 2 else hostname

        tokens = [t for t in re.split(r"[-_]", sld) if t]

        for token in tokens:
            for brand in self.TARGET_BRANDS:
                if token == brand:
                    continue

                dist = levenshtein_distance(token, brand)
                if 1 <= dist <= self.max_distance:
                    return RuleResult(
                        rule_id=self.rule_id,
                        name=self.name,
                        triggered=True,
                        severity=RuleSeverity.HIGH,
                        score_impact=35,
                        description=f"El token '{token}' en el dominio es sospechosamente similar a la marca '{brand}' (Distancia Levenshtein: {dist}).",
                        details={
                            "sld": sld,
                            "suspicious_token": token,
                            "target_brand": brand,
                            "levenshtein_distance": dist,
                        },
                    )

        return RuleResult(
            rule_id=self.rule_id,
            name=self.name,
            triggered=False,
            severity=RuleSeverity.INFO,
            score_impact=0,
            description="No se detectó coincidencia de typosquatting.",
        )


class IDNHomographRule(BaseRule):
    """Detecta el uso de Internationalized Domain Names (IDN) o caracteres homóglifos (Punycode xn--)."""

    def __init__(self):
        super().__init__(
            rule_id="RULE-URL-004",
            name="Ataque de Homóglifos IDN (Punycode / Homoglyph)",
        )

    def evaluate(self, url: str, parsed_dom: Any | None = None) -> RuleResult:
        hostname = (urlparse(url).hostname or "").lower()

        is_punycode = "xn--" in hostname
        contains_non_ascii = any(ord(char) > 127 for char in hostname)

        if is_punycode or contains_non_ascii:
            return RuleResult(
                rule_id=self.rule_id,
                name=self.name,
                triggered=True,
                severity=RuleSeverity.CRITICAL if is_punycode else RuleSeverity.HIGH,
                score_impact=45,
                description=f"El dominio '{hostname}' utiliza caracteres IDN no estándar o codificación Punycode ('xn--'), técnica asociada a engaños visuales.",
                details={
                    "hostname": hostname,
                    "is_punycode": is_punycode,
                    "contains_non_ascii": contains_non_ascii,
                },
            )

        return RuleResult(
            rule_id=self.rule_id,
            name=self.name,
            triggered=False,
            severity=RuleSeverity.INFO,
            score_impact=0,
            description="El dominio utiliza caracteres ASCII estándar.",
        )


class SubdomainInfiltrationRule(BaseRule):
    """Detecta exceso de subdominios o inyección de marcas/palabras clave sensibles en los subdominios."""

    TARGET_KEYWORDS: list[str] = [
        "paypal",
        "google",
        "microsoft",
        "apple",
        "netflix",
        "amazon",
        "facebook",
        "binance",
        "bankofamerica",
        "secure",
        "login",
        "account",
        "verification",
        "signin",
        "update",
    ]

    def __init__(self, max_subdomains: int = 3):
        super().__init__(
            rule_id="RULE-URL-005",
            name="Exceso de Subdominios / Inyección de Marcas en Subdominio",
        )
        self.max_subdomains = max_subdomains

    def evaluate(self, url: str, parsed_dom: Any | None = None) -> RuleResult:
        hostname = (urlparse(url).hostname or "").lower()
        parts = hostname.split(".")

        subdomains = parts[:-2] if len(parts) >= 2 else []

        detected_keywords = [
            kw
            for kw in self.TARGET_KEYWORDS
            if any(kw in sub for sub in subdomains)
        ]

        if len(subdomains) >= self.max_subdomains or len(detected_keywords) > 0:
            impact = 35 if detected_keywords else 20
            severity = (
                RuleSeverity.HIGH if detected_keywords else RuleSeverity.MEDIUM
            )
            desc = (
                f"Inyección de palabras clave o marca sensible en subdominios: {detected_keywords}"
                if detected_keywords
                else f"Estructura anidada inusual con {len(subdomains)} niveles de subdominio."
            )
            return RuleResult(
                rule_id=self.rule_id,
                name=self.name,
                triggered=True,
                severity=severity,
                score_impact=impact,
                description=desc,
                details={
                    "hostname": hostname,
                    "subdomains": subdomains,
                    "detected_keywords": detected_keywords,
                },
            )

        return RuleResult(
            rule_id=self.rule_id,
            name=self.name,
            triggered=False,
            severity=RuleSeverity.INFO,
            score_impact=0,
            description="Estructura de subdominios estándar.",
        )


class SuspiciousTLDRule(BaseRule):
    """Detecta dominios registrados bajo TLDs de alto riesgo o frecuentemente vulnerados."""

    HIGH_RISK_TLDS: set[str] = {
        "tk",
        "ml",
        "ga",
        "cf",
        "gq",
        "top",
        "xyz",
        "zip",
        "mov",
        "cc",
        "icu",
        "work",
        "click",
        "rest",
        "fit",
        "surf",
        "country",
        "kim",
    }

    def __init__(self):
        super().__init__(
            rule_id="RULE-URL-006",
            name="Uso de TLD de Alto Riesgo / Gratuito",
        )

    def evaluate(self, url: str, parsed_dom: Any | None = None) -> RuleResult:
        hostname = (urlparse(url).hostname or "").lower()
        parts = hostname.split(".")
        tld = parts[-1] if len(parts) > 1 else ""

        if tld in self.HIGH_RISK_TLDS:
            return RuleResult(
                rule_id=self.rule_id,
                name=self.name,
                triggered=True,
                severity=RuleSeverity.MEDIUM,
                score_impact=20,
                description=f"El dominio utiliza el TLD '.{tld}', asociado a alta incidencia de abusos y phishing.",
                details={"hostname": hostname, "tld": tld},
            )

        return RuleResult(
            rule_id=self.rule_id,
            name=self.name,
            triggered=False,
            severity=RuleSeverity.INFO,
            score_impact=0,
            description="El TLD no pertenece a la lista de alto riesgo.",
        )