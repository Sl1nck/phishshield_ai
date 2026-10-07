"""Motor principal de análisis heurístico para PhishShield AI."""

import ipaddress
import math
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any
from urllib.parse import urlparse

try:
    from phishshield.core.rules.schemas import RuleResult, RuleSeverity
except ImportError:
    class RuleSeverity(str, Enum):
        INFO = "INFO"
        LOW = "LOW"
        MEDIUM = "MEDIUM"
        HIGH = "HIGH"
        CRITICAL = "CRITICAL"

    @dataclass
    class RuleResult:
        rule_id: str
        name: str
        triggered: bool
        score_impact: int
        description: str
        severity: RuleSeverity = RuleSeverity.MEDIUM

SEVERITY_ORDER = {
    RuleSeverity.INFO: 0,
    RuleSeverity.LOW: 1,
    RuleSeverity.MEDIUM: 2,
    RuleSeverity.HIGH: 3,
    RuleSeverity.CRITICAL: 4,
}


@dataclass
class HeuristicResult:
    """Resultado agregativo de la evaluación heurística."""
    total_score: int  # Puntuación acumulada (0 a 100)
    triggered_rules: list[RuleResult] = field(default_factory=list)
    max_severity: RuleSeverity = RuleSeverity.INFO
    all_results: list[RuleResult] = field(default_factory=list)

    @property
    def is_suspicious(self) -> bool:
        return self.total_score >= 30 or self.max_severity in (
            RuleSeverity.HIGH,
            RuleSeverity.CRITICAL,
        )


def _normalize_url(url: str) -> str:
    """Asegura que la URL tenga un esquema adecuado para un parseo correcto."""
    if not url:
        return ""
    url = url.strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+-.]*://", url):
        return f"http://{url}"
    return url


def _is_ip_address(host: str) -> bool:
    """Verifica si el host es una dirección IPv4 o IPv6 directa."""
    if not host:
        return False
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _calculate_shannon_entropy(text: str) -> float:
    """Calcula la entropía de Shannon de una cadena de texto."""
    if not text:
        return 0.0
    entropy = 0.0
    length = len(text)
    for char in set(text):
        p_x = text.count(char) / length
        entropy -= p_x * math.log2(p_x)
    return round(entropy, 3)


def _levenshtein_distance(s1: str, s2: str) -> int:
    """Calcula la distancia de Levenshtein de forma iterativa."""
    if len(s1) < len(s2):
        s1, s2 = s2, s1
    if not s2:
        return len(s1)

    previous_row = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]


def _get_val(obj: Any, attr_or_key: str, default: Any = None) -> Any:
    """Obtiene un valor de forma segura tanto de diccionarios como de objetos."""
    if obj is None:
        return default
    if isinstance(obj, dict):
        return obj.get(attr_or_key, default)
    return getattr(obj, attr_or_key, default)


class HeuristicEngine:
    """Motor de heurísticas estáticas para detección instantánea de patrones de phishing."""

    SUSPICIOUS_TLDS = {
        ".xyz", ".top", ".tk", ".ml", ".ga", ".cf", ".gq", ".zip", ".mov",
        ".icu", ".click", ".work", ".rest", ".country", ".kim", ".fit",
        ".surf", ".cc",
    }
    TARGET_BRANDS = {
        "paypal": ("PayPal", "paypal.com"),
        "google": ("Google", "google.com"),
        "microsoft": ("Microsoft", "microsoft.com"),
        "amazon": ("Amazon", "amazon.com"),
        "netflix": ("Netflix", "netflix.com"),
        "facebook": ("Facebook", "facebook.com"),
        "apple": ("Apple", "apple.com"),
        "binance": ("Binance", "binance.com"),
        "bankofamerica": ("Bank of America", "bankofamerica.com"),
        "chase": ("Chase", "chase.com"),
    }

    DEFAULT_RULE_IDS = [
        "HEUR-01", "HEUR-02", "HEUR-03", "HEUR-04", "HEUR-05",
        "HEUR-06", "HEUR-07", "HEUR-08", "HEUR-09", "HEUR-10", "HEUR-11"
    ]

    def __init__(self, rules: list[Any] | None = None):
        if rules is not None:
            self.rules = rules
        else:
            self.rules = list(self.DEFAULT_RULE_IDS)

    def analyze(
        self,
        parsed_dom_or_url: Any = None,
        url_or_html: str | None = None,
        url: str | None = None,
        html_content: str | None = None,
    ) -> HeuristicResult:
        """
        Ejecuta las reglas heurísticas configuradas sobre la URL y el DOM proporcionado.
        """
        target_dom = None
        raw_url = ""

        if url is not None:
            raw_url = url
            if parsed_dom_or_url is not None and not isinstance(parsed_dom_or_url, str):
                target_dom = parsed_dom_or_url
        elif isinstance(parsed_dom_or_url, str) and (
            "://" in parsed_dom_or_url or "." in parsed_dom_or_url
        ):
            raw_url = parsed_dom_or_url
        else:
            target_dom = parsed_dom_or_url
            raw_url = url_or_html or ""

        target_url = _normalize_url(raw_url)

        # Evaluación con reglas modulares personalizadas (objetos BaseRule)
        if self.rules and hasattr(self.rules[0], "evaluate"):
            triggered: list[RuleResult] = []
            all_results: list[RuleResult] = []
            total_score = 0
            highest_severity = RuleSeverity.INFO

            for rule in self.rules:
                res = rule.evaluate(url=target_url, parsed_dom=target_dom)
                all_results.append(res)
                if res.triggered:
                    triggered.append(res)
                    total_score += res.score_impact
                    if SEVERITY_ORDER.get(res.severity, 0) > SEVERITY_ORDER.get(highest_severity, 0):
                        highest_severity = res.severity

            return HeuristicResult(
                total_score=min(total_score, 100),
                triggered_rules=triggered,
                max_severity=highest_severity,
                all_results=all_results,
            )

        # Evaluación con reglas heurísticas estáticas por defecto
        active_rule_ids = set(self.rules) if isinstance(self.rules, (list, tuple, set)) else set()
        triggered: list[RuleResult] = []
        all_results: list[RuleResult] = []

        parsed_url = urlparse(target_url) if target_url else urlparse("")
        host_without_port = parsed_url.netloc.split(":")[0].lower() if parsed_url.netloc else ""

        # 1. IP Address
        if "HEUR-01" in active_rule_ids:
            r1_trig = _is_ip_address(host_without_port)
            res1 = RuleResult(
                rule_id="HEUR-01",
                name="Uso de Dirección IP Directa",
                triggered=r1_trig,
                score_impact=35 if r1_trig else 0,
                description="El sitio utiliza una dirección IP cruda en lugar de un nombre de dominio.",
                severity=RuleSeverity.HIGH,
            )
            all_results.append(res1)
            if r1_trig:
                triggered.append(res1)

        # 2. Suspicious TLD
        if "HEUR-02" in active_rule_ids:
            domain_parts = host_without_port.split(".") if host_without_port else []
            r2_trig = bool(len(domain_parts) > 1 and f".{domain_parts[-1]}" in self.SUSPICIOUS_TLDS)
            res2 = RuleResult(
                rule_id="HEUR-02",
                name="TLD de Alto Riesgo",
                triggered=r2_trig,
                score_impact=20 if r2_trig else 0,
                description=f"El dominio utiliza un TLD comúnmente asociado a malware/phishing (.{domain_parts[-1] if domain_parts else ''}).",
                severity=RuleSeverity.MEDIUM,
            )
            all_results.append(res2)
            if r2_trig:
                triggered.append(res2)

        # 3. Form Password
        if "HEUR-03" in active_rule_ids:
            input_fields = _get_val(target_dom, "input_fields", []) or []
            has_password = bool(_get_val(target_dom, "has_password_field", False)) or any(
                _get_val(inp, "type") == "password" for inp in input_fields
            )
            impact3 = (25 if parsed_url.scheme != "https" else 15) if has_password else 0
            res3 = RuleResult(
                rule_id="HEUR-03",
                name="Formulario de Captura de Credenciales",
                triggered=has_password,
                score_impact=impact3,
                description="Se detectó un campo de entrada tipo 'password' en el DOM.",
                severity=RuleSeverity.MEDIUM,
            )
            all_results.append(res3)
            if has_password:
                triggered.append(res3)

        # 4. Form Actions
        if "HEUR-04" in active_rule_ids:
            r4_trig = False
            action_desc = ""
            form_actions = _get_val(target_dom, "form_actions", []) or []
            for action in form_actions:
                if not action:
                    continue
                action_norm = _normalize_url(action)
                action_parsed = urlparse(action_norm)
                action_host = action_parsed.netloc.split(":")[0].lower()
                
                if action.startswith("http://") or (action_host and host_without_port and action_host != host_without_port):
                    r4_trig = True
                    action_desc = f"Formulario envía datos sensibles hacia una URL insegura o externa: {action}"
                    break
            res4 = RuleResult(
                rule_id="HEUR-04",
                name="Envío de Formulario No Cifrado o Externo",
                triggered=r4_trig,
                score_impact=30 if r4_trig else 0,
                description=action_desc if r4_trig else "No se detectaron envíos insecure/externos.",
                severity=RuleSeverity.HIGH,
            )
            all_results.append(res4)
            if r4_trig:
                triggered.append(res4)

        # 5. Typosquatting / Brand Impersonation
        if "HEUR-05" in active_rule_ids:
            r5_trig = False
            r5_desc = ""
            if host_without_port and not _is_ip_address(host_without_port):
                host_tokens = re.split(r"[\.-]", host_without_port)
                for brand_key, (brand_name, legit_domain) in self.TARGET_BRANDS.items():
                    legit_host = legit_domain.lower()
                    if host_without_port == legit_host or host_without_port.endswith("." + legit_host):
                        continue

                    # Check 1: Inclusión indebida de la marca en un dominio no autorizado (ej. paypal-security-update.com)
                    if brand_key in host_without_port:
                        r5_trig = True
                        r5_desc = f"El dominio contiene el nombre de la marca '{brand_name}' sin ser el sitio oficial ({legit_domain})."
                        break

                    # Check 2: Typosquatting por Levenshtein (ej. paypa1.com)
                    for token in host_tokens:
                        if not token or len(token) < 4:
                            continue
                        dist = _levenshtein_distance(token, brand_key)
                        if 1 <= dist <= 2:
                            r5_trig = True
                            r5_desc = f"El dominio contiene el término '{token}' que imita a la marca legítima '{brand_name}'."
                            break
                    if r5_trig:
                        break

            res5 = RuleResult(
                rule_id="HEUR-05",
                name="Posible Typosquatting o Suplantación de Marca",
                triggered=r5_trig,
                score_impact=30 if r5_trig else 0,
                description=r5_desc if r5_trig else "No se detectaron patrones de typosquatting.",
                severity=RuleSeverity.HIGH,
            )
            all_results.append(res5)
            if r5_trig:
                triggered.append(res5)

        # 6. Hidden Sensitive Field
        if "HEUR-06" in active_rule_ids:
            r6_trig = False
            input_fields = _get_val(target_dom, "input_fields", []) or []
            r6_trig = any(
                _get_val(inp, "is_hidden") is True and _get_val(inp, "type") == "password"
                for inp in input_fields
            )
            res6 = RuleResult(
                rule_id="HEUR-06",
                name="Campo Sensible Oculto Detectado",
                triggered=r6_trig,
                score_impact=25 if r6_trig else 0,
                description="Se detectó un campo de entrada sensible (password) oculto en la interfaz.",
                severity=RuleSeverity.MEDIUM,
            )
            all_results.append(res6)
            if r6_trig:
                triggered.append(res6)

        # 7. Excessive Subdomains
        if "HEUR-07" in active_rule_ids:
            domain_parts = host_without_port.split(".") if host_without_port else []
            r7_trig = len(domain_parts) > 4
            subdomain_count = max(0, len(domain_parts) - 2) if r7_trig else 0
            res7 = RuleResult(
                rule_id="HEUR-07",
                name="Anidamiento Excesivo de Subdominios",
                triggered=r7_trig,
                score_impact=20 if r7_trig else 0,
                description=f"El host utiliza una estructura sospechosa con {subdomain_count} niveles de subdominios.",
                severity=RuleSeverity.MEDIUM,
            )
            all_results.append(res7)
            if r7_trig:
                triggered.append(res7)

        # 8. Brand Title Mismatch
        if "HEUR-08" in active_rule_ids:
            r8_trig = False
            r8_desc = ""
            page_title = _get_val(target_dom, "title")
            if page_title:
                title_lower = page_title.lower()
                for brand_key, (brand_name, legit_domain) in self.TARGET_BRANDS.items():
                    if (brand_key in title_lower or brand_name.lower() in title_lower) and brand_key not in host_without_port:
                        r8_trig = True
                        r8_desc = f"El título menciona la marca '{brand_name}', pero el dominio ({host_without_port}) no pertenece a la misma."
                        break
            res8 = RuleResult(
                rule_id="HEUR-08",
                name="Inconsistencia de Marca en Título",
                triggered=r8_trig,
                score_impact=25 if r8_trig else 0,
                description=r8_desc if r8_trig else "Título consistente con la marca o dominio.",
                severity=RuleSeverity.HIGH,
            )
            all_results.append(res8)
            if r8_trig:
                triggered.append(res8)

        # 9. iFrames
        if "HEUR-09" in active_rule_ids:
            r9_trig = False
            ext_iframes = []
            iframes = _get_val(target_dom, "iframes", []) or []
            for iframe in iframes:
                if not iframe:
                    continue
                iframe_norm = _normalize_url(iframe)
                iframe_host = urlparse(iframe_norm).netloc.split(":")[0].lower()
                if iframe_host and host_without_port and iframe_host != host_without_port:
                    ext_iframes.append(iframe)
            if ext_iframes:
                r9_trig = True
            res9 = RuleResult(
                rule_id="HEUR-09",
                name="iFrame Externo Sospechoso Detectado",
                triggered=r9_trig,
                score_impact=20 if r9_trig else 0,
                description=f"Se detectó la inclusión de {len(ext_iframes)} iFrame(s) desde dominio(s) externo(s).",
                severity=RuleSeverity.MEDIUM,
            )
            all_results.append(res9)
            if r9_trig:
                triggered.append(res9)

        # 10. Homoglyphs
        if "HEUR-10" in active_rule_ids:
            r10_trig = False
            if host_without_port:
                is_punycode = "xn--" in host_without_port
                contains_non_ascii = any(ord(char) > 127 for char in host_without_port)
                r10_trig = is_punycode or contains_non_ascii
            res10 = RuleResult(
                rule_id="HEUR-10",
                name="Uso de Homóglifos IDN o Punycode",
                triggered=r10_trig,
                score_impact=40 if r10_trig else 0,
                description=f"El host '{host_without_port}' utiliza caracteres no latinos o codificación Punycode para suplantación visual.",
                severity=RuleSeverity.CRITICAL,
            )
            all_results.append(res10)
            if r10_trig:
                triggered.append(res10)

        # 11. Domain Entropy
        if "HEUR-11" in active_rule_ids:
            r11_trig = False
            if host_without_port and not _is_ip_address(host_without_port):
                domain_parts = host_without_port.split(".")
                sld = domain_parts[-2] if len(domain_parts) >= 2 else host_without_port
                entropy = _calculate_shannon_entropy(sld)
                if entropy > 3.8 and len(sld) > 8:
                    r11_trig = True
            res11 = RuleResult(
                rule_id="HEUR-11",
                name="Alta Entropía de Dominio (DGA)",
                triggered=r11_trig,
                score_impact=25 if r11_trig else 0,
                description="El dominio de segundo nivel presenta una entropía inusual.",
                severity=RuleSeverity.MEDIUM,
            )
            all_results.append(res11)
            if r11_trig:
                triggered.append(res11)

        highest_severity = RuleSeverity.INFO
        for r in triggered:
            if SEVERITY_ORDER.get(r.severity, 0) > SEVERITY_ORDER.get(highest_severity, 0):
                highest_severity = r.severity

        total_score = min(sum(r.score_impact for r in triggered), 100)
        return HeuristicResult(
            total_score=total_score,
            triggered_rules=triggered,
            max_severity=highest_severity,
            all_results=all_results,
        )