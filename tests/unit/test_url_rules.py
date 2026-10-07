from phishshield.core.rules.schemas import RuleSeverity
from phishshield.core.rules.url_rules import (
    BrandTyposquattingRule,
    DomainEntropyRule,
    IDNHomographRule,
    IPAddressURLRule,
    SubdomainInfiltrationRule,
    SuspiciousTLDRule,
    calculate_shannon_entropy,
    levenshtein_distance,
)


def test_levenshtein_distance():
    assert levenshtein_distance("paypal", "paypal") == 0
    assert levenshtein_distance("paypa1", "paypal") == 1
    assert levenshtein_distance("pypal", "paypal") == 1
    # Cobertura para len(s2) == 0 (Línea 28)
    assert levenshtein_distance("abc", "") == 3


def test_shannon_entropy():
    # Cobertura para cadena vacía (Línea 14)
    assert calculate_shannon_entropy("") == 0.0
    # Cadena repetitiva -> baja entropía
    assert calculate_shannon_entropy("aaaaaaa") == 0.0
    # Cadena variada -> mayor entropía
    assert calculate_shannon_entropy("qzkxwp98731") > 3.0


def test_ip_address_rule_trigger():
    rule = IPAddressURLRule()
    # IPv4 directa
    res_ip = rule.evaluate("http://192.168.1.1/login")
    assert res_ip.triggered is True
    assert res_ip.severity == RuleSeverity.HIGH
    assert res_ip.score_impact == 40

    # IPv6 directa (comienza con '[')
    res_ipv6 = rule.evaluate("http://[2001:db8::1]/index.html")
    assert res_ipv6.triggered is True

    # Nombre de dominio legítimo
    res_domain = rule.evaluate("https://example.com")
    assert res_domain.triggered is False


def test_domain_entropy_rule_trigger():
    rule = DomainEntropyRule(entropy_threshold=3.0)
    # Alta entropía con len(sld) > 8
    res_high = rule.evaluate("https://qzkxwp98731m.com")
    assert res_high.triggered is True
    assert res_high.severity == RuleSeverity.MEDIUM

    # Alta entropía pero len(sld) <= 8
    res_short = rule.evaluate("https://qzkx98.com")
    assert res_short.triggered is False

    # Entropía normal
    res_normal = rule.evaluate("https://google.com")
    assert res_normal.triggered is False


def test_brand_typosquatting_rule_trigger():
    rule = BrandTyposquattingRule()
    # Typosquatting detectado
    res_typo = rule.evaluate("https://paypa1-security.com")
    assert res_typo.triggered is True
    assert res_typo.severity == RuleSeverity.HIGH
    assert res_typo.details["target_brand"] == "paypal"

    # Marca exacta legítima (ejecuta la rama token == brand)
    res_legit = rule.evaluate("https://paypal.com")
    assert res_legit.triggered is False


def test_idn_homograph_rule_trigger():
    rule = IDNHomographRule()
    # Punycode ('xn--') -> Severidad CRITICAL (Líneas 190-210)
    res_puny = rule.evaluate("https://xn--80akhbyknj4f.com")
    assert res_puny.triggered is True
    assert res_puny.severity == RuleSeverity.CRITICAL
    assert res_puny.details["is_punycode"] is True

    # Caracteres Unicode no ASCII -> Severidad HIGH
    res_non_ascii = rule.evaluate("https://pàypal.com")
    assert res_non_ascii.triggered is True
    assert res_non_ascii.severity == RuleSeverity.HIGH

    # Dominio ASCII normal
    res_legit = rule.evaluate("https://paypal.com")
    assert res_legit.triggered is False


def test_subdomain_infiltration_rule_trigger():
    rule = SubdomainInfiltrationRule(max_subdomains=3)

    # Inyección de marca/palabra sensible en subdominio -> HIGH (Líneas 249-284)
    res_keyword = rule.evaluate("https://paypal.login.attacker.com")
    assert res_keyword.triggered is True
    assert res_keyword.severity == RuleSeverity.HIGH
    assert res_keyword.score_impact == 35

    # Exceso de subdominios sin palabras clave -> MEDIUM
    res_excess = rule.evaluate("https://a.b.c.attacker.com")
    assert res_excess.triggered is True
    assert res_excess.severity == RuleSeverity.MEDIUM
    assert res_excess.score_impact == 20

    # Subdominios legítimos dentro del rango permitido
    res_normal = rule.evaluate("https://sub.example.com")
    assert res_normal.triggered is False


def test_suspicious_tld_rule_trigger():
    rule = SuspiciousTLDRule()

    # TLD de alto riesgo (.xyz) -> (Líneas 325-340)
    res_tld = rule.evaluate("https://phishingsite.xyz")
    assert res_tld.triggered is True
    assert res_tld.severity == RuleSeverity.MEDIUM
    assert res_tld.details["tld"] == "xyz"

    # TLD estándar (.com)
    res_legit = rule.evaluate("https://example.com")
    assert res_legit.triggered is False

    # Hostname sin TLD (ej. localhost)
    res_no_tld = rule.evaluate("http://localhost")
    assert res_no_tld.triggered is False