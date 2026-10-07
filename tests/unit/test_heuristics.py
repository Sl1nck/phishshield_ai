from phishshield.heuristics.engine import (
    HeuristicEngine,
    _calculate_shannon_entropy,
    _levenshtein_distance,
)
from phishshield.scraper.parser import ParsedDOM


# --- Pruebas de Funciones Auxiliares ---

def test_shannon_entropy_helpers():
    assert _calculate_shannon_entropy("") == 0.0
    assert _calculate_shannon_entropy("aaaaaaa") < 1.0
    assert _calculate_shannon_entropy("a1b2c3d4e5f6g7h8") > 3.5


def test_levenshtein_distance_helpers():
    # Prueba cadena secundaria vacía (s2 == "")
    assert _levenshtein_distance("paypal", "") == 6
    # Prueba intercambio s1 < s2
    assert _levenshtein_distance("cat", "catwoman") == 5
    # Prueba igualdad total
    assert _levenshtein_distance("google", "google") == 0


# --- Tests Principales de Integración (Existentes) ---

def test_heuristic_engine_detects_ip_address_and_password():
    engine = HeuristicEngine()
    dom = ParsedDOM(
        title="Login Falso",
        input_fields=[{"type": "password", "name": "pass"}],
        form_actions=["http://192.168.1.100/login.php"],
    )

    result = engine.analyze(dom, "http://192.168.1.100/index.html")

    assert result.is_suspicious is True
    assert result.total_score >= 60
    rule_ids = [r.rule_id for r in result.triggered_rules]
    assert "HEUR-01" in rule_ids
    assert "HEUR-03" in rule_ids
    assert "HEUR-04" in rule_ids


def test_heuristic_engine_clean_site():
    engine = HeuristicEngine()
    dom = ParsedDOM(
        title="Sitio Legítimo",
        input_fields=[{"type": "text", "name": "search"}],
        form_actions=["https://ejemplo.com/search"],
    )

    result = engine.analyze(dom, "https://ejemplo.com")

    assert result.is_suspicious is False
    assert result.total_score == 0
    assert len(result.triggered_rules) == 0


# --- Cobertura de Reglas Específicas (HEUR-02 a HEUR-11) ---

def test_heur02_suspicious_tld():
    engine = HeuristicEngine()
    dom = ParsedDOM(title="Test TLD")

    result = engine.analyze(dom, "https://login-portal.xyz")
    rule_ids = [r.rule_id for r in result.triggered_rules]
    assert "HEUR-02" in rule_ids


def test_heur03_password_https_impact():
    engine = HeuristicEngine()
    dom = ParsedDOM(
        title="Login HTTPS",
        input_fields=[{"type": "password"}],
    )

    result = engine.analyze(dom, "https://example.com/login")
    rule = next(r for r in result.triggered_rules if r.rule_id == "HEUR-03")
    # Bajo HTTPS el impacto se reduce a 15 (en comparación a 25 bajo HTTP)
    assert rule.score_impact == 15


def test_heur05_typosquatting_and_exact_brand():
    engine = HeuristicEngine()
    dom = ParsedDOM(title="Typosquatting Test")

    # Marca exacta legítima -> No debe disparar HEUR-05
    res_legit = engine.analyze(dom, "https://paypal.com/login")
    assert "HEUR-05" not in [r.rule_id for r in res_legit.triggered_rules]

    # Imitación visual ("paypa1") -> Dispara HEUR-05
    res_typo = engine.analyze(dom, "https://paypa1-security.com")
    assert "HEUR-05" in [r.rule_id for r in res_typo.triggered_rules]


def test_heur06_hidden_sensitive_field():
    engine = HeuristicEngine()
    dom = ParsedDOM(
        title="Hidden Input",
        input_fields=[{"type": "password", "is_hidden": True}],
    )

    result = engine.analyze(dom, "https://example.com")
    rule_ids = [r.rule_id for r in result.triggered_rules]
    assert "HEUR-06" in rule_ids


def test_heur07_excessive_subdomains():
    engine = HeuristicEngine()
    dom = ParsedDOM(title="Subdomains")

    url = "https://login.account.security.update.check.example.com"
    result = engine.analyze(dom, url)
    rule_ids = [r.rule_id for r in result.triggered_rules]
    assert "HEUR-07" in rule_ids


def test_heur08_brand_title_inconsistency():
    engine = HeuristicEngine()
    dom = ParsedDOM(title="Microsoft Azure Portal")

    result = engine.analyze(dom, "https://unrelated-phishing-domain.com")
    rule_ids = [r.rule_id for r in result.triggered_rules]
    assert "HEUR-08" in rule_ids


def test_heur09_external_iframe():
    engine = HeuristicEngine()
    dom = ParsedDOM(title="iFrame Test")
    dom.iframes = ["https://malicious-external.com/embed"]

    result = engine.analyze(dom, "https://legit-looking-site.com")
    rule_ids = [r.rule_id for r in result.triggered_rules]
    assert "HEUR-09" in rule_ids


def test_heur10_punycode_and_homoglyphs():
    engine = HeuristicEngine()
    dom = ParsedDOM(title="IDN Test")

    # Test Punycode (xn--)
    res_puny = engine.analyze(dom, "https://xn--pypal-4ve.com")
    assert "HEUR-10" in [r.rule_id for r in res_puny.triggered_rules]

    # Test Caracter no ASCII (Cirílico 'а')
    res_unicode = engine.analyze(dom, "https://pаypal.com")
    assert "HEUR-10" in [r.rule_id for r in res_unicode.triggered_rules]


def test_heur11_dga_high_entropy():
    engine = HeuristicEngine()
    dom = ParsedDOM(title="DGA Domain")

    # Cadena con alta variedad de caracteres para superar el umbral de entropía (3.8)
    url = "https://a1b2c3d4e5f6g7h8i9j0k.com"
    result = engine.analyze(dom, url)
    rule_ids = [r.rule_id for r in result.triggered_rules]
    assert "HEUR-11" in rule_ids