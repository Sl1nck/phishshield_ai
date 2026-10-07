from phishshield.heuristics.engine import HeuristicEngine
from phishshield.scraper.parser import ParsedDOM


def test_heuristic_engine_detects_typosquatting():
    engine = HeuristicEngine()
    dom = ParsedDOM(
        title="Inicie sesión en su cuenta",
        input_fields=[{"type": "password", "name": "pass"}],
    )

    # URL sospechosa imitando "paypal" (paypa1)
    result = engine.analyze(dom, "https://paypa1-security.com/login")

    rule_ids = [r.rule_id for r in result.triggered_rules]
    assert "HEUR-05" in rule_ids
    assert any("PayPal" in r.description for r in result.triggered_rules)


def test_heuristic_engine_detects_hidden_sensitive_inputs():
    engine = HeuristicEngine()
    dom = ParsedDOM(
        title="Verificación de Seguridad",
        input_fields=[
            {"type": "text", "name": "user"},
            {
                "type": "password",
                "name": "pass",
                "is_hidden": True,
            },  # Campo password oculto por CSS/HTML
        ],
    )

    result = engine.analyze(dom, "https://secure-login-check.com")

    rule_ids = [r.rule_id for r in result.triggered_rules]
    assert "HEUR-06" in rule_ids
    assert any("oculto" in r.description.lower() for r in result.triggered_rules)


def test_heuristic_engine_detects_excessive_subdomains():
    engine = HeuristicEngine()
    dom = ParsedDOM(
        title="Verificación de Cuenta",
        input_fields=[{"type": "text", "name": "user"}],
    )

    # URL con más de 3 niveles de subdominio engañosos
    result = engine.analyze(
        dom, "https://paypal.com.verify.account.security-check.site.com"
    )

    rule_ids = [r.rule_id for r in result.triggered_rules]
    assert "HEUR-07" in rule_ids
    assert any("subdominios" in r.description.lower() for r in result.triggered_rules)


def test_heuristic_engine_detects_brand_title_mismatch():
    engine = HeuristicEngine()
    dom = ParsedDOM(
        title="PayPal - Iniciar sesión en su cuenta",
        input_fields=[{"type": "password", "name": "pass"}],
    )

    # El título menciona PayPal, pero el dominio no tiene ninguna relación con paypal.com
    result = engine.analyze(dom, "https://verification-center-alert12.com")

    rule_ids = [r.rule_id for r in result.triggered_rules]
    assert "HEUR-08" in rule_ids
    assert any("marca" in r.description.lower() for r in result.triggered_rules)
