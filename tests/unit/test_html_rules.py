from bs4 import BeautifulSoup

from phishshield.core.rules.html_rules import (
    CredentialFormPresenceRule,
    ExternalFormActionRule,
    ObfuscatedScriptRule,
)
from phishshield.core.rules.schemas import RuleSeverity


def test_rules_without_dom_or_invalid_dom():
    rule_ext = ExternalFormActionRule()
    rule_cred = CredentialFormPresenceRule()
    rule_script = ObfuscatedScriptRule()

    for invalid_dom in [None, "cadena_no_bs4", 123]:
        res_ext = rule_ext.evaluate("https://example.com", parsed_dom=invalid_dom)
        assert res_ext.triggered is False
        assert res_ext.severity == RuleSeverity.INFO

        res_cred = rule_cred.evaluate("https://example.com", parsed_dom=invalid_dom)
        assert res_cred.triggered is False
        assert res_cred.severity == RuleSeverity.INFO

        res_script = rule_script.evaluate("https://example.com", parsed_dom=invalid_dom)
        assert res_script.triggered is False
        assert res_script.severity == RuleSeverity.INFO


def test_external_form_action_rule():
    rule = ExternalFormActionRule()

    # Formulario hacia dominio externo
    html_external = '<html><body><form action="https://malicious-receiver.com/login"></form></body></html>'
    dom_ext = BeautifulSoup(html_external, "html.parser")
    res_ext = rule.evaluate("https://legit.com", parsed_dom=dom_ext)
    assert res_ext.triggered is True
    assert res_ext.severity == RuleSeverity.HIGH
    assert res_ext.score_impact == 35

    # Formulario relativo, interno, hash o javascript:
    html_internal = """
    <html>
        <body>
            <form action="/api/login"></form>
            <form action="#"></form>
            <form action="javascript:void(0)"></form>
            <form action=""></form>
            <form action="https://legit.com/auth"></form>
        </body>
    </html>
    """
    dom_int = BeautifulSoup(html_internal, "html.parser")
    res_int = rule.evaluate("https://legit.com", parsed_dom=dom_int)
    assert res_int.triggered is False


def test_credential_form_presence_rule():
    rule = CredentialFormPresenceRule()

    # Campo de contraseña
    html_pass = '<html><body><input type="password" name="pwd"></body></html>'
    res_pass = rule.evaluate(
        "https://example.com", parsed_dom=BeautifulSoup(html_pass, "html.parser")
    )
    assert res_pass.triggered is True
    assert res_pass.severity == RuleSeverity.MEDIUM
    assert res_pass.score_impact == 20

    # Campos de datos financieros/sensibles
    html_card = '<html><body><input type="text" name="creditcard_number" placeholder="Enter Card"></body></html>'
    res_card = rule.evaluate(
        "https://example.com", parsed_dom=BeautifulSoup(html_card, "html.parser")
    )
    assert res_card.triggered is True
    assert res_card.severity == RuleSeverity.HIGH
    assert res_card.score_impact == 30

    # Formulario limpio
    html_clean = '<html><body><input type="text" name="search"></body></html>'
    res_clean = rule.evaluate(
        "https://example.com", parsed_dom=BeautifulSoup(html_clean, "html.parser")
    )
    assert res_clean.triggered is False


def test_obfuscated_script_rule():
    rule = ObfuscatedScriptRule()

    # Script con patrones de ofuscación
    html_eval = """
    <html>
        <body>
            <script>eval(function(p,a,c,k,e,r){ return "obfuscated"; })</script>
            <script>document.write(unescape("%3Cscript%3E"));</script>
            <script>var x = String.fromCharCode(65, 66, 67);</script>
            <script>var hex = "\\x61\\x62\\x63\\x64\\x65\\x66";</script>
            <script>window["\\x65\\x76\\x61\\x6c"]();</script>
        </body>
    </html>
    """
    res_eval = rule.evaluate(
        "https://example.com", parsed_dom=BeautifulSoup(html_eval, "html.parser")
    )
    assert res_eval.triggered is True
    assert res_eval.severity == RuleSeverity.HIGH
    assert res_eval.score_impact == 30

    # Script limpio
    html_clean = '<script>console.log("Hello world");</script>'
    res_clean = rule.evaluate(
        "https://example.com", parsed_dom=BeautifulSoup(html_clean, "html.parser")
    )
    assert res_clean.triggered is False