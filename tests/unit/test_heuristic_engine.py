from phishshield.heuristics.engine import HeuristicEngine
from phishshield.core.rules.base import BaseRule
from phishshield.core.rules.schemas import RuleResult, RuleSeverity


class DummyRule(BaseRule):
    """Regla auxiliar para verificar ordenamiento de severidad y puntajes."""

    def __init__(
        self, rule_id: str, severity: RuleSeverity, score: int, triggered: bool
    ):
        super().__init__(rule_id=rule_id, name=f"Dummy {rule_id}")
        self._severity = severity
        self._score = score
        self._triggered = triggered

    def evaluate(self, url: str, parsed_dom=None) -> RuleResult:
        return RuleResult(
            rule_id=self.rule_id,
            name=self.name,
            triggered=self._triggered,
            severity=self._severity,
            score_impact=self._score if self._triggered else 0,
            description="Resultado dummy de prueba",
        )


def test_engine_default_initialization():
    engine = HeuristicEngine()
    assert len(engine.rules) > 0


def test_engine_custom_rules_initialization():
    dummy = DummyRule("DUMMY-001", RuleSeverity.LOW, 10, True)
    engine = HeuristicEngine(rules=[dummy])
    assert len(engine.rules) == 1


def test_engine_analyze_clean_site():
    engine = HeuristicEngine()
    res = engine.analyze("https://google.com")
    assert res.is_suspicious is False
    assert res.total_score == 0
    assert res.max_severity == RuleSeverity.INFO
    assert len(res.triggered_rules) == 0


def test_engine_analyze_suspicious_phishing():
    engine = HeuristicEngine()
    html_content = """
    <html>
        <body>
            <form action="http://192.168.1.100/login">
                <input type="password" name="pwd">
            </form>
            <script>eval(function(p,a,c,k,e,r){ return "test"; })</script>
        </body>
    </html>
    """
    res = engine.analyze(
        url="http://192.168.1.1/login.php", html_content=html_content
    )
    assert res.is_suspicious is True
    assert res.total_score >= 30
    assert len(res.triggered_rules) > 0


def test_engine_severity_ordering_and_suspicious_flags():
    r1 = DummyRule("DUMMY-1", RuleSeverity.LOW, 5, True)
    r2 = DummyRule("DUMMY-2", RuleSeverity.CRITICAL, 10, True)
    engine = HeuristicEngine(rules=[r1, r2])

    res = engine.analyze("https://example.com")
    assert res.max_severity == RuleSeverity.CRITICAL
    assert res.total_score == 15
    assert res.is_suspicious is True