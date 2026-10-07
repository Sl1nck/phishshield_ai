from phishshield.analyzer.phish_analyzer import PhishAnalyzer


def test_phish_analyzer_execution():
    analyzer = PhishAnalyzer()
    res = analyzer.analyze_url("https://paypa1-login.com")

    assert res["target_url"] == "https://paypa1-login.com"
    assert "heuristic_analysis" in res
    assert res["heuristic_analysis"]["total_heuristic_score"] > 0
    assert res["requires_ai_escalation"] is True
