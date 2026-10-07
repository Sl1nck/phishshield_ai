from pathlib import Path
import pytest
from phishshield.scraper.parser import DOMParser
from phishshield.heuristics.engine import HeuristicEngine

SAMPLES_DIR = Path(__file__).parent.parent / "fixtures" / "samples"

def test_phishing_login_sample_detection():
    html_path = SAMPLES_DIR / "phishing_login.html"
    html_content = html_path.read_text(encoding="utf-8")
    
    parser = DOMParser(html_content)
    parsed_dom = parser.parse()
    
    engine = HeuristicEngine()
    result = engine.analyze(parsed_dom, url="http://192.168.1.50/login")
    
    # Debe ser detectado con puntaje alto por formulario y por IP directa
    assert result.total_score >= 30
    assert parsed_dom.has_password_field is True

def test_legitimate_site_sample_detection():
    html_path = SAMPLES_DIR / "legitimate_site.html"
    html_content = html_path.read_text(encoding="utf-8")
    
    parser = DOMParser(html_content)
    parsed_dom = parser.parse()
    
    engine = HeuristicEngine()
    result = engine.analyze(parsed_dom, url="https://ejemplo-legitimo.com/blog")
    
    # Debe mantener un puntaje bajo (seguro)
    assert result.total_score < 30
    assert parsed_dom.has_password_field is False
