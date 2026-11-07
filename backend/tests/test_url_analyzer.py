
from app.services.url_analyzer import analyze_url


def test_safe_https_url():
    result = analyze_url("https://example.com")

    assert result["risk_score"] == 0
    assert result["risk_level"] == "Low Risk"
    assert result["findings"] == []


def test_http_url():
    result = analyze_url("http://example.com")

    assert result["risk_score"] == 15
    assert result["risk_level"] == "Low Risk"


def test_suspicious_keyword():
    result = analyze_url("https://example.com/login")

    assert result["risk_score"] == 5
    assert len(result["findings"]) == 1


def test_ip_address_url():
    result = analyze_url("http://192.168.1.1")

    assert result["risk_score"] == 35
    assert result["risk_level"] == "Medium Risk"


def test_url_shortener():
    result = analyze_url("https://bit.ly/abc123")

    assert result["risk_score"] == 15
    assert result["risk_level"] == "Low Risk"
