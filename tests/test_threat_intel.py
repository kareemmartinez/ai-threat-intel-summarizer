"""tests/test_threat_intel.py"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from threat_intel import (
    parse_cves,
    get_mock_cves,
    rule_based_analysis,
    analyze_with_ai,
)


def test_mock_cves_returns_list():
    assert isinstance(get_mock_cves(), list)
    assert len(get_mock_cves()) > 0


def test_parse_cves_returns_required_keys():
    required = {"cve_id", "published", "severity", "score", "vector", "cwe", "description"}
    for cve in parse_cves(get_mock_cves()):
        assert required.issubset(cve.keys())


def test_parsed_cves_sorted_by_score():
    parsed = parse_cves(get_mock_cves())
    scores = [float(p["score"]) for p in parsed if p["score"] != "N/A"]
    assert scores == sorted(scores, reverse=True)


def test_rule_based_analysis_returns_string():
    cve    = parse_cves(get_mock_cves())[0]
    result = rule_based_analysis(cve)
    assert isinstance(result, str)
    assert len(result) > 0


def test_rule_based_analysis_contains_required_sections():
    cve    = parse_cves(get_mock_cves())[0]
    result = rule_based_analysis(cve)
    assert "THREAT SUMMARY"    in result
    assert "IMMEDIATE ACTIONS" in result
    assert "NIST 800-53"       in result


def test_critical_cve_gets_24hr_timeline():
    cve = {
        "cve_id":      "CVE-TEST-001",
        "severity":    "CRITICAL",
        "score":       "9.8",
        "vector":      "NETWORK",
        "cwe":         "CWE-120",
        "published":   "2024-01-01",
        "description": "Test critical vulnerability"
    }
    result = rule_based_analysis(cve)
    assert "24 hours" in result


def test_analyze_with_ai_falls_back_without_key():
    os.environ.pop("ANTHROPIC_API_KEY", None)
    cve    = parse_cves(get_mock_cves())[0]
    result = analyze_with_ai(cve)
    assert isinstance(result, str)
    assert len(result) > 0


def test_high_severity_gets_7_day_timeline():
    cve = {
        "cve_id":      "CVE-TEST-002",
        "severity":    "HIGH",
        "score":       "8.1",
        "vector":      "NETWORK",
        "cwe":         "CWE-89",
        "published":   "2024-01-01",
        "description": "Test high severity vulnerability"
    }
    result = rule_based_analysis(cve)
    assert "7 days" in result
