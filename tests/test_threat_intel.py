"""tests/test_threat_intel.py"""
import sys, os, json
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
from unittest.mock import patch, MagicMock

from threat_intel import (
    parse_cves,
    get_mock_cves,
    rule_based_analysis,
    analyze_with_ai,
    fetch_cves,
    generate_report,
    print_console_report,
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


# ─────────────────────────────────────────────
# NEW: parse_cves edge cases
# ─────────────────────────────────────────────

def test_parse_cves_empty_input():
    assert parse_cves([]) == []


def test_parse_cves_missing_metrics_defaults():
    """CVEs without CVSS metrics should get N/A score and UNKNOWN severity."""
    raw = [{"cve": {
        "id": "CVE-2024-0000",
        "published": "2024-06-01T12:00:00.000",
        "descriptions": [{"lang": "en", "value": "No metrics CVE"}],
        "metrics": {},
        "weaknesses": [],
    }}]
    parsed = parse_cves(raw)
    assert len(parsed) == 1
    assert parsed[0]["score"] == "N/A"
    assert parsed[0]["severity"] == "UNKNOWN"
    assert parsed[0]["vector"] == "UNKNOWN"
    assert parsed[0]["cwe"] == "Unknown"


def test_parse_cves_no_english_description():
    """CVEs with only non-English descriptions should fall back to default."""
    raw = [{"cve": {
        "id": "CVE-2024-0001",
        "published": "2024-06-01T00:00:00.000",
        "descriptions": [{"lang": "es", "value": "Descripción en español"}],
        "metrics": {},
        "weaknesses": [],
    }}]
    parsed = parse_cves(raw)
    assert parsed[0]["description"] == "No description available"


def test_parse_cves_sorts_na_scores_last():
    """CVEs with N/A scores should sort below scored CVEs."""
    raw = [
        {"cve": {"id": "CVE-LOW", "published": "2024-01-01T00:00:00.000",
                 "descriptions": [{"lang": "en", "value": "low"}],
                 "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 3.0, "baseSeverity": "LOW", "attackVector": "LOCAL"}}]},
                 "weaknesses": []}},
        {"cve": {"id": "CVE-NONE", "published": "2024-01-01T00:00:00.000",
                 "descriptions": [{"lang": "en", "value": "none"}],
                 "metrics": {},
                 "weaknesses": []}},
    ]
    parsed = parse_cves(raw)
    assert parsed[0]["cve_id"] == "CVE-LOW"
    assert parsed[1]["cve_id"] == "CVE-NONE"


# ─────────────────────────────────────────────
# NEW: rule_based_analysis — missing branches
# ─────────────────────────────────────────────

def test_medium_severity_gets_30_day_timeline():
    cve = {
        "cve_id": "CVE-TEST-003", "severity": "MEDIUM", "score": "5.0",
        "vector": "NETWORK", "cwe": "CWE-79", "published": "2024-01-01",
        "description": "Test medium severity vulnerability"
    }
    result = rule_based_analysis(cve)
    assert "30 days" in result
    assert "scheduled patching" in result


def test_rule_based_network_vector_description():
    cve = {
        "cve_id": "CVE-TEST-NET", "severity": "HIGH", "score": "8.0",
        "vector": "NETWORK", "cwe": "CWE-89", "published": "2024-01-01",
        "description": "Network vector test"
    }
    result = rule_based_analysis(cve)
    assert "remotely exploitable" in result


def test_rule_based_local_vector_description():
    cve = {
        "cve_id": "CVE-TEST-LOCAL", "severity": "HIGH", "score": "7.5",
        "vector": "LOCAL", "cwe": "CWE-362", "published": "2024-01-01",
        "description": "Local vector test"
    }
    result = rule_based_analysis(cve)
    assert "requires local access" in result


def test_rule_based_analysis_all_sections_present():
    """Verify all six expected sections are in the output."""
    cve = {
        "cve_id": "CVE-TEST-SEC", "severity": "CRITICAL", "score": "9.8",
        "vector": "NETWORK", "cwe": "CWE-120", "published": "2024-01-01",
        "description": "Section check"
    }
    result = rule_based_analysis(cve)
    for section in ["THREAT SUMMARY", "ATTACK SCENARIO", "AFFECTED ORGANIZATIONS",
                     "IMMEDIATE ACTIONS", "NIST 800-53 CONTROLS", "ANALYST CONFIDENCE"]:
        assert section in result, f"Missing section: {section}"


# ─────────────────────────────────────────────
# NEW: fetch_cves — mocked network tests
# ─────────────────────────────────────────────

def test_fetch_cves_success_returns_vulnerabilities():
    mock_response_body = json.dumps({
        "vulnerabilities": [{"cve": {"id": "CVE-2024-9999"}}]
    }).encode("utf-8")
    mock_response = MagicMock()
    mock_response.read.return_value = mock_response_body
    mock_response.__enter__ = lambda s: s
    mock_response.__exit__ = MagicMock(return_value=False)

    with patch("threat_intel.urllib.request.urlopen", return_value=mock_response):
        result = fetch_cves(keyword="test", max_results=1)
    assert len(result) == 1
    assert result[0]["cve"]["id"] == "CVE-2024-9999"


def test_fetch_cves_network_error_falls_back_to_mock():
    with patch("threat_intel.urllib.request.urlopen", side_effect=Exception("timeout")):
        result = fetch_cves(keyword="test", max_results=1)
    assert isinstance(result, list)
    assert len(result) > 0
    assert result[0]["cve"]["id"] == "CVE-2024-1234"


# ─────────────────────────────────────────────
# NEW: generate_report — file output tests
# ─────────────────────────────────────────────

def test_generate_report_creates_json_and_text(tmp_path):
    cves_with_analysis = [{
        "cve": {
            "cve_id": "CVE-2024-1234", "severity": "CRITICAL", "score": 9.8,
            "vector": "NETWORK", "published": "2024-03-01",
        },
        "analysis": "Test analysis content"
    }]
    json_path, text_path = generate_report(cves_with_analysis, "test", output_dir=str(tmp_path))
    assert os.path.exists(json_path)
    assert os.path.exists(text_path)

    with open(json_path) as f:
        data = json.load(f)
    assert data["metadata"]["keyword"] == "test"
    assert data["metadata"]["total_cves"] == 1
    assert len(data["findings"]) == 1

    with open(text_path) as f:
        text = f.read()
    assert "CVE-2024-1234" in text
    assert "CRITICAL" in text


def test_generate_report_creates_output_dir(tmp_path):
    new_dir = str(tmp_path / "nested" / "output")
    cves_with_analysis = [{
        "cve": {"cve_id": "CVE-X", "severity": "LOW", "score": 2.0,
                "vector": "LOCAL", "published": "2024-01-01"},
        "analysis": "Minimal"
    }]
    json_path, text_path = generate_report(cves_with_analysis, "kw", output_dir=new_dir)
    assert os.path.isdir(new_dir)
    assert os.path.exists(json_path)


# ─────────────────────────────────────────────
# NEW: print_console_report — smoke test
# ─────────────────────────────────────────────

def test_print_console_report_runs_without_error(capsys):
    cves_with_analysis = [{
        "cve": {
            "cve_id": "CVE-2024-1234", "severity": "HIGH", "score": 8.5,
            "vector": "NETWORK", "published": "2024-03-01",
        },
        "analysis": "Line 1\nLine 2\nLine 3\nLine 4\nLine 5"
    }]
    print_console_report(cves_with_analysis, "test_keyword")
    captured = capsys.readouterr()
    assert "CVE-2024-1234" in captured.out
    assert "test_keyword" in captured.out


# ─────────────────────────────────────────────
# NEW: analyze_with_ai — mocked API tests
# ─────────────────────────────────────────────

def test_analyze_with_ai_api_error_falls_back():
    """When the API key is set but the request fails, fall back to rule-based."""
    cve = {
        "cve_id": "CVE-TEST-API", "severity": "HIGH", "score": "8.0",
        "vector": "NETWORK", "cwe": "CWE-79", "published": "2024-01-01",
        "description": "API error fallback test"
    }
    with patch("threat_intel.ANTHROPIC_API_KEY", "fake-key"), \
         patch("threat_intel.urllib.request.urlopen", side_effect=Exception("API error")):
        result = analyze_with_ai(cve)
    assert "THREAT SUMMARY" in result
    assert "7 days" in result


def test_analyze_with_ai_success():
    """When the API returns successfully, the response text is extracted."""
    cve = {
        "cve_id": "CVE-TEST-OK", "severity": "CRITICAL", "score": "9.5",
        "vector": "NETWORK", "cwe": "CWE-120", "published": "2024-01-01",
        "description": "Successful API test"
    }
    mock_api_response = json.dumps({
        "content": [{"text": "AI-generated analysis text here"}]
    }).encode("utf-8")
    mock_response = MagicMock()
    mock_response.read.return_value = mock_api_response
    mock_response.__enter__ = lambda s: s
    mock_response.__exit__ = MagicMock(return_value=False)

    with patch("threat_intel.ANTHROPIC_API_KEY", "fake-key"), \
         patch("threat_intel.urllib.request.urlopen", return_value=mock_response):
        result = analyze_with_ai(cve)
    assert result == "AI-generated analysis text here"
