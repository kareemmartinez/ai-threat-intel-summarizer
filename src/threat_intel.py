"""
threat_intel.py
---------------
AI-Powered Threat Intelligence Summarizer
Pulls live CVE data from the NIST NVD API, feeds it to the Anthropic Claude API,
and generates plain-English threat summaries with actionable remediation guidance.

Author: Kareem Martinez | Seraph LLC
"""

import json
import os
import datetime
import urllib.request
import urllib.parse


# ─────────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────────
# Set your Anthropic API key as an environment variable:
# export ANTHROPIC_API_KEY="your_key_here"
# Get a free key at: https://console.anthropic.com

ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
ANTHROPIC_API_URL = "https://api.anthropic.com/v1/messages"
MODEL             = "claude-3-haiku-20240307"


# ─────────────────────────────────────────────
# STEP 1: Fetch CVE Data from NVD API
# ─────────────────────────────────────────────

def fetch_cves(keyword="ransomware", max_results=5):
    print(f"[+] Fetching CVEs for keyword: '{keyword}'...")
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    query_params   = {
        "keywordSearch":  keyword,
        "resultsPerPage": max_results,
    }
    request_url = base_url + "?" + urllib.parse.urlencode(query_params)
    try:
        http_request = urllib.request.Request(request_url, headers={"User-Agent": "ThreatIntelSummarizer/1.0"})
        with urllib.request.urlopen(http_request, timeout=15) as response:
            nvd_response_data = json.loads(response.read().decode("utf-8"))
        vulnerability_entries = nvd_response_data.get("vulnerabilities", [])
        print(f"[+] Retrieved {len(vulnerability_entries)} CVEs.")
        return vulnerability_entries
    except Exception as e:
        print(f"[!] NVD API failed: {e}. Using mock data.")
        return get_mock_cves()


def get_mock_cves():
    return [
        {"cve": {
            "id": "CVE-2024-1234",
            "published": "2024-03-01T00:00:00.000",
            "descriptions": [{"lang": "en", "value": "A critical buffer overflow vulnerability in OpenSSL 3.x allows remote attackers to execute arbitrary code via a specially crafted certificate chain. This affects all versions prior to 3.2.1 and can be exploited without authentication."}],
            "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL", "attackVector": "NETWORK", "attackComplexity": "LOW", "privilegesRequired": "NONE"}}]},
            "weaknesses": [{"description": [{"value": "CWE-120"}]}],
        }},
        {"cve": {
            "id": "CVE-2024-5678",
            "published": "2024-03-05T00:00:00.000",
            "descriptions": [{"lang": "en", "value": "SQL injection vulnerability in the authentication module of Apache HTTP Server allows unauthenticated remote attackers to bypass login controls and exfiltrate sensitive database contents through crafted HTTP requests."}],
            "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 8.6, "baseSeverity": "HIGH", "attackVector": "NETWORK", "attackComplexity": "LOW", "privilegesRequired": "NONE"}}]},
            "weaknesses": [{"description": [{"value": "CWE-89"}]}],
        }},
        {"cve": {
            "id": "CVE-2024-9101",
            "published": "2024-03-10T00:00:00.000",
            "descriptions": [{"lang": "en", "value": "Privilege escalation vulnerability in Windows kernel driver allows local attackers with low-privilege user accounts to gain SYSTEM-level privileges through a race condition in memory management routines."}],
            "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 7.8, "baseSeverity": "HIGH", "attackVector": "LOCAL", "attackComplexity": "LOW", "privilegesRequired": "LOW"}}]},
            "weaknesses": [{"description": [{"value": "CWE-362"}]}],
        }},
    ]


# ─────────────────────────────────────────────
# STEP 2: Parse CVEs
# ─────────────────────────────────────────────

def parse_cves(raw_cves):
    parsed_vulnerabilities = []
    for vulnerability_entry in raw_cves:
        cve_data     = vulnerability_entry.get("cve", {})
        cve_id       = cve_data.get("id", "Unknown")
        published    = cve_data.get("published", "")[:10]
        descriptions = cve_data.get("descriptions", [])
        description  = next(
            (d["value"] for d in descriptions if d.get("lang") == "en"),
            "No description available"
        )
        cvss_base_score = "N/A"
        cvss_severity   = "UNKNOWN"
        attack_vector   = "UNKNOWN"
        cvss_metrics    = cve_data.get("metrics", {})
        if "cvssMetricV31" in cvss_metrics:
            cvss_v31_data   = cvss_metrics["cvssMetricV31"][0]["cvssData"]
            cvss_base_score = cvss_v31_data.get("baseScore", "N/A")
            cvss_severity   = cvss_v31_data.get("baseSeverity", "UNKNOWN")
            attack_vector   = cvss_v31_data.get("attackVector", "UNKNOWN")
        weaknesses = cve_data.get("weaknesses", [])
        cwe = "Unknown"
        if weaknesses:
            cwe_descriptions = weaknesses[0].get("description", [])
            if cwe_descriptions:
                cwe = cwe_descriptions[0].get("value", "Unknown")
        parsed_vulnerabilities.append({
            "cve_id":      cve_id,
            "published":   published,
            "severity":    cvss_severity,
            "score":       cvss_base_score,
            "vector":      attack_vector,
            "cwe":         cwe,
            "description": description,
        })
    parsed_vulnerabilities.sort(key=lambda x: float(x["score"]) if x["score"] != "N/A" else 0, reverse=True)
    return parsed_vulnerabilities


# ─────────────────────────────────────────────
# STEP 3: AI Analysis
# ─────────────────────────────────────────────

def analyze_with_ai(cve):
    if not ANTHROPIC_API_KEY:
        print(f"  [!] No API key found. Using rule-based analysis for {cve['cve_id']}.")
        return rule_based_analysis(cve)

    print(f"  [AI] Analyzing {cve['cve_id']} with Claude...")

    analysis_prompt = f"""You are a senior cybersecurity analyst. Analyze this CVE and provide a structured threat intelligence report.

CVE ID:        {cve['cve_id']}
Severity:      {cve['severity']} (CVSS {cve['score']})
Attack Vector: {cve['vector']}
CWE:           {cve['cwe']}
Published:     {cve['published']}
Description:   {cve['description']}

Provide your analysis in exactly this format:

THREAT SUMMARY:
[2-3 sentences explaining what this vulnerability is and why it matters in plain English]

ATTACK SCENARIO:
[1-2 sentences describing how a real attacker would exploit this]

AFFECTED ORGANIZATIONS:
[Which types of organizations or systems are most at risk]

IMMEDIATE ACTIONS:
1. [First priority action]
2. [Second priority action]
3. [Third priority action]

NIST 800-53 CONTROLS:
[List 2-3 relevant NIST controls this vulnerability violates]

ANALYST CONFIDENCE: [HIGH/MEDIUM/LOW]"""

    api_request_payload = {
        "model":      MODEL,
        "max_tokens": 600,
        "messages":   [{"role": "user", "content": analysis_prompt}]
    }
    api_request_headers = {
        "Content-Type":      "application/json",
        "x-api-key":         ANTHROPIC_API_KEY,
        "anthropic-version": "2023-06-01",
    }
    try:
        encoded_payload = json.dumps(api_request_payload).encode("utf-8")
        api_request     = urllib.request.Request(ANTHROPIC_API_URL, data=encoded_payload, headers=api_request_headers, method="POST")
        with urllib.request.urlopen(api_request, timeout=30) as response:
            api_response_data = json.loads(response.read().decode("utf-8"))
            analysis_text     = api_response_data.get("content", [{}])[0].get("text", "")
            return analysis_text
    except Exception as e:
        print(f"  [!] AI API call failed: {e}. Using rule-based analysis.")
        return rule_based_analysis(cve)


def rule_based_analysis(cve):
    cvss_severity = cve["severity"]
    attack_vector = cve["vector"]
    cvss_score    = cve["score"]

    if cvss_severity == "CRITICAL":
        patch_urgency  = "immediate emergency patching"
        patch_timeline = "within 24 hours"
    elif cvss_severity == "HIGH":
        patch_urgency  = "priority patching"
        patch_timeline = "within 7 days"
    else:
        patch_urgency  = "scheduled patching"
        patch_timeline = "within 30 days"

    attack_vector_description = "remotely exploitable without authentication — highest priority" if attack_vector == "NETWORK" else "requires local access to exploit"

    return f"""THREAT SUMMARY:
This {cvss_severity} severity vulnerability (CVSS {cvss_score}) represents a significant security risk. The flaw is {attack_vector_description}. Organizations running affected software should treat this as requiring {patch_urgency}.

ATTACK SCENARIO:
An attacker could leverage this vulnerability to compromise affected systems. The network-accessible attack surface increases exposure significantly for internet-facing assets.

AFFECTED ORGANIZATIONS:
Any organization running the affected software version. Cloud environments, enterprises with internet-facing services, and organizations without automated patch management are at highest risk.

IMMEDIATE ACTIONS:
1. Identify all systems running affected software versions immediately
2. Apply vendor patches or implement compensating controls {patch_timeline}
3. Monitor security logs for exploitation indicators and anomalous activity

NIST 800-53 CONTROLS:
SI-2 (Flaw Remediation), CM-6 (Configuration Settings), RA-5 (Vulnerability Monitoring)

ANALYST CONFIDENCE: MEDIUM"""


# ─────────────────────────────────────────────
# STEP 4: Generate Reports
# ─────────────────────────────────────────────

def generate_report(cves_with_analysis, keyword, output_dir="sample_output"):
    os.makedirs(output_dir, exist_ok=True)
    report_timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

    json_report_path = os.path.join(output_dir, f"threat_intel_{report_timestamp}.json")
    report_data = {
        "metadata": {
            "generated_at": datetime.datetime.now().isoformat(),
            "keyword":      keyword,
            "tool":         "AI Threat Intelligence Summarizer v1.0",
            "author":       "Kareem Martinez | Seraph LLC",
            "model":        MODEL,
            "total_cves":   len(cves_with_analysis),
        },
        "findings": cves_with_analysis,
    }
    with open(json_report_path, "w") as f:
        json.dump(report_data, f, indent=4)
    print(f"\n[+] JSON report saved: {json_report_path}")

    text_report_path = os.path.join(output_dir, f"threat_intel_{report_timestamp}.txt")
    with open(text_report_path, "w") as f:
        f.write("=" * 70 + "\n")
        f.write("  AI THREAT INTELLIGENCE REPORT\n")
        f.write(f"  Seraph LLC | Generated: {datetime.datetime.now().strftime('%B %d, %Y %H:%M UTC')}\n")
        f.write(f"  Keyword: {keyword} | CVEs Analyzed: {len(cves_with_analysis)}\n")
        f.write("=" * 70 + "\n\n")
        for cve_finding in cves_with_analysis:
            cve_data = cve_finding["cve"]
            f.write(f"{'─' * 70}\n")
            f.write(f"  {cve_data['cve_id']}  |  {cve_data['severity']}  |  CVSS {cve_data['score']}\n")
            f.write(f"  Published: {cve_data['published']}  |  Vector: {cve_data['vector']}\n")
            f.write(f"{'─' * 70}\n\n")
            f.write(cve_finding["analysis"] + "\n\n")

    print(f"[+] Text report saved: {text_report_path}")
    return json_report_path, text_report_path


def print_console_report(cves_with_analysis, keyword):
    print("\n" + "=" * 70)
    print("  AI THREAT INTELLIGENCE SUMMARY")
    print(f"  Keyword: {keyword} | Analyzed: {len(cves_with_analysis)} CVEs")
    print("=" * 70)
    for cve_finding in cves_with_analysis:
        cve_data = cve_finding["cve"]
        print(f"\n  [{cve_data['severity']:8}] {cve_data['cve_id']}  —  CVSS {cve_data['score']}")
        print(f"  Published: {cve_data['published']}  |  Vector: {cve_data['vector']}")
        print(f"  {'-' * 60}")
        analysis_lines = [line for line in cve_finding["analysis"].split("\n") if line.strip()]
        for line in analysis_lines[:4]:
            print(f"  {line}")
        print()
    print("=" * 70 + "\n")


# ─────────────────────────────────────────────
# STEP 5: Entry Point
# ─────────────────────────────────────────────

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="AI-Powered Threat Intelligence Summarizer")
    parser.add_argument("--keyword", default="ransomware", help="CVE search keyword")
    parser.add_argument("--results", default=3, type=int,  help="Number of CVEs to analyze")
    parser.add_argument("--no-save", action="store_true",  help="Skip saving reports")
    args = parser.parse_args()

    print("\n" + "=" * 70)
    print("  AI THREAT INTELLIGENCE SUMMARIZER  |  Seraph LLC")
    print("=" * 70)

    if not ANTHROPIC_API_KEY:
        print("\n  [!] ANTHROPIC_API_KEY not set — running in rule-based mode.")
        print("  [!] Set your key to enable AI-powered analysis:\n")
        print("      export ANTHROPIC_API_KEY='your_key_here'\n")
    else:
        print(f"\n  [+] AI Mode: Active (Model: {MODEL})")

    raw_cve_entries    = fetch_cves(keyword=args.keyword, max_results=args.results)
    parsed_cve_entries = parse_cves(raw_cve_entries)

    print(f"\n[+] Analyzing {len(parsed_cve_entries)} CVEs...\n")
    cve_analysis_results = []
    for cve in parsed_cve_entries:
        cve_analysis = analyze_with_ai(cve)
        cve_analysis_results.append({"cve": cve, "analysis": cve_analysis})

    print_console_report(cve_analysis_results, args.keyword)

    if not args.no_save:
        generate_report(cve_analysis_results, args.keyword)

    print("[+] Threat intelligence analysis complete.\n")
