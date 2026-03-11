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
    params   = {
        "keywordSearch":  keyword,
        "resultsPerPage": max_results,
    }
    url = base_url + "?" + urllib.parse.urlencode(params)
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "ThreatIntelSummarizer/1.0"})
        with urllib.request.urlopen(req, timeout=15) as response:
            data = json.loads(response.read().decode("utf-8"))
        cves = data.get("vulnerabilities", [])
        print(f"[+] Retrieved {len(cves)} CVEs.")
        return cves
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
    parsed = []
    for item in raw_cves:
        cve         = item.get("cve", {})
        cve_id      = cve.get("id", "Unknown")
        published   = cve.get("published", "")[:10]
        descriptions = cve.get("descriptions", [])
        description  = next(
            (d["value"] for d in descriptions if d.get("lang") == "en"),
            "No description available"
        )
        score    = "N/A"
        severity = "UNKNOWN"
        vector   = "UNKNOWN"
        metrics  = cve.get("metrics", {})
        if "cvssMetricV31" in metrics:
            cvss     = metrics["cvssMetricV31"][0]["cvssData"]
            score    = cvss.get("baseScore", "N/A")
            severity = cvss.get("baseSeverity", "UNKNOWN")
            vector   = cvss.get("attackVector", "UNKNOWN")
        weaknesses = cve.get("weaknesses", [])
        cwe = "Unknown"
        if weaknesses:
            cwe_list = weaknesses[0].get("description", [])
            if cwe_list:
                cwe = cwe_list[0].get("value", "Unknown")
        parsed.append({
            "cve_id":      cve_id,
            "published":   published,
            "severity":    severity,
            "score":       score,
            "vector":      vector,
            "cwe":         cwe,
            "description": description,
        })
    parsed.sort(key=lambda x: float(x["score"]) if x["score"] != "N/A" else 0, reverse=True)
    return parsed


# ─────────────────────────────────────────────
# STEP 3: AI Analysis
# ─────────────────────────────────────────────

def analyze_with_ai(cve):
    if not ANTHROPIC_API_KEY:
        print(f"  [!] No API key found. Using rule-based analysis for {cve['cve_id']}.")
        return rule_based_analysis(cve)

    print(f"  [AI] Analyzing {cve['cve_id']} with Claude...")

    prompt = f"""You are a senior cybersecurity analyst. Analyze this CVE and provide a structured threat intelligence report.

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

    payload = {
        "model":      MODEL,
        "max_tokens": 600,
        "messages":   [{"role": "user", "content": prompt}]
    }
    headers = {
        "Content-Type":      "application/json",
        "x-api-key":         ANTHROPIC_API_KEY,
        "anthropic-version": "2023-06-01",
    }
    try:
        data = json.dumps(payload).encode("utf-8")
        req  = urllib.request.Request(ANTHROPIC_API_URL, data=data, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=30) as response:
            result  = json.loads(response.read().decode("utf-8"))
            content = result.get("content", [{}])[0].get("text", "")
            return content
    except Exception as e:
        print(f"  [!] AI API call failed: {e}. Using rule-based analysis.")
        return rule_based_analysis(cve)


def rule_based_analysis(cve):
    severity = cve["severity"]
    vector   = cve["vector"]
    score    = cve["score"]

    if severity == "CRITICAL":
        urgency  = "immediate emergency patching"
        timeline = "within 24 hours"
    elif severity == "HIGH":
        urgency  = "priority patching"
        timeline = "within 7 days"
    else:
        urgency  = "scheduled patching"
        timeline = "within 30 days"

    network_note = "remotely exploitable without authentication — highest priority" if vector == "NETWORK" else "requires local access to exploit"

    return f"""THREAT SUMMARY:
This {severity} severity vulnerability (CVSS {score}) represents a significant security risk. The flaw is {network_note}. Organizations running affected software should treat this as requiring {urgency}.

ATTACK SCENARIO:
An attacker could leverage this vulnerability to compromise affected systems. The network-accessible attack surface increases exposure significantly for internet-facing assets.

AFFECTED ORGANIZATIONS:
Any organization running the affected software version. Cloud environments, enterprises with internet-facing services, and organizations without automated patch management are at highest risk.

IMMEDIATE ACTIONS:
1. Identify all systems running affected software versions immediately
2. Apply vendor patches or implement compensating controls {timeline}
3. Monitor security logs for exploitation indicators and anomalous activity

NIST 800-53 CONTROLS:
SI-2 (Flaw Remediation), CM-6 (Configuration Settings), RA-5 (Vulnerability Monitoring)

ANALYST CONFIDENCE: MEDIUM"""


# ─────────────────────────────────────────────
# STEP 4: Generate Reports
# ─────────────────────────────────────────────

def generate_report(cves_with_analysis, keyword, output_dir="sample_output"):
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

    json_file = os.path.join(output_dir, f"threat_intel_{timestamp}.json")
    report = {
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
    with open(json_file, "w") as f:
        json.dump(report, f, indent=4)
    print(f"\n[+] JSON report saved: {json_file}")

    txt_file = os.path.join(output_dir, f"threat_intel_{timestamp}.txt")
    with open(txt_file, "w") as f:
        f.write("=" * 70 + "\n")
        f.write("  AI THREAT INTELLIGENCE REPORT\n")
        f.write(f"  Seraph LLC | Generated: {datetime.datetime.now().strftime('%B %d, %Y %H:%M UTC')}\n")
        f.write(f"  Keyword: {keyword} | CVEs Analyzed: {len(cves_with_analysis)}\n")
        f.write("=" * 70 + "\n\n")
        for item in cves_with_analysis:
            cve = item["cve"]
            f.write(f"{'─' * 70}\n")
            f.write(f"  {cve['cve_id']}  |  {cve['severity']}  |  CVSS {cve['score']}\n")
            f.write(f"  Published: {cve['published']}  |  Vector: {cve['vector']}\n")
            f.write(f"{'─' * 70}\n\n")
            f.write(item["analysis"] + "\n\n")

    print(f"[+] Text report saved: {txt_file}")
    return json_file, txt_file


def print_console_report(cves_with_analysis, keyword):
    print("\n" + "=" * 70)
    print("  AI THREAT INTELLIGENCE SUMMARY")
    print(f"  Keyword: {keyword} | Analyzed: {len(cves_with_analysis)} CVEs")
    print("=" * 70)
    for item in cves_with_analysis:
        cve = item["cve"]
        print(f"\n  [{cve['severity']:8}] {cve['cve_id']}  —  CVSS {cve['score']}")
        print(f"  Published: {cve['published']}  |  Vector: {cve['vector']}")
        print(f"  {'-' * 60}")
        lines = [l for l in item["analysis"].split("\n") if l.strip()]
        for line in lines[:4]:
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

    raw_cves    = fetch_cves(keyword=args.keyword, max_results=args.results)
    parsed_cves = parse_cves(raw_cves)

    print(f"\n[+] Analyzing {len(parsed_cves)} CVEs...\n")
    results = []
    for cve in parsed_cves:
        analysis = analyze_with_ai(cve)
        results.append({"cve": cve, "analysis": analysis})

    print_console_report(results, args.keyword)

    if not args.no_save:
        generate_report(results, args.keyword)

    print("[+] Threat intelligence analysis complete.\n")
