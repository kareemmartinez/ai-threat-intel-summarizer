# AI-Powered Threat Intelligence Summarizer

A Python tool that combines **live CVE data from the NIST NVD API** with **Anthropic Claude AI** to generate plain-English threat intelligence reports with actionable remediation guidance — the kind of analysis that normally takes a senior analyst hours to produce.

Built by **Kareem Martinez | Seraph LLC**

---

## What It Does

- Pulls live CVE data from the NIST National Vulnerability Database
- Feeds each vulnerability to Claude AI for deep threat analysis
- Generates structured intelligence reports including:
  - Plain-English threat summary
  - Real-world attack scenario
  - Affected organization types
  - Prioritized immediate actions
  - NIST 800-53 control mappings
  - Analyst confidence rating
- Exports reports in JSON and plain text
- Falls back to rule-based analysis if no API key is available

---

## Sample Output
```
══════════════════════════════════════════════════════════════════════
  AI THREAT INTELLIGENCE REPORT  |  Seraph LLC
  Generated: March 10, 2026  |  Keyword: ransomware  |  CVEs: 3
══════════════════════════════════════════════════════════════════════

  [CRITICAL ] CVE-2024-1234  —  CVSS 9.8
  Published: 2024-03-01  |  Vector: NETWORK
  ────────────────────────────────────────────────────────────────────

  THREAT SUMMARY:
  This critical buffer overflow in OpenSSL 3.x enables unauthenticated
  remote code execution. Any internet-facing service using OpenSSL is
  exposed. Treat as an emergency — patch immediately.

  ATTACK SCENARIO:
  An attacker sends a malformed certificate chain to trigger the overflow,
  gaining shell access without credentials on unpatched systems.

  IMMEDIATE ACTIONS:
  1. Audit all systems for OpenSSL versions below 3.2.1 within 2 hours
  2. Apply vendor patch or isolate affected systems from network
  3. Enable IDS signatures for CVE-2024-1234 exploitation attempts

  NIST 800-53 CONTROLS:
  SI-2 (Flaw Remediation), CM-6 (Configuration Settings), SC-7 (Boundary Protection)

  ANALYST CONFIDENCE: HIGH
```

---

## Quick Start
```bash
git clone https://github.com/YOUR_USERNAME/ai-threat-intel-summarizer.git
cd ai-threat-intel-summarizer

# Rule-based mode (no API key needed)
python src/threat_intel.py --keyword ransomware --results 3

# AI-powered mode (requires free Anthropic API key)
export ANTHROPIC_API_KEY="your_key_here"
python src/threat_intel.py --keyword ransomware --results 5
```

Get a free Anthropic API key at: https://console.anthropic.com

---

## CLI Options
```bash
python src/threat_intel.py --keyword apache    # Search by technology
python src/threat_intel.py --results 10        # Analyze 10 CVEs
python src/threat_intel.py --no-save           # Skip saving reports
```

---

## Project Structure
```
ai-threat-intel-summarizer/
├── src/
│   └── threat_intel.py          # Core logic: fetch, parse, AI analysis, report
├── tests/
│   └── test_threat_intel.py     # Unit tests (pytest)
├── sample_output/               # Reports saved here (git-ignored)
├── .github/
│   └── workflows/
│       └── ci.yml               # GitHub Actions CI
├── requirements.txt
└── README.md
```

---

## How It Works
```
NVD API → Raw CVE Data
    ↓
Parse & Normalize (CVSS score, vector, CWE, description)
    ↓
Anthropic Claude API (structured threat analysis prompt)
    ↓
Plain-English Report (summary, attack scenario, NIST controls)
    ↓
JSON + Text Export
```

---

## Running Tests
```bash
pip install pytest
python -m pytest tests/ -v
```

8 unit tests — all pass in both AI and rule-based modes.

---

## Skills Demonstrated

- AI/LLM API integration (Anthropic Claude)
- REST API consumption (NIST NVD)
- Structured prompt engineering for security analysis
- Graceful fallback design (rule-based when AI unavailable)
- JSON and text report generation
- Argparse CLI interface
- NIST 800-53 control mapping

---

## Roadmap

- [ ] Slack and email delivery of daily threat briefings
- [ ] MITRE ATT&CK technique mapping per CVE
- [ ] Multi-keyword batch analysis with trend detection
- [ ] AWS Lambda deployment for scheduled daily reports
- [ ] Web dashboard with historical threat tracking

---

## About Seraph LLC

Seraph LLC is a cybersecurity consulting firm specializing in compliance
automation, cloud security, and AI-powered security tooling for small
and mid-sized organizations.

---

## Author

**Kareem Martinez** | Cybersecurity Professional | DOE Q Clearance
Pursuing: CCSP · CISSP · AWS Certified Cloud Practitioner
