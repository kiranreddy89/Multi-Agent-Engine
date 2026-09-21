# SentinelAI: External Security Datasets & Requirements Index

The Knowledge Agent (RAG) uses a vector database to supply local security expertise. To ensure maximum accuracy, you should feed high-quality external datasets into the vector database.

This document lists the recommended sources, download instructions, and folder structures to enrich your local knowledge base.

---

## Folder Structure for Ingestion

Before starting, create the following ingestion folder structure in your workspace:
```text
c:\sentinalai\data\
└── raw_datasets\
    ├── cves\
    ├── mitre_attack\
    ├── owasp\
    ├── malware_reports\
    └── threat_rules\
```
*Note: Any files (PDF, DOCX, TXT, MD, JSON) dropped into these directories can be uploaded and indexed into ChromaDB via the **Data Ingestion** section on the web frontend.*

---

## 1. Vulnerability Databases (CVE / NVD / CISA KEV)

### CISA KEV (Known Exploited Vulnerabilities)
The Cybersecurity and Infrastructure Security Agency (CISA) maintains a catalog of vulnerabilities known to be actively exploited in the wild.
- **Download Format**: JSON or CSV
- **Download Link**: [CISA KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) (Direct JSON: `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`)
- **Action**: Download `known_exploited_vulnerabilities.json` and save to `data/raw_datasets/cves/`.

### NVD / CVE Feeds
- **Download Format**: JSON
- **Sources**: 
  - To index specific historical CVEs, search and copy their descriptions from [CVE Search](https://cve.mitre.org/) or [NVD Search](https://nvd.nist.gov/).
  - Create markdown files with CVE details, e.g., `CVE-2024-3400.md` detailing the Palo Alto GlobalProtect firewall remote code execution vulnerability.

---

## 2. Threat Tactics & Techniques (MITRE ATT&CK)

MITRE ATT&CK is a globally-accessible knowledge base of adversary tactics and techniques based on real-world observations.
- **Download Link**: [MITRE ATT&CK STIX 2.1 Repository](https://github.com/mitre-attack/attack-stix-data)
- **Direct Download**: Clone or download files from the GitHub repository, specifically `enterprise-attack/enterprise-attack.json`.
- **Action**: Save the enterprise attack JSON to `data/raw_datasets/mitre_attack/`.
- **Alternative**: Save descriptions of specific techniques (e.g. T1190 - Exploit Public-Facing Application, T1110 - Brute Force) as Markdown/Text files in this folder.

---

## 3. Web & API Security Guides (OWASP)

OWASP guidelines represent the gold standard in web application security.
- **OWASP Top 10 (2021)**: Download the PDF report from [OWASP Top 10 Project](https://owasp.org/www-project-top-ten/).
- **OWASP API Security Top 10 (2023)**: Download the PDF report from [OWASP API Security Project](https://owasp.org/www-project-api-security/).
- **OWASP Cheat Sheets**:
  - Clone or download cheat sheets from [OWASP Cheat Sheet Series Repository](https://github.com/OWASP/CheatSheetSeries).
  - Select the markdown files relevant to your scope (e.g. `SQL_Injection_Prevention_Cheat_Sheet.md`, `Cross_Site_Scripting_Prevention_Cheat_Sheet.md`).
- **Action**: Move selected PDFs or Markdown files to `data/raw_datasets/owasp/`.

---

## 4. Industry Malware & Threat Intelligence Reports

Adversary analysis reports from leading security firms provide detailed context on campaign operations.
- **Microsoft Security Blogs & Reports**: Download reports such as the Microsoft Digital Defense Report (MDDR) or copy articles from [Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/).
- **CrowdStrike Intelligence**: Copy threat intelligence logs or blogs from [CrowdStrike Blog](https://www.crowdstrike.com/blog/).
- **Palo Alto Unit 42**: Save blogs on major threats (e.g., Ransomware profiles) from [Unit 42 Blog](https://unit42.paloaltonetworks.com/).
- **Cisco Talos / Mandiant**: Save threat briefs as PDFs or Markdown files.
- **Action**: Move files to `data/raw_datasets/malware_reports/`.

---

## 5. Security Detection Rules (Sigma / YARA / Snort / Suricata)

Indexing detection rules lets the RAG agent help translate logs into matching signatures.
- **Sigma Rules**: Clone the official [Sigma Rules Github Repository](https://github.com/SigmaHQ/sigma) and extract YAML rule files (e.g., Windows Event Log, Web Log detectors).
- **YARA Rules**: Download common malware signatures from [Yara-Rules Awesome List](https://github.com/InQuest/awesome-yara) or [YARA Rules Github](https://github.com/Yara-Rules/rules).
- **Snort & Suricata Rules**: Save rule text files (`.rules`) that match network signatures.
- **Action**: Move selected files to `data/raw_datasets/threat_rules/`.
