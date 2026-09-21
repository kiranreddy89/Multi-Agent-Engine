import json
import urllib.request
import urllib.error
from typing import Dict, Any, List

from backend.config import OLLAMA_API_URL, OLLAMA_LLM_MODEL

class ExecutionAgent:
    """
    Execution Agent.
    Responsible for:
    1. Synthesizing the outputs of the Planning, Research, and Validation Agents.
    2. Generating immediate tactical containment actions (e.g., firewall block rules, EDR isolation, Sigma/YARA rules).
    3. Generating actionable remediation and hardening playbooks.
    4. Compiling the final authoritative Markdown security report for the SOC dashboard.
    """
    def __init__(self, model_name: str = OLLAMA_LLM_MODEL, api_url: str = OLLAMA_API_URL):
        self.model_name = model_name
        self.api_url = api_url.rstrip("/")

    def execute(
        self,
        user_input: str,
        plan_result: Dict[str, Any],
        research_result: Dict[str, Any],
        validation_result: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Synthesizes verified findings into containment actions and the final security report.
        """
        goals = plan_result.get("execution_goals", [])
        classification = validation_result.get("classification", "Unknown Threat")
        severity = validation_result.get("severity", "Info")
        mitre_mapping = validation_result.get("mitre_mapping", [])
        evidence = validation_result.get("evidence", [])
        iocs = research_result.get("extracted_iocs", [])
        chunks = research_result.get("chunks", [])

        system_prompt = (
            "You are a Senior Incident Commander and Security Automation Execution Agent.\n"
            "Your objective is to generate immediate containment actions and remediation playbooks based on validated incident data.\n"
            "You MUST output a valid JSON object with the following schema:\n"
            "{\n"
            '  "containment_actions": [\n'
            '    "Immediate action 1 (e.g., iptables -A INPUT -s <IP> -j DROP, revoke API token, isolate host via EDR)",\n'
            '    "Immediate action 2"\n'
            '  ],\n'
            '  "mitigation_playbook": [\n'
            '    "Long-term hardening step 1 (e.g. patch CVE, enforce MFA, deploy WAF rule)",\n'
            '    "Long-term hardening step 2"\n'
            '  ],\n'
            '  "detection_signatures": [\n'
            '    "Sigma rule or YARA pattern or Suricata snort rule recommendation"\n'
            '  ]\n'
            "}\n\n"
            "Return ONLY the JSON object. No conversational preamble or code block tags."
        )

        user_content = (
            f"Validated Classification: {classification}\n"
            f"Severity: {severity}\n"
            f"Execution Goals: {json.dumps(goals)}\n"
            f"Identified IOCs: {json.dumps(iocs)}\n"
            f"Evidence: {json.dumps(evidence)}\n"
            f"MITRE Alignment: {json.dumps(mitre_mapping)}\n\n"
            "Generate tactical containment actions and mitigation steps now. Output JSON."
        )

        containment_data = {}
        try:
            url = f"{self.api_url}/api/chat"
            payload = {
                "model": self.model_name,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_content}
                ],
                "stream": False,
                "format": "json",
                "options": {
                    "num_predict": 200,
                    "num_ctx": 1024,
                    "temperature": 0.1
                }
            }
            req = urllib.request.Request(
                url,
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=25) as response:
                res_data = json.loads(response.read().decode("utf-8"))
                response_text = res_data["message"]["content"].strip()
                if response_text.startswith("```"):
                    lines = response_text.splitlines()
                    if lines[0].startswith("```"):
                        lines = lines[1:]
                    if lines and lines[-1].startswith("```"):
                        lines = lines[:-1]
                    response_text = "\n".join(lines).strip()
                containment_data = json.loads(response_text)
        except Exception as e:
            print(f"[ExecutionAgent] Fallback containment generation due to: {e}")
            containment_data = self._heuristic_containment(classification, iocs)

        # Build final markdown security report
        final_markdown_report = self._build_markdown_report(
            user_input=user_input,
            plan_result=plan_result,
            research_result=research_result,
            validation_result=validation_result,
            containment_data=containment_data
        )

        return {
            "status": "success",
            "confidence": 0.95,
            "result": {
                "containment_actions": containment_data.get("containment_actions", []),
                "mitigation_playbook": containment_data.get("mitigation_playbook", []),
                "detection_signatures": containment_data.get("detection_signatures", []),
                "final_report": final_markdown_report
            }
        }

    def _heuristic_containment(self, classification: str, iocs: List[Dict[str, str]]) -> Dict[str, Any]:
        """
        Expert cybersecurity containment actions when LLM is unavailable.
        """
        c_lower = classification.lower()
        extracted_ips = [i["value"] for i in iocs if i["type"] == "IPv4 Address"]
        ip_target = extracted_ips[0] if extracted_ips else "ATTACKER_IP"

        if "sql" in c_lower:
            return {
                "containment_actions": [
                    f"iptables -I INPUT -s {ip_target} -j DROP",
                    "Enable WAF SQL injection inspection profile (OWASP Core Rule Set 942xxx).",
                    "Terminate active vulnerable database sessions."
                ],
                "mitigation_playbook": [
                    "Migrate raw SQL queries to parameterized Prepared Statements (ORM).",
                    "Enforce strict input validation regex whitelist on API parameters.",
                    "Audit and restrict database account privileges (least privilege)."
                ],
                "detection_signatures": [
                    "alert http any any -> any any (msg:\"SQLi Injection Attempt\"; content:\"UNION SELECT\"; nocase; sid:1000001;)"
                ]
            }
        elif "ransomware" in c_lower:
            return {
                "containment_actions": [
                    "Immediately isolate infected endpoint from local network (VLAN quarantine / EDR isolate).",
                    f"Block outbound C2 communication to Tor and IP {ip_target} at perimeter firewall.",
                    "Kill rogue process trees and freeze volume shadow copies."
                ],
                "mitigation_playbook": [
                    "Restore affected storage volumes from immutable, offline air-gapped backups.",
                    "Deploy AppLocker or WDAC application control policies to block unsigned executables.",
                    "Enforce multi-factor authentication (MFA) across all administrative tools."
                ],
                "detection_signatures": [
                    "rule Ransomware_WannaCry_Indicators { strings: $ext = \".wannacry\" condition: $ext }"
                ]
            }
        elif "brute" in c_lower:
            return {
                "containment_actions": [
                    f"fail2ban-client set sshd banip {ip_target}",
                    "Temporarily lock targeted user accounts pending identity confirmation.",
                    "Terminate active unauthenticated SSH/RDP sessions from offending subnet."
                ],
                "mitigation_playbook": [
                    "Disable password-based SSH authentication; mandate Ed25519 SSH keys.",
                    "Enforce rate-limiting on login endpoints (e.g. 5 attempts per 15 minutes).",
                    "Implement multi-factor authentication (TOTP/FIDO2) for remote administration."
                ],
                "detection_signatures": [
                    "Sigma: title: Potential SSH Brute Force Detection | condition: selection | count() > 5"
                ]
            }
        elif "xss" in c_lower:
            return {
                "containment_actions": [
                    "Purge and sanitize persisted user comments from the web application database.",
                    "Invalidate active user session tokens potentially captured via stolen cookies.",
                    "Enable strict Content-Security-Policy (CSP) headers: `default-src 'self'`."
                ],
                "mitigation_playbook": [
                    "Implement contextual output encoding (HTML, JavaScript, Attribute contexts).",
                    "Set `HttpOnly`, `Secure`, and `SameSite=Strict` flags on all session cookies.",
                    "Adopt automated SAST/DAST checks for client-side injection vulnerabilities."
                ],
                "detection_signatures": [
                    "alert http any any -> any any (msg:\"XSS Script Injection\"; content:\"<script>\"; nocase; sid:1000002;)"
                ]
            }
        elif "ddos" in c_lower:
            return {
                "containment_actions": [
                    "Activate cloud DDoS mitigation shield / Cloudflare Under Attack mode.",
                    f"Rate-limit IP {ip_target} and associated CIDR block to 1 req/sec.",
                    "Enable CAPTCHA challenge for the `/api/login` route."
                ],
                "mitigation_playbook": [
                    "Implement upstream reverse proxy burst rate limiting (`limit_req_zone`).",
                    "Autoscale backend worker instances across independent availability zones.",
                    "Place static caching frontends in front of public application endpoints."
                ],
                "detection_signatures": [
                    "Sigma: title: High Frequency HTTP Flood | condition: count(http_request) > 20 by src_ip"
                ]
            }
        else:
            return {
                "containment_actions": [
                    "Maintain continuous monitoring of host and network audit trails.",
                    "Verify telemetry against baseline operating metrics."
                ],
                "mitigation_playbook": [
                    "Ensure software packages and OS dependencies are updated with latest patches.",
                    "Review access control lists periodically."
                ],
                "detection_signatures": [
                    "Generic SOC telemetry baseline tracking."
                ]
            }

    def _build_markdown_report(
        self,
        user_input: str,
        plan_result: Dict[str, Any],
        research_result: Dict[str, Any],
        validation_result: Dict[str, Any],
        containment_data: Dict[str, Any]
    ) -> str:
        """
        Compiles the findings into an authoritative, beautifully structured Markdown security report.
        """
        classification = validation_result.get("classification", "Unknown Incident")
        severity = validation_result.get("severity", "Info")
        confidence = validation_result.get("confidence_score", 0.85) * 100
        is_threat = validation_result.get("is_valid_threat", True)
        notes = validation_result.get("validation_notes", "Analysis complete.")
        root_cause = validation_result.get("root_cause", "N/A")
        evidence = validation_result.get("evidence", [])
        mitre_mapping = validation_result.get("mitre_mapping", [])
        
        containment_actions = containment_data.get("containment_actions", [])
        mitigation_playbook = containment_data.get("mitigation_playbook", [])
        signatures = containment_data.get("detection_signatures", [])
        
        chunks = research_result.get("chunks", [])
        iocs = research_result.get("extracted_iocs", [])
        plan_summary = plan_result.get("plan_summary", "Multi-agent security pipeline executed.")

        severity_badges = {
            "HIGH": "🔴 HIGH",
            "MEDIUM": "🟡 MEDIUM",
            "LOW": "🟢 LOW",
            "INFO": "🔵 INFO"
        }
        badge = severity_badges.get(severity.upper(), f"⚪ {severity}")
        verdict = "🚨 CONFIRMED THREAT" if is_threat else "🛡️ BENIGN / NORMAL TRAFFIC"

        # MITRE Markdown
        mitre_text = ""
        if mitre_mapping:
            mitre_text = "| Tactic | Technique ID | Technique Name |\n| :--- | :--- | :--- |\n"
            for m in mitre_mapping:
                mitre_text += f"| `{m.get('tactic', 'N/A')}` | `{m.get('technique_id', 'N/A')}` | **{m.get('technique_name', 'N/A')}** |\n"
        else:
            mitre_text = "*No MITRE ATT&CK techniques identified for this input.*"

        # References Markdown
        ref_text = ""
        if chunks:
            for idx, ch in enumerate(chunks):
                src = ch["metadata"].get("source", "Knowledge Base Document")
                score = ch.get("score", 0.0)
                ref_text += f"- [{idx+1}] **Source**: `{src}` (Relevance Score: `{score:.4f}`)\n"
        else:
            ref_text = "*No vector knowledge base references required.*"

        report = f"""# MULTI-AGENT SECURITY INCIDENT REPORT

## 1. Executive Summary
- **Primary Classification**: `{classification}`
- **Threat Verdict**: {verdict}
- **Severity Rating**: {badge}
- **Analysis Confidence**: `{confidence:.1f}%`
- **Strategic Plan**: *{plan_summary}*

---

## 2. Multi-Agent Pipeline Trace
| Agent | Operational Role | Outcome |
| :--- | :--- | :--- |
| **Planning Agent** | Intent classification & investigation strategy | Established {len(plan_result.get('investigation_steps', []))} investigation steps |
| **Research Agent** | RAG vector search & IOC pattern extraction | Discovered {len(iocs)} indicators, queried {len(research_result.get('searched_queries', []))} knowledge topics |
| **Validation Agent** | False positive elimination & MITRE mapping | Verified threat status with `{confidence:.1f}%` confidence |
| **Execution Agent** | Containment actions & playbook synthesis | Formulated {len(containment_actions)} tactical responses and executive report |

---

## 3. Threat Assessment & Technical Validation
{notes}

- **Identified Root Cause**: {root_cause}

---

## 4. Evidence & IOC Identifiers
"""
        if evidence:
            for ev in evidence:
                report += f"- Evidence: `{ev}`\n"
        elif iocs:
            for ioc in iocs:
                report += f"- IOC: **{ioc.get('type')}**: `{ioc.get('value')}`\n"
        else:
            report += "- *No malicious evidence indicators found in input telemetry.*\n"

        report += f"""
---

## 5. MITRE ATT&CK Framework Alignment
{mitre_text}

---

## 6. Immediate Containment Actions (Execution Agent)
"""
        for idx, act in enumerate(containment_actions):
            report += f"{idx+1}. `{act}`\n"
        if not containment_actions:
            report += "1. No emergency containment required. Routine log monitoring active.\n"

        report += f"""
---

## 7. Remediation & Hardening Playbook
"""
        for idx, step in enumerate(mitigation_playbook):
            report += f"{idx+1}. **{step}**\n"

        if signatures:
            report += f"""
---

## 8. Detection Signatures
"""
            for sig in signatures:
                report += f"```text\n{sig}\n```\n"

        report += f"""
---

## 9. Authoritative Knowledge Base Citations (RAG)
{ref_text}
"""
        return report
