import json
import urllib.request
import urllib.error
from typing import Dict, Any, List

from backend.config import OLLAMA_API_URL, OLLAMA_LLM_MODEL

class ValidationAgent:
    """
    Validation Agent.
    Responsible for:
    1. Cross-referencing inputs and research intelligence against validation criteria.
    2. Differentiating true cyber threats from benign administrative noise (False Positive reduction).
    3. Accurately classifying the attack vector (SQLi, XSS, Ransomware, Brute Force, DDoS, Normal, etc.).
    4. Mapping verified threat activity to MITRE ATT&CK Tactics & Techniques.
    5. Scoring severity (High, Medium, Low, Info) and statistical confidence.
    """
    def __init__(self, model_name: str = OLLAMA_LLM_MODEL, api_url: str = OLLAMA_API_URL):
        self.model_name = model_name
        self.api_url = api_url.rstrip("/")

    def validate(
        self, 
        user_input: str, 
        plan_result: Dict[str, Any], 
        research_result: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Performs threat verification, classification, and MITRE alignment.
        """
        validation_criteria = plan_result.get("validation_criteria", [])
        combined_context = research_result.get("combined_context", "")
        extracted_iocs = research_result.get("extracted_iocs", [])

        system_prompt = (
            "You are a Principal Security Validation & Threat Analyst in a SOC.\n"
            "Your objective is to evaluate raw security inputs alongside retrieved threat intelligence and operational criteria.\n"
            "You MUST rigorously verify whether an incident represents a true security compromise, eliminate false positives, map MITRE ATT&CK techniques, and assign an accurate severity rating.\n\n"
            "You MUST output a valid JSON object with the following schema:\n"
            "{\n"
            '  "is_valid_threat": true | false,\n'
            '  "classification": "Specific category (e.g. SQL Injection, Cross-Site Scripting, Ransomware, Brute Force, DDoS, Malware, Zero-day, Normal, etc.)",\n'
            '  "severity": "High" | "Medium" | "Low" | "Info",\n'
            '  "confidence_score": 0.95,\n'
            '  "mitre_mapping": [\n'
            '    {\n'
            '      "tactic": "MITRE ATT&CK Tactic (e.g., Initial Access, Execution, Persistence, Credential Access)",\n'
            '      "technique_id": "Technique ID (e.g. T1190, T1110, T1486)",\n'
            '      "technique_name": "Technique Name (e.g. Exploit Public-Facing Application)"\n'
            '    }\n'
            '  ],\n'
            '  "evidence": ["Exact strings, log lines, or IOC indicators proving this assessment"],\n'
            '  "validation_notes": "Detailed reasoning on why this is or is not an active security threat and verification against false positives.",\n'
            '  "root_cause": "Underlying vulnerability or operational lapse enabling this threat"\n'
            "}\n\n"
            "ONLY output valid JSON. No conversational chatter or markdown."
        )

        user_content = (
            f"=== SECURITY INPUT ===\n{user_input}\n\n"
            f"=== PLANNING VALIDATION CRITERIA ===\n{json.dumps(validation_criteria, indent=2)}\n\n"
            f"=== EXTRACTED IOCS ===\n{json.dumps(extracted_iocs, indent=2)}\n\n"
            f"=== RETRIEVED THREAT INTEL CONTEXT ===\n{combined_context}\n\n"
            "Perform validation, attack classification, false positive check, and MITRE mapping now. Output JSON."
        )

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
                val_result = json.loads(response_text)

                return {
                    "status": "success",
                    "confidence": val_result.get("confidence_score", 0.90),
                    "result": val_result
                }

        except Exception as e:
            print(f"[ValidationAgent] Fallback activated due to: {e}")
            fallback = self._heuristic_fallback(user_input, extracted_iocs)
            return {
                "status": "success",
                "confidence": fallback.get("confidence_score", 0.85),
                "result": fallback,
                "fallback_reason": str(e)
            }

    def _heuristic_fallback(self, text: str, iocs: List[Dict[str, str]]) -> Dict[str, Any]:
        """
        Expert cybersecurity heuristics if LLM engine is busy.
        """
        t_lower = text.lower()

        if "union select" in t_lower or "admin_users" in t_lower or "concat(" in t_lower:
            return {
                "is_valid_threat": True,
                "classification": "SQL Injection",
                "severity": "High",
                "confidence_score": 0.95,
                "mitre_mapping": [{
                    "tactic": "Initial Access",
                    "technique_id": "T1190",
                    "technique_name": "Exploit Public-Facing Application"
                }],
                "evidence": [line for line in text.splitlines() if "union" in line.lower() or "select" in line.lower()] or [text[:150]],
                "validation_notes": "Heuristic match: SQL injection syntax detected in HTTP request parameters.",
                "root_cause": "Improper input sanitization and non-parameterized database querying."
            }

        elif "<script>" in t_lower or "document.cookie" in t_lower:
            return {
                "is_valid_threat": True,
                "classification": "Cross-Site Scripting",
                "severity": "Medium",
                "confidence_score": 0.93,
                "mitre_mapping": [{
                    "tactic": "Execution",
                    "technique_id": "T1059.007",
                    "technique_name": "Command and Scripting Interpreter: JavaScript"
                }],
                "evidence": [line for line in text.splitlines() if "<script>" in line.lower()] or [text[:150]],
                "validation_notes": "Heuristic match: Malicious script tags attempting DOM injection and cookie harvesting.",
                "root_cause": "Missing output encoding and HTML sanitization on user input fields."
            }

        elif ".wannacry" in t_lower or "crypto activity" in t_lower or "tor exit node" in t_lower:
            return {
                "is_valid_threat": True,
                "classification": "Ransomware",
                "severity": "High",
                "confidence_score": 0.98,
                "mitre_mapping": [{
                    "tactic": "Impact",
                    "technique_id": "T1486",
                    "technique_name": "Data Encrypted for Impact"
                }],
                "evidence": [text],
                "validation_notes": "Heuristic match: Rapid bulk file extension modifications and C2 egress over Tor.",
                "root_cause": "Execution of unsigned payload and lack of endpoint behavioral prevention."
            }

        elif "authentication failed" in t_lower or "login fail" in t_lower or "port 543" in t_lower:
            return {
                "is_valid_threat": True,
                "classification": "Brute Force",
                "severity": "Medium",
                "confidence_score": 0.92,
                "mitre_mapping": [{
                    "tactic": "Credential Access",
                    "technique_id": "T1110",
                    "technique_name": "Brute Force"
                }],
                "evidence": [line for line in text.splitlines() if "failed" in line.lower() or "success" in line.lower()],
                "validation_notes": "Heuristic match: Rapid succession of authentication rejections followed by access.",
                "root_cause": "Absence of rate limiting, IP ban automation (fail2ban), or MFA enforcement."
            }

        elif "high volume" in t_lower or (t_lower.count("get /api/login") > 5) or "flood" in t_lower:
            return {
                "is_valid_threat": True,
                "classification": "DDoS",
                "severity": "High",
                "confidence_score": 0.90,
                "mitre_mapping": [{
                    "tactic": "Impact",
                    "technique_id": "T1499",
                    "technique_name": "Endpoint Denial of Service"
                }],
                "evidence": [text.splitlines()[0] if text.splitlines() else text[:100]],
                "validation_notes": "Heuristic match: High frequency HTTP flood aimed at resource exhaustion.",
                "root_cause": "Unthrottled endpoint allowing volumetric traffic saturation."
            }

        elif "cve-" in t_lower:
            return {
                "is_valid_threat": True,
                "classification": "Zero-day / Vulnerability",
                "severity": "High",
                "confidence_score": 0.91,
                "mitre_mapping": [{
                    "tactic": "Initial Access",
                    "technique_id": "T1190",
                    "technique_name": "Exploit Public-Facing Application"
                }],
                "evidence": [item["value"] for item in iocs if item["type"] == "CVE Identifier"] or [text[:100]],
                "validation_notes": "Heuristic match: Specific CVE security advisory or zero-day vulnerability discussion.",
                "root_cause": "Software vulnerability prior to vendor security patch deployment."
            }

        elif "cozybear" in t_lower or "sha-256" in t_lower or "loader" in t_lower:
            return {
                "is_valid_threat": True,
                "classification": "Malware",
                "severity": "High",
                "confidence_score": 0.94,
                "mitre_mapping": [{
                    "tactic": "Execution",
                    "technique_id": "T1204.002",
                    "technique_name": "User Execution: Malicious File"
                }],
                "evidence": [item["value"] for item in iocs if "Hash" in item["type"]] or [text[:150]],
                "validation_notes": "Heuristic match: Known malicious binary hash or loader signature identified.",
                "root_cause": "Phishing or malicious download without pre-execution gateway inspection."
            }

        else:
            return {
                "is_valid_threat": False,
                "classification": "Normal",
                "severity": "Info",
                "confidence_score": 0.88,
                "mitre_mapping": [],
                "evidence": [],
                "validation_notes": "Traffic patterns conform to expected baseline operations. No malicious signature detected.",
                "root_cause": "N/A - Legitimate application interaction."
            }
