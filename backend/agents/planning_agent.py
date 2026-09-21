import json
import urllib.request
import urllib.error
from typing import Dict, Any, List

from backend.config import OLLAMA_API_URL, OLLAMA_LLM_MODEL

class PlanningAgent:
    """
    Planning Agent.
    Responsible for:
    1. Receiving user security input (raw logs, alerts, CVE questions, incident text).
    2. Analyzing intent and breaking down the problem into structured investigation phases.
    3. Generating targeted research queries for the Research Agent.
    4. Defining validation criteria and hypothesis tests for the Validation Agent.
    5. Specifying remediation and containment goals for the Execution Agent.
    """
    def __init__(self, model_name: str = OLLAMA_LLM_MODEL, api_url: str = OLLAMA_API_URL):
        self.model_name = model_name
        self.api_url = api_url.rstrip("/")

    def plan(self, user_input: str) -> Dict[str, Any]:
        """
        Generates a comprehensive, structured cybersecurity investigation plan.
        """
        system_prompt = (
            "You are a Cybersecurity Strategic Planning Agent in a multi-agent SOC.\n"
            "Your objective is to analyze the user's security request, log snippet, alert, or query, and construct a precise, multi-agent operational plan.\n"
            "You DO NOT answer technical questions or perform the analysis yourself. Instead, you design the investigation roadmap.\n\n"
            "You MUST output a valid JSON object with the following schema:\n"
            "{\n"
            '  "intent": "log_analysis" | "threat_intel" | "incident_response" | "vulnerability_assessment" | "general_security",\n'
            '  "plan_summary": "1-2 sentence executive summary of the strategic investigation approach",\n'
            '  "investigation_steps": [\n'
            '    "Step 1 description",\n'
            '    "Step 2 description"\n'
            '  ],\n'
            '  "research_queries": [\n'
            '    "Specific query 1 for knowledge base vector search (e.g., CVE IDs, attack technique keywords, syntax patterns)",\n'
            '    "Specific query 2"\n'
            '  ],\n'
            '  "validation_criteria": [\n'
            '    "Criteria 1: indicators to differentiate true attacks from benign false positives",\n'
            '    "Criteria 2: specific MITRE tactics/techniques to verify"\n'
            '  ],\n'
            '  "execution_goals": [\n'
            '    "Goal 1: immediate containment or mitigation actions required",\n'
            '    "Goal 2: reporting and playbook compilation"\n'
            '  ]\n'
            "}\n\n"
            "DO NOT include markdown code blocks, conversational greetings, or preamble. Return ONLY the JSON object."
        )

        try:
            url = f"{self.api_url}/api/chat"
            payload = {
                "model": self.model_name,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": f"Security Input to Plan:\n{user_input}"}
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
                # Clean possible markdown fence
                if response_text.startswith("```"):
                    lines = response_text.splitlines()
                    if lines[0].startswith("```"):
                        lines = lines[1:]
                    if lines and lines[-1].startswith("```"):
                        lines = lines[:-1]
                    response_text = "\n".join(lines).strip()
                plan_result = json.loads(response_text)

                return {
                    "status": "success",
                    "confidence": 0.95,
                    "result": plan_result
                }

        except Exception as e:
            # Fallback deterministic heuristic planning if LLM fails or is slow
            print(f"[PlanningAgent] Fallback activated due to: {e}")
            input_lower = user_input.lower()

            if any(k in input_lower for k in ["cve", "what is", "mitigate", "owasp", "explain"]):
                intent = "threat_intel"
                summary = "Investigate vulnerability documentation, exploit mechanisms, and mitigation guidance."
            elif any(k in input_lower for k in ["union select", "<script>", "wannacry", "failed for", "get /api/login"]):
                intent = "log_analysis"
                summary = "Analyze suspicious log telemetry for active exploitation, persistence, or denial of service."
            else:
                intent = "general_security"
                summary = "Perform general cybersecurity assessment and threat validation on provided input."

            fallback_plan = {
                "intent": intent,
                "plan_summary": summary,
                "investigation_steps": [
                    "Query vector knowledge base for relevant CVEs, tactics, and detection patterns.",
                    "Extract network/host IOCs and evaluate against attack signatures.",
                    "Validate true attack probability versus benign noise.",
                    "Formulate incident containment actions and compile executive report."
                ],
                "research_queries": [
                    user_input[:200],
                    "Mitigation and detection guidance for detected patterns"
                ],
                "validation_criteria": [
                    "Confirm presence of exploit syntax or anomalous authentication thresholds.",
                    "Verify alignment with MITRE ATT&CK technique catalog."
                ],
                "execution_goals": [
                    "Isolate offending host or block malicious IPs/payloads.",
                    "Draft comprehensive incident response report with remediation steps."
                ]
            }

            return {
                "status": "success",
                "confidence": 0.80,
                "result": fallback_plan,
                "fallback_reason": str(e)
            }
