import uuid
from typing import Dict, Any, List

from backend.config import OLLAMA_API_URL, OLLAMA_LLM_MODEL
from backend.database.chroma_manager import ChromaManager
from backend.agents.planning_agent import PlanningAgent
from backend.agents.research_agent import ResearchAgent
from backend.agents.validation_agent import ValidationAgent
from backend.agents.execution_agent import ExecutionAgent

class MultiAgentOrchestrator:
    """
    Multi-Agent Security Orchestrator.
    Sequences the 4-agent cybersecurity pipeline:
    1. Planning Agent: Intent detection, task decomposition, and investigation roadmap.
    2. Research Agent: ChromaDB RAG vector search, threat intelligence retrieval, IOC extraction.
    3. Validation Agent: False positive checking, MITRE ATT&CK alignment, classification & scoring.
    4. Execution Agent: Incident containment rules, remediation playbooks, and final report generation.
    """
    def __init__(
        self,
        model_name: str = OLLAMA_LLM_MODEL,
        api_url: str = OLLAMA_API_URL,
        chroma_manager: ChromaManager = None,
        planning_agent: PlanningAgent = None,
        research_agent: ResearchAgent = None,
        validation_agent: ValidationAgent = None,
        execution_agent: ExecutionAgent = None
    ):
        self.model_name = model_name
        self.api_url = api_url.rstrip("/")
        self.chroma_manager = chroma_manager or ChromaManager()

        self.planning_agent = planning_agent or PlanningAgent(model_name=self.model_name, api_url=self.api_url)
        self.research_agent = research_agent or ResearchAgent(chroma_manager=self.chroma_manager)
        self.validation_agent = validation_agent or ValidationAgent(model_name=self.model_name, api_url=self.api_url)
        self.execution_agent = execution_agent or ExecutionAgent(model_name=self.model_name, api_url=self.api_url)

    def process_request(self, user_request: str) -> Dict[str, Any]:
        """
        Executes the full 4-agent pipeline and records the inter-agent communication logs.
        """
        task_id = str(uuid.uuid4())[:8]
        communication_logs = []

        # =====================================================================
        # Phase 1: Planning Agent
        # =====================================================================
        communication_logs.append({
            "task_id": task_id,
            "sender": "Orchestrator",
            "receiver": "Planning Agent",
            "objective": "Analyze user input, detect intent, and devise investigation roadmap",
            "context": user_request[:300] + "..." if len(user_request) > 300 else user_request,
            "knowledge": f"LLM Engine: {self.model_name}"
        })

        plan_res = self.planning_agent.plan(user_request)
        plan_data = plan_res.get("result", {})

        communication_logs.append({
            "task_id": task_id,
            "sender": "Planning Agent",
            "receiver": "Orchestrator",
            "status": plan_res.get("status", "success"),
            "confidence": plan_res.get("confidence", 0.95),
            "result": {
                "intent": plan_data.get("intent"),
                "plan_summary": plan_data.get("plan_summary"),
                "research_queries": plan_data.get("research_queries", []),
                "validation_criteria": plan_data.get("validation_criteria", []),
                "execution_goals": plan_data.get("execution_goals", [])
            }
        })

        # =====================================================================
        # Phase 2: Research Agent (RAG & IOC Extraction)
        # =====================================================================
        search_queries = plan_data.get("research_queries", [user_request])
        communication_logs.append({
            "task_id": task_id,
            "sender": "Orchestrator",
            "receiver": "Research Agent (RAG)",
            "objective": "Query local vector database and extract security IOCs",
            "context": f"Queries: {search_queries}",
            "knowledge": "ChromaDB Security Knowledge Base"
        })

        research_res = self.research_agent.research(user_request, queries=search_queries)
        research_data = research_res.get("result", {})

        communication_logs.append({
            "task_id": task_id,
            "sender": "Research Agent (RAG)",
            "receiver": "Orchestrator",
            "status": research_res.get("status", "success"),
            "confidence": research_res.get("confidence", 1.0),
            "result": {
                "chunks_retrieved": len(research_data.get("chunks", [])),
                "extracted_iocs": research_data.get("extracted_iocs", []),
                "context_preview": research_data.get("combined_context", "")[:250] + "..."
            }
        })

        # =====================================================================
        # Phase 3: Validation Agent (Verification & MITRE Mapping)
        # =====================================================================
        communication_logs.append({
            "task_id": task_id,
            "sender": "Orchestrator",
            "receiver": "Validation Agent",
            "objective": "Verify threat indicators, eliminate false positives, map MITRE ATT&CK",
            "context": f"Input: {user_request[:150]} | Plan Criteria: {len(plan_data.get('validation_criteria', []))} items",
            "knowledge": f"Retrieved Context: {len(research_data.get('chunks', []))} chunks grounded"
        })

        validation_res = self.validation_agent.validate(user_request, plan_data, research_data)
        validation_data = validation_res.get("result", {})

        communication_logs.append({
            "task_id": task_id,
            "sender": "Validation Agent",
            "receiver": "Orchestrator",
            "status": validation_res.get("status", "success"),
            "confidence": validation_res.get("confidence", 0.90),
            "result": {
                "is_valid_threat": validation_data.get("is_valid_threat"),
                "classification": validation_data.get("classification"),
                "severity": validation_data.get("severity"),
                "confidence_score": validation_data.get("confidence_score"),
                "mitre_mapping": validation_data.get("mitre_mapping", []),
                "evidence_count": len(validation_data.get("evidence", []))
            }
        })

        # =====================================================================
        # Phase 4: Execution Agent (Containment Playbook & Final Report)
        # =====================================================================
        communication_logs.append({
            "task_id": task_id,
            "sender": "Orchestrator",
            "receiver": "Execution Agent",
            "objective": "Formulate containment rules, mitigation playbook, and final markdown report",
            "context": f"Threat: {validation_data.get('classification')} | Severity: {validation_data.get('severity')}",
            "knowledge": f"Execution Goals: {plan_data.get('execution_goals', [])}"
        })

        execution_res = self.execution_agent.execute(user_request, plan_data, research_data, validation_data)
        execution_data = execution_res.get("result", {})

        communication_logs.append({
            "task_id": task_id,
            "sender": "Execution Agent",
            "receiver": "Orchestrator",
            "status": execution_res.get("status", "success"),
            "confidence": execution_res.get("confidence", 0.95),
            "result": {
                "containment_actions_count": len(execution_data.get("containment_actions", [])),
                "mitigation_steps_count": len(execution_data.get("mitigation_playbook", [])),
                "report_generated": True
            }
        })

        # Compile final consolidated analysis payload for compatibility with UI and test bench
        analysis_raw = {
            "threat_detected": validation_data.get("validation_notes", ""),
            "classification": validation_data.get("classification", "Unknown"),
            "severity": validation_data.get("severity", "Info"),
            "mitre_mapping": validation_data.get("mitre_mapping", []),
            "confidence_score": validation_data.get("confidence_score", 0.85),
            "evidence": validation_data.get("evidence", []),
            "recommendations": execution_data.get("mitigation_playbook", []),
            "containment_actions": execution_data.get("containment_actions", []),
            "root_cause": validation_data.get("root_cause", "")
        }

        return {
            "task_id": task_id,
            "intent": plan_data.get("intent", "general_security"),
            "planning": plan_data.get("plan_summary", "4-agent security pipeline completed."),
            "execution_order": [
                "Planning Agent",
                "Research Agent",
                "Validation Agent",
                "Execution Agent"
            ],
            "communication_logs": communication_logs,
            "report": execution_data.get("final_report", ""),
            "analysis_raw": analysis_raw,
            "retrieved_chunks": research_data.get("chunks", [])
        }
