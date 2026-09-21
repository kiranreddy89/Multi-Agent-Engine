"""
Legacy Coordinator alias.
The 3-agent architecture has been replaced with the 4-agent architecture:
- Planning Agent (backend.agents.planning_agent)
- Research Agent (backend.agents.research_agent)
- Validation Agent (backend.agents.validation_agent)
- Execution Agent (backend.agents.execution_agent)

Orchestrated via backend.agents.orchestrator.MultiAgentOrchestrator.
"""

from backend.agents.orchestrator import MultiAgentOrchestrator

# Backwards-compatibility alias
CoordinatorAgent = MultiAgentOrchestrator
