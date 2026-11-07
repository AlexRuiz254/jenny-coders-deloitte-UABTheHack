"""Único agente LLM que sigue el runbook y utiliza evidencias existentes."""
from tarvia_soc.llm import LLMClient
from tarvia_soc.models import (
    RawAlert, ContextSnapshot, Evidence, IntelEntry,
    InvestigationPlan, Analysis, SearchPlan,
)

class InvestigationAgent:
    def __init__(self, llm: LLMClient) -> None:
        raise NotImplementedError

    def plan_searches(self, *, alert: RawAlert, runbook_text: str,
                      plan: InvestigationPlan, context: ContextSnapshot,
                      evidence: list[Evidence]) -> SearchPlan:
        """Primera salida estructurada del LLM: búsquedas justificadas."""
        raise NotImplementedError

    def analyze(self, *, alert: RawAlert, runbook_text: str,
                context: ContextSnapshot, intel: list[IntelEntry],
                evidence: list[Evidence], related_alerts: list[RawAlert]) -> Analysis:
        """Segunda salida estructurada: hallazgos, referencias, incertidumbre y veredicto propuesto."""
        raise NotImplementedError
