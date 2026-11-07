"""Comprobar que el veredicto propuesto por el LLM está respaldado por pruebas."""
from tarvia_soc.models import Analysis, Evidence, ContextSnapshot, VerdictDecision

class VerdictEngine:
    def decide(self, analysis: Analysis, evidence: list[Evidence],
               context: ContextSnapshot) -> VerdictDecision:
        """Verificar referencias, contradicciones y actividad autorizada."""
        raise NotImplementedError
