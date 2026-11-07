"""Proponer contención conforme a autorizaciones; nunca ejecutarla en N1."""
from tarvia_soc.models import Analysis, ContextSnapshot, TicketAction

class ActionRecommender:
    def recommend(self, analysis: Analysis,
                  context: ContextSnapshot) -> list[TicketAction]:
        """Seleccionar acción/objetivo y requires_approval; respetar OT/servidores."""
        raise NotImplementedError
