"""Construye salida final Pydantic según ticket_salida.schema.json."""
from src.triage.models import (
    RawAlert, Analysis, VerdictDecision, SeverityDecision, Escalation,
    Evidence, IntelEntry, ContextSnapshot, TicketAction, Ticket,
)

class TicketBuilder:
    def build(
            self, *, 
            alert: RawAlert, 
            related_alerts: list[RawAlert],
            context: ContextSnapshot, 
            analysis: Analysis,
            verdict: VerdictDecision, 
            severity: SeverityDecision,
            escalation: Escalation, 
            actions: list[TicketAction],
            evidence: list[Evidence], 
            intel: list[IntelEntry],
            triage_seconds: float
    ) -> Ticket:
        """Completar los 10 campos obligatorios y los opcionales útiles; validar con Pydantic."""
        
        raise NotImplementedError
