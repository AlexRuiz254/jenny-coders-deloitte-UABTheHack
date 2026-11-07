"""Escalado obligatorio y SLA conforme a politica_soc.md."""
from tarvia_soc.models import Analysis, VerdictDecision, SeverityDecision, Escalation, RawAlert

class EscalationEngine:
    def decide(self, analysis: Analysis, verdict: VerdictDecision,
               severity: SeverityDecision, related_alerts: list[RawAlert]) -> Escalation:
        """Escalar TP high/critical, malware ejecutado, fraude, DLP, cadena, etc."""
        raise NotImplementedError
