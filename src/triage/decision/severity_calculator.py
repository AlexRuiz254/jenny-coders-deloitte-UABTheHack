"""Aplicar matriz oficial de politica_soc.md y ajustes máximos de ±1."""
from src.triage.models import (
    RawAlert, ContextSnapshot, Analysis, VerdictDecision, SeverityDecision,
)

class SeverityCalculator:
    def calculate(
            self, alert: RawAlert,
            context: ContextSnapshot,
            analysis: Analysis,
            verdict: VerdictDecision
    ) -> SeverityDecision:
        """Cruce severidad regla/criticidad y excepciones autorizadas."""

        severidadRegla = alert["severity"]
