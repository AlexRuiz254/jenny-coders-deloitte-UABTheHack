"""AISecurityStrategy: RB-07.

Comprobaciones previstas: Sesión completa, prompt injection, controles, herramientas, datos de terceros.
Logs prioritarios: ai_gateway
"""
from tarvia_soc.models import RawAlert, InvestigationPlan
from tarvia_soc.investigation.strategies.base import BaseRunbookStrategy

class AISecurityStrategy(BaseRunbookStrategy):
    def build_plan(self, alert: RawAlert) -> InvestigationPlan:
        """Concretar checks de RB-07 según rule_id sin duplicar texto del runbook."""
        raise NotImplementedError
