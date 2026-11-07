"""OTStrategy: RB-08.

Comprobaciones previstas: Origen/destino, puertos OT, mantenimiento autorizado y prohibición de contención SOC.
Logs prioritarios: firewall, edr_events
"""
from tarvia_soc.models import RawAlert, InvestigationPlan
from tarvia_soc.investigation.strategies.base import BaseRunbookStrategy

class OTStrategy(BaseRunbookStrategy):
    def build_plan(self, alert: RawAlert) -> InvestigationPlan:
        """Concretar checks de RB-08 según rule_id sin duplicar texto del runbook."""
        raise NotImplementedError
