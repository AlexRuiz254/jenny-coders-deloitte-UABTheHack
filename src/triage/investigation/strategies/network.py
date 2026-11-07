"""NetworkStrategy: RB-09.

Comprobaciones previstas: Beaconing/C2, IOC, escáner autorizado, tunneling DNS, movimiento lateral, UC-NET-006.
Logs prioritarios: proxy, dns, firewall, edr_events
"""
from tarvia_soc.models import RawAlert, InvestigationPlan
from tarvia_soc.investigation.strategies.base import BaseRunbookStrategy

class NetworkStrategy(BaseRunbookStrategy):
    def build_plan(self, alert: RawAlert) -> InvestigationPlan:
        """Concretar checks de RB-09 según rule_id sin duplicar texto del runbook."""
        raise NotImplementedError
