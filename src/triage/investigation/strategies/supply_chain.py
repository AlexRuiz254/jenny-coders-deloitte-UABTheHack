"""SupplyChainStrategy: RB-10.

Comprobaciones previstas: Paquete/registro origen, postinstall, secretos, CI/CD, nube y despliegue.
Logs prioritarios: cicd_builds, cloudtrail, proxy, dns
"""
from tarvia_soc.models import RawAlert, InvestigationPlan
from tarvia_soc.investigation.strategies.base import BaseRunbookStrategy

class SupplyChainStrategy(BaseRunbookStrategy):
    def build_plan(self, alert: RawAlert) -> InvestigationPlan:
        """Concretar checks de RB-10 según rule_id sin duplicar texto del runbook."""
        raise NotImplementedError
