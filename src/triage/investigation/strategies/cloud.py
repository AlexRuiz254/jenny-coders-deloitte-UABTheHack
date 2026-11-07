"""CloudStrategy: RB-06.

Comprobaciones previstas: Accesos/llaves, IAM, cambios de privilegios, buckets, descargas, cambios aprobados.
Logs prioritarios: cloudtrail, cicd_builds
"""
from tarvia_soc.models import RawAlert, InvestigationPlan
from tarvia_soc.investigation.strategies.base import BaseRunbookStrategy

class CloudStrategy(BaseRunbookStrategy):
    def build_plan(self, alert: RawAlert) -> InvestigationPlan:
        """Concretar checks de RB-06 según rule_id sin duplicar texto del runbook."""
        raise NotImplementedError
