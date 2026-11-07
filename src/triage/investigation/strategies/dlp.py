"""DLPStrategy: RB-04.

Comprobaciones previstas: Tipo/volumen/destino de datos, SQL audit, autorización y contexto RRHH.
Logs prioritarios: dlp, sql_audit, edr_events
"""
from tarvia_soc.models import RawAlert, InvestigationPlan
from tarvia_soc.investigation.strategies.base import BaseRunbookStrategy

class DLPStrategy(BaseRunbookStrategy):
    def build_plan(self, alert: RawAlert) -> InvestigationPlan:
        """Concretar checks de RB-04 según rule_id sin duplicar texto del runbook."""
        raise NotImplementedError
