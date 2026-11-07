"""EcommerceStrategy: RB-05.

Comprobaciones previstas: WAF, pentest autorizado, logins correctos, cambios de cuenta, gift cards, webshell.
Logs prioritarios: waf, ecom_auth, ecom_account, edr_events
"""
from tarvia_soc.models import RawAlert, InvestigationPlan
from tarvia_soc.investigation.strategies.base import BaseRunbookStrategy

class EcommerceStrategy(BaseRunbookStrategy):
    def build_plan(self, alert: RawAlert) -> InvestigationPlan:
        """Concretar checks de RB-05 según rule_id sin duplicar texto del runbook."""
        raise NotImplementedError
