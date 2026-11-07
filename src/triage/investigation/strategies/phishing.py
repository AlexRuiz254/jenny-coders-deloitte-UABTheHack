"""PhishingStrategy: RB-01.

Comprobaciones previstas: Emisor SPF/DKIM/DMARC, adjuntos/URLs, receptores, clics, actividad posterior y fraude IBAN.
Logs prioritarios: email, email_clicks, proxy, edr_events, idp_signins
"""
from tarvia_soc.models import RawAlert, InvestigationPlan
from tarvia_soc.investigation.strategies.base import BaseRunbookStrategy

class PhishingStrategy(BaseRunbookStrategy):
    def build_plan(self, alert: RawAlert) -> InvestigationPlan:
        """Concretar checks de RB-01 según rule_id sin duplicar texto del runbook."""
        raise NotImplementedError
