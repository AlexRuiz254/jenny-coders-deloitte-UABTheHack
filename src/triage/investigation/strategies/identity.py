"""IdentityStrategy: RB-03.

Comprobaciones previstas: Origen/GeoIP, MFA, dispositivo, cuentas privilegiadas, RRHH, VPN, cambios AD y OAuth.
Logs prioritarios: idp_signins, idp_audit, ad_events, vpn
"""
from tarvia_soc.models import RawAlert, InvestigationPlan
from tarvia_soc.investigation.strategies.base import BaseRunbookStrategy

class IdentityStrategy(BaseRunbookStrategy):
    def build_plan(self, alert: RawAlert) -> InvestigationPlan:
        """Concretar checks de RB-03 según rule_id sin duplicar texto del runbook."""
        raise NotImplementedError
