"""OTStrategy: RB-08.

Comprobaciones previstas: Origen/destino, puertos OT, mantenimiento autorizado y prohibición de contención SOC.
Logs prioritarios: firewall, edr_events
"""
from __future__ import annotations

from tarvia_soc.investigation.strategies.base import BaseRunbookStrategy
from tarvia_soc.models import InvestigationPlan, LogSource, RawAlert


class OTStrategy(BaseRunbookStrategy):
    """Estrategia determinista para el runbook RB-08 (Logística y OT)."""

    RUNBOOK_ID = "RB-08"

    _COMMON_CHECKS: tuple[str, ...] = (
        "check_source_host_authorization_eng_ws01_or_wms01",
        "check_destination_ot_asset_and_network_zone_criticality",
        "check_industrial_protocols_modbus_502_and_ethernet_ip_44818",
        "check_approved_maintenance_window_and_vendor_account",
        "check_prior_suspicious_activity_on_source_host",
        "check_potential_plc_modification_and_logistics_impact",
        "check_prohibit_direct_soc_ot_containment_escalate_to_operations",
    )

    _RULE_CHECKS: dict[str, tuple[str, ...]] = {
        "UC-OT-001": (
            "check_unauthorized_origin_traffic_to_logistics_ot_zone",
        ),
    }

    _DEFAULT_SOURCES: tuple[LogSource, ...] = (
        "firewall",
        "edr_events",
    )

    def build_plan(self, alert: RawAlert) -> InvestigationPlan:
        """Concretar checks de RB-08 según rule_id sin duplicar texto del runbook."""
        if not isinstance(alert, dict) or alert.get("runbook") != self.RUNBOOK_ID:
            raise ValueError(
                f"OTStrategy requiere runbook '{self.RUNBOOK_ID}', "
                f"pero recibió {alert.get('runbook') if isinstance(alert, dict) else alert!r}."
            )

        rule_id = str(alert.get("rule_id") or "").strip()
        checks: list[str] = list(self._COMMON_CHECKS)

        if rule_id in self._RULE_CHECKS:
            for check in self._RULE_CHECKS[rule_id]:
                if check not in checks:
                    checks.append(check)
        else:
            checks.append("check_unknown_rule_context")

        return InvestigationPlan(
            runbook_id=self.RUNBOOK_ID,
            required_checks=checks,
            suggested_sources=list(self._DEFAULT_SOURCES),
        )
