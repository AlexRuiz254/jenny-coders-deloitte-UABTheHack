"""NetworkStrategy: RB-09.

Comprobaciones previstas: Beaconing/C2, IOC, escáner autorizado, tunneling DNS, movimiento lateral, UC-NET-006.
Logs prioritarios: proxy, dns, firewall, edr_events
"""
from __future__ import annotations

from tarvia_soc.investigation.strategies.base import BaseRunbookStrategy
from tarvia_soc.models import InvestigationPlan, LogSource, RawAlert


class NetworkStrategy(BaseRunbookStrategy):
    """Estrategia determinista para el runbook RB-09 (Red: C2, escaneos y movimiento lateral)."""

    RUNBOOK_ID = "RB-09"

    _COMMON_CHECKS: tuple[str, ...] = (
        "check_destination_ip_and_domain_threat_intel_reputation",
        "check_originating_endpoint_process_in_edr",
        "check_multi_host_correlation_for_network_indicators",
    )

    _RULE_CHECKS: dict[str, tuple[str, ...]] = {
        "UC-NET-001": (
            "check_beaconing_interval_periodicity_and_variance",
            "check_domain_age_prevalence_and_http_user_agent",
            "check_c2_communication_and_process_persistence",
        ),
        "UC-NET-002": (
            "check_threat_intel_ioc_confidence_and_age",
            "check_outbound_firewall_and_proxy_connection_status",
            "check_c2_communication_and_process_persistence",
        ),
        "UC-NET-003": (
            "check_authorized_nessus01_scanner_and_wednesday_window",
            "check_internal_port_scan_scope_and_target_zones",
        ),
        "UC-NET-004": (
            "check_lateral_movement_smb_rdp_psexec_protocol",
            "check_admin_account_jump01_origin_restriction",
            "check_approved_change_or_maintenance_ticket",
        ),
        "UC-NET-005": (
            "check_dga_domain_entropy_vs_legitimate_cloud_cdn_subdomain",
            "check_subsequent_proxy_or_firewall_connections_to_resolved_ip",
        ),
        "UC-NET-006": (
            "check_dns_tunneling_long_subdomain_queries_volume_and_encoding",
            "check_dns_exfiltration_or_c2_channel_process",
        ),
    }

    _DEFAULT_SOURCES: tuple[LogSource, ...] = (
        "proxy",
        "dns",
        "firewall",
        "edr_events",
    )

    _RULE_SOURCES: dict[str, tuple[LogSource, ...]] = {
        "UC-NET-001": ("proxy", "dns", "edr_events", "firewall"),
        "UC-NET-002": ("firewall", "proxy", "dns", "edr_events"),
        "UC-NET-003": ("firewall", "edr_events"),
        "UC-NET-004": ("firewall", "edr_events", "ad_events", "idp_signins"),
        "UC-NET-005": ("dns", "proxy", "firewall", "edr_events"),
        "UC-NET-006": ("dns", "edr_events", "proxy", "firewall"),
    }

    def build_plan(self, alert: RawAlert) -> InvestigationPlan:
        """Concretar checks de RB-09 según rule_id sin duplicar texto del runbook."""
        if not isinstance(alert, dict) or alert.get("runbook") != self.RUNBOOK_ID:
            raise ValueError(
                f"NetworkStrategy requiere runbook '{self.RUNBOOK_ID}', "
                f"pero recibió {alert.get('runbook') if isinstance(alert, dict) else alert!r}."
            )

        rule_id = str(alert.get("rule_id") or "").strip()
        checks: list[str] = list(self._COMMON_CHECKS)

        if rule_id in self._RULE_CHECKS:
            for check in self._RULE_CHECKS[rule_id]:
                if check not in checks:
                    checks.append(check)
            sources = list(self._RULE_SOURCES[rule_id])
        else:
            checks.append("check_unknown_rule_context")
            sources = list(self._DEFAULT_SOURCES)

        return InvestigationPlan(
            runbook_id=self.RUNBOOK_ID,
            required_checks=checks,
            suggested_sources=sources,
        )
