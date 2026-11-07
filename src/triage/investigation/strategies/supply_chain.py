"""SupplyChainStrategy: RB-10.

Comprobaciones previstas: Paquete/registro origen, postinstall, secretos, CI/CD, nube y despliegue.
Logs prioritarios: cicd_builds, cloudtrail, proxy, dns, edr_events
"""
from __future__ import annotations

from tarvia_soc.investigation.strategies.base import BaseRunbookStrategy
from tarvia_soc.models import InvestigationPlan, LogSource, RawAlert


class SupplyChainStrategy(BaseRunbookStrategy):
    """Estrategia determinista para el runbook RB-10 (Cadena de suministro y CI/CD)."""

    RUNBOOK_ID = "RB-10"

    _COMMON_CHECKS: tuple[str, ...] = (
        "check_package_popularity_known_binary_downloader_vs_new_package",
        "check_package_registry_origin_and_tarvia_scope_dependency_confusion",
        "check_typosquatting_on_internal_tarvia_packages",
        "check_postinstall_script_commands_and_process_execution",
        "check_environment_secrets_and_aws_or_npm_token_access",
        "check_runner_outbound_network_connections_to_unknown_domains",
        "check_build_artifact_deployment_status",
        "check_subsequent_aws_credential_usage_in_cloudtrail",
    )

    _RULE_CHECKS: dict[str, tuple[str, ...]] = {
        "UC-DEV-001": (
            "check_ci_runner01_postinstall_secret_exfiltration",
        ),
    }

    _DEFAULT_SOURCES: tuple[LogSource, ...] = (
        "cicd_builds",
        "cloudtrail",
        "proxy",
        "dns",
        "edr_events",
    )

    def build_plan(self, alert: RawAlert) -> InvestigationPlan:
        """Concretar checks de RB-10 según rule_id sin duplicar texto del runbook."""
        if not isinstance(alert, dict) or alert.get("runbook") != self.RUNBOOK_ID:
            raise ValueError(
                f"SupplyChainStrategy requiere runbook '{self.RUNBOOK_ID}', "
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
