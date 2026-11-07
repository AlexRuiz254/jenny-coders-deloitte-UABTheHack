"""CloudStrategy: RB-06.

Comprobaciones previstas: Accesos/llaves, IAM, cambios de privilegios, buckets, descargas, cambios aprobados.
Logs prioritarios: cloudtrail, cicd_builds, proxy, dns
"""
from __future__ import annotations

from tarvia_soc.investigation.strategies.base import BaseRunbookStrategy
from tarvia_soc.models import InvestigationPlan, LogSource, RawAlert


class CloudStrategy(BaseRunbookStrategy):
    """Estrategia determinista para el runbook RB-06 (Cloud AWS)."""

    RUNBOOK_ID = "RB-06"

    _COMMON_CHECKS: tuple[str, ...] = (
        "check_access_key_baseline_usage_and_identity",
        "check_source_ip_asn_and_user_agent_anomalies",
        "check_known_terraform_pipeline_or_approved_change",
        "check_cloud_reconnaissance_calls_get_caller_identity_or_list",
    )

    _RULE_CHECKS: dict[str, tuple[str, ...]] = {
        "UC-CLD-001": (
            "check_unusual_asn_access_key_compromise",
            "check_subsequent_iam_or_resource_modifications",
        ),
        "UC-CLD-002": (
            "check_privileged_iam_user_role_or_key_creation",
            "check_cloud_persistence_and_privilege_escalation",
        ),
        "UC-CLD-003": (
            "check_s3_bucket_acl_or_policy_public_exposure",
            "check_unauthorized_external_bucket_access",
        ),
        "UC-CLD-004": (
            "check_mass_s3_get_object_download_volume_and_bucket_criticality",
            "check_personal_data_exfiltration_dpo_notification_required",
        ),
    }

    _DEFAULT_SOURCES: tuple[LogSource, ...] = (
        "cloudtrail",
        "cicd_builds",
        "proxy",
        "dns",
    )

    _RULE_SOURCES: dict[str, tuple[LogSource, ...]] = {
        "UC-CLD-001": ("cloudtrail", "cicd_builds", "proxy"),
        "UC-CLD-002": ("cloudtrail", "cicd_builds"),
        "UC-CLD-003": ("cloudtrail", "cicd_builds"),
        "UC-CLD-004": ("cloudtrail", "proxy", "dns"),
    }

    def build_plan(self, alert: RawAlert) -> InvestigationPlan:
        """Concretar checks de RB-06 según rule_id sin duplicar texto del runbook."""
        if not isinstance(alert, dict) or alert.get("runbook") != self.RUNBOOK_ID:
            raise ValueError(
                f"CloudStrategy requiere runbook '{self.RUNBOOK_ID}', "
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
