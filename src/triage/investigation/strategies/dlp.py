"""DLPStrategy: RB-04.

Comprobaciones previstas: Tipo/volumen/destino de datos, SQL audit, autorización y contexto RRHH.
Logs prioritarios: dlp, sql_audit, edr_events, proxy
"""
from __future__ import annotations

from tarvia_soc.investigation.strategies.base import BaseRunbookStrategy
from tarvia_soc.models import InvestigationPlan, LogSource, RawAlert


class DLPStrategy(BaseRunbookStrategy):
    """Estrategia determinista para el runbook RB-04 (Fuga de datos - DLP)."""

    RUNBOOK_ID = "RB-04"

    _COMMON_CHECKS: tuple[str, ...] = (
        "check_data_type_classification_and_match_volume",
        "check_encrypted_or_uninspectable_files",
        "check_transfer_destination_corporate_vendor_or_personal",
        "check_user_role_justification_and_hr_departure_status",
        "check_approved_business_transfer_flow_or_change",
        "check_prior_bulk_sql_queries_and_local_archiving",
    )

    _RULE_CHECKS: dict[str, tuple[str, ...]] = {
        "UC-DLP-001": (
            "check_personal_cloud_storage_upload_volume_and_service",
            "check_endpoint_file_staging_and_compression",
        ),
        "UC-DLP-002": (
            "check_external_email_recipient_and_pii_dni_iban_content",
            "check_authorized_payroll_agency_exception",
        ),
    }

    _DEFAULT_SOURCES: tuple[LogSource, ...] = (
        "dlp",
        "sql_audit",
        "edr_events",
        "proxy",
    )

    _RULE_SOURCES: dict[str, tuple[LogSource, ...]] = {
        "UC-DLP-001": ("dlp", "proxy", "sql_audit", "edr_events"),
        "UC-DLP-002": ("dlp", "email", "sql_audit", "edr_events"),
    }

    def build_plan(self, alert: RawAlert) -> InvestigationPlan:
        """Concretar checks de RB-04 según rule_id sin duplicar texto del runbook."""
        if not isinstance(alert, dict) or alert.get("runbook") != self.RUNBOOK_ID:
            raise ValueError(
                f"DLPStrategy requiere runbook '{self.RUNBOOK_ID}', "
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
