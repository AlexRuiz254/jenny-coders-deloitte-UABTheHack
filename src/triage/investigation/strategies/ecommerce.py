"""EcommerceStrategy: RB-05.

Comprobaciones previstas: WAF, pentest autorizado, logins correctos, cambios de cuenta, gift cards, webshell.
Logs prioritarios: waf, ecom_auth, ecom_account, edr_events, proxy, sql_audit
"""
from __future__ import annotations

from tarvia_soc.investigation.strategies.base import BaseRunbookStrategy
from tarvia_soc.models import InvestigationPlan, LogSource, RawAlert


class EcommerceStrategy(BaseRunbookStrategy):
    """Estrategia determinista para el runbook RB-05 (Tienda online, fraude y ataques web)."""

    RUNBOOK_ID = "RB-05"

    _COMMON_CHECKS: tuple[str, ...] = (
        "check_waf_action_blocked_or_passed_to_backend",
        "check_authorized_external_pentest_window_and_source",
        "check_target_endpoint_existence_and_vulnerability_status",
    )

    _RULE_CHECKS: dict[str, tuple[str, ...]] = {
        "UC-WEB-001": (
            "check_web_injection_payload_sqli_xss_lfi",
            "check_backend_exploitation_and_database_queries",
        ),
        "UC-WEB-002": (
            "check_credential_stuffing_volume_ips_and_device_fingerprint",
            "check_successful_customer_logins_after_attack",
            "check_post_login_account_changes_and_gift_card_purchases",
        ),
        "UC-WEB-003": (
            "check_account_takeover_email_or_address_change",
            "check_rapid_gift_card_purchase_and_payment_fraud",
            "check_prior_suspicious_customer_authentication",
        ),
        "UC-EDR-009": (
            "check_web_server_spawned_shell_or_system_utility",
            "check_webshell_file_and_secret_access_on_server",
            "check_correlating_inbound_waf_requests_and_outbound_traffic",
        ),
    }

    _DEFAULT_SOURCES: tuple[LogSource, ...] = (
        "waf",
        "ecom_auth",
        "ecom_account",
        "edr_events",
        "proxy",
        "sql_audit",
    )

    _RULE_SOURCES: dict[str, tuple[LogSource, ...]] = {
        "UC-WEB-001": ("waf", "sql_audit", "edr_events", "ecom_auth"),
        "UC-WEB-002": ("waf", "ecom_auth", "ecom_account"),
        "UC-WEB-003": ("ecom_account", "ecom_auth", "waf"),
        "UC-EDR-009": ("edr_events", "waf", "proxy", "sql_audit"),
    }

    def build_plan(self, alert: RawAlert) -> InvestigationPlan:
        """Concretar checks de RB-05 según rule_id sin duplicar texto del runbook."""
        if not isinstance(alert, dict) or alert.get("runbook") != self.RUNBOOK_ID:
            raise ValueError(
                f"EcommerceStrategy requiere runbook '{self.RUNBOOK_ID}', "
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
