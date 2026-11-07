"""PhishingStrategy: RB-01.

Comprobaciones previstas: Emisor SPF/DKIM/DMARC, adjuntos/URLs, receptores, clics, actividad posterior y fraude IBAN.
Logs prioritarios: email, email_clicks, proxy, dns, edr_events, idp_signins
"""
from __future__ import annotations

from tarvia_soc.investigation.strategies.base import BaseRunbookStrategy
from tarvia_soc.models import InvestigationPlan, LogSource, RawAlert


class PhishingStrategy(BaseRunbookStrategy):
    """Estrategia determinista para el runbook RB-01 (Phishing y correo malicioso)."""

    RUNBOOK_ID = "RB-01"

    _COMMON_CHECKS: tuple[str, ...] = (
        "check_sender_spf_dkim_dmarc",
        "check_sender_domain_and_reply_to_consistency",
        "check_recipient_scope_and_message_delivery",
        "check_domain_and_url_reputation",
    )

    _RULE_CHECKS: dict[str, tuple[str, ...]] = {
        "UC-EML-001": (
            "check_phishing_simulation_or_legitimate_newsletter",
            "check_url_clicks_and_user_interaction",
        ),
        "UC-EML-002": (
            "check_attachment_type_extension_and_hash",
            "check_attachment_sandbox_verdict",
            "check_post_delivery_file_download_and_execution",
            "check_anomalous_post_delivery_signins",
        ),
        "UC-EML-003": (
            "check_url_clicks_and_redirect_chain",
            "check_post_click_proxy_and_dns_traffic",
            "check_post_click_endpoint_execution",
            "check_anomalous_post_click_signins",
        ),
        "UC-EML-004": (
            "check_iban_change_or_payment_fraud_indicators",
            "check_historical_legitimate_supplier_emails",
            "check_out_of_band_supplier_verification_required",
        ),
    }

    _DEFAULT_SOURCES: tuple[LogSource, ...] = (
        "email",
        "email_clicks",
        "proxy",
        "dns",
        "edr_events",
        "idp_signins",
    )

    _RULE_SOURCES: dict[str, tuple[LogSource, ...]] = {
        "UC-EML-001": ("email", "email_clicks", "proxy", "dns"),
        "UC-EML-002": ("email", "proxy", "edr_events", "idp_signins"),
        "UC-EML-003": ("email", "email_clicks", "proxy", "dns", "edr_events", "idp_signins"),
        "UC-EML-004": ("email", "idp_signins", "idp_audit"),
    }

    def build_plan(self, alert: RawAlert) -> InvestigationPlan:
        """Concretar checks de RB-01 según rule_id sin duplicar texto del runbook."""
        if not isinstance(alert, dict) or alert.get("runbook") != self.RUNBOOK_ID:
            raise ValueError(
                f"PhishingStrategy requiere runbook '{self.RUNBOOK_ID}', "
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
