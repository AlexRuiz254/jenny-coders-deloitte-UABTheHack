"""IdentityStrategy: RB-03.

Comprobaciones previstas: Origen/GeoIP, MFA, dispositivo, cuentas privilegiadas, RRHH, VPN, cambios AD y OAuth.
Logs prioritarios: idp_signins, idp_audit, ad_events, vpn
"""
from __future__ import annotations

from tarvia_soc.investigation.strategies.base import BaseRunbookStrategy
from tarvia_soc.models import InvestigationPlan, LogSource, RawAlert


class IdentityStrategy(BaseRunbookStrategy):
    """Estrategia determinista para el runbook RB-03 (Identidad: inicios de sesión y cuentas)."""

    RUNBOOK_ID = "RB-03"

    _COMMON_CHECKS: tuple[str, ...] = (
        "check_source_geoip_asn_and_hosting_or_tor",
        "check_device_compliance_and_user_agent",
        "check_authentication_history_and_mfa_result",
        "check_account_privilege_vip_or_service_account_exceptions",
        "check_hr_travel_vacation_or_leave_status",
        "check_post_signin_audit_activity",
    )

    _RULE_CHECKS: dict[str, tuple[str, ...]] = {
        "UC-IDP-001": (
            "check_impossible_travel_locations_and_time_delta",
            "check_notified_business_travel_in_hr",
        ),
        "UC-IDP-002": (
            "check_password_spraying_targeted_accounts_and_failures",
            "check_subsequent_successful_signins_from_attacker_ip",
        ),
        "UC-IDP-003": (
            "check_mfa_fatigue_push_bombing_sequence",
            "check_post_approval_session_actions",
        ),
        "UC-IDP-004": (
            "check_anonymous_tor_vpn_or_hosting_infrastructure",
            "check_session_persistence_creation",
        ),
        "UC-IDP-005": (
            "check_suspicious_mailbox_forwarding_or_deletion_rule",
            "check_financial_keyword_targeting_in_mailbox_rules",
        ),
        "UC-IDP-006": (
            "check_session_token_reuse_aitm_ip_and_device_mismatch",
            "check_concurrent_session_abuse",
        ),
        "UC-IDP-007": (
            "check_unverified_oauth_app_consent_and_permissions",
            "check_mail_read_or_sensitive_scopes_granted",
        ),
        "UC-IDP-008": (
            "check_active_directory_privileged_group_membership_change",
            "check_admin_jump_host_and_approved_change_ticket",
        ),
        "UC-VPN-001": (
            "check_third_party_vpn_contractual_schedule_and_source_asn",
            "check_vendor_authorized_target_host_restrictions",
        ),
    }

    _DEFAULT_SOURCES: tuple[LogSource, ...] = (
        "idp_signins",
        "idp_audit",
        "ad_events",
        "vpn",
    )

    _RULE_SOURCES: dict[str, tuple[LogSource, ...]] = {
        "UC-IDP-001": ("idp_signins", "idp_audit", "vpn"),
        "UC-IDP-002": ("idp_signins", "idp_audit", "ad_events"),
        "UC-IDP-003": ("idp_signins", "idp_audit", "vpn"),
        "UC-IDP-004": ("idp_signins", "idp_audit", "vpn"),
        "UC-IDP-005": ("idp_audit", "idp_signins", "email"),
        "UC-IDP-006": ("idp_signins", "idp_audit"),
        "UC-IDP-007": ("idp_audit", "idp_signins"),
        "UC-IDP-008": ("ad_events", "idp_signins", "idp_audit"),
        "UC-VPN-001": ("vpn", "idp_signins", "ad_events"),
    }

    def build_plan(self, alert: RawAlert) -> InvestigationPlan:
        """Concretar checks de RB-03 según rule_id sin duplicar texto del runbook."""
        if not isinstance(alert, dict) or alert.get("runbook") != self.RUNBOOK_ID:
            raise ValueError(
                f"IdentityStrategy requiere runbook '{self.RUNBOOK_ID}', "
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
