"""AISecurityStrategy: RB-07.

Comprobaciones previstas: Sesión completa, prompt injection, controles, herramientas, datos de terceros.
Logs prioritarios: ai_gateway, ecom_auth, ecom_account, sql_audit
"""
from __future__ import annotations

from tarvia_soc.investigation.strategies.base import BaseRunbookStrategy
from tarvia_soc.models import InvestigationPlan, LogSource, RawAlert


class AISecurityStrategy(BaseRunbookStrategy):
    """Estrategia determinista para el runbook RB-07 (Asistente de compra con IA - Vela)."""

    RUNBOOK_ID = "RB-07"

    _COMMON_CHECKS: tuple[str, ...] = (
        "check_full_ai_session_conversation_by_session_id",
        "check_authenticated_customer_identity_and_ip_correlation",
        "check_guardrail_action_blocked_vs_flagged_only",
        "check_model_responses_for_internal_or_customer_data_leakage",
    )

    _RULE_CHECKS: dict[str, tuple[str, ...]] = {
        "UC-AI-001": (
            "check_prompt_injection_intent_vs_benign_natural_language_correction",
            "check_system_prompt_override_and_unauthorized_tool_calls",
        ),
        "UC-AI-002": (
            "check_cross_customer_tool_invocation_and_parameter_tampering",
            "check_tool_authorization_enforcement_and_actual_data_returned",
            "check_other_sessions_from_same_customer_or_ip",
        ),
    }

    _DEFAULT_SOURCES: tuple[LogSource, ...] = (
        "ai_gateway",
        "ecom_auth",
        "ecom_account",
        "sql_audit",
    )

    _RULE_SOURCES: dict[str, tuple[LogSource, ...]] = {
        "UC-AI-001": ("ai_gateway", "ecom_auth"),
        "UC-AI-002": ("ai_gateway", "ecom_auth", "ecom_account", "sql_audit"),
    }

    def build_plan(self, alert: RawAlert) -> InvestigationPlan:
        """Concretar checks de RB-07 según rule_id sin duplicar texto del runbook."""
        if not isinstance(alert, dict) or alert.get("runbook") != self.RUNBOOK_ID:
            raise ValueError(
                f"AISecurityStrategy requiere runbook '{self.RUNBOOK_ID}', "
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
