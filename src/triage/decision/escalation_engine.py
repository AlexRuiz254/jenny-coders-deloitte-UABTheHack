"""Escalado obligatorio y SLA conforme a politica_soc.md."""

from src.triage.models import Analysis, VerdictDecision, SeverityDecision, Escalation, RawAlert


class EscalationEngine:
    def decide(
        self,
        analysis: Analysis,
        verdict: VerdictDecision,
        severity: SeverityDecision,
        related_alerts: list[RawAlert],
    ) -> Escalation:
        """Aplicar la política a las decisiones finales y señales del investigador."""
        final_verdict = verdict.verdict
        final_severity = severity.severity
        signals = analysis.signals
        mandatory_reasons: list[str] = []

        if final_verdict == "true_positive" and final_severity in ("high", "critical"):
            mandatory_reasons.append(f"True positive de severidad {final_severity}.")

        # Estas señales ya proceden de la investigación; no se revalidan aquí.
        compromise_reasons = [
            description
            for active, description in (
                (signals.malicious_execution, "ejecución maliciosa"),
                (signals.credentials_compromised, "credenciales comprometidas"),
                (signals.persistence, "persistencia maliciosa"),
                (signals.personal_data_exposure, "posible exposición de datos personales"),
                (signals.financial_fraud, "fraude económico"),
                (signals.attack_chain, "cadena de ataque"),
            )
            if active
        ]

        if compromise_reasons:
            mandatory_reasons.append(
                "El investigador señala: " + "; ".join(compromise_reasons) + "."
            )

        if mandatory_reasons:
            reasons = ["Escalado obligatorio a N2 según la política SOC."]
            reasons.extend(mandatory_reasons)
            if final_verdict in ("false_positive", "benign_true_positive"):
                reasons.append(
                    f"Existe una discrepancia entre el veredicto {final_verdict} y las "
                    "señales de compromiso que debe revisar N2; no se da por confirmado el incidente."
                )
            elif final_verdict == "needs_more_info":
                reasons.append(
                    "El veredicto needs_more_info mantiene información pendiente de resolver por N2."
                )
        elif final_verdict == "needs_more_info" and final_severity in ("high", "critical"):
            # Convención preventiva: la política no detalla este veredicto.
            reasons = [
                f"Escalado preventivo por riesgo de severidad {final_severity} sin resolver "
                "(veredicto needs_more_info)."
            ]
        else:
            reason = (
                f"Veredicto validado: {final_verdict}; severidad final: {final_severity}. "
                "No se cumplen criterios de escalado obligatorio según la política SOC "
                "ni se han comunicado señales específicas de compromiso."
            )
            # El modelo no tiene otros indicadores específicos de compromiso.
            # Ejecución/acceso y datos sensibles, por sí solos, no lo demuestran.
            if final_severity == "medium" or final_verdict == "needs_more_info":
                reason += " Mantener la investigación en N1."
            return Escalation(escalate=False, to="", reason=reason)

        reasons.append(f"Severidad final: {final_severity}.")
        if signals.attack_chain and related_alerts:
            reasons.append(
                f"Contexto de la cadena identificada: {len(related_alerts)} alertas relacionadas."
            )
        if signals.personal_data_exposure:
            reasons.append("Es necesario implicar al DPO según el procedimiento correspondiente.")

        recipient = "N2"
        if final_severity == "critical":
            recipient = "N2 de guardia"
            reasons.append(
                "Escalado inmediato a N2 de guardia por teléfono. "
                "Notificar al responsable SOC y al CISO. SLA de triaje: 15 minutos."
            )
        elif final_severity == "high":
            reasons.append(
                "Escalado a N2 en la misma jornada. "
                "Notificar al responsable SOC. SLA de triaje: 30 minutos."
            )

        return Escalation(escalate=True, to=recipient, reason=" ".join(reasons))
