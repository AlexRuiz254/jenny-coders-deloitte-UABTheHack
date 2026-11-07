"""Comprobar que el veredicto propuesto por el LLM está respaldado por pruebas."""

from src.triage.models import Analysis, Evidence, ContextSnapshot, VerdictDecision


class VerdictEngine:
    def decide(
        self,
        analysis: Analysis,
        evidence: list[Evidence],
        context: ContextSnapshot,
    ) -> VerdictDecision:
        """Conservar la propuesta o pedir información, sin reinterpretar el ataque.

        La confianza nunca aumenta. Los límites 0.8 (limitaciones) y 0.5
        (propuesta definitiva sin justificar) son cautelas, no probabilidades
        calibradas. La confianza de un needs_more_info propuesto se conserva:
        puede existir alta confianza en que falta información.
        """
        problems = self._validate_findings(analysis, evidence)
        contradictions, limitations = self._check_consistency(analysis, context)
        problems.extend(contradictions)

        if analysis.verdict == "benign_true_positive" or analysis.signals.authorized_activity:
            # Coincidir en equipo y ventana no valida las restricciones libres
            # de detalle/alcance. El contrato actual no permite comprobarlas.
            problems.append(
                "La autorización alegada no se puede verificar: el calendario "
                "describe actividad y alcance en texto libre, sin un vínculo "
                "estructurado con los eventos. No se presupone autorización "
                "ni se deduce malicia de esta limitación."
            )

        verdict = analysis.verdict
        confidence = analysis.confidence
        if verdict != "needs_more_info":
            if problems:
                verdict = "needs_more_info"
                confidence = min(confidence, 0.5)
            elif limitations:
                confidence = min(confidence, 0.8)

        if verdict != analysis.verdict:
            rationale = f"No se acepta la propuesta {analysis.verdict}."
        elif verdict == "needs_more_info":
            rationale = "Se mantiene la solicitud de información del investigador."
        else:
            rationale = (
                f"Se mantiene {verdict}: los hallazgos tienen referencias "
                "comprobables y no se detectan contradicciones decisivas."
            )

        details = problems + limitations
        if details:
            rationale += " " + " ".join(details)
        rationale += (
            " La existencia de un evento citado no demuestra la interpretación "
            "del hallazgo; esa valoración corresponde al investigador. "
            "Los PolicySignals son afirmaciones de la IA, no hechos confirmados."
        )
        return VerdictDecision(verdict=verdict, confidence=confidence, rationale=rationale)

    def _validate_findings(
        self,
        analysis: Analysis,
        evidence: list[Evidence],
    ) -> list[str]:
        """
        Verificar trazabilidad, no el significado de los registros.

        Finding no indica qué hallazgos son decisivos. Por prudencia, todos
        deben poder trazarse antes de aceptar una conclusión definitiva.
        """
        problems: list[str] = []
        events: dict[str, Evidence] = {}
        ambiguous_ids: set[str] = set()
        for item in evidence:
            if not item.event_id or not item.event_id.strip():
                continue
            previous = events.get(item.event_id)
            if previous is not None and previous != item:
                ambiguous_ids.add(item.event_id)
            events[item.event_id] = item

        if not analysis.findings:
            return ["El análisis no contiene hallazgos que respalden la conclusión."]

        for number, finding in enumerate(analysis.findings, start=1):
            if not finding.statement.strip():
                problems.append(f"El hallazgo {number} no contiene una afirmación evaluable.")
            if not finding.evidence_ids:
                problems.append(f"El hallazgo {number} no cita evidencias identificables.")
                continue

            for event_id in dict.fromkeys(finding.evidence_ids):
                item = events.get(event_id)
                if item is None:
                    problems.append(
                        f"El hallazgo {number} cita una evidencia inexistente: {event_id!r}."
                    )
                elif event_id in ambiguous_ids:
                    problems.append(
                        f"La referencia {event_id!r} del hallazgo {number} es ambigua: "
                        "identifica registros diferentes."
                    )
                elif not item.raw:
                    problems.append(
                        f"La evidencia {event_id!r} no contiene datos del evento para su revisión."
                    )
                elif "event_id" in item.raw and item.raw["event_id"] != event_id:
                    problems.append(
                        f"La evidencia {event_id!r} tiene un event_id diferente en el registro."
                    )
        return problems

    def _check_consistency(
        self,
        analysis: Analysis,
        context: ContextSnapshot,
    ) -> tuple[list[str], list[str]]:
        """
        Separar contradicciones internas de limitaciones de alcance desconocido.

        No se interpretan statement, summary, preguntas ni mensajes de error
        mediante palabras clave. Tampoco se confirma un signal con otro.
        """
        problems: list[str] = []
        limitations: list[str] = []
        signals = analysis.signals
        if signals.malicious_execution and not signals.execution_or_access_confirmed:
            problems.append(
                "PolicySignals afirma ejecución maliciosa pero niega ejecución o acceso confirmado."
            )

        malicious_claims = [
            name
            for name in ("malicious_execution", "credentials_compromised", "financial_fraud")
            if getattr(signals, name)
        ]
        if analysis.verdict in ("false_positive", "benign_true_positive") and malicious_claims:
            problems.append(
                "El veredicto de cierre entra en conflicto con afirmaciones de compromiso: "
                + ", ".join(malicious_claims)
                + ". Hace falta resolver esta discrepancia, no asumir que las señales son ciertas."
            )

        # Ambas señales pueden referirse a eventos distintos de la misma alerta.
        if signals.blocked_before_effect and signals.execution_or_access_confirmed:
            limitations.append(
                "Se afirma bloqueo previo al efecto y ejecución o acceso confirmado, "
                "pero las señales no identifican eventos para comprobar si comparten alcance."
            )
        if any(question.strip() for question in analysis.open_questions):
            limitations.append(
                "Hay preguntas pendientes sin un campo que indique si condicionan el veredicto."
            )
        if context.missing_lookups:
            limitations.append(
                "Hay consultas de contexto sin resolver: "
                + ", ".join(context.missing_lookups)
                + ". Su relevancia para la conclusión no está estructurada."
            )
        return problems, limitations
