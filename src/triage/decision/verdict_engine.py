
"""Comprobar que el veredicto propuesto por el LLM está respaldado por pruebas."""

from datetime import datetime, timezone
import re
from zoneinfo import ZoneInfo

from src.triage.models import Analysis, Evidence, ContextSnapshot, VerdictDecision


class VerdictEngine:
    def decide(
        self,
        analysis: Analysis,
        evidence: list[Evidence],
        context: ContextSnapshot,
    ) -> VerdictDecision:
        """Conservar el veredicto o solicitar más información si hay problemas decisivos.

        Los descuentos de confianza son heurísticos, no probabilidades calibradas.
        Nunca se aumenta la confianza propuesta por el investigador.
        """
        problems, limitations = self._validate_findings(analysis, evidence, context)
        contradictions, other_limitations = self._check_consistency(analysis, context)
        problems.extend(contradictions)
        limitations.extend(other_limitations)

        if analysis.verdict == "benign_true_positive":
            authorized, reason = self._check_authorization(analysis, evidence, context)
            if not authorized:
                problems.append(reason)
            else:
                # Solo se verifican la referencia y la ventana general del cambio.
                limitations.append(reason)

        verdict = analysis.verdict
        if verdict != "needs_more_info" and problems:
            verdict = "needs_more_info"

        # Cada problema decisivo pesa más que una limitación no decisiva.
        # No hay máximos fijos (0.5, 0.8): influye la cantidad de incidencias.
        confidence = max(
            0.0,
            round(analysis.confidence - 0.20 * len(problems) - 0.03 * len(limitations), 2),
        )

        if verdict != analysis.verdict:
            rationale = f"No se acepta la propuesta {analysis.verdict}."
        elif verdict == "needs_more_info":
            rationale = "Se mantiene la solicitud de información del investigador."
        else:
            rationale = f"Se mantiene {verdict}: no se detectan problemas decisivos verificables."

        details = problems + limitations
        if details:
            rationale += " " + " ".join(details)
        rationale += (
            " Se comprueba la trazabilidad y la coherencia, no el significado técnico "
            "de todos los eventos. Los PolicySignals son afirmaciones del LLM."
        )
        return VerdictDecision(verdict=verdict, confidence=confidence, rationale=rationale)

    def _validate_findings(
        self,
        analysis: Analysis,
        evidence: list[Evidence],
        context: ContextSnapshot,
    ) -> tuple[list[str], list[str]]:
        """Separar falta total de pruebas (grave) de referencias secundarias ausentes."""
        problems: list[str] = []
        limitations: list[str] = []
        events: dict[str, Evidence] = {}
        ambiguous_ids: set[str] = set()

        for item in evidence:
            if not item.event_id or not item.event_id.strip():
                continue
            previous = events.get(item.event_id)
            if previous is not None and previous != item:
                ambiguous_ids.add(item.event_id)
            events[item.event_id] = item

        # Los cambios se reciben en ContextSnapshot, no necesariamente como Evidence.
        changes = {
            change["id"]: change
            for change in context.changes
            if isinstance(change, dict) and change.get("id")
        }

        if not analysis.findings:
            if analysis.verdict != "needs_more_info":
                problems.append("El análisis no aporta hallazgos para justificar su veredicto.")
            return problems, limitations

        valid_findings = 0
        for number, finding in enumerate(analysis.findings, start=1):
            if not finding.statement.strip():
                limitations.append(f"El hallazgo {number} no contiene una afirmación evaluable.")
            if not finding.evidence_ids:
                limitations.append(f"El hallazgo {number} no cita ninguna evidencia identificable.")
                continue

            finding_supported = False
            for event_id in dict.fromkeys(finding.evidence_ids):
                item = events.get(event_id)
                if event_id in changes:
                    finding_supported = True  # Solo verifica que el cambio existe.
                elif item is None:
                    limitations.append(
                        f"El hallazgo {number} cita una referencia ausente: {event_id!r}."
                    )
                elif event_id in ambiguous_ids:
                    limitations.append(f"La referencia {event_id!r} identifica registros diferentes.")
                elif not item.raw:
                    limitations.append(f"La evidencia {event_id!r} no contiene datos revisables.")
                elif "event_id" in item.raw and item.raw["event_id"] != event_id:
                    limitations.append(f"El registro {event_id!r} tiene un ID interno diferente.")
                else:
                    finding_supported = True

            if finding_supported and finding.statement.strip():
                valid_findings += 1

        if valid_findings == 0 and analysis.verdict != "needs_more_info":
            problems.append("Ningún hallazgo tiene una referencia verificable suficiente.")
        return problems, limitations

    def _check_authorization(
        self,
        analysis: Analysis,
        evidence: list[Evidence],
        context: ContextSnapshot,
    ) -> tuple[bool, str]:
        """Verificar referencia a cambio y ventana general; no interpretar alcance libre."""
        if not analysis.signals.authorized_activity:
            return False, "Se propone actividad autorizada, pero authorized_activity=False."

        changes = {
            change["id"]: change
            for change in context.changes
            if isinstance(change, dict) and change.get("id")
        }
        cited = {
            ref
            for finding in analysis.findings
            for ref in finding.evidence_ids
            if ref in changes
        }
        if not cited:
            return False, (
                "No se cita ningún cambio o flujo autorizado comprobable en context.changes."
            )

        # Contrastar la fecha real de los eventos citados (UTC) con el calendario local.
        cited_event_ids = {ref for f in analysis.findings for ref in f.evidence_ids}
        times = []
        for item in evidence:
            if item.event_id not in cited_event_ids:
                continue
            value = item.timestamp or item.raw.get("timestamp")
            if not isinstance(value, str):
                continue
            try:
                timestamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
                if timestamp.tzinfo is None:
                    timestamp = timestamp.replace(tzinfo=timezone.utc)
                times.append(timestamp.astimezone(ZoneInfo("Europe/Madrid")))
            except ValueError:
                continue

        if not times:
            return False, "No hay timestamps de eventos citados para comprobar la autorización."

        for change_id in cited:
            change = changes[change_id]
            try:
                start = datetime.fromisoformat(change["inicio"]).replace(
                    tzinfo=ZoneInfo("Europe/Madrid")
                )
                end = datetime.fromisoformat(change["fin"]).replace(
                    tzinfo=ZoneInfo("Europe/Madrid")
                )
            except (KeyError, TypeError, ValueError):
                continue
            if start > end or not all(start <= timestamp <= end for timestamp in times):
                continue

            # Algunos cambios periódicos (p. ej. SCCM) también incluyen una
            # franja horaria HH:MM-HH:MM en su campo detalle.
            detail = change.get("detalle", "")
            hours = re.search(r"(?<!\d)(\d{1,2}:\d{2})\s*[-–]\s*(\d{1,2}:\d{2})(?!\d)", detail)
            if hours:
                try:
                    hour_start = datetime.strptime(hours.group(1), "%H:%M").time()
                    hour_end = datetime.strptime(hours.group(2), "%H:%M").time()
                    if not all(hour_start <= timestamp.time() <= hour_end for timestamp in times):
                        continue
                except ValueError:
                    continue

            return True, (
                f"Se comprobó el cambio {change_id} y su ventana temporal; "
                "las restricciones de origen, destino y alcance que figuren "
                "en texto libre no se han validado automáticamente."
            )

        return False, "Ningún cambio citado cubre la fecha de los eventos disponibles."

    def _check_consistency(
        self,
        analysis: Analysis,
        context: ContextSnapshot,
    ) -> tuple[list[str], list[str]]:
        """Separar contradicciones estructurales de lagunas informativas."""
        problems: list[str] = []
        limitations: list[str] = []
        signals = analysis.signals

        if signals.malicious_execution and not signals.execution_or_access_confirmed:
            problems.append(
                "PolicySignals declara ejecución maliciosa, pero niega ejecución o acceso confirmado."
            )

        malicious_claims = [
            name
            for name in ("malicious_execution", "credentials_compromised", "financial_fraud")
            if getattr(signals, name)
        ]
        if analysis.verdict in ("false_positive", "benign_true_positive") and malicious_claims:
            problems.append(
                "El veredicto entra en conflicto con señales de compromiso: "
                + ", ".join(malicious_claims)
                + ". Debe resolverse la discrepancia."
            )

        # Bloqueo y ejecución pueden corresponder a etapas diferentes: no es una
        # contradicción automática ni justifica reducir la confianza por sí solo.
        for question in analysis.open_questions:
            if question.strip():
                limitations.append(f"Pregunta pendiente: {question.strip()}")
        for lookup in context.missing_lookups:
            if lookup.strip():
                limitations.append(f"Consulta de contexto incompleta: {lookup.strip()}")

        return problems, limitations
