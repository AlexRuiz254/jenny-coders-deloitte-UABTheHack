
"""Comprobar que el veredicto propuesto por el LLM está respaldado por pruebas."""

from datetime import datetime, timezone
from ipaddress import ip_address
import re
from unicodedata import normalize
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
                # Las condiciones en texto libre pueden requerir revisión humana.
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
        references: dict[str, Evidence] = {}
        ambiguous_ids: set[str] = set()

        for item in evidence:
            reference = item.event_id
            if not reference and item.raw.get("kind") == "query_summary":
                reference = item.raw.get("query_id")
            if not reference or not reference.strip():
                continue
            previous = references.get(reference)
            if previous is not None and previous != item:
                ambiguous_ids.add(reference)
            references[reference] = item

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

            cited_evidence: list[Evidence] = []
            finding_supported = False
            for reference in dict.fromkeys(finding.evidence_ids):
                item = references.get(reference)
                if reference in changes:
                    finding_supported = True  # Solo verifica que el cambio existe.
                elif item is None:
                    limitations.append(
                        f"El hallazgo {number} cita una referencia ausente: {reference!r}."
                    )
                elif reference in ambiguous_ids:
                    limitations.append(f"La referencia {reference!r} identifica registros diferentes.")
                elif not item.raw:
                    limitations.append(f"La evidencia {reference!r} no contiene datos revisables.")
                elif item.event_id and "event_id" in item.raw and item.raw["event_id"] != reference:
                    limitations.append(f"El registro {reference!r} tiene un ID interno diferente.")
                else:
                    finding_supported = True
                    cited_evidence.append(item)

            issues = self._finding_limitations(finding.statement, cited_evidence)
            if issues:
                limitations.extend(f"Hallazgo {number}: {issue}" for issue in issues)
                finding_supported = False

            if finding_supported and finding.statement.strip():
                valid_findings += 1

        if valid_findings == 0 and analysis.verdict != "needs_more_info":
            problems.append("Ningún hallazgo tiene una referencia verificable suficiente.")
        return problems, limitations

    @staticmethod
    def _finding_limitations(statement: str, cited: list[Evidence]) -> list[str]:
        """Detectar unos pocos excesos evidentes; no validar semántica libre."""
        if not cited:
            return []
        text = normalize("NFKD", statement.casefold()).encode("ascii", "ignore").decode()
        queries = [item for item in cited if item.raw.get("kind") == "query_summary"]
        events = [item for item in cited if item.raw.get("kind") != "query_summary"]
        blocked_only = bool(events) and all(
            item.source.casefold() == "waf"
            and item.raw.get("action") == "blocked"
            and str(item.raw.get("status")) == "403"
            for item in events
        )
        issues: list[str] = []
        # Evaluar frases cortas y omitir menciones negadas: no son afirmaciones de éxito.
        for clause in re.split(r"[.;\n]|\b(?:pero|but)\b", text):
            success = re.search(
                r"\b(?:explotacion (?:exitosa|con exito|confirmada)|acceso exitoso|"
                r"ejecucion maliciosa confirmada|successful exploitation|exploitation succeeded)\b",
                clause,
            )
            if blocked_only and success and not re.search(
                r"\b(?:no|sin|not|without)\b", clause[:success.start()]
            ):
                issues.append("Un WAF blocked/403 acredita bloqueo de la solicitud, no éxito de explotación.")

        absence = re.search(
            r"\b(?:(?:no (?:hubo|hay|existe|existio|ocurrio)|sin|"
            r"ausencia (?:global )?de|se descarta) (?:ningun[a]? )?"
            r"(?:compromiso|exfiltracion|web\s*shell)|"
            r"no (?:compromise|exfiltration|web\s*shell))\b", text,
        )
        if absence and (len(queries) == len(cited) or blocked_only):
            issues.append(
                "Las referencias no demuestran ausencia global de compromiso, web shell o exfiltración. "
                "Una consulta, incluso con count=0, solo describe coincidencias en su fuente, filtro y ventana."
            )

        for clause in re.split(r"[.;\n]", text):
            complete = re.search(
                r"\b(?:revision completa|cobertura completa|todos los eventos|"
                r"complete review|all events)\b", clause,
            )
            if complete and any(item.raw.get("truncated") is True for item in queries) and not re.search(
                r"\b(?:no|sin|not|without)\b", clause[:complete.start()]
            ):
                issues.append("Una consulta truncada no acredita una revisión completa de los eventos.")
        return list(dict.fromkeys(issues))

    def _check_authorization(
        self,
        analysis: Analysis,
        evidence: list[Evidence],
        context: ContextSnapshot,
    ) -> tuple[bool, str]:
        """Verificar ventana y discrepancias explícitas; no interpretar alcance libre."""
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
        cited_events = []
        for item in evidence:
            if (
                item.event_id not in cited_event_ids or item.source == "changes"
                or item.raw.get("kind") == "query_summary"
            ):
                continue
            cited_events.append(item)
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

            # Solo contrastar alcances con nombres literales y orígenes IP explícitos.
            # Las descripciones libres y los grupos de activos siguen siendo una limitación.
            scope = str(change.get("alcance", "")).strip()
            hosts = {
                str(item.raw[key]).casefold() for item in cited_events
                for key in ("hostname", "host", "client_host") if item.raw.get(key)
            }
            if re.fullmatch(r"[A-Z][A-Z0-9_-]*\d+(?:\s*,\s*[A-Z][A-Z0-9_-]*\d+)*", scope):
                allowed_hosts = {host.strip().casefold() for host in scope.split(",")}
                if hosts and not hosts <= allowed_hosts:
                    continue
            origin = re.search(
                r"\b(?:IPs? origen|origen|desde)\s+(\d{1,3}(?:\.\d{1,3}){3})(?:-(\d{1,3}))?\b",
                detail, re.IGNORECASE,
            )
            if origin:
                try:
                    first = ip_address(origin.group(1))
                    last = first
                    if origin.group(2):
                        last = ip_address(origin.group(1).rsplit(".", 1)[0] + "." + origin.group(2))
                    sources = [
                        ip_address(item.raw["src_ip"]) for item in cited_events
                        if item.raw.get("src_ip")
                    ]
                    if last < first or not sources or not all(first <= source <= last for source in sources):
                        continue
                except (TypeError, ValueError):
                    continue

            return True, (
                f"Se comprobó el cambio {change_id} y su ventana temporal; "
                "las restricciones de origen, destino y alcance que figuren "
                "en texto libre no se han validado automáticamente."
            )

        return False, (
            "Ningún cambio citado cubre la fecha y las condiciones explícitas "
            "de alcance y origen de los eventos disponibles."
        )

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
