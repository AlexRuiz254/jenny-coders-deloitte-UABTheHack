
"""Comprobar que el veredicto propuesto por el LLM está respaldado por pruebas."""

import re
from unicodedata import normalize

from src.triage.models import Analysis, Evidence, ContextSnapshot, RawAlert, VerdictDecision
from src.triage.investigation.authorization import check_authorization


class VerdictEngine:
    def decide(
        self,
        analysis: Analysis,
        evidence: list[Evidence],
        context: ContextSnapshot,
        *, alert: RawAlert | None = None,
    ) -> VerdictDecision:
        """Conservar el veredicto o solicitar más información si hay problemas decisivos.

        Los descuentos de confianza son heurísticos, no probabilidades calibradas.
        Nunca se aumenta la confianza propuesta por el investigador.
        """
        problems, limitations = self._validate_findings(analysis, evidence, context)
        contradictions, other_limitations = self._check_consistency(analysis, context)
        problems.extend(contradictions)
        limitations.extend(other_limitations)
        problems.extend(self._check_waf_activity(analysis, evidence, alert))
        if (alert and alert.get("rule_id") == "UC-CLD-003" and analysis.verdict == "true_positive"
                and not any(getattr(analysis.signals, name) for name in (
                    "credentials_compromised", "persistence", "personal_data_exposure", "malicious_execution"))):
            problems.append("La política pública está observada, pero falta resolver autorización y clasificación del bucket. "
                            "PutBucketPolicy exitoso y ausencia de cambio documentado no prueban por sí solos actividad maliciosa o no autorizada.")

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

    @staticmethod
    def _check_waf_activity(
        analysis: Analysis, evidence: list[Evidence], alert: RawAlert | None,
    ) -> list[str]:
        """Contrastar la actividad citada, sin equiparar bloqueo y falsa alarma."""
        references = {ref for finding in analysis.findings for ref in finding.evidence_ids}
        events = [ev for ev in evidence if ev.source == "waf" and ev.event_id in references]
        if not events or alert and alert.get("source_product") != "WAF":
            return []
        declared_rule = (alert.get("evidence") or {}).get("rule_id") if alert else None
        original = [ev for ev in events if not alert or ev.event_id in alert.get("related_events", [])]
        if declared_rule and any(str(ev.raw.get("rule_id")) != str(declared_rule) for ev in original):
            return ["La regla WAF declarada no coincide con el evento original; resolver la discrepancia."]
        attack_refs = set()
        for ev in events:
            raw = ev.raw
            uri = str(raw.get("uri", "")).casefold()
            scanner = ("scanner" in str(raw.get("rule_msg", "")).casefold()
                       and re.search(r"nuclei|zgrab|sqlmap|nikto", str(raw.get("user_agent", "")), re.I))
            payload = re.search(r"union\s+select|<script\b|(?:\.\./){2,}|/etc/passwd|eval-stdin\.php|/cgi-bin/luci/;stok=", uri)
            if raw.get("rule_id") and (scanner or payload):
                attack_refs.add(ev.event_id)
        attack_findings = [f for f in analysis.findings if attack_refs.intersection(f.evidence_ids)
                           and re.search(r"escaneo|intento|ataque|explotaci[oó]n|scan|attack", f.statement, re.I)]
        if analysis.verdict == "false_positive" and attack_findings:
            return ["False positive contradice los hallazgos de escaneo o intento malicioso real. "
                    "El bloqueo no convierte la detección en falsa alarma; distinguir malicia, autorización y error de regla."]
        return []

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

        return check_authorization(analysis.findings, evidence, context)

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
        # Las preguntas ya matizan la confianza del investigador. Su cantidad no
        # mide la calidad de las pruebas ni justifica una segunda penalización.
        for lookup in context.missing_lookups:
            if lookup.strip():
                limitations.append(f"Consulta de contexto incompleta: {lookup.strip()}")

        return problems, limitations
