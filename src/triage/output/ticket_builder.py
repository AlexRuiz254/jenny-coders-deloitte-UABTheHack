"""Construye salida final Pydantic según ticket_salida.schema.json."""
from uuid import uuid4

from src.triage.models import (
    RawAlert, Analysis, VerdictDecision, SeverityDecision, Escalation,
    Evidence, Finding, IntelEntry, ContextSnapshot, TicketAction, TicketEvidence, Ticket,
)


class TicketBuilder:
    def build(
            self, *, 
            alert: RawAlert, 
            related_alerts: list[RawAlert],
            context: ContextSnapshot, 
            analysis: Analysis,
            verdict: VerdictDecision, 
            severity: SeverityDecision,
            escalation: Escalation, 
            actions: list[TicketAction],
            evidence: list[Evidence], 
            intel: list[IntelEntry],
            triage_seconds: float
    ) -> Ticket:
        """Reunir los resultados finales sin tomar nuevas decisiones de triaje.

        Serializar con model_dump(mode="json", exclude_none=True) para omitir
        los opcionales nulos que el esquema oficial no admite.
        """
        title = analysis.title
        summary = analysis.summary
        
        if verdict.verdict != analysis.verdict:
            title = f"Alerta reevaluada: {analysis.title}"
            summary = (
                f"Veredicto final validado: {verdict.verdict}. {verdict.rationale}\n\n"
                f"Resumen inicial de la investigación (no definitivo): {analysis.summary}"
            )

        identifiers = {
            "hosts": ("hostname", "asset_id", "ip"),
            "users": ("upn", "username", "user_id"),
            "customers": ("customer_id",),
        }
        affected = {}
        for key, values in (alert.get("entities") or {}).items():
            if isinstance(values, (dict, str)):
                values = [values]
            if not isinstance(values, list):
                continue
            normalized = []
            for value in values:
                if isinstance(value, dict) and key in identifiers:
                    value = next(
                        (value[field] for field in identifiers[key] if value.get(field)),
                        value,
                    )
                # Conservar registros sin identificador y contextos como cloud.
                if value and value not in normalized:
                    normalized.append(value)
            if normalized:
                affected[key] = normalized

        for service in context.services:
            name = service.get("servicio")
            if name:
                services = affected.setdefault("business_services", [])
                if name not in services:
                    services.append(name)

        ticket_evidence = self._build_evidence(analysis.findings, evidence)
        resolved_ids = {item.event_id for item in ticket_evidence}
        resolved_ids.update(
            item.raw["query_id"] for item in evidence
            if not item.event_id and item.source and item.raw.get("kind") == "query_summary"
            and item.raw.get("query_id") and "q" in item.raw
        )
        open_questions = list(analysis.open_questions)
        references = dict.fromkeys(
            reference for finding in analysis.findings for reference in finding.evidence_ids
        )
        for reference in references:
            if reference not in resolved_ids:
                question = (
                    f"Referencia sin evidencia disponible en las evidencias recibidas: {reference!r}. "
                    "Revisar su trazabilidad."
                )
                if question not in open_questions:
                    open_questions.append(question)

        technique_id = (alert.get("mitre") or {}).get("technique_id")

        return Ticket(
            ticket_id=f"TRIAGE-{uuid4()}",
            # Correlador y orquestador deben confirmar la agrupación del incidente.
            alert_ids=[alert["alert_id"]],
            title=title,
            verdict=verdict.verdict,
            confidence=verdict.confidence,
            severity=severity.severity,
            severity_rationale=severity.rationale,
            summary=summary,
            evidence=ticket_evidence,
            recommended_actions=actions,
            escalation=escalation,
            affected=affected,
            enrichment=intel,
            mitre=[technique_id] if technique_id else [],
            executed_actions=[],
            open_questions=open_questions,
            triage_seconds=triage_seconds,
        )

    def _build_evidence(
        self, findings: list[Finding], evidence: list[Evidence],
    ) -> list[TicketEvidence]:
        """Vincular hallazgos a eventos, cambios y consultas sin inventar eventos."""
        by_id: dict[str, list[Evidence]] = {}
        for item in evidence:
            if item.event_id and item.source:
                by_id.setdefault(item.event_id, []).append(item)

        result: list[TicketEvidence] = []
        seen: set[tuple[str, str, str]] = set()
        statements_by_ref: dict[str, list[str]] = {}
        for finding in findings:
            for reference in finding.evidence_ids:
                statements_by_ref.setdefault(reference, []).append(finding.statement)
                for item in by_id.get(reference, []):
                    key = (item.source, reference, finding.statement)
                    if key in seen:
                        continue
                    seen.add(key)
                    result.append(TicketEvidence(
                        source=item.source,
                        event_id=item.event_id,
                        finding=finding.statement,
                    ))
        # Resultados de consultas: observaciones reproducibles, sin event_id de log.
        seen_queries = set()
        for item in evidence:
            raw = item.raw
            if item.event_id or not item.source or "q" not in raw:
                continue
            key = (item.source, raw["q"], raw.get("desde"), raw.get("hasta"))
            if key in seen_queries:
                continue
            seen_queries.add(key)
            observation = (
                f"Consulta {raw.get('query_id', '(sin ID)')} literal en {item.source}: q={raw['q']!r}; "
                f"desde={raw.get('desde') or 'desconocido'}; hasta={raw.get('hasta') or 'desconocido'}; "
                f"registros devueltos={raw.get('count', 'desconocido')}; "
                f"truncated={raw.get('truncated', 'desconocido')}. "
                "Cobertura limitada a esa fuente, subcadena y ventana; no descarta compromiso. "
                "Si está truncada, el recuento no representa el total."
            )
            if raw.get("count") == 0:
                observation += " No se encontraron coincidencias en esa consulta concreta."
            if raw.get("reason"):
                observation += f" Motivo: {raw['reason']}"
            if "exact_event_found" in raw:
                observation += f" Evento exacto recuperado={raw['exact_event_found']}."
            if raw.get("kind") == "query_summary":
                statements = dict.fromkeys(statements_by_ref.get(raw.get("query_id"), []))
                if statements:
                    observation += " Hallazgos relacionados: " + " ".join(statements)
            result.append(TicketEvidence(source=item.source, finding=observation))
        return result
