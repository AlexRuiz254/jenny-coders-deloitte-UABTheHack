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
        open_questions = list(analysis.open_questions)
        references = dict.fromkeys(
            reference for finding in analysis.findings for reference in finding.evidence_ids
        )
        for reference in references:
            if reference not in resolved_ids:
                question = (
                    f"Referencia sin evento disponible en las evidencias recibidas: {reference!r}. "
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
        """Vincular hallazgos a eventos recibidos, sin inventar referencias."""
        by_id: dict[str, list[Evidence]] = {}
        for item in evidence:
            if item.event_id and item.source:
                by_id.setdefault(item.event_id, []).append(item)

        result: list[TicketEvidence] = []
        seen: set[tuple[str, str, str]] = set()
        for finding in findings:
            for event_id in finding.evidence_ids:
                for item in by_id.get(event_id, []):
                    key = (item.source, event_id, finding.statement)
                    if key in seen:
                        continue
                    seen.add(key)
                    result.append(TicketEvidence(
                        source=item.source,
                        event_id=event_id,
                        finding=finding.statement,
                    ))
        return result
