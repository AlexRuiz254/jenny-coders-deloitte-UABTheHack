"""Coordinar N3 sobre investigaciones guardadas, sin ejecutar N1/N2 ni persistir.

Los repositorios reales ofrecen get(ticket_id). N2 guarda source_ticket_ids;
esas claves recuperan los artefactos N1 sin find_by_alert ni consultas a la API.
No se importan AttackReconstructor/ScopeAnalyzer, todavía pendientes. Sus métodos
reciben InvestigationBundle y devuelven datos compatibles con los contratos
ReconstructionResult/ScopeResult documentados en incident_report_builder.py.
Cada etapa se llama una sola vez por run; no hay caché entre ejecuciones ni
repositorio de informes N3 existente que permita reutilizarlos con garantías.
"""
from __future__ import annotations

from collections.abc import Callable
from typing import Any, Protocol

from pydantic import BaseModel

from src.triage.level2.incident_decision_service import AlertInvestigationInput
from src.triage.level3.investigation_expander import InvestigationBundle
from src.triage.level3.incident_report_builder import (
    IncidentReport, ReconstructionResult, ScopeResult, validate_report,
)
from src.triage.models import Ticket


class TicketReader(Protocol):
    def get(self, ticket_id: str) -> dict | None: ...


class Expander(Protocol):
    def expand(self, incident: Ticket, tickets: list[AlertInvestigationInput]) -> InvestigationBundle: ...


class AttackReconstructor(Protocol):
    def reconstruct(self, bundle: InvestigationBundle) -> ReconstructionResult | BaseModel | dict: ...


class ScopeAnalyzer(Protocol):
    def assess(self, bundle: InvestigationBundle) -> ScopeResult | BaseModel | dict: ...


class ReportBuilder(Protocol):
    def build(self, incident: Ticket, bundle: InvestigationBundle,
              reconstruction: ReconstructionResult | BaseModel | dict,
              scope: ScopeResult | BaseModel | dict) -> IncidentReport: ...


class Level3Orchestrator:
    def __init__(self, *, n1_store: TicketReader, n2_store: TicketReader,
                 expander: Expander, reconstructor: AttackReconstructor,
                 scope_analyzer: ScopeAnalyzer, report_builder: ReportBuilder) -> None:
        for name, component, method in (
            ("n1_store", n1_store, "get"), ("n2_store", n2_store, "get"),
            ("expander", expander, "expand"), ("reconstructor", reconstructor, "reconstruct"),
            ("scope_analyzer", scope_analyzer, "assess"), ("report_builder", report_builder, "build"),
        ):
            if not callable(getattr(component, method, None)):
                raise TypeError(f"Falta la dependencia obligatoria {name}.{method}")
        self.n1_store, self.n2_store = n1_store, n2_store
        self.expander, self.reconstructor = expander, reconstructor
        self.scope_analyzer, self.report_builder = scope_analyzer, report_builder

    @staticmethod
    def _call(name: str, operation: Callable, *args: Any) -> Any:
        try:
            return operation(*args)
        except NotImplementedError as exc:
            exc.add_note(f"Dependencia N3 pendiente: {name}")
            raise

    @staticmethod
    def _is_n2(record: dict) -> bool:
        details = record.get("details", {})
        return (details.get("level") == "N2" or details.get("tier") == "N2"
                or details.get("type") == "incident" or details.get("is_incident") is True)

    def _load(self, incident_id: str) -> tuple[Ticket, list[AlertInvestigationInput]]:
        record = self._call("n2_store.get", self.n2_store.get, incident_id)
        if record is None:
            raise LookupError(f"Incidente N2 no encontrado: {incident_id}")
        if not isinstance(record, dict) or not self._is_n2(record):
            raise ValueError(f"{incident_id} no es un registro de incidente N2")
        details = record["details"]
        incident = Ticket.model_validate(details["ticket"])
        if (record.get("id") != incident_id or incident.ticket_id != incident_id
                or details.get("incident_id", incident_id) != incident_id):
            raise ValueError("El repositorio N2 devolvió otro incidente")
        if (not incident.alert_ids or any(not key.strip() for key in incident.alert_ids)
                or len(incident.alert_ids) != len(set(incident.alert_ids))):
            raise ValueError("El incidente N2 debe identificar alertas únicas no vacías")
        source_ids = details.get("source_ticket_ids")
        if (not isinstance(source_ids, list) or not source_ids
                or any(not isinstance(key, str) or not key.strip() for key in source_ids)):
            raise ValueError(f"{incident_id}: faltan source_ticket_ids N1 válidos")
        investigations = []
        for source_id in sorted(set(source_ids)):
            source = self._call("n1_store.get", self.n1_store.get, source_id)
            if source is None:
                raise LookupError(f"Investigación N1 no encontrada: {source_id}")
            if not isinstance(source, dict) or self._is_n2(source):
                raise ValueError(f"{source_id} no es una investigación N1")
            data = source["details"]
            ticket = Ticket.model_validate(data["ticket"])
            if source.get("id") != source_id or ticket.ticket_id != source_id or len(ticket.alert_ids) != 1:
                raise ValueError(f"Registro N1 incompatible con su ticket: {source_id}")
            alert_id = ticket.alert_ids[0]
            if alert_id not in incident.alert_ids or data.get("alert", {}).get("alert_id") != alert_id:
                raise ValueError(f"La investigación {source_id} pertenece a otra alerta/incidente")
            if any(data.get(field) is None for field in ("analysis", "context", "evidence")):
                raise ValueError(f"Investigación N1 incompleta: {source_id}; se requieren analysis, context y evidence")
            investigations.append(AlertInvestigationInput.model_validate({
                "alert_id": alert_id, "alert": data["alert"], "ticket": ticket,
                "analysis": data["analysis"], "context": data["context"], "evidence": data["evidence"],
                "verdict_decision": data.get("verdict"), "related_alerts": data.get("related_alerts", []),
            }).model_copy(deep=True))
        if (len(investigations) != len(incident.alert_ids)
                or {item.alert_id for item in investigations} != set(incident.alert_ids)):
            raise ValueError("Faltan investigaciones N1 o hay varias versiones de una alerta del incidente")
        return incident.model_copy(deep=True), sorted(investigations, key=lambda item: item.alert_id)

    def run(self, incident_id: str) -> IncidentReport:
        """Cargar, ampliar, reconstruir, evaluar alcance, construir y validar."""
        if not isinstance(incident_id, str) or not incident_id.strip():
            raise ValueError("incident_id debe ser una cadena no vacía")
        incident, investigations = self._load(incident_id)
        value = self._call("InvestigationExpander.expand", self.expander.expand,
                           incident.model_copy(deep=True), [item.model_copy(deep=True) for item in investigations])
        bundle = InvestigationBundle.model_validate(value).model_copy(deep=True)
        source_ids = {item.ticket.ticket_id for item in investigations}
        if (bundle.incident_id != incident_id or set(bundle.alert_ids) != set(incident.alert_ids)
                or len(bundle.alert_ids) != len(set(bundle.alert_ids))
                or {item.ticket_id for item in bundle.source_tickets} != source_ids):
            raise ValueError("InvestigationExpander devolvió otro incidente o perdió sus tickets N1")
        # Copias independientes: un componente no altera la entrada del siguiente.
        reconstruction = self._call("AttackReconstructor.reconstruct", self.reconstructor.reconstruct,
                                    bundle.model_copy(deep=True))
        reconstruction = ReconstructionResult.model_validate(
            reconstruction.model_dump(mode="json", exclude_none=True)
            if isinstance(reconstruction, BaseModel) else reconstruction
        )
        if reconstruction.incident_id != incident_id:
            raise ValueError("AttackReconstructor devolvió otro incidente")
        scope = self._call("ScopeAnalyzer.assess", self.scope_analyzer.assess, bundle.model_copy(deep=True))
        scope = ScopeResult.model_validate(
            scope.model_dump(mode="json", exclude_none=True) if isinstance(scope, BaseModel) else scope
        )
        if scope.incident_id != incident_id:
            raise ValueError("ScopeAnalyzer devolvió otro incidente")
        report = self._call("IncidentReportBuilder.build", self.report_builder.build,
                            incident.model_copy(deep=True), bundle.model_copy(deep=True), reconstruction, scope)
        report = validate_report(report)
        if (report.incident_id != incident_id or set(report.alert_ids) != set(incident.alert_ids)
                or set(report.source_ticket_ids) != source_ids):
            raise ValueError("El informe final contiene otro incidente o tickets ajenos")
        return report
