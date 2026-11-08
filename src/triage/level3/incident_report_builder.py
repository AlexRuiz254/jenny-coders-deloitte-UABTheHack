"""Informe N3: fusión de la presentación remota y los contratos con evidencias locales.

Se acepta AttackReconstruction real y el contrato ReconstructionResult. Los IDs de
supporting_evidence se resuelven con las fuentes explícitas de su cronología y
después se verifican contra el bundle. ScopeAnalysis real se conserva como alcance
no verificado: su interfaz actual no proporciona citas. No se inventan para
confirmar o proponer hipótesis. ScopeResult mantiene el contrato con citas.

normalize_scope comparte con el orquestador la asociación al ID conocido de la
ejecución y la conservación de los datos de alcance sin citas como no verificados.
Las conversiones de entrada de los servicios se realizan en el orquestador.
No se modifica ni parchea ninguno de los módulos de los compañeros.

Cada conclusión confirmada o hipotética debe citar source + event_id del bundle.
La existencia de una cita permite trazabilidad; no demuestra que su interpretación
sea correcta. Esa responsabilidad corresponde a los servicios y al analista.
El esquema oficial permite propiedades adicionales: se usan para preservar
evidencias, estados, limitaciones y trazabilidad sin alterar su contrato.
"""
from __future__ import annotations

from functools import lru_cache
import json
from pathlib import Path
from typing import Any, Literal

from jsonschema import Draft202012Validator
from pydantic import BaseModel, ConfigDict, Field, model_validator

from src.triage.level3.investigation_expander import InvestigationBundle
from src.triage.models import Evidence, Ticket
from src.triage.time_windows import api_time, parse_utc

_CONFIG = ConfigDict(extra="forbid", strict=True)
_SCHEMA_PATH = (Path(__file__).resolve().parents[3]
                / "RepositoriDeloitte/01_contexto/informe_incidente.schema.json")


class EvidenceReference(BaseModel):
    model_config = _CONFIG
    source: str = Field(min_length=1)
    event_id: str = Field(min_length=1)


class SupportedConclusion(BaseModel):
    """statement es también el identificador para entradas de hosts/users/services."""
    model_config = _CONFIG
    statement: str | None = None
    status: Literal["confirmed", "hypothesis", "unknown"] = "unknown"
    evidence: list[EvidenceReference] = Field(default_factory=list)


class TimelineEvent(BaseModel):
    model_config = _CONFIG
    timestamp: str
    description: str = Field(min_length=1)
    status: Literal["confirmed", "hypothesis"] = "confirmed"
    evidence: list[EvidenceReference]
    event_id: str | None = None
    mitre: str | None = None


class RecommendedMeasure(BaseModel):
    """Solo una propuesta; este módulo nunca ejecuta ni aprueba acciones."""
    model_config = _CONFIG
    action: str = Field(min_length=1)
    target: str = Field(min_length=1)
    justification: str = Field(min_length=1)
    evidence: list[EvidenceReference] = Field(default_factory=list)
    approver: str | None = None
    business_impact: str | None = None
    requires_approval: Literal[True] = True


class ReconstructionResult(BaseModel):
    """Datos esperados de AttackReconstructor, sin imponer su clase concreta."""
    model_config = _CONFIG
    undated_events: list[dict[str, Any]] = Field(default_factory=list)
    native_details: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="before")
    @classmethod
    def from_reconstructor(cls, value: Any) -> Any:
        return _adapt_reconstruction(value)

    incident_id: str
    patient_zero: SupportedConclusion = Field(default_factory=SupportedConclusion)
    initial_access: SupportedConclusion = Field(default_factory=SupportedConclusion)
    root_cause: SupportedConclusion = Field(default_factory=SupportedConclusion)
    timeline: list[TimelineEvent] = Field(default_factory=list)
    confidence: float | None = Field(default=None, ge=0, le=1)
    open_questions: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)


class ScopeResult(BaseModel):
    """Datos esperados de ScopeAnalyzer; no inferir compromiso de una coincidencia."""
    model_config = _CONFIG
    unverified_scope: dict[str, Any] = Field(default_factory=dict)
    incident_id: str
    hosts: list[SupportedConclusion] = Field(default_factory=list)
    users: list[SupportedConclusion] = Field(default_factory=list)
    services: list[SupportedConclusion] = Field(default_factory=list)
    data: SupportedConclusion = Field(default_factory=SupportedConclusion)
    business_impact: SupportedConclusion = Field(default_factory=SupportedConclusion)
    containment_plan: list[RecommendedMeasure] = Field(default_factory=list)
    eradication_and_recovery: list[str] = Field(default_factory=list)
    notifications: list[str] = Field(default_factory=list)
    detection_gaps: list[str] = Field(default_factory=list)
    confidence: float | None = Field(default=None, ge=0, le=1)
    open_questions: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)


class ScopeDetails(BaseModel):
    """Acceso por atributos y claves para los dos consumidores existentes."""
    model_config = _CONFIG
    hosts: list[str] = Field(default_factory=list)
    users: list[str] = Field(default_factory=list)
    services: list[str] = Field(default_factory=list)
    data: str = "No determinado con la evidencia disponible."
    business_impact: str = "No determinado con la evidencia disponible."

    def __getitem__(self, name: str) -> Any:
        return getattr(self, name)


# Nombres públicos de ambas ramas.
TimelineEntry = TimelineEvent
ContainmentAction = RecommendedMeasure


class IncidentReport(BaseModel):
    """Campos oficiales y extensiones de trazabilidad admitidas por el esquema.

    Exportar con model_dump(mode='json', exclude_none=True) o model_dump_json
    (exclude_none=True): el esquema oficial no permite null en campos opcionales.
    La confianza de cada servicio queda en reconstruction/scope_analysis; no se
    inventa una confianza global ni se transforma la confianza N2 en confianza N3.
    """
    model_config = _CONFIG
    incident_id: str = Field(min_length=1)
    title: str = Field(min_length=1)
    alert_ids: list[str] = Field(min_length=1)
    patient_zero: str
    initial_access: str
    timeline: list[TimelineEvent]
    scope: ScopeDetails
    root_cause: str
    containment_plan: list[RecommendedMeasure]
    related_incidents: list[str] = Field(default_factory=list)
    eradication_and_recovery: list[str] = Field(default_factory=list)
    notifications: list[str] = Field(default_factory=list)
    detection_gaps: list[str] = Field(default_factory=list)
    open_questions: list[str] = Field(default_factory=list)
    summary: str
    source_ticket_ids: list[str]
    evidence: list[Evidence]
    reconstruction: ReconstructionResult
    scope_analysis: ScopeResult
    potentially_affected: dict[str, list[str]]
    related_incident_details: list[dict[str, Any]]
    investigation_window: dict[str, str]
    consulted_sources: list[str]
    searches: list[dict[str, Any]]
    limitations: list[str]
    confidence: float | None = Field(default=None, ge=0, le=1)
    impact_level: str | None = None
    affected_services: list[str] = Field(default_factory=list)
    affected_network_zones: list[str] = Field(default_factory=list)
    confirmed_findings: list[str] = Field(default_factory=list)
    suspected_findings: list[str] = Field(default_factory=list)
    soc_recommendations: list[str] = Field(default_factory=list)
    investigation_limitations: list[str] = Field(default_factory=list)
    unverified_findings: list[str] = Field(default_factory=list)
    undated_events: list[dict[str, Any]] = Field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json", exclude_none=True)


def _payload(value: BaseModel | dict) -> dict:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json", exclude_none=True)
    if not isinstance(value, dict):
        raise TypeError("El resultado debe ser un modelo Pydantic o un dict")
    return value



def _adapt_reconstruction(value: Any) -> Any:
    """Adaptar datos de AttackReconstruction conservando la salida original."""
    if isinstance(value, BaseModel):
        value = _payload(value)
    if not isinstance(value, dict):
        return value
    native = ("attack_phases" in value or "related_entities" in value
              or any("source" in row and "evidence" not in row for row in value.get("timeline", []))
              or any(isinstance(value.get(key), str)
                     or isinstance(value.get(key), dict) and "conclusion" in value[key]
                     for key in ("patient_zero", "initial_access", "root_cause")))
    if not native:
        return value
    raw = json.loads(json.dumps(value))
    by_id: dict[str, set[str]] = {}
    for row in raw.get("timeline", []):
        if row.get("event_id") and row.get("source"):
            by_id.setdefault(row["event_id"], set()).add(row["source"])

    def reference(token: str) -> dict[str, str]:
        matches = [(source, event_id) for event_id, sources in by_id.items() for source in sources
                   if token in (event_id, f"{source}:{event_id}")]
        if len(matches) != 1:
            raise ValueError(f"Referencia de reconstrucción inexistente o ambigua: {token}")
        source, event_id = matches[0]
        return {"source": source, "event_id": event_id}

    result: dict[str, Any] = {
        "incident_id": raw.get("incident_id", ""), "native_details": raw,
        "confidence": raw.get("confidence"), "open_questions": raw.get("uncertainties", raw.get("open_questions", [])),
        "limitations": list(raw.get("uncertainties", [])), "timeline": [], "undated_events": [],
    }
    for key in ("patient_zero", "initial_access", "root_cause"):
        conclusion = raw.get(key) or {}
        if isinstance(conclusion, str):
            result[key] = {}
            result["limitations"].append(f"{key}: texto recibido sin estado ni referencias; no validado.")
            continue
        status = conclusion.get("status", "undetermined")
        status = "unknown" if status == "undetermined" else status
        refs = [reference(token) for token in conclusion.get("supporting_evidence", [])]
        if status != "unknown" and not refs:
            raise ValueError(f"{key}: una conclusión {status} requiere supporting_evidence")
        result[key] = {"statement": conclusion.get("conclusion"), "status": status, "evidence": refs}
    for row in raw.get("timeline", []):
        if not row.get("event_id") or not row.get("source"):
            result["limitations"].append("Evento sin referencia source/event_id; conservado en native_details.")
            continue
        refs = [reference(f"{row['source']}:{row['event_id']}")]
        try:
            parse_utc(row.get("timestamp"))
        except (ValueError, TypeError, AttributeError):
            result["undated_events"].append({**row, "evidence": refs})
            result["limitations"].append(f"{row['event_id']}: fecha desconocida; no se inventa una posición temporal.")
            continue
        result["timeline"].append({
            "timestamp": row["timestamp"], "description": row["description"], "status": "confirmed",
            "evidence": refs, "event_id": row["event_id"], "mitre": row.get("mitre"),
        })
    return result


def normalize_scope(value: Any, incident_id: str) -> ScopeResult:
    """Asociar la respuesta a su ejecución, sin inventar evidencia de sus hallazgos.

    ScopeAnalysis carece de ID y de citas: se conserva íntegro en unverified_scope.
    Un ScopeResult con citas mantiene sus datos y debe identificar este incidente.
    La validación de esas citas contra el bundle sigue siendo tarea del builder.
    """
    if value is None:
        return ScopeResult(incident_id=incident_id, limitations=["No se ha aportado análisis de alcance."])
    data = _payload(value)
    if "affected_assets" not in data and "confirmed_findings" not in data:
        result = ScopeResult.model_validate(data)
        if result.incident_id != incident_id:
            raise ValueError("ScopeResult pertenece a otro incidente")
        return result
    if data.get("incident_id", incident_id) != incident_id:
        raise ValueError("ScopeAnalysis pertenece a otro incidente")
    # ScopeAnalysis no incluye ni incident_id ni referencias. Asociarlo aquí al
    # incidente explícito no convierte sus afirmaciones en conclusiones verificadas.
    return ScopeResult(
        incident_id=incident_id, unverified_scope=data,
        limitations=["ScopeAnalysis carece de referencias a evidencias: sus afirmaciones se conservan "
                     "como datos no verificados, sin confirmar compromiso ni impacto."],
        open_questions=data.get("unknowns", []),
    )


def _builder_inputs(incident: Any, bundle: Any) -> tuple[dict, InvestigationBundle]:
    data = _payload(incident)
    data = data.get("details", {}).get("ticket", data)
    incident_id = data.get("ticket_id") or data.get("incident_id")
    ids = data.get("alert_ids")
    if (not isinstance(incident_id, str) or not incident_id.strip() or not isinstance(ids, list)
            or not ids or any(not isinstance(key, str) or not key.strip() for key in ids)
            or len(ids) != len(set(ids))):
        raise ValueError("Se requiere el ID real del incidente y sus alert_ids únicos; no se generan IDs ficticios")
    if isinstance(bundle, InvestigationBundle):
        return data, bundle.model_copy(deep=True)
    raw = dict(_payload(bundle))
    raw.setdefault("incident_id", incident_id)
    raw.setdefault("alert_ids", ids)
    raw.setdefault("window", {})  # Ventana no suministrada; nunca una fecha artificial.
    raw.setdefault("original_evidence", raw.get("evidence", []))
    raw.setdefault("additional_evidence", raw.get("expanded_evidence", []))
    raw.setdefault("source_tickets", raw.get("tickets", []))
    for ticket in raw["source_tickets"]:
        alert_ids = _payload(ticket).get("alert_ids", [])
        if set(alert_ids) - set(ids):
            raise ValueError("El bundle contiene tickets de alertas ajenas al incidente")
    return data, InvestigationBundle.model_validate(raw)


@lru_cache(maxsize=1)
def incident_report_validator() -> Draft202012Validator:
    schema = json.loads(_SCHEMA_PATH.read_text(encoding="utf-8-sig"))
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


def validate_report(value: IncidentReport | dict) -> IncidentReport:
    """Validar el JSON original antes de aplicar los valores por defecto locales."""
    payload = _payload(value)
    incident_report_validator().validate(payload)
    report = IncidentReport.model_validate(payload)
    if (not report.incident_id.strip() or not report.title.strip()
            or any(not item.strip() for item in report.alert_ids)
            or len(report.alert_ids) != len(set(report.alert_ids))):
        raise ValueError("El informe debe identificar un incidente y alertas únicas no vacías")
    if (report.reconstruction.incident_id != report.incident_id
            or report.scope_analysis.incident_id != report.incident_id):
        raise ValueError("El informe contiene resultados de otro incidente")
    incident_report_validator().validate(report.model_dump(mode="json", exclude_none=True))
    return report


class IncidentReportBuilder:
    def __init__(self, schema_path: Path | str | None = None) -> None:
        """El esquema oficial es obligatorio; un esquema adicional solo restringe."""
        self.schema_path = Path(schema_path) if schema_path is not None else _SCHEMA_PATH
        self._schema = json.loads(self.schema_path.read_text(encoding="utf-8-sig"))
        Draft202012Validator.check_schema(self._schema)
        self._validator = Draft202012Validator(self._schema)

    def validate(self, report: IncidentReport | dict) -> None:
        checked = validate_report(report)
        self._validator.validate(checked.to_dict())

    @staticmethod
    def _text(conclusion: SupportedConclusion) -> str:
        if conclusion.status == "unknown":
            return "No determinado con la evidencia disponible." + (
                f" {conclusion.statement}" if conclusion.statement else ""
            )
        label = "Confirmado" if conclusion.status == "confirmed" else "Hipótesis"
        return f"{label}: {conclusion.statement}"

    def build(self, incident: Ticket | BaseModel | dict, bundle: InvestigationBundle | BaseModel | dict,
              reconstruction: ReconstructionResult | BaseModel | dict,
              scope: ScopeResult | BaseModel | dict | None = None) -> IncidentReport:
        """Formatear conclusiones aportadas, comprobar citas y validar el informe."""
        incident_data, bundle = _builder_inputs(incident, bundle)
        incident_id = incident_data.get("ticket_id") or incident_data["incident_id"]
        for ticket in bundle.source_tickets:
            if len(ticket.alert_ids) != 1 or set(ticket.alert_ids) - set(incident_data["alert_ids"]):
                raise ValueError("Se requieren tickets N1 individuales del incidente, sin alertas ajenas")
        reconstruction_data = dict(_payload(reconstruction))
        reconstruction_data.setdefault("incident_id", incident_id)
        # Una cronología antigua puede omitir source. Solo se completa si el ID
        # identifica una única fuente real en el bundle; no se deduce del nombre.
        observed_sources: dict[str, set[str]] = {}
        for observed in [*bundle.original_evidence, *bundle.additional_evidence, *bundle.events]:
            if observed.event_id:
                observed_sources.setdefault(observed.event_id, set()).add(observed.source)
        reconstruction_data = json.loads(json.dumps(reconstruction_data))
        for row in reconstruction_data.get("timeline", []):
            sources = observed_sources.get(row.get("event_id"), set())
            if not row.get("source") and "evidence" not in row and len(sources) == 1:
                row["source"] = next(iter(sources))
        reconstruction = ReconstructionResult.model_validate(reconstruction_data)
        if set(reconstruction.native_details.get("alert_ids", [])) - set(incident_data["alert_ids"]):
            raise ValueError("La reconstrucción contiene alertas ajenas al incidente")
        scope = normalize_scope(scope, incident_id)
        if (incident_id != bundle.incident_id
                or set(incident_data["alert_ids"]) != set(bundle.alert_ids)
                or len(bundle.alert_ids) != len(set(bundle.alert_ids))
                or reconstruction.incident_id != bundle.incident_id
                or scope.incident_id != bundle.incident_id):
            raise ValueError("Incidente, bundle y resultados N3 deben identificar el mismo incidente")

        # El bundle es el conjunto de evidencias disponibles, no una conclusión.
        values = {json.dumps(item.model_dump(), ensure_ascii=False, sort_keys=True): item
                  for item in [*bundle.original_evidence, *bundle.additional_evidence, *bundle.events]}
        evidence = [values[key] for key in sorted(values)]
        known: dict[tuple[str, str], list[Evidence]] = {}
        for item in evidence:
            if item.event_id:
                known.setdefault((item.source, item.event_id), []).append(item)

        def check_references(refs: list[EvidenceReference], *, required: bool) -> None:
            if required and not refs:
                raise ValueError("Una conclusión o evento requiere referencias a evidencias")
            for ref in refs:
                if (ref.source, ref.event_id) not in known:
                    raise ValueError(f"Evidencia no disponible en el bundle: {ref.source}/{ref.event_id}")

        conclusions = [reconstruction.patient_zero, reconstruction.initial_access,
                       reconstruction.root_cause, scope.data, scope.business_impact,
                       *scope.hosts, *scope.users, *scope.services]
        for conclusion in conclusions:
            if conclusion.status != "unknown" and (not conclusion.statement or not conclusion.statement.strip()):
                raise ValueError("Una conclusión conocida requiere statement no vacío")
            check_references(conclusion.evidence, required=conclusion.status != "unknown")
        for measure in scope.containment_plan:
            if not all(value.strip() for value in (measure.action, measure.target, measure.justification)):
                raise ValueError("Una recomendación requiere acción, objetivo y justificación")
            check_references(measure.evidence, required=False)

        for row in reconstruction.undated_events:
            check_references([EvidenceReference.model_validate(ref) for ref in row.get("evidence", [])], required=True)
        timeline = []
        for item in reconstruction.timeline:
            check_references(item.evidence, required=True)
            if item.event_id and item.event_id not in {ref.event_id for ref in item.evidence}:
                raise ValueError("El event_id de la cronología no está entre sus referencias")
            instant = parse_utc(item.timestamp)
            dates = []
            for ref in item.evidence:
                if item.event_id and ref.event_id != item.event_id:
                    continue
                for observed in known[(ref.source, ref.event_id)]:
                    timestamp = observed.timestamp or observed.raw.get("timestamp") or observed.raw.get("eventTime")
                    try:
                        dates.append(parse_utc(timestamp))
                    except (ValueError, TypeError, AttributeError):
                        continue  # Una cita sin fecha no permite inventar la fecha del evento.
            if instant not in dates:
                raise ValueError("La fecha de la cronología no coincide con ninguna evidencia citada")
            normalized = item.model_copy(update={"timestamp": api_time(instant)})
            timeline.append(normalized)
        timeline.sort(key=lambda item: (parse_utc(item.timestamp), item.event_id or "", item.description))
        reconstruction.timeline = timeline

        limitations = [*bundle.limitations, *reconstruction.limitations, *scope.limitations]
        if not evidence:
            limitations.append("No se dispone de evidencias; no se pueden confirmar conclusiones.")
        if not timeline:
            limitations.append("No se ha aportado una cronología del ataque respaldada por evidencias.")
        if any(item.status == "hypothesis" for item in conclusions):
            limitations.append("Las hipótesis requieren verificación; no se presentan como hechos confirmados.")
        if bundle.related_incidents:
            limitations.append("Los incidentes relacionados son propuestas de conexión, sin fusión ni causalidad confirmada.")
        declared_relations = set(incident_data.get("related_incidents") or []) | set(
            reconstruction.native_details.get("related_incidents") or []
        )
        if any(not isinstance(key, str) or not key.strip() for key in declared_relations):
            raise ValueError("Los incidentes relacionados deben tener identificadores reales no vacíos")
        related_details = list(bundle.related_incidents)
        known_relations = {item["incident_id"] for item in related_details}
        for key in sorted(declared_relations - known_relations - {incident_id}):
            related_details.append({"incident_id": key, "status": "unverified",
                                    "justification": "Relación declarada en la entrada; sin evidencias de conexión aportadas."})
        if declared_relations:
            limitations.append("Las relaciones declaradas sin evidencias se conservan como no verificadas, no como hipótesis confirmadas.")
        for name, conclusion in (("Paciente cero", reconstruction.patient_zero),
                                 ("Acceso inicial", reconstruction.initial_access),
                                 ("Causa raíz", reconstruction.root_cause),
                                 ("Datos afectados", scope.data), ("Impacto de negocio", scope.business_impact)):
            if conclusion.status == "unknown":
                limitations.append(f"{name}: no determinado con la evidencia disponible.")
        affected = {name: sorted({item.statement for item in getattr(scope, name) if item.status == "confirmed"})
                    for name in ("hosts", "users", "services")}
        potential = {name: sorted({item.statement for item in getattr(scope, name) if item.status == "hypothesis"})
                     for name in ("hosts", "users", "services")}
        questions = [*incident_data.get("open_questions", []), *reconstruction.open_questions, *scope.open_questions]
        for ticket in bundle.source_tickets:
            questions.extend(ticket.open_questions)
        plan = list(scope.containment_plan)
        recovery = list(scope.eradication_and_recovery)
        notifications = list(scope.notifications)
        # Propuestas condicionadas a conclusiones ya citadas, nunca acciones ejecutadas.
        # No se bloquean IOC genéricos ni se presupone persistencia, exfiltración o brecha legal.
        for name, action in (("hosts", "Valorar aislamiento coordinado y preservación forense"),
                             ("users", "Valorar revocación de sesiones y rotación de credenciales")):
            for conclusion in getattr(scope, name):
                if conclusion.status != "confirmed":
                    continue
                target = conclusion.statement
                if name == "hosts" and target.upper().startswith(("PLC-", "HMI-")):
                    action_text = "Coordinar una posible contención OT con Operaciones, sin aislamiento automático"
                else:
                    action_text = action
                if not any(measure.target == target for measure in plan):
                    plan.append(RecommendedMeasure(
                        action=action_text, target=target, approver="N2 y responsable del activo o identidad",
                        justification="Propuesta basada en la conclusión de alcance citada; pendiente de aprobación.",
                        evidence=conclusion.evidence,
                        business_impact="Evaluar la interrupción operativa antes de aprobar la medida.",
                    ))
                recovery.append(f"Evaluar restauración segura de {target} tras verificar y erradicar los artefactos confirmados."
                                if name == "hosts" else f"Revisar y recuperar de forma segura el acceso de {target}.")
        if scope.data.status == "confirmed" and any(
            word in (scope.data.statement or "").casefold() for word in ("rgpd", "personal", "pci")
        ):
            notifications.append("Solicitar al DPO y responsables de cumplimiento la valoración de comunicaciones aplicables.")
        report = IncidentReport(
            incident_id=incident_id, title=incident_data.get("title") or f"Investigación N3: {incident_id}",
            alert_ids=sorted(incident_data["alert_ids"]),
            patient_zero=self._text(reconstruction.patient_zero),
            initial_access=self._text(reconstruction.initial_access), root_cause=self._text(reconstruction.root_cause),
            timeline=timeline, scope={**affected, "data": self._text(scope.data),
                                      "business_impact": self._text(scope.business_impact)},
            containment_plan=plan,
            related_incidents=sorted({item["incident_id"] for item in related_details}),
            eradication_and_recovery=list(dict.fromkeys(recovery)), notifications=list(dict.fromkeys(notifications)),
            detection_gaps=scope.detection_gaps, open_questions=list(dict.fromkeys(questions)),
            summary=f"Investigación de {len(incident_data['alert_ids'])} alertas; {len(evidence)} evidencias disponibles. "
                    "Las conclusiones y sus incertidumbres se detallan con sus referencias.",
            source_ticket_ids=sorted({ticket.ticket_id for ticket in bundle.source_tickets}),
            evidence=evidence, reconstruction=reconstruction, scope_analysis=scope,
            potentially_affected=potential, related_incident_details=related_details,
            investigation_window=bundle.window, consulted_sources=bundle.consulted_sources,
            searches=bundle.searches, limitations=list(dict.fromkeys(limitations)),
        )
        report.affected_services = affected["services"]
        report.confirmed_findings = [item.statement for item in conclusions if item.status == "confirmed"]
        report.suspected_findings = [item.statement for item in conclusions if item.status == "hypothesis"]
        report.unverified_findings = list(scope.unverified_scope.get("confirmed_findings", [])) + list(
            scope.unverified_scope.get("suspected_findings", [])
        )
        report.undated_events = reconstruction.undated_events
        report.investigation_limitations = report.limitations.copy()
        report.soc_recommendations = (
            ["Preservar evidencias y revisar las propuestas con el analista antes de aprobar cualquier medida."]
            if evidence else ["Recuperar evidencias verificables antes de concluir o recomendar contención."]
        )
        report.summary += (f" Paciente cero: {report.patient_zero} Acceso inicial: {report.initial_access} "
                           f"Causa raíz: {report.root_cause} Datos: {report.scope.data} "
                           f"Impacto de negocio: {report.scope.business_impact}")
        self.validate(report)
        return report
