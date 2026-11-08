"""Coordinar N4 sin endpoints, aprobaciones implícitas ni memoria duradera ficticia.

Contratos provisionales: ApprovalService debe autenticar la intervención humana,
sus roles sobre el objetivo y la vigencia de la autorización; un token /approvals
de la API simulada, por sí solo, NO cumple ese contrato. ContainmentExecutor debe
revalidar política/objetivo y ejecutar con idempotency_key=proposal.proposal_id.

report_loader(id) recupera IncidentReport ya guardado. No existe todavía un
repositorio N3 que lo haga: se inyecta, sin ejecutar de nuevo N1/N2/N3.

ResponseStore es obligatorio. Su implementación debe persistir estados/auditoría,
usar compare-and-set por version y reservar ejecuciones atómicamente. claim debe
impedir usar un mismo digest de token para propuestas distintas. Un estado
executing tras una caída, o failed tras un timeout, exige conciliación manual;
no se reintenta automáticamente una acción de resultado incierto.
"""
from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timezone
from hashlib import sha256
from typing import Any, Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field, SecretStr

from src.triage.level3.incident_report_builder import IncidentReport, validate_report
from src.triage.level4.response_planner import ApprovalRole, ContainmentProposal, report_fingerprint

_CONFIG = ConfigDict(extra="forbid", strict=True)


class HumanDecision(BaseModel):
    """Evento explícito del cliente autenticado; ApprovalService verifica su autor."""
    model_config = _CONFIG
    decision_id: str = Field(min_length=1)
    actor: str = Field(min_length=1)
    approved: bool
    reason: str = Field(min_length=1)


class ApprovalRecord(BaseModel):
    """Recibo de Persona 2, sin secretos. Puede permanecer pending entre aprobadores."""
    model_config = _CONFIG
    approval_id: str = Field(min_length=1)
    proposal_id: str
    incident_id: str
    action: str | None
    target: str
    status: Literal["pending", "approved", "rejected"]
    human_verified: bool
    decision_ids: list[str]
    approved_roles: list[ApprovalRole]
    expires_at: datetime | None = None


class ExecutionAuthorization(ApprovalRecord):
    status: Literal["approved"]
    human_verified: Literal[True]
    expires_at: datetime
    token: SecretStr


class ActionResult(BaseModel):
    """Resultado de Persona 3: details debe excluir tokens y otros secretos."""
    model_config = _CONFIG
    proposal_id: str
    incident_id: str
    action: str
    target: str
    success: bool
    details: dict[str, Any] = Field(default_factory=dict)


class ProposalState(BaseModel):
    model_config = _CONFIG
    proposal: ContainmentProposal
    status: Literal["pending", "approved", "rejected", "executing", "succeeded", "failed"] = "pending"
    version: int = Field(default=0, ge=0)
    approval: ApprovalRecord | None = None
    result: ActionResult | None = None
    last_error: str | None = None
    history: list[dict[str, Any]] = Field(default_factory=list)


class Planner(Protocol):
    def plan(self, report: IncidentReport) -> list[ContainmentProposal]: ...


class ApprovalService(Protocol):
    def record_decision(self, proposal: ContainmentProposal, decision: HumanDecision) -> ApprovalRecord:
        """Autenticar actor/roles, persistir el evento humano e identificar duplicados por decision_id."""
        ...
    def validate(self, proposal: ContainmentProposal, approval_id: str) -> ExecutionAuthorization:
        """Comprobar vigencia/revocación y todos los aprobadores para este objetivo/política."""
        ...


class ContainmentExecutor(Protocol):
    def execute(self, proposal: ContainmentProposal, approval: ExecutionAuthorization) -> ActionResult: ...


class ResponseStore(Protocol):
    def get(self, proposal_id: str) -> ProposalState | None: ...
    def insert_if_absent(self, state: ProposalState) -> ProposalState: ...
    def save(self, state: ProposalState, *, expected_version: int) -> None: ...
    def claim(self, proposal_id: str, *, expected_version: int, token_digest: str,
              event: dict[str, Any]) -> ProposalState:
        """Atómico: approved -> executing, version+1 e historial+event.

        Rechazar otra versión/estado y cualquier token_digest ya reservado para
        otra propuesta, incluso fallida. No revelar ni persistir el token en claro.
        """
        ...


def _model(cls: type[BaseModel], value: Any) -> Any:
    return cls.model_validate(value.model_dump(mode="python") if isinstance(value, BaseModel) else value)


class Level4Orchestrator:
    def __init__(self, *, report_loader: Callable[[str], IncidentReport | dict | None],
                 planner: Planner, approvals: ApprovalService, executor: ContainmentExecutor,
                 store: ResponseStore, clock: Callable[[], datetime] | None = None) -> None:
        if not callable(report_loader):
            raise TypeError("Se requiere report_loader(incident_id), sin ejecutar N3")
        for component, methods in ((planner, ("plan",)), (approvals, ("record_decision", "validate")),
                                   (executor, ("execute",)), (store, ("get", "insert_if_absent", "save", "claim"))):
            if any(not callable(getattr(component, method, None)) for method in methods):
                raise TypeError(f"Dependencia obligatoria incompatible: {methods}")
        self.report_loader, self.planner = report_loader, planner
        self.approvals, self.executor, self.store = approvals, executor, store
        self.clock = clock if clock is not None else lambda: datetime.now(timezone.utc)

    def _event(self, name: str, **data: Any) -> dict:
        instant = self.clock()
        if instant.utcoffset() is None:
            raise ValueError("El reloj N4 debe devolver una fecha con zona horaria")
        return {"event": name, "timestamp": instant.isoformat(), **data}

    def _report(self, incident_id: str) -> IncidentReport:
        value = self.report_loader(incident_id)
        if value is None:
            raise LookupError(f"Informe N3 no encontrado: {incident_id}")
        report = validate_report(value)
        if report.incident_id != incident_id:
            raise ValueError("El cargador devolvió otro incidente N3")
        return report

    def get_state(self, proposal_id: str) -> ProposalState:
        value = self.store.get(proposal_id)
        if value is None:
            raise LookupError(f"Propuesta no encontrada: {proposal_id}")
        state = _model(ProposalState, value).model_copy(deep=True)
        state.proposal.verify_identity()
        if state.proposal.proposal_id != proposal_id:
            raise ValueError("El almacén devolvió otra propuesta")
        if state.result is not None and (
            state.result.proposal_id, state.result.incident_id, state.result.action, state.result.target
        ) != (proposal_id, state.proposal.incident_id, state.proposal.action, state.proposal.target):
            raise ValueError("El estado guardado contiene el resultado de otra acción")
        if state.status == "succeeded" and (state.result is None or not state.result.success):
            raise ValueError("Estado de éxito sin un resultado satisfactorio")
        return state

    def _save(self, state: ProposalState, event: dict, **changes: Any) -> ProposalState:
        saved = state.model_copy(deep=True, update={**changes, "version": state.version + 1,
                                                  "history": [*state.history, event]})
        self.store.save(saved, expected_version=state.version)
        return saved

    def _failure(self, state: ProposalState, stage: str, exc: Exception, **changes: Any) -> None:
        # No almacenar mensajes de servicios que podrían contener tokens/secretos.
        try:
            self._save(state, self._event("error", stage=stage, error_type=type(exc).__name__),
                       last_error=f"{stage}: {type(exc).__name__}", **changes)
        except Exception as storage_error:
            exc.add_note(f"No se pudo registrar el fallo de {stage}: {type(storage_error).__name__}")

    def prepare(self, incident_id: str) -> list[ContainmentProposal]:
        if not isinstance(incident_id, str) or not incident_id.strip():
            raise ValueError("Se requiere un incident_id no vacío")
        report = self._report(incident_id)
        proposals = self.planner.plan(report.model_copy(deep=True))
        # Validar todo el lote antes de registrar la primera propuesta.
        validated = []
        for value in proposals:
            proposal = _model(ContainmentProposal, value)
            proposal.verify_identity()
            if proposal.incident_id != incident_id or proposal.report_digest != report_fingerprint(report):
                raise ValueError("La propuesta no pertenece al informe solicitado")
            validated.append(proposal)
        result, seen = [], set()
        for proposal in validated:
            if proposal.proposal_id in seen:
                continue
            seen.add(proposal.proposal_id)
            state = _model(ProposalState, self.store.insert_if_absent(ProposalState(
                proposal=proposal, history=[self._event("prepared")],
            )))
            if state.proposal != proposal:
                raise ValueError("La propuesta ya registrada tiene otro contenido")
            result.append(state.proposal.model_copy(deep=True))
        return result

    def _check_approval(self, proposal: ContainmentProposal, approval: ApprovalRecord) -> None:
        if (approval.proposal_id, approval.incident_id, approval.action, approval.target) != (
            proposal.proposal_id, proposal.incident_id, proposal.action, proposal.target
        ):
            raise PermissionError("La aprobación corresponde a otra propuesta, incidente, acción u objetivo")
        if approval.status == "approved":
            if (not approval.human_verified or not approval.decision_ids
                    or not set(proposal.required_approvals) <= set(approval.approved_roles)):
                raise PermissionError("Falta intervención humana verificada o aprobadores requeridos")
            if (approval.expires_at is None or approval.expires_at.utcoffset() is None
                    or approval.expires_at <= self.clock()):
                raise PermissionError("La aprobación no está vigente")

    def record_decision(self, proposal_id: str, decision: HumanDecision | dict) -> ProposalState:
        state = self.get_state(proposal_id)
        if state.status not in {"pending", "approved"}:
            raise PermissionError(f"No se puede registrar una decisión en estado {state.status}")
        decision = _model(HumanDecision, decision)
        if not all(value.strip() for value in (decision.actor, decision.decision_id, decision.reason)):
            raise ValueError("La decisión requiere identificador, actor y motivo explícitos")
        try:
            record = _model(ApprovalRecord, self.approvals.record_decision(
                state.proposal.model_copy(deep=True), decision.model_copy(deep=True)))
            self._check_approval(state.proposal, record)
            if (not record.human_verified or decision.decision_id not in record.decision_ids
                    or not decision.approved and record.status != "rejected"):
                raise PermissionError("El servicio no ha registrado la decisión humana recibida")
        except Exception as exc:
            self._failure(state, "approval_record", exc)
            raise
        return self._save(state, self._event("human_decision", decision_id=decision.decision_id,
                                            actor=decision.actor, approved=decision.approved, reason=decision.reason),
                          approval=record, status=record.status, last_error=None)

    def execute_approved(self, proposal_id: str) -> ActionResult:
        state = self.get_state(proposal_id)
        if state.status == "succeeded" and state.result is not None:
            return state.result.model_copy(deep=True)
        if state.status != "approved" or state.approval is None or state.approval.status != "approved":
            raise PermissionError(f"La propuesta está {state.status}; no se permite ejecutarla")
        proposal = state.proposal
        if not proposal.executable or proposal.action is None:
            raise PermissionError("Propuesta de revisión manual: no es ejecutable")
        try:
            if report_fingerprint(self._report(proposal.incident_id)) != proposal.report_digest:
                raise PermissionError("El informe N3 ha cambiado; preparar y revisar nuevas propuestas")
            self._check_approval(proposal, state.approval)
            authorization = _model(ExecutionAuthorization, self.approvals.validate(
                proposal.model_copy(deep=True), state.approval.approval_id))
            self._check_approval(proposal, authorization)
            if (authorization.approval_id != state.approval.approval_id
                    or set(authorization.decision_ids) != set(state.approval.decision_ids)
                    or not authorization.token.get_secret_value().strip()):
                raise PermissionError("Autorización distinta de las decisiones registradas o token vacío")
        except Exception as exc:
            self._failure(state, "approval_validation", exc)
            raise
        digest = sha256(authorization.token.get_secret_value().encode()).hexdigest()
        try:
            claimed = _model(ProposalState, self.store.claim(
                proposal_id, expected_version=state.version, token_digest=digest, event=self._event("execution_claimed")))
            if (claimed.status != "executing" or claimed.proposal != proposal
                    or claimed.version != state.version + 1):
                raise RuntimeError("El almacén no ha reservado correctamente la ejecución")
        except Exception as exc:
            self._failure(state, "execution_claim", exc)
            raise
        state = claimed
        try:
            # La reserva puede esperar a otro proceso: comprobar de nuevo la
            # caducidad justo antes de delegar la ejecución.
            self._check_approval(proposal, authorization)
            result = _model(ActionResult, self.executor.execute(proposal.model_copy(deep=True), authorization))
            if (result.proposal_id, result.incident_id, result.action, result.target) != (
                proposal_id, proposal.incident_id, proposal.action, proposal.target
            ):
                raise ValueError("El ejecutor devolvió el resultado de otra acción")
        except Exception as exc:
            self._failure(state, "execution", exc, status="failed")
            raise
        if not result.success:
            self._save(state, self._event("execution_failed"), status="failed", result=result,
                       last_error="El ejecutor ha comunicado un fallo; requiere conciliación manual")
            raise RuntimeError("El ejecutor ha comunicado un fallo; requiere conciliación manual")
        self._save(state, self._event("execution_succeeded"), status="succeeded", result=result, last_error=None)
        return result.model_copy(deep=True)
