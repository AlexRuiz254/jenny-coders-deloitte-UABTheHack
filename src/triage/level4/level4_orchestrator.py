"""Coordinar N4 sin aprobaciones implícitas ni memoria duradera ficticia.

with_soc_services conecta ApprovalService y ContainmentExecutor existentes.
El cliente inyecta verify_actor para autenticar la sesión y su ámbito sobre el
objetivo; los roles se obtienen del registro de ApprovalPolicy. SOCTokenBridge
registra la autorización en la API simulada sin sustituir TokenService. Un token
/approvals, por sí solo, no acredita identidad, permisos ni decisión humana.

report_loader(id) recupera IncidentReport ya guardado. SQLiteResponseStore permite
importarlo y recuperarlo sin ejecutar N1/N2/N3. La preparación funciona sin
servicios de aprobación/ejecución; las etapas posteriores los exigen explícitamente.

ResponseStore es obligatorio. Su implementación debe persistir estados/auditoría,
usar compare-and-set por version y reservar ejecuciones atómicamente. claim debe
impedir usar un mismo digest de token para propuestas distintas. Un estado
executing tras una caída, o failed tras un timeout, exige conciliación manual;
no se reintenta automáticamente una acción de resultado incierto.
"""
from __future__ import annotations

from collections.abc import Callable
from contextlib import closing
from contextvars import ContextVar
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import json
from pathlib import Path
import sqlite3
import threading
from typing import Any, Literal, Protocol
from urllib.parse import urlsplit

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
    identity_mode: Literal["authenticated", "demo_simulated"] = "authenticated"
    decision_ids: list[str]
    approved_roles: list[ApprovalRole]
    expires_at: datetime | None = None


class ExecutionAuthorization(ApprovalRecord):
    status: Literal["approved"]
    human_verified: Literal[True]
    expires_at: datetime
    token: SecretStr
    approved_by: list[str] = Field(default_factory=list)
    content_digest: str | None = None

    @property
    def approval_token(self) -> str:
        """Solo para la frontera con Persona 3; no se serializa en la auditoría."""
        return self.token.get_secret_value()

    @property
    def approver(self) -> str:
        return ", ".join(self.approved_by)

    @property
    def proposal_hash(self) -> str:
        return self.content_digest or self.proposal_id


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


class SQLiteResponseStore:
    """Estados, recibos sin tokens, resultados, auditoría y fuentes N3 versionadas.

    store_report importa un informe YA generado/validado; no ejecuta N3.
    load_report es un report_loader real. La ruta es explícita y cada operación
    abre/cierra su conexión; BEGIN IMMEDIATE protege reservas entre procesos.
    No implementa ApprovalService ni autentica decisiones humanas.
    """
    def __init__(self, db_path: str | Path) -> None:
        if str(db_path) == ":memory:":
            raise ValueError("Se requiere una ruta SQLite persistente")
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with closing(self._connect()) as con, con:
            con.executescript("""
                CREATE TABLE IF NOT EXISTS response_states (
                    proposal_id TEXT PRIMARY KEY, version INTEGER NOT NULL,
                    status TEXT NOT NULL, payload TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS response_token_claims (
                    token_digest TEXT PRIMARY KEY, proposal_id TEXT NOT NULL UNIQUE);
                CREATE TABLE IF NOT EXISTS response_reports (
                    digest TEXT PRIMARY KEY, incident_id TEXT NOT NULL, payload TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS response_report_heads (
                    incident_id TEXT PRIMARY KEY, digest TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS workflow_operations (
                    operation_id TEXT PRIMARY KEY, payload TEXT NOT NULL);
            """)

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.db_path, timeout=30)

    def store_report(self, value: IncidentReport | dict) -> None:
        report = validate_report(value)
        digest = report_fingerprint(report)
        with closing(self._connect()) as con, con:
            con.execute("BEGIN IMMEDIATE")
            con.execute("INSERT OR IGNORE INTO response_reports VALUES (?, ?, ?)",
                        (digest, report.incident_id, report.model_dump_json(exclude_none=True)))
            con.execute("INSERT INTO response_report_heads VALUES (?, ?) ON CONFLICT(incident_id) "
                        "DO UPDATE SET digest=excluded.digest", (report.incident_id, digest))

    def load_report(self, incident_id: str, *, digest: str | None = None) -> IncidentReport | None:
        with closing(self._connect()) as con:
            if digest is None:
                row = con.execute("SELECT r.digest,r.payload FROM response_reports r "
                                  "JOIN response_report_heads h ON r.digest=h.digest "
                                  "WHERE h.incident_id=? AND r.incident_id=?", (incident_id, incident_id)).fetchone()
            else:
                row = con.execute("SELECT digest,payload FROM response_reports WHERE incident_id=? AND digest=?",
                                  (incident_id, digest)).fetchone()
        if row is None:
            return None
        report = validate_report(json.loads(row[1]))
        if report.incident_id != incident_id or report_fingerprint(report) != row[0]:
            raise ValueError("El informe N3 persistido no coincide con su contenido/identificador")
        return report

    def list_reports(self, *, incident_id: str = "", limit: int = 100) -> list[dict]:
        with closing(self._connect()) as con:
            rows = con.execute(
                "SELECT r.incident_id,r.digest,json_extract(r.payload,'$.title'),"
                "json_array_length(r.payload,'$.timeline'),h.digest=r.digest "
                "FROM response_reports r LEFT JOIN response_report_heads h ON h.incident_id=r.incident_id "
                "WHERE (?='' OR r.incident_id=?) ORDER BY r.rowid DESC LIMIT ?",
                (incident_id, incident_id, limit)).fetchall()
        return [dict(zip(("incident_id", "digest", "title", "events", "current"), row)) for row in rows]

    def list_states(self, *, incident_id: str = "", limit: int = 200) -> list[ProposalState]:
        with closing(self._connect()) as con:
            rows = con.execute("SELECT payload FROM response_states WHERE "
                               "(?='' OR json_extract(payload,'$.proposal.incident_id')=?) ORDER BY rowid DESC LIMIT ?",
                               (incident_id, incident_id, limit)).fetchall()
        return [ProposalState.model_validate_json(row[0]) for row in rows]

    def save_operation(self, operation: dict) -> None:
        with closing(self._connect()) as con, con:
            con.execute("INSERT INTO workflow_operations VALUES (?,?) ON CONFLICT(operation_id) "
                        "DO UPDATE SET payload=excluded.payload",
                        (operation["operation_id"], json.dumps(operation, ensure_ascii=False)))

    def list_operations(self, *, limit: int = 20) -> list[dict]:
        with closing(self._connect()) as con:
            rows = con.execute("SELECT payload FROM workflow_operations ORDER BY rowid DESC LIMIT ?", (limit,)).fetchall()
        return [json.loads(row[0]) for row in rows]

    def get(self, proposal_id: str) -> ProposalState | None:
        with closing(self._connect()) as con:
            row = con.execute("SELECT payload FROM response_states WHERE proposal_id=?", (proposal_id,)).fetchone()
        return ProposalState.model_validate_json(row[0]) if row else None

    def insert_if_absent(self, state: ProposalState) -> ProposalState:
        state.proposal.verify_identity()
        if state.version != 0 or state.status != "pending" or state.approval is not None or state.result is not None:
            raise ValueError("Solo se insertan propuestas nuevas pendientes, sin aprobaciones/resultados")
        with closing(self._connect()) as con, con:
            con.execute("BEGIN IMMEDIATE")
            con.execute("INSERT OR IGNORE INTO response_states VALUES (?, ?, ?, ?)",
                        (state.proposal.proposal_id, state.version, state.status, state.model_dump_json()))
            row = con.execute("SELECT payload FROM response_states WHERE proposal_id=?",
                              (state.proposal.proposal_id,)).fetchone()
            stored = ProposalState.model_validate_json(row[0])
            if stored.proposal != state.proposal:
                raise ValueError("Propuesta ya registrada con contenido diferente")
            return stored

    def save(self, state: ProposalState, *, expected_version: int) -> None:
        with closing(self._connect()) as con, con:
            con.execute("BEGIN IMMEDIATE")
            row = con.execute("SELECT payload FROM response_states WHERE proposal_id=?",
                              (state.proposal.proposal_id,)).fetchone()
            if row is None:
                raise LookupError("Propuesta no encontrada al persistir")
            previous = ProposalState.model_validate_json(row[0])
            if (previous.version != expected_version or state.version != expected_version + 1
                    or previous.proposal != state.proposal):
                raise RuntimeError("Conflicto de versión o modificación de una propuesta registrada")
            transitions = {"pending": {"pending", "approved", "rejected"},
                           "approved": {"pending", "approved", "rejected"}, "executing": {"failed", "succeeded"},
                           "rejected": {"rejected"}, "failed": {"failed"}, "succeeded": {"succeeded"}}
            if state.status not in transitions[previous.status]:
                raise PermissionError("Transición de estado no permitida; requiere conciliación manual")
            if previous.status == "approved" and state.status == "pending" and (
                    state.approval is None or state.approval.status != "pending"
                    or state.approval.decision_ids or previous.approval is None
                    or previous.approval.approval_id == state.approval.approval_id
                    or not state.history or state.history[-1].get("event") != "approval_restarted"):
                raise PermissionError("Renovar requiere una nueva solicitud sin votos ni autorizaciones heredadas")
            con.execute("UPDATE response_states SET version=?,status=?,payload=? WHERE proposal_id=?",
                        (state.version, state.status, state.model_dump_json(), state.proposal.proposal_id))

    def claim(self, proposal_id: str, *, expected_version: int, token_digest: str,
              event: dict[str, Any]) -> ProposalState:
        with closing(self._connect()) as con, con:
            con.execute("BEGIN IMMEDIATE")
            row = con.execute("SELECT payload FROM response_states WHERE proposal_id=?", (proposal_id,)).fetchone()
            if row is None:
                raise LookupError("Propuesta no encontrada al reservar ejecución")
            state = ProposalState.model_validate_json(row[0])
            if state.status != "approved" or state.version != expected_version:
                raise RuntimeError("La propuesta no está aprobada o ya ha sido reservada por otro proceso")
            if con.execute("SELECT 1 FROM response_token_claims WHERE token_digest=? OR proposal_id=?",
                           (token_digest, proposal_id)).fetchone():
                raise PermissionError("Token o propuesta ya reservados; no se permite otra ejecución")
            con.execute("INSERT INTO response_token_claims VALUES (?, ?)", (token_digest, proposal_id))
            claimed = state.model_copy(update={"status": "executing", "version": state.version + 1,
                                               "history": [*state.history, event]})
            con.execute("UPDATE response_states SET version=?,status=?,payload=? WHERE proposal_id=?",
                        (claimed.version, claimed.status, claimed.model_dump_json(), proposal_id))
            return claimed


class _ExecutorApprovalBridge:
    """Adaptador de firma para Persona 3; delega siempre al servicio de Persona 2."""
    def __init__(self, validator: Callable[[ContainmentProposal, ExecutionAuthorization], bool]) -> None:
        self.validator = validator

    def validate_approval(self, proposal: ContainmentProposal, approval: ExecutionAuthorization) -> bool:
        return self.validator(proposal, approval)


def _clean_result(value: Any, token: str) -> Any:
    if isinstance(value, dict):
        return {key: _clean_result(item, token) for key, item in value.items()
                if key.casefold() not in {"token", "approval_token", "authorization", "api_key", "secret"}}
    if isinstance(value, list):
        return [_clean_result(item, token) for item in value]
    if isinstance(value, str) and token:
        return value.replace(token, "[REDACTED]")
    return value


def _check_local_soc_url(base_url: str) -> None:
    url = urlsplit(base_url)
    if (url.scheme != "http" or url.hostname not in {"localhost", "127.0.0.1", "::1"}
            or url.username or url.password or url.path not in {"", "/"} or url.query or url.fragment):
        raise PermissionError("N4 solo permite la API SOC simulada por HTTP en loopback")


class SOCTokenBridge:
    """Traduce tokens SOC a los tokens del TokenService real, sin sustituir su validación.

    Solo emite dentro de approve() de Persona 2 después de una decisión explícita
    verificada. No se llama /approvals durante prepare(). El mapa, como el
    TokenService original, vive en memoria: tras reinicio falla cerrado.
    """
    def __init__(self, crypto: Any, repository: Any, api_client: Any) -> None:
        _check_local_soc_url(api_client.base_url)
        if api_client.session.trust_env or api_client.session.max_redirects != 0:
            raise PermissionError("La sesión SOC requiere trust_env=False y max_redirects=0")
        self.crypto, self.repository, self.api_client = crypto, repository, api_client
        self.default_ttl_seconds = crypto.default_ttl_seconds
        self._context = ContextVar("n4_explicit_decision", default=None)
        self._tokens: dict[str, tuple[str, datetime]] = {}
        self._lock = threading.RLock()

    def for_decision(self, decision: HumanDecision, proposal_id: str, operation: Callable) -> Any:
        context = self._context.set((decision.actor, decision.reason, proposal_id))
        try:
            return operation()
        finally:
            self._context.reset(context)

    def generate_token(self, approval_id: str, proposal_id: str, proposal_hash: str,
                       ttl_seconds: int | None = None) -> str:
        context = self._context.get()
        if context is None or context[2] != proposal_id:
            raise PermissionError("No hay una decisión explícita verificada para emitir el token")
        # El cliente/sesión son mutables: comprobar también al emitir, no solo
        # en el constructor, antes de registrar una autorización en la API.
        _check_local_soc_url(self.api_client.base_url)
        if self.api_client.session.trust_env or self.api_client.session.max_redirects != 0:
            raise PermissionError("La sesión SOC requiere trust_env=False y max_redirects=0")
        approval = self.repository.get(approval_id)
        if approval is None or approval.proposal_id != proposal_id or approval.proposal_hash != proposal_hash:
            raise PermissionError("La solicitud persistida no corresponde al token solicitado")
        ttl = ttl_seconds if ttl_seconds is not None else self.default_ttl_seconds
        if ttl <= 0:
            raise ValueError("La vigencia del token debe ser positiva")
        # Límite conservador, anterior al instante de emisión del TokenService.
        expires = datetime.now(timezone.utc) + timedelta(seconds=ttl)
        internal = self.crypto.generate_token(approval_id, proposal_id, proposal_hash, ttl_seconds=ttl)
        try:
            response = self.api_client.session.post(self.api_client.base_url + "/approvals", json={
                "action": approval.action, "target": approval.target, "approver": context[0], "reason": context[1],
            }, timeout=self.api_client.timeout, allow_redirects=False)
            if response.status_code != 200:
                raise RuntimeError(f"La API SOC rechazó registrar la autorización: HTTP {response.status_code}")
            data = response.json()
            token = data.get("approval_token", "")
            if (not isinstance(token, str) or not token.startswith("APR-")
                    or data.get("action") != approval.action or data.get("target") != approval.target
                    or data.get("approver") != context[0]):
                raise ValueError("La API SOC devolvió una autorización de otro alcance o malformada")
        except Exception:
            self.crypto.revoke_token(internal)
            raise
        with self._lock:
            self._tokens[token] = (internal, expires)
        return token

    def expiry(self, token: str) -> datetime:
        with self._lock:
            if token not in self._tokens:
                raise PermissionError("Token desconocido: la sesión de tokens no se conserva tras reinicio")
            return self._tokens[token][1]

    def validate_token(self, token: str, approval_id: str, proposal_id: str, proposal_hash: str) -> bool:
        with self._lock:
            entry = self._tokens.get(token)
            return bool(entry and entry[1] > datetime.now(timezone.utc) and self.crypto.validate_token(
                entry[0], approval_id, proposal_id, proposal_hash))

    def consume_token(self, token: str) -> bool:
        with self._lock:
            entry = self._tokens.get(token)
            return bool(entry and self.crypto.consume_token(entry[0]))

    def revoke_token(self, token: str) -> bool:
        with self._lock:
            entry = self._tokens.get(token)
            return bool(entry and self.crypto.revoke_token(entry[0]))


def _covered_roles(roles: list[str]) -> set[str]:
    covered = set()
    for role in roles:
        if role.upper() in {"N2", "SOC_LEAD", "CISO"}:
            covered.update(("N1", "N2"))
        elif role.upper() == "N1":
            covered.add("N1")
        elif role.casefold() in {"business", "business_owner"}:
            covered.add("business_owner")
        elif role.casefold() == "service_owner":
            covered.add("service_owner")
    return covered


class _ProposalPolicyBridge:
    """Añade requisitos de CMDB/N4 a la política real; nunca elimina los suyos."""
    def __init__(self, policy: Any) -> None:
        self.policy = policy
        self._required: dict[tuple[str, str], set[str]] = {}

    def __getattr__(self, name: str) -> Any:
        return getattr(self.policy, name)

    def register(self, proposal: ContainmentProposal) -> None:
        proposal.verify_identity()
        roles = {"business" if role == "business_owner" else role for role in proposal.required_approvals}
        self._required.setdefault((proposal.action, proposal.target.casefold()), set()).update(roles)

    def get_required_approvers(self, action: str, target: str) -> list[str]:
        return sorted(set(self.policy.get_required_approvers(action, target))
                      | self._required.get((action.strip().lower(), target.casefold()), set()))


class NativeApprovalAdapter:
    """Adapta las firmas reales de Persona 2, con identidad verificada externamente.

    verify_actor(decision, proposal) comprueba la sesión autenticada y su ámbito
    sobre el objetivo (especialmente propietarios de negocio/servicio), sin fiarse
    del nombre declarado. Las pruebas inyectan un verificador de ensayo explícito.
    Los roles salen solo del registro configurado: nunca del cliente ni de los
    heurísticos por subcadena de ApprovalPolicy.resolve_role().
    """
    def __init__(self, service: Any, store: ResponseStore,
                 verify_actor: Callable[[HumanDecision, ContainmentProposal], bool], requester_id: str = "soc_n4_planner",
                 identity_mode: Literal["authenticated", "demo_simulated"] = "authenticated") -> None:
        if not callable(verify_actor):
            raise TypeError("Se requiere un verificador de identidad de la sesión humana")
        self.service, self.store = service, store
        self.verify_actor, self.requester_id = verify_actor, requester_id
        self.identity_mode = identity_mode
        self._lock = threading.RLock()

    def _binding(self, proposal: ContainmentProposal, approval: Any) -> None:
        proposal.verify_identity()
        if approval is None:
            raise PermissionError("No existe la solicitud de aprobación persistida")
        if (approval.proposal_id, approval.ticket_id, approval.action, approval.target, approval.proposal_hash) != (
            proposal.proposal_id, proposal.incident_id, proposal.action, proposal.target, proposal.content_hash
        ):
            raise PermissionError("La autorización persistida no corresponde al incidente/acción/objetivo/contenido")

    def _roles(self, approval: Any) -> set[str]:
        roles = []
        for vote in approval.approvals_received:
            trusted = self.service.policy.user_roles.get(vote.get("reviewer_id", "").casefold())
            if trusted is None or trusted.casefold() != vote.get("reviewer_role", "").casefold():
                raise PermissionError("Un voto no coincide con el registro vigente de roles")
            roles.append(trusted)
        return _covered_roles(roles)

    @staticmethod
    def _check_recorded_votes(approval: Any, state: ProposalState | None) -> None:
        events = state.history if state is not None else []
        for vote in approval.approvals_received:
            if not any(event.get("event") == "human_decision" and event.get("approved") is True
                       and event.get("actor", "").casefold() == vote.get("reviewer_id", "").casefold()
                       and event.get("reason") == vote.get("reason") for event in events):
                raise PermissionError("Hay votos sin su decisión N4 auditada; requieren conciliación")

    def _record(self, proposal: ContainmentProposal, approval: Any, ids: list[str], verified: bool) -> ApprovalRecord:
        self._binding(proposal, approval)
        roles = self._roles(approval)
        required = set(proposal.required_approvals) | _covered_roles(approval.required_approvers)
        if approval.status == "approved" and not required <= roles:
            raise PermissionError("Persona 2 no ha obtenido todos los aprobadores exigidos por N4")
        return ApprovalRecord(
            approval_id=approval.approval_id, proposal_id=proposal.proposal_id, incident_id=proposal.incident_id,
            action=proposal.action, target=proposal.target,
            status="rejected" if approval.status in {"rejected", "revoked", "expired"} else approval.status,
            human_verified=verified, decision_ids=ids, approved_roles=sorted(roles),
            identity_mode=self.identity_mode,
            expires_at=self.service.token_service.expiry(approval.approval_token) if approval.status == "approved" else None,
        )

    def request(self, proposal: ContainmentProposal) -> ApprovalRecord:
        with self._lock:
            if isinstance(self.service.policy, _ProposalPolicyBridge):
                self.service.policy.register(proposal)
            existing = self.service.get_approvals_for_proposal(proposal.proposal_id)
            if any(item.status != "pending" for item in existing):
                raise PermissionError("Hay decisiones externas sin historial N4 asociado; requieren conciliación")
            approval = self.service.request_approval(proposal, requester_id=self.requester_id)
            self._binding(proposal, approval)
            if approval.approvals_received:
                raise PermissionError("No se adoptan votos externos sin sus eventos humanos N4")
            return self._record(proposal, approval, [], False)

    def record_decision(self, proposal: ContainmentProposal, decision: HumanDecision) -> ApprovalRecord:
        with self._lock:
            if not proposal.executable or proposal.action is None:
                raise PermissionError("Esta propuesta solo permite revisión/escalado manual, no aprobación ejecutable")
            if self.verify_actor(decision, proposal) is not True:
                raise PermissionError("La identidad humana no ha sido verificada")
            role = self.service.policy.user_roles.get(decision.actor.casefold())
            if role is None:
                raise PermissionError("El revisor no figura en el registro autorizado; no se infiere su rol del nombre")
            state = self.store.get(proposal.proposal_id)
            receipt = state.approval if state else None
            if receipt is None:
                receipt = self.request(proposal)
            approval = self.service.get_approval(receipt.approval_id)
            self._binding(proposal, approval)
            self._check_recorded_votes(approval, state)
            ids = list(receipt.decision_ids)
            if decision.decision_id not in ids:
                ids.append(decision.decision_id)
            if decision.approved:
                required = _covered_roles(approval.required_approvers)
                if not set(proposal.required_approvals) <= required:
                    raise PermissionError("ApprovalPolicy omite aprobadores de CMDB/N4; debe corregirse en Persona 2")
                if role.casefold() == "ciso" and required - {"N1", "N2"}:
                    raise PermissionError("El atajo CISO de Persona 2 no sustituye la aprobación de negocio/servicio")
                if not isinstance(self.service.token_service, SOCTokenBridge):
                    raise RuntimeError("Inyectar SOCTokenBridge para emitir tokens que reconozca la API SOC")
                approval = self.service.token_service.for_decision(decision, proposal.proposal_id, lambda:
                    self.service.approve(approval.approval_id, decision.actor, decision.reason, reviewer_role=role))
            elif approval.status == "approved":
                if not self.service.policy.is_reviewer_authorized(decision.actor, role, proposal.action,
                                                                  proposal.target, approval.required_approvers):
                    raise PermissionError("El revisor no está autorizado para revocar")
                approval = self.service.revoke(approval.approval_id, decision.actor, decision.reason)
            else:
                approval = self.service.reject(approval.approval_id, decision.actor, decision.reason, reviewer_role=role)
            return self._record(proposal, approval, ids, True)

    def validate(self, proposal: ContainmentProposal, approval_id: str) -> ExecutionAuthorization:
        approval = self.service.get_approval(approval_id)
        if approval is None or approval.status != "approved":
            raise PermissionError("La solicitud no está aprobada o ha sido revocada")
        self._binding(proposal, approval)
        if not self.service.validate_approval(proposal, approval):
            raise PermissionError("ApprovalService ha rechazado la autorización o su token")
        state = self.store.get(proposal.proposal_id)
        if state is None or state.approval is None or state.approval.approval_id != approval_id:
            raise PermissionError("No existe un recibo N4 de las decisiones humanas de esta aprobación")
        self._check_recorded_votes(approval, state)
        receipt = self._record(proposal, approval, state.approval.decision_ids, True)
        return ExecutionAuthorization(**receipt.model_dump(), token=SecretStr(approval.approval_token),
                                      content_digest=approval.proposal_hash)

    def restart(self, proposal: ContainmentProposal, decision: HumanDecision) -> ApprovalRecord:
        """Descartar una autorización caducada o de una sesión anterior; volver a votar."""
        with self._lock:
            if self.verify_actor(decision, proposal) is not True:
                raise PermissionError("La identidad del revisor no ha sido verificada")
            state = self.store.get(proposal.proposal_id)
            if state is None or state.status not in {"pending", "approved"} or state.approval is None:
                raise PermissionError("No se pueden reabrir propuestas rechazadas, reservadas o ejecutadas")
            approval = self.service.get_approval(state.approval.approval_id)
            self._binding(proposal, approval)
            role = self.service.policy.user_roles.get(decision.actor.casefold())
            if role is None or not self.service.policy.is_reviewer_authorized(
                    decision.actor, role, proposal.action, proposal.target, approval.required_approvers):
                raise PermissionError("El rol no permite renovar esta solicitud")
            self.service.revoke(approval.approval_id, decision.actor, decision.reason)
            self.service.policy.register(proposal)
            fresh = self.service.request_approval(proposal, requester_id=self.requester_id)
            return self._record(proposal, fresh, [], False)

    def consume(self, authorization: ExecutionAuthorization) -> None:
        if not self.service.token_service.consume_token(authorization.approval_token):
            raise RuntimeError("La acción se ejecutó, pero no se pudo consumir su token; conciliar manualmente")


class Level4Orchestrator:
    @classmethod
    def with_soc_services(cls, *, planner: Planner, store: SQLiteResponseStore, approval_service: Any,
                          api_client: Any, verify_actor: Callable[[HumanDecision, ContainmentProposal], bool],
                          requester_id: str = "soc_n4_planner",
                          identity_mode: Literal["authenticated", "demo_simulated"] = "authenticated") -> Level4Orchestrator:
        """Cablear los servicios existentes, sin reemplazar validaciones ni ejecutar N3."""
        from src.triage.level4.containment_executor import ContainmentExecutor as SOCExecutor
        if not isinstance(approval_service.token_service, SOCTokenBridge):
            approval_service.token_service = SOCTokenBridge(approval_service.token_service,
                                                           approval_service.repository, api_client)
        elif approval_service.token_service.api_client.base_url != api_client.base_url:
            raise ValueError("No se pueden trasladar autorizaciones a otra API SOC")
        if not isinstance(approval_service.policy, _ProposalPolicyBridge):
            approval_service.policy = _ProposalPolicyBridge(approval_service.policy)
        adapter = NativeApprovalAdapter(approval_service, store, verify_actor, requester_id, identity_mode)
        return cls(report_loader=store.load_report, planner=planner, approvals=adapter,
                   executor=SOCExecutor(api_client), store=store)

    def __init__(self, *, report_loader: Callable[[str], IncidentReport | dict | None],
                 planner: Planner, approvals: ApprovalService | None = None, executor: ContainmentExecutor | None = None,
                 store: ResponseStore, clock: Callable[[], datetime] | None = None) -> None:
        if not callable(report_loader):
            raise TypeError("Se requiere report_loader(incident_id), sin ejecutar N3")
        dependencies = [(planner, ("plan",)), (store, ("get", "insert_if_absent", "save", "claim"))]
        if approvals is not None:
            dependencies.append((approvals, ("record_decision", "validate")))
        if executor is not None:
            dependencies.append((executor, ("execute",)))
        for component, methods in dependencies:
            if any(not callable(getattr(component, method, None)) for method in methods):
                raise TypeError(f"Dependencia obligatoria incompatible: {methods}")
        self.report_loader, self.planner = report_loader, planner
        self.approvals, self.executor, self.store = approvals, executor, store
        self.clock = clock if clock is not None else lambda: datetime.now(timezone.utc)
        from src.triage.level4.containment_executor import ContainmentExecutor as SOCExecutor
        if isinstance(executor, SOCExecutor):
            if executor.approval_service is None or executor.approval_service is approvals:
                executor.approval_service = _ExecutorApprovalBridge(self._revalidate_executor_approval)
            elif not callable(getattr(executor.approval_service, "validate_approval", None)):
                raise TypeError("El validador del ejecutor debe ofrecer validate_approval(proposal, approval)")

    def _revalidate_executor_approval(self, proposal: ContainmentProposal,
                                    authorization: ExecutionAuthorization) -> bool:
        """Persona 3 vuelve a consultar a Persona 2; no se sustituye por True fijo."""
        checked = _model(ExecutionAuthorization, self.approvals.validate(proposal, authorization.approval_id))
        self._check_approval(proposal, checked)
        return (checked.approval_id == authorization.approval_id
                and checked.expires_at == authorization.expires_at
                and set(checked.decision_ids) == set(authorization.decision_ids)
                and set(checked.approved_roles) == set(authorization.approved_roles)
                and checked.token.get_secret_value() == authorization.token.get_secret_value()
                and (checked.content_digest is None or checked.content_digest == authorization.content_digest)
                and (not checked.approved_by or set(checked.approved_by) == set(authorization.approved_by)))

    @staticmethod
    def _check_soc_destination(executor: Any) -> None:
        """Limitar el cliente real a loopback y rechazar redirecciones/proxies."""
        _check_local_soc_url(executor.api_client.base_url)
        session = executor.api_client.session
        if session.trust_env or session.max_redirects != 0:
            raise PermissionError("Configurar la sesión SOC con trust_env=False y max_redirects=0")

    def _execute(self, proposal: ContainmentProposal, authorization: ExecutionAuthorization) -> ActionResult:
        from src.triage.level4.containment_executor import ContainmentExecutor as SOCExecutor, ActionResult as SOCResult
        if isinstance(self.executor, SOCExecutor):
            self._check_soc_destination(self.executor)
        value = self.executor.execute(proposal.model_copy(deep=True), authorization)
        if not isinstance(value, SOCResult):
            return _model(ActionResult, value)
        if value.ticket_id != proposal.incident_id:
            raise ValueError("El ejecutor no ha asociado el resultado al incidente N3 solicitado")
        details = _clean_result(value.model_dump(mode="json", exclude_none=True), authorization.approval_token)
        return ActionResult(proposal_id=value.proposal_id, incident_id=value.ticket_id,
                            action=value.action, target=value.target, success=value.success, details=details)

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

    def _blocked(self, state: ProposalState, reason: str) -> None:
        error = PermissionError(reason)
        try:
            self._save(state, self._event("execution_blocked", reason=reason), last_error=reason)
        except Exception as storage_error:
            error.add_note(f"No se pudo auditar el bloqueo: {type(storage_error).__name__}")
        raise error

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
            if isinstance(self.approvals, NativeApprovalAdapter) and proposal.executable and state.approval is None:
                receipt = self.approvals.request(proposal)
                state = self._save(state, self._event("approval_requested"), approval=receipt)
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
        if self.approvals is None:
            raise RuntimeError("ApprovalService no está implementado/configurado; no se registran aprobaciones ficticias")
        state = self.get_state(proposal_id)
        if state.status not in {"pending", "approved"}:
            raise PermissionError(f"No se puede registrar una decisión en estado {state.status}")
        decision = _model(HumanDecision, decision)
        if not all(value.strip() for value in (decision.actor, decision.decision_id, decision.reason)):
            raise ValueError("La decisión requiere identificador, actor y motivo explícitos")
        for event in state.history:
            if event.get("event") == "human_decision" and event.get("decision_id") == decision.decision_id:
                if (event.get("actor"), event.get("approved"), event.get("reason")) != (
                    decision.actor, decision.approved, decision.reason
                ):
                    raise ValueError("decision_id ya utilizado con otro contenido")
                return state
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
            self._blocked(state, f"La propuesta está {state.status}; no se permite ejecutarla")
        proposal = state.proposal
        if not proposal.executable or proposal.action is None:
            self._blocked(state, "Propuesta de revisión manual: no es ejecutable")
        if self.approvals is None or self.executor is None:
            raise RuntimeError("Se requieren ApprovalService y ContainmentExecutor reales para ejecutar N4")
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
            if authorization.content_digest is not None and authorization.content_digest != proposal.content_hash:
                raise PermissionError("La autorización no corresponde al contenido aprobado")
            actors = {entry["decision_id"]: entry["actor"] for entry in state.history
                      if entry.get("event") == "human_decision" and entry.get("approved") is True}
            if not set(authorization.decision_ids) <= actors.keys():
                raise PermissionError("Faltan las intervenciones humanas explícitas de esta autorización")
            approved_by = sorted({actors[key] for key in authorization.decision_ids})
            if authorization.approved_by and set(authorization.approved_by) != set(approved_by):
                raise PermissionError("Los aprobadores no corresponden a las decisiones registradas")
            authorization = authorization.model_copy(update={"approved_by": approved_by,
                                                               "content_digest": proposal.content_hash})
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
            result = self._execute(proposal, authorization)
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
        if isinstance(self.approvals, NativeApprovalAdapter):
            try:
                self.approvals.consume(authorization)
            except Exception as exc:
                self._failure(state, "token_consumption", exc, status="failed", result=result)
                raise
        self._save(state, self._event("execution_succeeded"), status="succeeded", result=result, last_error=None)
        return result.model_copy(deep=True)

    def restart_approval(self, proposal_id: str, decision: HumanDecision) -> ProposalState:
        state = self.get_state(proposal_id)
        if not isinstance(self.approvals, NativeApprovalAdapter):
            raise RuntimeError("La renovación requiere los servicios SOC de aprobación")
        if not decision.actor.strip() or not decision.reason.strip():
            raise ValueError("La renovación requiere revisor y motivo explícitos")
        receipt = self.approvals.restart(state.proposal, decision)
        return self._save(state, self._event("approval_restarted", actor=decision.actor, reason=decision.reason),
                          approval=receipt, status="pending", last_error=None)


def _main() -> None:
    """Preparar o demostrar una decisión de ensayo explícita con los servicios reales."""
    import argparse
    from src.data.reference_repository import ReferenceRepository
    from src.data.soc_api_client import SOCAPIClient
    from src.triage.level4.response_planner import ResponsePlanner

    root = Path(__file__).resolve().parents[3]
    parser = argparse.ArgumentParser(description="Preparación N4; contención de ensayo solo con --demo-decision y una propuesta exacta")
    parser.add_argument("--report", required=True, type=Path, help="JSON N3 exportado con to_dict()/exclude_none=True")
    parser.add_argument("--db-path", required=True, type=Path, help="SQLite de estados, auditoría e informes N4")
    parser.add_argument("--api-url", default="http://127.0.0.1:8000")
    parser.add_argument("--dataset-root", type=Path, default=root / "RepositoriDeloitte")
    parser.add_argument("--demo-decision", choices=("approve", "reject"),
                        help="ENSAYO: identidad simulada; registra esta decisión explícita y ejecuta solo si queda aprobada")
    parser.add_argument("--proposal-id", help="Propuesta exacta sobre la que decidir en el ensayo")
    parser.add_argument("--demo-reviewer", default="analyst_n2", help="Identidad de ensayo del registro configurado de Tarvia")
    args = parser.parse_args()
    if args.demo_decision and not args.proposal_id:
        parser.error("--demo-decision requiere --proposal-id; nunca se aprueban propuestas en bloque")
    _check_local_soc_url(args.api_url)
    report = validate_report(json.loads(args.report.read_text(encoding="utf-8-sig")))
    store = SQLiteResponseStore(args.db_path)
    store.store_report(report)
    api = SOCAPIClient(args.api_url)
    api.session.trust_env = False
    api.session.max_redirects = 0
    containment_client = None
    try:
        planner = ResponsePlanner(api=api, references=ReferenceRepository(args.dataset_root))
        if args.demo_decision:
            from src.triage.level4.approval_repository import ApprovalRepository
            from src.triage.level4.approval_service import ApprovalService as RealApprovalService
            from src.triage.level4.containment_api_client import ContainmentAPIClient
            import requests
            session = requests.Session()
            session.trust_env = False
            session.max_redirects = 0
            containment_client = ContainmentAPIClient(args.api_url, session=session)
            approvals = RealApprovalService(repository=ApprovalRepository(args.db_path))
            service = Level4Orchestrator.with_soc_services(
                planner=planner, store=store, approval_service=approvals, api_client=containment_client,
                verify_actor=lambda decision, proposal: decision.actor == args.demo_reviewer,
            )
        else:
            service = Level4Orchestrator(report_loader=store.load_report, planner=planner, store=store)
        proposals = service.prepare(report.incident_id)
        if args.demo_decision:
            if args.proposal_id not in {proposal.proposal_id for proposal in proposals}:
                raise ValueError("La propuesta seleccionada no pertenece al informe actual")
            state = service.get_state(args.proposal_id)
            if state.status != "succeeded" or args.demo_decision == "reject":
                decision_id = "DEMO-" + sha256((args.proposal_id + args.demo_reviewer + args.demo_decision).encode()).hexdigest()[:24]
                state = service.record_decision(args.proposal_id, HumanDecision(
                    decision_id=decision_id, actor=args.demo_reviewer, approved=args.demo_decision == "approve",
                    reason="ENSAYO EXPLÍCITO: identidad simulada, no autenticación humana real",
                ))
                if args.demo_decision == "approve" and state.status == "approved":
                    service.execute_approved(args.proposal_id)
        print(json.dumps({"incident_id": report.incident_id,
                          "mode": "DEMO_SIMULATED_IDENTITY" if args.demo_decision else "prepare_only",
                          "states": [service.get_state(p.proposal_id).model_dump(mode="json") for p in proposals]},
                         ensure_ascii=False, indent=2))
    finally:
        api.close()
        if containment_client is not None:
            containment_client.close()


if __name__ == "__main__":
    _main()
