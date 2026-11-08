"""Repositorio SQLite para persistencia y recuperación de aprobaciones (Fase 4 - N4).

Garantiza atomicidad, integridad transaccional, protección contra duplicados
y soporte para consultas por propuesta y estado.
"""
from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime
import json
import logging
from pathlib import Path
import sqlite3
import threading
from typing import Any, Iterator, Optional

from src.triage.level4.approval_models import ApprovalResult

logger = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).resolve().parents[3]


class ApprovalRepository:
    """Repositorio de persistencia SQLite para aprobaciones de contención."""

    def __init__(self, db_path: Optional[Path | str] = None) -> None:
        """Inicializar la conexión y crear las tablas requeridas."""
        self.is_memory = db_path == ":memory:"
        if db_path is None:
            self.db_path = PROJECT_ROOT / "approvals.sqlite3"
        elif self.is_memory:
            self.db_path = Path(":memory:")
        else:
            self.db_path = Path(db_path)
            if not self.db_path.is_absolute():
                self.db_path = PROJECT_ROOT / self.db_path

        if not self.is_memory:
            self.db_path.parent.mkdir(parents=True, exist_ok=True)

        self._lock = threading.RLock()
        self._shared_memory_conn: Optional[sqlite3.Connection] = None

        if self.is_memory:
            # Mantener una conexión activa para bases de datos en memoria
            self._shared_memory_conn = sqlite3.connect(":memory:", check_same_thread=False, timeout=30.0)
            self._shared_memory_conn.row_factory = sqlite3.Row

        self._init_db()

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        """Obtener conexión SQLite en un contexto transaccional seguro."""
        with self._lock:
            if self.is_memory and self._shared_memory_conn is not None:
                yield self._shared_memory_conn
            else:
                con = sqlite3.connect(str(self.db_path), timeout=30.0)
                con.row_factory = sqlite3.Row
                try:
                    with con:
                        yield con
                finally:
                    con.close()

    def _init_db(self) -> None:
        """Crear esquema de tabla e índices si no existen."""
        with self._connect() as con:
            con.execute("""
                CREATE TABLE IF NOT EXISTS approvals (
                    approval_id TEXT PRIMARY KEY,
                    proposal_id TEXT NOT NULL,
                    action TEXT NOT NULL,
                    target TEXT NOT NULL,
                    status TEXT NOT NULL,
                    reviewer_id TEXT NOT NULL,
                    decision_timestamp TEXT,
                    reason TEXT,
                    approval_token TEXT,
                    proposal_hash TEXT NOT NULL,
                    requester_id TEXT,
                    ticket_id TEXT,
                    required_approvers TEXT,
                    approvals_received TEXT,
                    created_at TEXT NOT NULL,
                    expires_at TEXT,
                    details TEXT
                )
            """)
            con.execute("CREATE INDEX IF NOT EXISTS idx_approvals_prop ON approvals(proposal_id)")
            con.execute("CREATE INDEX IF NOT EXISTS idx_approvals_stat ON approvals(status)")

    def save(self, approval: ApprovalResult | dict[str, Any]) -> ApprovalResult:
        """Insertar una nueva aprobación en la base de datos.

        Lanza ValueError si ya existe una aprobación con el mismo approval_id.
        """
        app_obj = self._to_model(approval)

        with self._connect() as con:
            cur = con.execute("SELECT 1 FROM approvals WHERE approval_id = ?", (app_obj.approval_id,))
            if cur.fetchone() is not None:
                raise ValueError(
                    f"Aprobación duplicada: ya existe una aprobación con ID '{app_obj.approval_id}'"
                )

            sql = """
                INSERT INTO approvals (
                    approval_id, proposal_id, action, target, status,
                    reviewer_id, decision_timestamp, reason, approval_token,
                    proposal_hash, requester_id, ticket_id, required_approvers,
                    approvals_received, created_at, expires_at, details
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """
            params = (
                app_obj.approval_id,
                app_obj.proposal_id,
                app_obj.action,
                app_obj.target,
                app_obj.status,
                app_obj.reviewer_id,
                app_obj.decision_timestamp.isoformat() if app_obj.decision_timestamp else None,
                app_obj.reason,
                app_obj.approval_token,
                app_obj.proposal_hash,
                app_obj.requester_id,
                app_obj.ticket_id,
                json.dumps(app_obj.required_approvers),
                json.dumps(app_obj.approvals_received),
                app_obj.created_at.isoformat(),
                app_obj.expires_at.isoformat() if app_obj.expires_at else None,
                json.dumps(app_obj.to_dict()),
            )
            con.execute(sql, params)

        return app_obj

    def get(self, approval_id: str) -> Optional[ApprovalResult]:
        """Recuperar una aprobación por su approval_id."""
        if not approval_id:
            return None

        with self._connect() as con:
            cur = con.execute("SELECT * FROM approvals WHERE approval_id = ?", (approval_id.strip(),))
            row = cur.fetchone()
            if not row:
                return None
            return self._row_to_model(row)

    def get_by_proposal(self, proposal_id: str) -> list[ApprovalResult]:
        """Obtener el historial de aprobaciones asociadas a una propuesta."""
        if not proposal_id:
            return []

        with self._connect() as con:
            cur = con.execute(
                "SELECT * FROM approvals WHERE proposal_id = ? ORDER BY created_at DESC",
                (proposal_id.strip(),)
            )
            return [self._row_to_model(row) for row in cur.fetchall()]

    def update(self, approval: ApprovalResult | dict[str, Any]) -> ApprovalResult:
        """Actualizar el estado y los campos de una aprobación existente."""
        app_obj = self._to_model(approval)

        with self._connect() as con:
            cur = con.execute("SELECT 1 FROM approvals WHERE approval_id = ?", (app_obj.approval_id,))
            if cur.fetchone() is None:
                raise KeyError(f"No existe ninguna aprobación registrada con ID '{app_obj.approval_id}'")

            sql = """
                UPDATE approvals SET
                    status = ?,
                    reviewer_id = ?,
                    decision_timestamp = ?,
                    reason = ?,
                    approval_token = ?,
                    proposal_hash = ?,
                    approvals_received = ?,
                    expires_at = ?,
                    details = ?
                WHERE approval_id = ?
            """
            params = (
                app_obj.status,
                app_obj.reviewer_id,
                app_obj.decision_timestamp.isoformat() if app_obj.decision_timestamp else None,
                app_obj.reason,
                app_obj.approval_token,
                app_obj.proposal_hash,
                json.dumps(app_obj.approvals_received),
                app_obj.expires_at.isoformat() if app_obj.expires_at else None,
                json.dumps(app_obj.to_dict()),
                app_obj.approval_id,
            )
            con.execute(sql, params)

        return app_obj

    def list_by_status(self, status: str) -> list[ApprovalResult]:
        """Listar aprobaciones filtradas por estado (e.g. pending, approved...)."""
        with self._connect() as con:
            cur = con.execute(
                "SELECT * FROM approvals WHERE status = ? ORDER BY created_at DESC",
                (status.strip().lower(),)
            )
            return [self._row_to_model(row) for row in cur.fetchall()]

    def list_all(self) -> list[ApprovalResult]:
        """Listar todas las aprobaciones ordenadas por fecha de creación descendente."""
        with self._connect() as con:
            cur = con.execute("SELECT * FROM approvals ORDER BY created_at DESC")
            return [self._row_to_model(row) for row in cur.fetchall()]

    def delete(self, approval_id: str) -> bool:
        """Eliminar una aprobación por ID (utilizado en tests de limpieza)."""
        if not approval_id:
            return False
        with self._connect() as con:
            cur = con.execute("DELETE FROM approvals WHERE approval_id = ?", (approval_id.strip(),))
            return cur.rowcount > 0

    def close(self) -> None:
        """Cerrar la conexión si se encuentra en modo memoria compartida."""
        with self._lock:
            if self._shared_memory_conn:
                self._shared_memory_conn.close()
                self._shared_memory_conn = None

    def _to_model(self, data: ApprovalResult | dict[str, Any]) -> ApprovalResult:
        if isinstance(data, ApprovalResult):
            return data
        return ApprovalResult.model_validate(data)

    def _row_to_model(self, row: sqlite3.Row) -> ApprovalResult:
        """Reconstruir un ApprovalResult a partir de una fila SQLite."""
        dec_ts = None
        if row["decision_timestamp"]:
            dec_ts = datetime.fromisoformat(row["decision_timestamp"])

        created_ts = datetime.fromisoformat(row["created_at"])
        exp_ts = None
        if row["expires_at"]:
            exp_ts = datetime.fromisoformat(row["expires_at"])

        req_approvers = json.loads(row["required_approvers"]) if row["required_approvers"] else []
        approvals_rec = json.loads(row["approvals_received"]) if row["approvals_received"] else []

        return ApprovalResult(
            approval_id=row["approval_id"],
            proposal_id=row["proposal_id"],
            action=row["action"],
            target=row["target"],
            status=row["status"],
            reviewer_id=row["reviewer_id"],
            decision_timestamp=dec_ts,
            reason=row["reason"],
            approval_token=row["approval_token"],
            proposal_hash=row["proposal_hash"],
            requester_id=row["requester_id"],
            ticket_id=row["ticket_id"],
            required_approvers=req_approvers,
            approvals_received=approvals_rec,
            created_at=created_ts,
            expires_at=exp_ts,
            approver=row["reviewer_id"],
        )
