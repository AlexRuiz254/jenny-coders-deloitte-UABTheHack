"""Modelos de datos para el sistema de aprobaciones humanas (Fase 4 - N4).

Define el modelo ApprovalResult, los estados permitidos de decisión y
el contrato de ContainmentProposal para la integración entre niveles.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
from typing import Any, Literal, Optional

from pydantic import BaseModel, Field, field_validator

ApprovalStatus = Literal["pending", "approved", "rejected", "expired", "revoked"]

ALLOWED_STATUSES: frozenset[str] = frozenset({
    "pending",
    "approved",
    "rejected",
    "expired",
    "revoked",
})


class ContainmentProposal(BaseModel):
    """Propuesta de contención recibida de Persona 1."""
    proposal_id: str
    action: str
    target: str
    ticket_id: Optional[str] = None
    justification: str = ""
    evidence: list[Any] = Field(default_factory=list)
    required_approvers: list[str] = Field(default_factory=list)
    requester_id: Optional[str] = None
    requires_approval: Optional[bool] = None
    content_hash: Optional[str] = None

    model_config = {"extra": "allow"}

    def calculate_hash(self) -> str:
        """Calcular un resumen criptográfico determinista del contenido de la propuesta."""
        raw = f"{self.proposal_id}:{self.action.strip().lower()}:{self.target.strip().lower()}:{self.justification.strip()}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


class ApprovalDecisionRecord(BaseModel):
    """Registro individual de voto/aprobación de un revisor."""
    reviewer_id: str
    reviewer_role: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    reason: Optional[str] = None


class ApprovalResult(BaseModel):
    """Resultado estructurado de una solicitud de aprobación humana.

    Cumple estrictamente los campos requeridos por Persona 2, Persona 3 y Persona 4.
    """
    approval_id: str
    proposal_id: str
    status: ApprovalStatus = "pending"
    reviewer_id: str = ""
    decision_timestamp: Optional[datetime] = None
    reason: Optional[str] = None
    approval_token: Optional[str] = None
    proposal_hash: str
    # Campos complementarios para interoperabilidad y trazabilidad
    action: str = ""
    target: str = ""
    approver: str = ""
    requester_id: Optional[str] = None
    ticket_id: Optional[str] = None
    required_approvers: list[str] = Field(default_factory=list)
    approvals_received: list[dict[str, Any]] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: Optional[datetime] = None

    model_config = {"extra": "allow"}

    @field_validator("status")
    def validate_status(cls, value: str) -> str:
        if value not in ALLOWED_STATUSES:
            raise ValueError(
                f"Estado '{value}' no permitido. Los estados válidos son: {sorted(ALLOWED_STATUSES)}"
            )
        return value

    def model_post_init(self, __context: Any) -> None:
        """Sincronizar campos auxiliares para compatibilidad cruzada con Persona 3."""
        if not self.approver and self.reviewer_id:
            self.approver = self.reviewer_id
        elif not self.reviewer_id and self.approver:
            self.reviewer_id = self.approver

        if self.decision_timestamp is None and self.status in {"approved", "rejected", "revoked"}:
            self.decision_timestamp = datetime.now(timezone.utc)

    def to_dict(self) -> dict[str, Any]:
        """Serializar el modelo a diccionario compatible con JSON."""
        return self.model_dump(mode="json", exclude_none=True)
