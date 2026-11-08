"""Módulo de Nivel 4 (N4): Respuesta y contención de incidentes autorizadas."""
from __future__ import annotations

from src.triage.level4.containment_api_client import (
    ContainmentAPIClient,
    ContainmentAPIError,
    ContainmentConnectionError,
    ContainmentHTTPError,
    ContainmentResponseError,
    ContainmentTimeoutError,
)
from src.triage.level4.containment_executor import (
    ActionResult,
    ApprovalResult,
    ContainmentExecutor,
    ContainmentProposal,
)

__all__ = [
    "ActionResult",
    "ApprovalResult",
    "ContainmentAPIClient",
    "ContainmentAPIError",
    "ContainmentConnectionError",
    "ContainmentExecutor",
    "ContainmentHTTPError",
    "ContainmentProposal",
    "ContainmentResponseError",
    "ContainmentTimeoutError",
]
