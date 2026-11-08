"""Ejecutor de contención autorizada para Fase 4 (N4).

Controla la ejecución de acciones previamente aprobadas garantizando el
cumplimiento de la política SOC de Tarvia, validando autorizaciones, aplicando
idempotencia contra ejecuciones duplicadas y manteniendo trazabilidad de auditoría.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import logging
import threading
from typing import Any, Optional

from pydantic import BaseModel, Field

from src.triage.level4.containment_api_client import (
    ContainmentAPIClient,
    ContainmentAPIError,
    ContainmentConnectionError,
    ContainmentHTTPError,
    ContainmentResponseError,
    ContainmentTimeoutError,
)

logger = logging.getLogger(__name__)

# Acciones de contención soportadas por la API SOC (mock_soc_api.py / politica_soc.md)
VALID_CONTAINMENT_ACTIONS: frozenset[str] = frozenset({
    "isolate_host",
    "disable_user",
    "revoke_sessions",
    "reset_password",
    "block_ioc",
    "purge_email",
    "disable_access_key",
})

# Acciones que el N1 puede ejecutar directamente sin aprobación previa formal
NO_APPROVAL_ACTIONS: frozenset[str] = frozenset({
    "block_ioc",
    "purge_email",
})

# Servicios de uso dual que requieren aprobación según la política SOC de Tarvia
DUAL_USE_DOMAINS: tuple[str, ...] = (
    "mega.nz",
    "mega",
    "anydesk.com",
    "anydesk",
    "teamviewer.com",
    "teamviewer",
    "dropbox.com",
)


class ActionResult(BaseModel):
    """Resultado estandarizado de la ejecución de una acción de contención."""
    proposal_id: str
    action: str
    target: str
    status: str  # "executed", "failed", "blocked", "unknown"
    success: bool
    message: str
    executed_at: Optional[datetime] = None
    ticket_id: Optional[str] = None
    approver: Optional[str] = None
    approval_token: Optional[str] = None
    api_response: Optional[dict[str, Any]] = None
    error_details: Optional[str] = None

    model_config = {"extra": "allow"}

    def to_dict(self) -> dict[str, Any]:
        """Serializar a diccionario para Persona 4 y presentación en UI/JSON."""
        return self.model_dump(mode="json", exclude_none=True)


class ContainmentProposal(BaseModel):
    """Modelo de propuesta de contención generado por Persona 1."""
    proposal_id: str
    action: str
    target: str
    justification: str = ""
    ticket_id: Optional[str] = None
    requires_approval: Optional[bool] = None
    content_hash: Optional[str] = None

    model_config = {"extra": "allow"}

    def calculate_hash(self) -> str:
        """Calcular resumen hash del contenido de la propuesta."""
        raw = f"{self.proposal_id}:{self.action.lower()}:{self.target.lower()}:{self.justification}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


class ApprovalResult(BaseModel):
    """Modelo de autorización humana generado por Persona 2."""
    proposal_id: str
    action: str
    target: str
    approver: str
    status: str = "approved"  # "approved", "rejected", "pending", "expired"
    approval_token: Optional[str] = None
    approval_id: Optional[str] = None
    reason: Optional[str] = ""
    proposal_hash: Optional[str] = None
    timestamp: Optional[datetime] = None

    model_config = {"extra": "allow"}


def _get_val(obj: Any, name: str, default: Any = None) -> Any:
    """Extraer atributo o clave de objeto o diccionario de forma tolerante."""
    if obj is None:
        return default
    if isinstance(obj, dict):
        return obj.get(name, default)
    return getattr(obj, name, default)


class ContainmentExecutor:
    """Ejecutor de contenciones autorizadas del SOC."""

    def __init__(
        self,
        api_client: Any,
        approval_service: Any = None,
        store: Any = None,
    ) -> None:
        """Inicializar ejecutor con inyección de cliente HTTP, servicio de aprobación y almacén."""
        self.api_client = api_client
        self.approval_service = approval_service
        self.store = store
        self._history: dict[str, ActionResult] = {}
        self._lock = threading.RLock()

    def execute(
        self,
        proposal: Any,
        approval: Any = None,
    ) -> ActionResult:
        """Ejecutar una propuesta de contención autorizada tras validar todas las políticas.

        Flujo obligatorio:
        1. Validar propuesta completa.
        2. Validar presencia y validez de la aprobación.
        3. Comprobar correspondencia exacta entre propuesta y aprobación.
        4. Validar política SOC (acciones permitidas, prohibición de OT, aprobadores).
        5. Validar que la propuesta no fue modificada tras la aprobación.
        6. Proteger contra ejecuciones duplicadas (idempotencia).
        7. Enviar a la API SOC y registrar resultado / auditoría.
        """
        # 1. Validar propuesta completa
        if proposal is None:
            return ActionResult(
                proposal_id="UNKNOWN",
                action="UNKNOWN",
                target="UNKNOWN",
                status="blocked",
                success=False,
                message="Propuesta inválida: la propuesta es None.",
                executed_at=datetime.now(timezone.utc),
            )

        proposal_id = _get_val(proposal, "proposal_id")
        action = _get_val(proposal, "action")
        target = _get_val(proposal, "target")
        justification = _get_val(proposal, "justification", "") or ""
        ticket_id = _get_val(proposal, "ticket_id")

        if not proposal_id or not str(proposal_id).strip():
            return ActionResult(
                proposal_id="UNKNOWN",
                action=str(action or "UNKNOWN"),
                target=str(target or "UNKNOWN"),
                status="blocked",
                success=False,
                message="Propuesta incompleta: falta 'proposal_id'.",
                executed_at=datetime.now(timezone.utc),
            )

        p_id_str = str(proposal_id).strip()

        if not action or not str(action).strip():
            return ActionResult(
                proposal_id=p_id_str,
                action="UNKNOWN",
                target=str(target or "UNKNOWN"),
                status="blocked",
                success=False,
                message="Propuesta incompleta: falta 'action'.",
                executed_at=datetime.now(timezone.utc),
            )

        if not target or not str(target).strip():
            return ActionResult(
                proposal_id=p_id_str,
                action=str(action).strip(),
                target="UNKNOWN",
                status="blocked",
                success=False,
                message="Propuesta incompleta: falta 'target'.",
                executed_at=datetime.now(timezone.utc),
            )

        act_str = str(action).strip().lower()
        tgt_str = str(target).strip()

        # 2. Comprobar política: acción permitida en SOC
        if act_str not in VALID_CONTAINMENT_ACTIONS:
            return self._record_and_return(
                proposal_id=p_id_str,
                action=act_str,
                target=tgt_str,
                ticket_id=str(ticket_id) if ticket_id else None,
                status="blocked",
                success=False,
                message=f"Acción prohibida por política SOC: '{act_str}' no está en las acciones permitidas.",
            )

        # 3. Comprobar política: prohibición absoluta de contención directa en red OT
        if self._is_ot_target(tgt_str):
            return self._record_and_return(
                proposal_id=p_id_str,
                action=act_str,
                target=tgt_str,
                ticket_id=str(ticket_id) if ticket_id else None,
                status="blocked",
                success=False,
                message="Política SOC: Prohibida la contención directa sobre infraestructura OT (Martorell). Escalar a Operaciones.",
            )

        # 4. Determinar si requiere aprobación humana
        requires_approval = self._action_requires_approval(act_str, tgt_str, proposal)

        approver_str = None
        token_str = None

        if requires_approval:
            if approval is None:
                return self._record_and_return(
                    proposal_id=p_id_str,
                    action=act_str,
                    target=tgt_str,
                    ticket_id=str(ticket_id) if ticket_id else None,
                    status="blocked",
                    success=False,
                    message=f"Acción '{act_str}' requiere aprobación humana obligatoria y no se proporcionó ninguna.",
                )

            # Validar estado de la aprobación
            app_status = str(_get_val(approval, "status", "") or "").strip().lower()
            approver_str = str(_get_val(approval, "approver", "") or "").strip()
            token_str = str(_get_val(approval, "approval_token", "") or "").strip()
            reason_str = str(_get_val(approval, "reason", "") or "").strip()

            if app_status == "rejected":
                msg = f"Aprobación rechazada por '{approver_str}'"
                if reason_str:
                    msg += f": {reason_str}"
                return self._record_and_return(
                    proposal_id=p_id_str,
                    action=act_str,
                    target=tgt_str,
                    approver=approver_str,
                    ticket_id=str(ticket_id) if ticket_id else None,
                    status="blocked",
                    success=False,
                    message=msg,
                )

            if app_status == "pending":
                return self._record_and_return(
                    proposal_id=p_id_str,
                    action=act_str,
                    target=tgt_str,
                    approver=approver_str,
                    ticket_id=str(ticket_id) if ticket_id else None,
                    status="blocked",
                    success=False,
                    message="La aprobación se encuentra en estado pendiente; no puede ejecutarse.",
                )

            if app_status == "expired":
                return self._record_and_return(
                    proposal_id=p_id_str,
                    action=act_str,
                    target=tgt_str,
                    approver=approver_str,
                    ticket_id=str(ticket_id) if ticket_id else None,
                    status="blocked",
                    success=False,
                    message="La autorización ha caducado.",
                )

            if app_status != "approved":
                return self._record_and_return(
                    proposal_id=p_id_str,
                    action=act_str,
                    target=tgt_str,
                    approver=approver_str,
                    ticket_id=str(ticket_id) if ticket_id else None,
                    status="blocked",
                    success=False,
                    message=f"Estado de aprobación no autorizado: '{app_status}'.",
                )

            # Validar token de aprobación
            if not token_str or not token_str.startswith("APR-"):
                return self._record_and_return(
                    proposal_id=p_id_str,
                    action=act_str,
                    target=tgt_str,
                    approver=approver_str,
                    ticket_id=str(ticket_id) if ticket_id else None,
                    status="blocked",
                    success=False,
                    message="Token de aprobación inválido o ausente.",
                )

            # Validar correspondencia exacta entre propuesta y aprobación
            app_p_id = str(_get_val(approval, "proposal_id", "") or "").strip()
            if app_p_id and app_p_id != p_id_str:
                return self._record_and_return(
                    proposal_id=p_id_str,
                    action=act_str,
                    target=tgt_str,
                    approver=approver_str,
                    ticket_id=str(ticket_id) if ticket_id else None,
                    status="blocked",
                    success=False,
                    message=f"Discrepancia en autorización: corresponde a '{app_p_id}', no a '{p_id_str}'.",
                )

            app_act = str(_get_val(approval, "action", "") or "").strip().lower()
            if app_act and app_act != act_str:
                return self._record_and_return(
                    proposal_id=p_id_str,
                    action=act_str,
                    target=tgt_str,
                    approver=approver_str,
                    ticket_id=str(ticket_id) if ticket_id else None,
                    status="blocked",
                    success=False,
                    message=f"Discrepancia en acción autorizada: '{app_act}' vs '{act_str}'.",
                )

            app_tgt = str(_get_val(approval, "target", "") or "").strip().lower()
            if app_tgt and app_tgt != tgt_str.lower():
                return self._record_and_return(
                    proposal_id=p_id_str,
                    action=act_str,
                    target=tgt_str,
                    approver=approver_str,
                    ticket_id=str(ticket_id) if ticket_id else None,
                    status="blocked",
                    success=False,
                    message=f"Discrepancia en objetivo autorizado: '{app_tgt}' vs '{tgt_str}'.",
                )

            # Validar integridad: la propuesta no debe haber sido alterada tras la aprobación
            prop_hash = _get_val(proposal, "content_hash")
            app_hash = _get_val(approval, "proposal_hash")
            if prop_hash and app_hash and str(prop_hash) != str(app_hash):
                return self._record_and_return(
                    proposal_id=p_id_str,
                    action=act_str,
                    target=tgt_str,
                    approver=approver_str,
                    ticket_id=str(ticket_id) if ticket_id else None,
                    status="blocked",
                    success=False,
                    message="Propuesta modificada después de la aprobación (hash de contenido alterado).",
                )

            # 5. Invocar validador de Persona 2 si está disponible
            if self.approval_service is not None:
                is_valid = self._call_approval_service_validator(proposal, approval)
                if not is_valid:
                    return self._record_and_return(
                        proposal_id=p_id_str,
                        action=act_str,
                        target=tgt_str,
                        approver=approver_str,
                        ticket_id=str(ticket_id) if ticket_id else None,
                        status="blocked",
                        success=False,
                        message="Validación rechazada por el servicio de aprobaciones (Persona 2).",
                    )
        else:
            # Acción en NO_APPROVAL
            if approval is not None:
                token_str = str(_get_val(approval, "approval_token", "") or "").strip()
                approver_str = str(_get_val(approval, "approver", "") or "").strip()

        # 6. Protección contra ejecuciones duplicadas y concurrencia (Idempotencia)
        with self._lock:
            if self.is_already_executed(p_id_str):
                prev = self._history.get(p_id_str)
                return ActionResult(
                    proposal_id=p_id_str,
                    action=act_str,
                    target=tgt_str,
                    status="blocked",
                    success=False,
                    message=f"Ejecución duplicada prevenida: la propuesta '{p_id_str}' ya fue ejecutada anteriormente.",
                    executed_at=prev.executed_at if prev else datetime.now(timezone.utc),
                    ticket_id=str(ticket_id) if ticket_id else None,
                    approver=approver_str,
                )

            # Marcar provisionalmente como en proceso para concurrencia
            self._history[p_id_str] = ActionResult(
                proposal_id=p_id_str,
                action=act_str,
                target=tgt_str,
                status="unknown",
                success=False,
                message="Ejecución en proceso...",
                executed_at=datetime.now(timezone.utc),
                ticket_id=str(ticket_id) if ticket_id else None,
                approver=approver_str,
            )

        # 7. Ejecutar a través de ContainmentAPIClient
        try:
            api_resp = self.api_client.execute_action(proposal, approval)

            # Interpretar respuesta
            res_text = str(api_resp.get("result", "")).lower()
            if "ok" in res_text:
                result = ActionResult(
                    proposal_id=p_id_str,
                    action=act_str,
                    target=tgt_str,
                    status="executed",
                    success=True,
                    message=f"Acción de contención '{act_str}' ejecutada con éxito sobre '{tgt_str}'.",
                    executed_at=datetime.now(timezone.utc),
                    ticket_id=str(ticket_id) if ticket_id else None,
                    approver=approver_str,
                    approval_token=token_str,
                    api_response=api_resp,
                )
            else:
                result = ActionResult(
                    proposal_id=p_id_str,
                    action=act_str,
                    target=tgt_str,
                    status="failed",
                    success=False,
                    message=f"La API SOC devolvió un resultado no satisfactorio: {api_resp.get('result')}",
                    executed_at=datetime.now(timezone.utc),
                    ticket_id=str(ticket_id) if ticket_id else None,
                    approver=approver_str,
                    api_response=api_resp,
                )

        except (ContainmentTimeoutError, TimeoutError) as exc:
            logger.warning("Timeout al ejecutar contención de %s: %s", p_id_str, exc)
            result = ActionResult(
                proposal_id=p_id_str,
                action=act_str,
                target=tgt_str,
                status="unknown",
                success=False,
                message="Timeout al comunicarse con la API SOC: estado de contención no confirmado.",
                executed_at=datetime.now(timezone.utc),
                ticket_id=str(ticket_id) if ticket_id else None,
                approver=approver_str,
                error_details=str(exc),
            )

        except ContainmentHTTPError as exc:
            logger.error("Error HTTP %d de la API SOC para %s: %s", exc.status_code, p_id_str, exc.detail)
            result = ActionResult(
                proposal_id=p_id_str,
                action=act_str,
                target=tgt_str,
                status="failed",
                success=False,
                message=f"Error HTTP {exc.status_code} de la API SOC: {exc.detail}",
                executed_at=datetime.now(timezone.utc),
                ticket_id=str(ticket_id) if ticket_id else None,
                approver=approver_str,
                api_response=exc.response_data,
                error_details=exc.detail,
            )

        except (ContainmentConnectionError, ConnectionError) as exc:
            logger.error("Error de conexión para %s: %s", p_id_str, exc)
            result = ActionResult(
                proposal_id=p_id_str,
                action=act_str,
                target=tgt_str,
                status="failed",
                success=False,
                message=f"Error de conexión con la API SOC: {exc}",
                executed_at=datetime.now(timezone.utc),
                ticket_id=str(ticket_id) if ticket_id else None,
                approver=approver_str,
                error_details=str(exc),
            )

        except (ContainmentResponseError, Exception) as exc:
            logger.error("Error inesperado al ejecutar %s: %s", p_id_str, exc)
            result = ActionResult(
                proposal_id=p_id_str,
                action=act_str,
                target=tgt_str,
                status="failed",
                success=False,
                message=f"Respuesta inesperada o fallo en la API SOC: {exc}",
                executed_at=datetime.now(timezone.utc),
                ticket_id=str(ticket_id) if ticket_id else None,
                approver=approver_str,
                error_details=str(exc),
            )

        # 8. Guardar resultado final en historial y store
        with self._lock:
            self._history[p_id_str] = result

        if self.store is not None:
            self._save_to_store(result)

        return result

    def get_execution_result(self, proposal_id: str) -> Optional[ActionResult]:
        """Recuperar el resultado de una ejecución previa a partir del ID de propuesta."""
        if not proposal_id:
            return None
        with self._lock:
            return self._history.get(str(proposal_id).strip())

    def is_already_executed(self, proposal_id: str) -> bool:
        """Comprobar si una propuesta ya tiene una ejecución registrada o confirmada."""
        if not proposal_id:
            return False
        with self._lock:
            res = self._history.get(str(proposal_id).strip())
            if res is None:
                return False
            # Si el estado es executed, failed o unknown, se considera ya procesada
            return res.status in {"executed", "unknown"}

    def _is_ot_target(self, target: str) -> bool:
        """Determinar si el objetivo pertenece a la red OT según la política de Tarvia."""
        tgt_upper = target.upper()
        if (
            tgt_upper.startswith("PLC-")
            or tgt_upper.startswith("HMI-")
            or "LOGISTICS-OT" in tgt_upper
            or tgt_upper.startswith("10.40.16.")
            or tgt_upper.startswith("10.40.17.")
            or tgt_upper.startswith("10.40.18.")
            or tgt_upper.startswith("10.40.19.")
        ):
            return True
        return False

    def _action_requires_approval(
        self,
        action: str,
        target: str,
        proposal: Any,
    ) -> bool:
        """Determinar si la acción exige aprobación humana según la política SOC."""
        req_flag = _get_val(proposal, "requires_approval")
        if req_flag is True:
            return True
        if req_flag is False and action in NO_APPROVAL_ACTIONS:
            return False

        if action not in NO_APPROVAL_ACTIONS:
            return True

        # Casos especiales de block_ioc para uso dual o comodines
        if action == "block_ioc":
            tgt_lower = target.lower()
            if any(dual in tgt_lower for dual in DUAL_USE_DOMAINS) or "*" in target:
                return True

        return False

    def _call_approval_service_validator(
        self,
        proposal: Any,
        approval: Any,
    ) -> bool:
        """Invocar método de validación de Persona 2 si existe."""
        for method_name in ("validate_approval", "is_valid", "verify", "validate"):
            validator = getattr(self.approval_service, method_name, None)
            if callable(validator):
                try:
                    res = validator(proposal, approval)
                    return bool(res) if res is not None else True
                except Exception as exc:
                    logger.warning("El validador de aprobaciones lanzó excepción: %s", exc)
                    return False
        return True

    def _record_and_return(
        self,
        proposal_id: str,
        action: str,
        target: str,
        status: str,
        success: bool,
        message: str,
        ticket_id: Optional[str] = None,
        approver: Optional[str] = None,
    ) -> ActionResult:
        """Construir, registrar en auditoría y devolver un ActionResult."""
        res = ActionResult(
            proposal_id=proposal_id,
            action=action,
            target=target,
            status=status,
            success=success,
            message=message,
            executed_at=datetime.now(timezone.utc),
            ticket_id=ticket_id,
            approver=approver,
        )
        with self._lock:
            self._history[proposal_id] = res

        if self.store is not None:
            self._save_to_store(res)

        return res

    def _save_to_store(self, result: ActionResult) -> None:
        """Guardar resultado en el almacén si este dispone de método compatible."""
        try:
            for method_name in ("record_containment_action", "save_containment", "save_action", "record_action"):
                save_fn = getattr(self.store, method_name, None)
                if callable(save_fn):
                    save_fn(result.to_dict())
                    return
        except Exception as exc:
            logger.debug("No se pudo persistir en store: %s", exc)
