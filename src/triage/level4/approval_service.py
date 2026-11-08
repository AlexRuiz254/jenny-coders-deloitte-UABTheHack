"""Servicio central de gestión de aprobaciones humanas (Fase 4 - N4).

Responsable de procesar solicitudes de aprobación, validar permisos de revisores,
asegurar separación de funciones, aplicar políticas multi-aprobador de Tarvia
y validar autorizaciones para Persona 3 (ContainmentExecutor).
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import logging
import threading
from typing import Any, Optional
import uuid

from src.triage.level4.approval_models import (
    ApprovalResult,
    ApprovalStatus,
    ContainmentProposal,
)
from src.triage.level4.approval_repository import ApprovalRepository
from src.triage.level4.token_service import TokenService

logger = logging.getLogger(__name__)

# Acciones de contención soportadas en Tarvia SOC (politica_soc.md)
VALID_ACTIONS: frozenset[str] = frozenset({
    "isolate_host",
    "disable_user",
    "revoke_sessions",
    "reset_password",
    "block_ioc",
    "purge_email",
    "disable_access_key",
})

# Servicios de uso dual que requieren escalado / aprobación N2 para block_ioc
DUAL_USE_DOMAINS: tuple[str, ...] = (
    "mega.nz",
    "mega",
    "anydesk.com",
    "anydesk",
    "teamviewer.com",
    "teamviewer",
    "dropbox.com",
)

# Servidores críticos de Tarvia que exigen doble aprobación (N2 + service_owner)
CRITICAL_SERVERS_PATTERNS: tuple[str, ...] = (
    "WEB-ECOM",
    "SQL-CRM",
    "PAY-GW",
    "DC01",
    "DC02",
    "ERP-",
    "WMS01",
    "BACKUP01",
    "AI-ASSIST01",
)


def _get_field_val(obj: Any, name: str, default: Any = None) -> Any:
    """Extraer atributo o valor de diccionario de forma segura."""
    if obj is None:
        return default
    if isinstance(obj, dict):
        return obj.get(name, default)
    return getattr(obj, name, default)


class ApprovalPolicy:
    """Reglas de política del SOC de Tarvia para aprobaciones de contención."""

    def __init__(
        self,
        allow_self_approval: bool = False,
        user_roles: Optional[dict[str, str]] = None,
    ) -> None:
        """Inicializar la política con mapeo de roles y regla de auto-aprobación."""
        self.allow_self_approval = allow_self_approval
        self.user_roles: dict[str, str] = {
            # Mapeo predeterminado según organización del SOC de Tarvia
            "ciso": "ciso",
            "alba.rovira": "ciso",
            "soc_lead": "soc_lead",
            "analyst_n2": "N2",
            "n2_guardia": "N2",
            "analyst_n1": "N1",
            "director_ecommerce": "service_owner",
            "director_financiero": "service_owner",
            "dpo": "service_owner",
            "director_tecnologia": "service_owner",
            "directora_operaciones": "business",
            **(user_roles or {}),
        }

    def resolve_role(self, reviewer_id: str, provided_role: Optional[str] = None) -> str:
        """Determinar el rol efectivo del revisor."""
        if provided_role and provided_role.strip():
            return provided_role.strip()
        clean_id = reviewer_id.strip().lower()
        if clean_id in self.user_roles:
            return self.user_roles[clean_id]
        if "ciso" in clean_id:
            return "ciso"
        if "lead" in clean_id or "soc_lead" in clean_id:
            return "soc_lead"
        if "n2" in clean_id:
            return "N2"
        if "n1" in clean_id:
            return "N1"
        if "director" in clean_id or "owner" in clean_id:
            return "service_owner"
        if "business" in clean_id or "operaciones" in clean_id:
            return "business"
        return "unauthorized"

    def is_action_allowed(self, action: str, target: str) -> tuple[bool, str]:
        """Comprobar si la acción sobre el objetivo está permitida por política."""
        act_clean = action.strip().lower()
        if act_clean not in VALID_ACTIONS:
            return False, f"Acción '{act_clean}' no contemplada en las 7 acciones oficiales del SOC."

        tgt_upper = target.strip().upper()
        # Prohibición absoluta de contención directa sobre OT
        if (
            tgt_upper.startswith("PLC-")
            or tgt_upper.startswith("HMI-")
            or "LOGISTICS-OT" in tgt_upper
            or tgt_upper.startswith("10.40.16.")
            or tgt_upper.startswith("10.40.17.")
            or tgt_upper.startswith("10.40.18.")
            or tgt_upper.startswith("10.40.19.")
        ):
            return False, "Política SOC: Prohibida la contención directa en red OT. Debe escalarse a Operaciones."

        return True, "Acción permitida por política."

    def get_required_approvers(self, action: str, target: str) -> list[str]:
        """Determinar los roles de aprobadores requeridos según el apartado 4 de politica_soc.md."""
        act_clean = action.strip().lower()
        tgt_upper = target.strip().upper()

        if act_clean == "isolate_host":
            # Servidores corporativos: N2 + Responsable del servicio
            if any(srv in tgt_upper for srv in CRITICAL_SERVERS_PATTERNS) or "SRV" in tgt_upper:
                return ["N2", "service_owner"]
            # TPV o frontales web en tiendas: N2 + Responsable de Negocio
            if tgt_upper.startswith("POS-T") or "TPV" in tgt_upper:
                return ["N2", "business"]
            # Puestos de trabajo normales (WS-*, LT-*): N2
            return ["N2"]

        if act_clean in {"disable_user", "revoke_sessions", "reset_password", "disable_access_key"}:
            return ["N2"]

        if act_clean == "block_ioc":
            tgt_lower = target.strip().lower()
            if any(dual in tgt_lower for dual in DUAL_USE_DOMAINS) or "*" in target:
                return ["N2"]
            return ["N1"]

        if act_clean == "purge_email":
            return ["N1"]

        return ["N2"]

    def is_reviewer_authorized(
        self,
        reviewer_id: str,
        reviewer_role: str,
        action: str,
        target: str,
        required_approvers: list[str],
    ) -> bool:
        """Comprobar si el revisor tiene permisos válidos para este tipo de acción."""
        role_upper = reviewer_role.upper()

        # El CISO tiene autoridad suprema sobre todas las aprobaciones
        if role_upper == "CISO":
            return True

        # Jerarquía de roles SOC
        is_n2_or_above = role_upper in {"N2", "SOC_LEAD", "CISO"}

        # Si se requiere service_owner
        if "service_owner" in required_approvers and role_upper == "SERVICE_OWNER":
            return True

        # Si se requiere business
        if "business" in required_approvers and role_upper == "BUSINESS":
            return True

        # Si se requiere N2
        if "N2" in required_approvers:
            return is_n2_or_above

        # Si solo se requiere N1
        if "N1" in required_approvers:
            return role_upper in {"N1", "N2", "SOC_LEAD", "CISO"}

        return False


class ApprovalService:
    """Servicio para orquestar el ciclo de vida de las aprobaciones humanas."""

    def __init__(
        self,
        repository: Optional[ApprovalRepository] = None,
        policy: Optional[ApprovalPolicy] = None,
        token_service: Optional[TokenService] = None,
    ) -> None:
        """Inicializar servicio con repositorio, política y gestor de tokens inyectados."""
        self.repository = repository or ApprovalRepository()
        self.policy = policy or ApprovalPolicy()
        self.token_service = token_service or TokenService()
        self._lock = threading.RLock()

    def request_approval(
        self,
        proposal: Any,
        requester_id: Optional[str] = None,
    ) -> ApprovalResult:
        """Crear una solicitud de aprobación para una propuesta de contención.

        1. Valida campos obligatorios de la propuesta.
        2. Comprueba que la acción está contemplada por la política SOC.
        3. Determina aprobadores y permisos requeridos.
        4. Calcula el hash criptográfico del contenido.
        5. Registra la solicitud con estado 'pending' (sin token).
        """
        if proposal is None:
            raise ValueError("La propuesta de contención no puede ser None")

        proposal_id = _get_field_val(proposal, "proposal_id")
        action = _get_field_val(proposal, "action")
        target = _get_field_val(proposal, "target")
        ticket_id = _get_field_val(proposal, "ticket_id")
        justification = _get_field_val(proposal, "justification", "") or ""
        p_requester = requester_id or _get_field_val(proposal, "requester_id")

        if not proposal_id or not str(proposal_id).strip():
            raise ValueError("La propuesta debe incluir un 'proposal_id' no vacío")
        if not action or not str(action).strip():
            raise ValueError("La propuesta debe incluir un 'action' no vacío")
        if not target or not str(target).strip():
            raise ValueError("La propuesta debe incluir un 'target' no vacío")

        p_id_clean = str(proposal_id).strip()
        act_clean = str(action).strip().lower()
        tgt_clean = str(target).strip()

        # 2. Comprobar política SOC
        allowed, reason = self.policy.is_action_allowed(act_clean, tgt_clean)
        if not allowed:
            raise ValueError(f"Acción denegada por política SOC: {reason}")

        # 3. Determinar aprobadores requeridos
        req_approvers = self.policy.get_required_approvers(act_clean, tgt_clean)

        # 4. Calcular hash de contenido
        raw_hash_data = f"{p_id_clean}:{act_clean}:{tgt_clean.lower()}:{str(justification).strip()}"
        prop_hash = hashlib.sha256(raw_hash_data.encode("utf-8")).hexdigest()[:16]

        with self._lock:
            # 5. Comprobar si ya existe una solicitud para esta propuesta (idempotencia)
            existing = self.repository.get_by_proposal(p_id_clean)
            for ex in existing:
                if ex.status == "pending" and ex.proposal_hash == prop_hash:
                    logger.info("Devolviendo solicitud de aprobación existente para propuesta %s", p_id_clean)
                    return ex

            # 6. Crear ApprovalResult con estado pending (sin token)
            approval_id = f"APP-{uuid.uuid4().hex[:10]}"
            approval = ApprovalResult(
                approval_id=approval_id,
                proposal_id=p_id_clean,
                action=act_clean,
                target=tgt_clean,
                status="pending",
                reviewer_id="",
                decision_timestamp=None,
                reason=None,
                approval_token=None,
                proposal_hash=prop_hash,
                requester_id=str(p_requester) if p_requester else None,
                ticket_id=str(ticket_id) if ticket_id else None,
                required_approvers=req_approvers,
                approvals_received=[],
                created_at=datetime.now(timezone.utc),
            )

            # 7. Persistir en repositorio SQLite
            self.repository.save(approval)

        logger.info("Solicitud de aprobación creada: %s para propuesta %s", approval_id, p_id_clean)
        return approval

    def approve(
        self,
        approval_id: str,
        reviewer_id: str,
        reason: Optional[str] = None,
        reviewer_role: Optional[str] = None,
    ) -> ApprovalResult:
        """Aprobar una solicitud de contención.

        Verifica permisos, separación de funciones e integridad de la propuesta.
        Si la política exige múltiples aprobadores, mantiene la solicitud pendiente
        hasta alcanzar todos los votos necesarios. Solo genera token al aprobar completamente.
        """
        if not approval_id or not str(approval_id).strip():
            raise ValueError("approval_id es obligatorio")
        if not reviewer_id or not str(reviewer_id).strip():
            raise ValueError("reviewer_id es obligatorio")

        clean_app_id = str(approval_id).strip()
        clean_reviewer = str(reviewer_id).strip()

        with self._lock:
            approval = self.repository.get(clean_app_id)
            if approval is None:
                raise KeyError(f"No se encontró la solicitud de aprobación '{clean_app_id}'")

            # Comprobar que sigue pendiente
            if approval.status == "approved":
                raise ValueError("Intento de aprobar una solicitud ya aprobada")
            if approval.status == "rejected":
                raise ValueError("Intento de aprobar una solicitud rechazada previamente")
            if approval.status in {"expired", "revoked"}:
                raise ValueError(f"No se puede aprobar una solicitud en estado '{approval.status}'")

            # Separación de funciones: solicitante no puede aprobar su propia propuesta
            if (
                approval.requester_id
                and clean_reviewer.lower() == approval.requester_id.lower()
                and not self.policy.allow_self_approval
            ):
                raise PermissionError(
                    f"Separación de funciones: el solicitante '{clean_reviewer}' no puede aprobar su propia propuesta"
                )

            # Verificar permisos del revisor
            effective_role = self.policy.resolve_role(clean_reviewer, reviewer_role)
            if not self.policy.is_reviewer_authorized(
                reviewer_id=clean_reviewer,
                reviewer_role=effective_role,
                action=approval.action,
                target=approval.target,
                required_approvers=approval.required_approvers,
            ):
                raise PermissionError(
                    f"El revisor '{clean_reviewer}' con rol '{effective_role}' no está autorizado para aprobar '{approval.action}'"
                )

            # Registrar voto en approvals_received evitando votos duplicados del mismo revisor
            now = datetime.now(timezone.utc)
            already_voted = any(
                str(v.get("reviewer_id", "")).lower() == clean_reviewer.lower()
                for v in approval.approvals_received
            )
            if not already_voted:
                approval.approvals_received.append({
                    "reviewer_id": clean_reviewer,
                    "reviewer_role": effective_role,
                    "timestamp": now.isoformat(),
                    "reason": reason or "",
                })

            # Comprobar si se han satisfecho todos los aprobadores requeridos
            roles_received = {
                str(v.get("reviewer_role", "")).upper()
                for v in approval.approvals_received
            }

            # Si el CISO aprobó, cubre todos los requerimientos de forma ejecutiva
            ciso_approved = "CISO" in roles_received
            all_satisfied = ciso_approved

            if not all_satisfied:
                all_satisfied = True
                for req in approval.required_approvers:
                    req_upper = req.upper()
                    if req_upper == "N2" and not ({"N2", "SOC_LEAD", "CISO"} & roles_received):
                        all_satisfied = False
                        break
                    elif req_upper == "SERVICE_OWNER" and "SERVICE_OWNER" not in roles_received:
                        all_satisfied = False
                        break
                    elif req_upper == "BUSINESS" and "BUSINESS" not in roles_received:
                        all_satisfied = False
                        break
                    elif req_upper == "N1" and not ({"N1", "N2", "SOC_LEAD", "CISO"} & roles_received):
                        all_satisfied = False
                        break

            if not all_satisfied:
                # Actualizar estado de votos pero mantener pending (sin token)
                approval.reviewer_id = clean_reviewer
                approval.reason = reason
                self.repository.update(approval)
                logger.info("Aprobación parcial registrada para %s por %s", clean_app_id, clean_reviewer)
                return approval

            # Todos los requerimientos alcanzados: cambiar a approved y generar token
            approval.status = "approved"
            approval.reviewer_id = clean_reviewer
            approval.approver = clean_reviewer
            approval.decision_timestamp = now
            approval.reason = reason

            # Generar token criptográficamente seguro
            token = self.token_service.generate_token(
                approval_id=approval.approval_id,
                proposal_id=approval.proposal_id,
                proposal_hash=approval.proposal_hash,
            )
            approval.approval_token = token

            self.repository.update(approval)
            logger.info("Aprobación completa exitosa: %s (token emitido)", clean_app_id)
            return approval

    def reject(
        self,
        approval_id: str,
        reviewer_id: str,
        reason: str,
        reviewer_role: Optional[str] = None,
    ) -> ApprovalResult:
        """Rechazar una solicitud de contención. El motivo es obligatorio."""
        if not approval_id or not str(approval_id).strip():
            raise ValueError("approval_id es obligatorio")
        if not reviewer_id or not str(reviewer_id).strip():
            raise ValueError("reviewer_id es obligatorio")
        if not reason or not str(reason).strip():
            raise ValueError("El motivo del rechazo debe ser obligatorio")

        clean_app_id = str(approval_id).strip()
        clean_reviewer = str(reviewer_id).strip()
        clean_reason = str(reason).strip()

        with self._lock:
            approval = self.repository.get(clean_app_id)
            if approval is None:
                raise KeyError(f"No se encontró la solicitud de aprobación '{clean_app_id}'")

            if approval.status != "pending":
                raise ValueError(
                    f"No se puede rechazar una solicitud con estado '{approval.status}' (solo pendiente)"
                )

            # Verificar permisos del revisor
            effective_role = self.policy.resolve_role(clean_reviewer, reviewer_role)
            if not self.policy.is_reviewer_authorized(
                reviewer_id=clean_reviewer,
                reviewer_role=effective_role,
                action=approval.action,
                target=approval.target,
                required_approvers=approval.required_approvers,
            ):
                raise PermissionError(
                    f"El revisor '{clean_reviewer}' no tiene permisos para decidir sobre '{approval.action}'"
                )

            approval.status = "rejected"
            approval.reviewer_id = clean_reviewer
            approval.approver = clean_reviewer
            approval.decision_timestamp = datetime.now(timezone.utc)
            approval.reason = clean_reason
            approval.approval_token = None

            self.repository.update(approval)
            logger.info("Solicitud %s rechazada por %s: %s", clean_app_id, clean_reviewer, clean_reason)
            return approval

    def revoke(
        self,
        approval_id: str,
        reviewer_id: str,
        reason: str,
    ) -> ApprovalResult:
        """Revocar una aprobación previamente concedida. Invalida su token."""
        if not approval_id or not str(approval_id).strip():
            raise ValueError("approval_id es obligatorio")
        if not reviewer_id or not str(reviewer_id).strip():
            raise ValueError("reviewer_id es obligatorio")
        if not reason or not str(reason).strip():
            raise ValueError("El motivo de la revocación es obligatorio")

        clean_app_id = str(approval_id).strip()
        clean_reviewer = str(reviewer_id).strip()
        clean_reason = str(reason).strip()

        with self._lock:
            approval = self.repository.get(clean_app_id)
            if approval is None:
                raise KeyError(f"No se encontró la solicitud '{clean_app_id}'")

            # Revocar token en el servicio de tokens si existe
            if approval.approval_token:
                self.token_service.revoke_token(approval.approval_token)

            approval.status = "revoked"
            approval.reviewer_id = clean_reviewer
            approval.decision_timestamp = datetime.now(timezone.utc)
            approval.reason = f"Revocada: {clean_reason}"

            self.repository.update(approval)
            logger.warning("Aprobación %s revocada por %s", clean_app_id, clean_reviewer)
            return approval

    def validate_approval(
        self,
        proposal: Any,
        approval: Any,
    ) -> bool:
        """Validar exhaustivamente una autorización antes de que Persona 3 la ejecute.

        Verifica:
        1. Existencia y estado 'approved'.
        2. Correspondencia exacta con la propuesta (proposal_id, action, target).
        3. Integridad del hash de la propuesta (no alterada tras aprobar).
        4. Validez y vigencia del token criptográfico.
        5. Que no haya sido revocada ni consumida.
        6. Coherencia con el estado persistido en el repositorio.
        """
        if proposal is None or approval is None:
            return False

        # 1. Comprobar estado 'approved'
        app_status = str(_get_field_val(approval, "status", "")).strip().lower()
        if app_status != "approved":
            return False

        # 2. Comprobar correspondencia de IDs
        prop_id = str(_get_field_val(proposal, "proposal_id", "")).strip()
        app_prop_id = str(_get_field_val(approval, "proposal_id", "")).strip()
        if not prop_id or prop_id != app_prop_id:
            return False

        # 3. Comprobar acción y objetivo
        prop_action = str(_get_field_val(proposal, "action", "")).strip().lower()
        app_action = str(_get_field_val(approval, "action", "")).strip().lower()
        if prop_action != app_action:
            return False

        prop_target = str(_get_field_val(proposal, "target", "")).strip().lower()
        app_target = str(_get_field_val(approval, "target", "")).strip().lower()
        if prop_target != app_target:
            return False

        # 4. Comprobar integridad del contenido (hash)
        app_hash = str(_get_field_val(approval, "proposal_hash", "")).strip()
        prop_hash = _get_field_val(proposal, "content_hash")
        if not prop_hash:
            justification = _get_field_val(proposal, "justification", "") or ""
            raw = f"{prop_id}:{prop_action}:{prop_target}:{str(justification).strip()}"
            prop_hash = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]

        if str(prop_hash) != app_hash:
            logger.warning("Validación fallida: el hash de la propuesta %s no coincide", prop_id)
            return False

        # 5. Comprobar token
        token = str(_get_field_val(approval, "approval_token", "") or "").strip()
        if not token or not token.startswith("APR-"):
            return False

        app_id = str(_get_field_val(approval, "approval_id", "")).strip()
        if not self.token_service.validate_token(
            token=token,
            approval_id=app_id,
            proposal_id=prop_id,
            proposal_hash=app_hash,
        ):
            return False

        # 6. Comprobar expiración del registro
        expires_at = _get_field_val(approval, "expires_at")
        if expires_at and isinstance(expires_at, datetime):
            if datetime.now(timezone.utc) > expires_at:
                return False

        # 7. Comprobar estado en repositorio
        stored = self.repository.get(app_id)
        if stored is None or stored.status != "approved":
            return False

        return True

    def get_approval(self, approval_id: str) -> Optional[ApprovalResult]:
        """Recuperar una solicitud de aprobación por su ID."""
        if not approval_id:
            return None
        return self.repository.get(str(approval_id).strip())

    def get_approvals_for_proposal(self, proposal_id: str) -> list[ApprovalResult]:
        """Recuperar el historial de aprobaciones de una propuesta."""
        if not proposal_id:
            return []
        return self.repository.get_by_proposal(str(proposal_id).strip())

    def list_pending_approvals(self) -> list[ApprovalResult]:
        """Listar solicitudes pendientes de decisión humana para Persona 4."""
        return self.repository.list_by_status("pending")

    def list_approved(self) -> list[ApprovalResult]:
        """Listar aprobaciones concedidas para Persona 4."""
        return self.repository.list_by_status("approved")

    def list_rejected(self) -> list[ApprovalResult]:
        """Listar aprobaciones rechazadas para Persona 4."""
        return self.repository.list_by_status("rejected")

    def list_revoked(self) -> list[ApprovalResult]:
        """Listar aprobaciones revocadas para Persona 4."""
        return self.repository.list_by_status("revoked")

    def list_all(self) -> list[ApprovalResult]:
        """Listar todas las solicitudes registradas."""
        return self.repository.list_all()
