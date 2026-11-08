"""Tests unitarios para ApprovalService (Fase 4 - N4).

Cubre los 20 escenarios obligatorios exigidos:
1. Solicitud de aprobación válida.
2. Propuesta incompleta.
3. Acción no permitida por política.
4. Aprobación válida.
5. Aprobador sin permisos suficientes.
6. Aprobación por persona no autorizada.
7. Rechazo válido con motivo.
8. Rechazo sin motivo (debe fallar).
9. Token inválido.
10. Token caducado.
11. Propuesta modificada después de solicitar aprobación.
12. Aprobación revocada.
13. Intento de aprobar una solicitud ya aprobada.
14. Intento de aprobar una solicitud rechazada.
15. Requisitos de múltiples aprobadores.
16. Persistencia SQLite.
17. Recuperación de aprobaciones.
18. Decisiones simultáneas (concurrencia).
19. Prevención de solicitudes duplicadas.
20. Separación entre solicitante, aprobador y ejecutor.
"""
from __future__ import annotations

import concurrent.futures
from datetime import datetime, timezone
from pathlib import Path
import pytest

from src.triage.level4.approval_models import (
    ApprovalResult,
    ContainmentProposal,
)
from src.triage.level4.approval_repository import ApprovalRepository
from src.triage.level4.approval_service import (
    ApprovalPolicy,
    ApprovalService,
)
from src.triage.level4.token_service import TokenService


@pytest.fixture
def repo(tmp_path: Path) -> ApprovalRepository:
    return ApprovalRepository(db_path=tmp_path / "approvals_service_test.sqlite3")


@pytest.fixture
def policy() -> ApprovalPolicy:
    return ApprovalPolicy(
        allow_self_approval=False,
        user_roles={
            "ciso": "ciso",
            "soc_lead": "soc_lead",
            "analyst_n2": "N2",
            "analyst_n1": "N1",
            "director_ecommerce": "service_owner",
            "directora_operaciones": "business",
        },
    )


@pytest.fixture
def token_service() -> TokenService:
    return TokenService(default_ttl_seconds=3600)


@pytest.fixture
def service(
    repo: ApprovalRepository, policy: ApprovalPolicy, token_service: TokenService
) -> ApprovalService:
    return ApprovalService(repository=repo, policy=policy, token_service=token_service)


# 1. Solicitud de aprobación válida
def test_request_approval_valid(service: ApprovalService) -> None:
    proposal = ContainmentProposal(
        proposal_id="PROP-VAL-01",
        action="isolate_host",
        target="WS-HQ-042",
        justification="Ransomware detectado",
        ticket_id="TKT-001",
    )

    approval = service.request_approval(proposal, requester_id="analyst_n1")

    assert approval.approval_id.startswith("APP-")
    assert approval.proposal_id == "PROP-VAL-01"
    assert approval.status == "pending"
    assert approval.approval_token is None
    assert approval.proposal_hash is not None
    assert approval.required_approvers == ["N2"]


# 2. Propuesta incompleta
def test_request_approval_incomplete(service: ApprovalService) -> None:
    with pytest.raises(ValueError, match="proposal_id"):
        service.request_approval({"proposal_id": "", "action": "isolate_host", "target": "WS-01"})

    with pytest.raises(ValueError, match="action"):
        service.request_approval({"proposal_id": "P1", "action": "", "target": "WS-01"})

    with pytest.raises(ValueError, match="target"):
        service.request_approval({"proposal_id": "P1", "action": "isolate_host", "target": ""})


# 3. Acción no permitida por política
def test_request_approval_action_not_allowed(service: ApprovalService) -> None:
    # Acción inexistente
    with pytest.raises(ValueError, match="política"):
        service.request_approval(
            {"proposal_id": "P-BAD", "action": "format_disk", "target": "WS-01"}
        )

    # Intento de contención en red OT (prohibido)
    with pytest.raises(ValueError, match="OT"):
        service.request_approval(
            {"proposal_id": "P-OT", "action": "isolate_host", "target": "PLC-SORT01"}
        )


# 4. Aprobación válida
def test_approve_valid(service: ApprovalService) -> None:
    proposal = ContainmentProposal(
        proposal_id="PROP-OK",
        action="isolate_host",
        target="WS-HQ-042",
    )
    req = service.request_approval(proposal, requester_id="analyst_n1")

    app = service.approve(
        approval_id=req.approval_id,
        reviewer_id="analyst_n2",
        reason="Aprobado por sospecha confirmada de persistencia",
    )

    assert app.status == "approved"
    assert app.reviewer_id == "analyst_n2"
    assert app.decision_timestamp is not None
    assert app.approval_token is not None
    assert app.approval_token.startswith("APR-")


# 5. Aprobador sin permisos suficientes
def test_approve_reviewer_without_permissions(service: ApprovalService) -> None:
    proposal = ContainmentProposal(
        proposal_id="PROP-PERM",
        action="isolate_host",
        target="WS-HQ-042",
    )
    req = service.request_approval(proposal)

    # analyst_n1 tiene rol N1; isolate_host requiere al menos N2
    with pytest.raises(PermissionError, match="no está autorizado"):
        service.approve(
            approval_id=req.approval_id,
            reviewer_id="analyst_n1",
            reviewer_role="N1",
        )


# 6. Aprobación por persona no autorizada
def test_approve_unauthorized_person(service: ApprovalService) -> None:
    proposal = ContainmentProposal(
        proposal_id="PROP-UNAUTH",
        action="disable_user",
        target="adm.test",
    )
    req = service.request_approval(proposal)

    with pytest.raises(PermissionError, match="no está autorizado"):
        service.approve(
            approval_id=req.approval_id,
            reviewer_id="unknown_attacker",
        )


# 7. Rechazo válido con motivo
def test_reject_valid(service: ApprovalService) -> None:
    proposal = ContainmentProposal(
        proposal_id="PROP-REJ",
        action="revoke_sessions",
        target="user.test",
    )
    req = service.request_approval(proposal)

    rejected = service.reject(
        approval_id=req.approval_id,
        reviewer_id="analyst_n2",
        reason="Falso positivo: usuario en viaje autorizado con cambio de IP",
    )

    assert rejected.status == "rejected"
    assert rejected.reviewer_id == "analyst_n2"
    assert rejected.reason == "Falso positivo: usuario en viaje autorizado con cambio de IP"
    assert rejected.approval_token is None


# 8. Rechazo sin motivo (debe fallar)
def test_reject_without_reason(service: ApprovalService) -> None:
    proposal = ContainmentProposal(
        proposal_id="PROP-REJ-NOREASON",
        action="disable_user",
        target="user.test",
    )
    req = service.request_approval(proposal)

    with pytest.raises(ValueError, match="motivo del rechazo"):
        service.reject(
            approval_id=req.approval_id,
            reviewer_id="analyst_n2",
            reason="",
        )


# 9. Token inválido
def test_validate_approval_invalid_token(service: ApprovalService) -> None:
    proposal = ContainmentProposal(
        proposal_id="PROP-BADTOK",
        action="isolate_host",
        target="WS-01",
    )
    req = service.request_approval(proposal)
    app = service.approve(req.approval_id, "analyst_n2")

    # Modificar el token por uno falso
    app_tampered = app.model_copy(update={"approval_token": "APR-fake999token"})
    assert service.validate_approval(proposal, app_tampered) is False


# 10. Token caducado
def test_validate_approval_expired_token(repo: ApprovalRepository, policy: ApprovalPolicy) -> None:
    # Crear token service con TTL de 0 segundos (caduca de inmediato)
    expired_token_service = TokenService(default_ttl_seconds=-1 if False else 1)
    svc = ApprovalService(repository=repo, policy=policy, token_service=expired_token_service)

    proposal = ContainmentProposal(
        proposal_id="PROP-EXP",
        action="purge_email",
        target="msg-1",
    )
    req = svc.request_approval(proposal)
    app = svc.approve(req.approval_id, "analyst_n1", reviewer_role="N1")

    # Forzar fecha de expiración pasada en el token
    token = app.approval_token
    meta = expired_token_service._tokens[token]
    meta.expires_at = datetime.fromtimestamp(0, tz=timezone.utc)

    assert svc.validate_approval(proposal, app) is False


# 11. Propuesta modificada después de solicitar aprobación
def test_validate_approval_modified_proposal_after_request(service: ApprovalService) -> None:
    proposal = ContainmentProposal(
        proposal_id="PROP-TAMPER",
        action="isolate_host",
        target="WS-HQ-042",
        justification="C2 sospechoso",
    )
    req = service.request_approval(proposal)
    app = service.approve(req.approval_id, "analyst_n2")

    # Modificar el objetivo o justificación de la propuesta
    modified_proposal = proposal.model_copy(update={"target": "WS-CRITICAL-SERVER"})
    assert service.validate_approval(modified_proposal, app) is False


# 12. Aprobación revocada
def test_revoke_approval(service: ApprovalService) -> None:
    proposal = ContainmentProposal(
        proposal_id="PROP-REVOKE",
        action="block_ioc",
        target="198.51.100.5",
    )
    req = service.request_approval(proposal)
    app = service.approve(req.approval_id, "analyst_n2")

    assert service.validate_approval(proposal, app) is True

    # Revocar la aprobación
    revoked = service.revoke(
        approval_id=app.approval_id,
        reviewer_id="ciso",
        reason="Orden de contención cancelada por pentest autorizado",
    )
    assert revoked.status == "revoked"

    # La validación debe fallar tras ser revocada
    assert service.validate_approval(proposal, revoked) is False


# 13. Intento de aprobar una solicitud ya aprobada
def test_attempt_to_approve_already_approved(service: ApprovalService) -> None:
    proposal = ContainmentProposal(
        proposal_id="PROP-ALREADY-APP",
        action="isolate_host",
        target="WS-01",
    )
    req = service.request_approval(proposal)
    service.approve(req.approval_id, "analyst_n2")

    with pytest.raises(ValueError, match="ya aprobada"):
        service.approve(req.approval_id, "analyst_n2")


# 14. Intento de aprobar una solicitud rechazada
def test_attempt_to_approve_rejected(service: ApprovalService) -> None:
    proposal = ContainmentProposal(
        proposal_id="PROP-ALREADY-REJ",
        action="isolate_host",
        target="WS-01",
    )
    req = service.request_approval(proposal)
    service.reject(req.approval_id, "analyst_n2", reason="No justificado")

    with pytest.raises(ValueError, match="rechazada"):
        service.approve(req.approval_id, "ciso")


# 15. Requisitos de múltiples aprobadores
def test_multiple_approvers_requirement(service: ApprovalService) -> None:
    # Aislar un servidor crítico exige N2 + service_owner
    proposal = ContainmentProposal(
        proposal_id="PROP-MULTI-APPROV",
        action="isolate_host",
        target="WEB-ECOM01",
        justification="Web shell detectada en frontal e-commerce",
    )
    req = service.request_approval(proposal)
    assert req.required_approvers == ["N2", "service_owner"]

    # 1ª aprobación (analyst_n2 con rol N2) -> debe mantenerse pendiente (sin token)
    step1 = service.approve(req.approval_id, reviewer_id="analyst_n2")
    assert step1.status == "pending"
    assert step1.approval_token is None
    assert len(step1.approvals_received) == 1

    # 2ª aprobación (director_ecommerce con rol service_owner) -> se completa
    step2 = service.approve(req.approval_id, reviewer_id="director_ecommerce")
    assert step2.status == "approved"
    assert step2.approval_token is not None
    assert step2.approval_token.startswith("APR-")
    assert len(step2.approvals_received) == 2

    assert service.validate_approval(proposal, step2) is True


# 16. Persistencia SQLite
def test_sqlite_persistence(tmp_path: Path, policy: ApprovalPolicy, token_service: TokenService) -> None:
    db_file = tmp_path / "persist_test.sqlite3"
    svc1 = ApprovalService(
        repository=ApprovalRepository(db_file),
        policy=policy,
        token_service=token_service,
    )

    proposal = ContainmentProposal(
        proposal_id="PROP-SQLITE",
        action="reset_password",
        target="adm.smith",
    )
    req = svc1.request_approval(proposal)
    app = svc1.approve(req.approval_id, "analyst_n2", reason="Aprobado en sesión 1")

    # Crear una nueva instancia con conexión independiente
    svc2 = ApprovalService(
        repository=ApprovalRepository(db_file),
        policy=policy,
        token_service=token_service,
    )
    loaded = svc2.get_approval(app.approval_id)

    assert loaded is not None
    assert loaded.approval_id == app.approval_id
    assert loaded.status == "approved"
    assert loaded.reviewer_id == "analyst_n2"
    assert loaded.approval_token == app.approval_token


# 17. Recuperación de aprobaciones
def test_retrieve_approvals(service: ApprovalService) -> None:
    p1 = ContainmentProposal(proposal_id="P-L1", action="purge_email", target="msg-1")
    p2 = ContainmentProposal(proposal_id="P-L2", action="purge_email", target="msg-2")
    r1 = service.request_approval(p1)
    r2 = service.request_approval(p2)
    service.approve(r2.approval_id, "analyst_n1")

    pending = service.list_pending_approvals()
    assert any(x.approval_id == r1.approval_id for x in pending)

    approved = service.list_approved()
    assert any(x.approval_id == r2.approval_id for x in approved)

    history = service.get_approvals_for_proposal("P-L1")
    assert len(history) == 1
    assert history[0].approval_id == r1.approval_id


# 18. Decisiones simultáneas (Concurrencia)
def test_concurrent_decisions(service: ApprovalService) -> None:
    proposal = ContainmentProposal(
        proposal_id="PROP-CONC",
        action="isolate_host",
        target="WS-01",
    )
    req = service.request_approval(proposal)

    def try_approve(rev_id: str) -> str:
        try:
            res = service.approve(req.approval_id, reviewer_id=rev_id)
            return res.status
        except ValueError:
            return "conflict"

    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as pool:
        futures = [pool.submit(try_approve, f"analyst_n2_{i}") for i in range(5)]
        results = [f.result() for f in futures]

    # Exactamente una aprobación debe tener éxito; las demás deben recibir conflicto
    approved_count = sum(1 for r in results if r == "approved")
    conflict_count = sum(1 for r in results if r == "conflict")

    assert approved_count == 1
    assert conflict_count == 4


# 19. Prevención de solicitudes duplicadas
def test_prevent_duplicate_requests(service: ApprovalService) -> None:
    proposal = ContainmentProposal(
        proposal_id="PROP-DUP-REQ",
        action="isolate_host",
        target="WS-01",
    )
    req1 = service.request_approval(proposal)
    req2 = service.request_approval(proposal)

    # Debe devolver la misma solicitud pendiente
    assert req1.approval_id == req2.approval_id


# 20. Separación entre solicitante, aprobador y ejecutor
def test_separation_of_requester_and_approver(service: ApprovalService) -> None:
    proposal = ContainmentProposal(
        proposal_id="PROP-SELF",
        action="isolate_host",
        target="WS-01",
        requester_id="analyst_n2",
    )
    req = service.request_approval(proposal, requester_id="analyst_n2")

    # analyst_n2 es el solicitante; no debe poder auto-aprobarse
    with pytest.raises(PermissionError, match="Separación de funciones"):
        service.approve(req.approval_id, reviewer_id="analyst_n2")

    # Pero otro analista N2 sí puede aprobarlo
    app = service.approve(req.approval_id, reviewer_id="soc_lead")
    assert app.status == "approved"


# Test 21: Integración completa de extremo a extremo con ContainmentExecutor (Persona 3)
def test_end_to_end_integration_with_containment_executor(service: ApprovalService) -> None:
    from unittest.mock import MagicMock
    from src.triage.level4.containment_api_client import ContainmentAPIClient
    from src.triage.level4.containment_executor import ContainmentExecutor

    mock_client = MagicMock(spec=ContainmentAPIClient)
    mock_client.execute_action.return_value = {
        "timestamp": "2026-11-08T04:00:00Z",
        "action": "isolate_host",
        "target": "WS-HQ-042",
        "result": "ok (simulado)",
    }

    executor = ContainmentExecutor(
        api_client=mock_client,
        approval_service=service,
    )

    proposal = ContainmentProposal(
        proposal_id="PROP-E2E-P2P3",
        action="isolate_host",
        target="WS-HQ-042",
        justification="Infección verificada",
        ticket_id="TKT-E2E",
        requester_id="analyst_n1",
    )

    # 1. Solicitar aprobación (Persona 1 -> Persona 2)
    req = service.request_approval(proposal, requester_id="analyst_n1")
    assert req.status == "pending"

    # Intentar ejecutar mientras está pendiente: ContainmentExecutor lo bloquea gracias a validate_approval
    res_pending = executor.execute(proposal, req)
    assert res_pending.status == "blocked"
    mock_client.execute_action.assert_not_called()

    # 2. Aprobar humanamente (Persona 2)
    app = service.approve(req.approval_id, reviewer_id="analyst_n2", reason="Aprobado para contención")
    assert app.status == "approved"

    # 3. Ejecutar acción autorizada (Persona 2 -> Persona 3)
    res_exec = executor.execute(proposal, app)
    assert res_exec.status == "executed"
    assert res_exec.success is True
    assert res_exec.approver == "analyst_n2"
    mock_client.execute_action.assert_called_once()

