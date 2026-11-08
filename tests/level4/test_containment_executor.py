"""Tests unitarios para ContainmentExecutor (Fase 4 - N4).

Cubre los 15 requisitos mínimos exigidos:
1. Ejecución correcta con aprobación válida.
2. Bloqueo de propuesta sin aprobación.
3. Bloqueo de aprobación rechazada.
4. Bloqueo de aprobación pendiente.
5. Bloqueo de token inválido.
6. Bloqueo de propuesta modificada después de aprobar.
7. Bloqueo de acción prohibida por política (OT y acciones inválidas).
8. Bloqueo de ejecución duplicada.
9. Error HTTP de la API SOC.
10. Timeout HTTP.
11. Respuesta inesperada de la API.
12. Consulta del registro de auditoría.
13. Recuperación de un resultado anterior.
14. Protección frente a ejecuciones simultáneas.
15. Estado desconocido cuando no se puede confirmar el resultado.
"""
from __future__ import annotations

import concurrent.futures
from unittest.mock import MagicMock
import pytest

from src.triage.level4.containment_api_client import (
    ContainmentAPIClient,
    ContainmentHTTPError,
    ContainmentTimeoutError,
)
from src.triage.level4.containment_executor import (
    ActionResult,
    ApprovalResult,
    ContainmentExecutor,
    ContainmentProposal,
)


@pytest.fixture
def mock_api_client() -> MagicMock:
    client = MagicMock(spec=ContainmentAPIClient)
    client.execute_action.return_value = {
        "timestamp": "2026-11-08T03:00:00Z",
        "action": "isolate_host",
        "target": "WS-HQ-042",
        "result": "ok (simulado)",
    }
    client.get_containment_log.return_value = [
        {"action": "isolate_host", "target": "WS-HQ-042", "result": "ok (simulado)"}
    ]
    return client


@pytest.fixture
def executor(mock_api_client: MagicMock) -> ContainmentExecutor:
    return ContainmentExecutor(api_client=mock_api_client)


# 1. Ejecución correcta con aprobación válida
def test_execute_success_with_valid_approval(
    executor: ContainmentExecutor, mock_api_client: MagicMock
) -> None:
    proposal = ContainmentProposal(
        proposal_id="PROP-101",
        action="isolate_host",
        target="WS-HQ-042",
        justification="C2 detectado",
        ticket_id="TKT-555",
    )
    approval = ApprovalResult(
        proposal_id="PROP-101",
        action="isolate_host",
        target="WS-HQ-042",
        approver="analyst_n2",
        status="approved",
        approval_token="APR-valid1234",
    )

    result = executor.execute(proposal, approval)

    assert result.status == "executed"
    assert result.success is True
    assert result.proposal_id == "PROP-101"
    assert result.action == "isolate_host"
    assert result.target == "WS-HQ-042"
    assert result.ticket_id == "TKT-555"
    assert result.approver == "analyst_n2"
    assert result.executed_at is not None
    assert result.api_response["result"] == "ok (simulado)"

    mock_api_client.execute_action.assert_called_once_with(proposal, approval)


# 2. Bloqueo de propuesta sin aprobación
def test_block_proposal_without_approval(
    executor: ContainmentExecutor, mock_api_client: MagicMock
) -> None:
    proposal = ContainmentProposal(
        proposal_id="PROP-NO-APP",
        action="isolate_host",
        target="WS-HQ-042",
    )

    result = executor.execute(proposal, approval=None)

    assert result.status == "blocked"
    assert result.success is False
    assert "aprobación humana obligatoria" in result.message
    mock_api_client.execute_action.assert_not_called()


# 3. Bloqueo de aprobación rechazada
def test_block_rejected_approval(
    executor: ContainmentExecutor, mock_api_client: MagicMock
) -> None:
    proposal = ContainmentProposal(
        proposal_id="PROP-REJ",
        action="disable_user",
        target="adm.gonzalez",
    )
    approval = ApprovalResult(
        proposal_id="PROP-REJ",
        action="disable_user",
        target="adm.gonzalez",
        approver="ciso",
        status="rejected",
        approval_token="APR-rej1234",
        reason="Usuario en viaje autorizado",
    )

    result = executor.execute(proposal, approval)

    assert result.status == "blocked"
    assert result.success is False
    assert "rechazada" in result.message.lower()
    mock_api_client.execute_action.assert_not_called()


# 4. Bloqueo de aprobación pendiente
def test_block_pending_approval(
    executor: ContainmentExecutor, mock_api_client: MagicMock
) -> None:
    proposal = ContainmentProposal(
        proposal_id="PROP-PEND",
        action="reset_password",
        target="j.garcia",
    )
    approval = ApprovalResult(
        proposal_id="PROP-PEND",
        action="reset_password",
        target="j.garcia",
        approver="soc_lead",
        status="pending",
        approval_token="APR-pend1234",
    )

    result = executor.execute(proposal, approval)

    assert result.status == "blocked"
    assert result.success is False
    assert "pendiente" in result.message.lower()
    mock_api_client.execute_action.assert_not_called()


# 5. Bloqueo de token inválido
def test_block_invalid_token(
    executor: ContainmentExecutor, mock_api_client: MagicMock
) -> None:
    proposal = ContainmentProposal(
        proposal_id="PROP-TOK",
        action="revoke_sessions",
        target="user1",
    )
    # Token vacío o que no sigue el formato APR-
    approval = ApprovalResult(
        proposal_id="PROP-TOK",
        action="revoke_sessions",
        target="user1",
        approver="analyst_n2",
        status="approved",
        approval_token="",
    )

    result = executor.execute(proposal, approval)

    assert result.status == "blocked"
    assert result.success is False
    assert "token" in result.message.lower()
    mock_api_client.execute_action.assert_not_called()


# 6. Bloqueo de propuesta modificada después de aprobar
def test_block_modified_proposal_after_approval(
    executor: ContainmentExecutor, mock_api_client: MagicMock
) -> None:
    proposal = ContainmentProposal(
        proposal_id="PROP-MOD",
        action="isolate_host",
        target="WS-HQ-042",
        content_hash="hash_original_123",
    )
    approval = ApprovalResult(
        proposal_id="PROP-MOD",
        action="isolate_host",
        target="WS-HQ-042",
        approver="analyst_n2",
        status="approved",
        approval_token="APR-mod1234",
        proposal_hash="hash_diferente_456",
    )

    result = executor.execute(proposal, approval)

    assert result.status == "blocked"
    assert result.success is False
    assert "modificada" in result.message.lower()
    mock_api_client.execute_action.assert_not_called()


# 7. Bloqueo de acción prohibida por política (OT y acciones no soportadas)
def test_block_prohibited_action_by_policy(
    executor: ContainmentExecutor, mock_api_client: MagicMock
) -> None:
    # Caso A: Acción no soportada por el SOC
    proposal_unsupported = ContainmentProposal(
        proposal_id="PROP-UNSUPP",
        action="format_disk",
        target="WS-01",
    )
    res_unsupp = executor.execute(proposal_unsupported)
    assert res_unsupp.status == "blocked"
    assert "prohibida por política" in res_unsupp.message.lower()

    # Caso B: Intento de contención en infraestructura OT
    proposal_ot = ContainmentProposal(
        proposal_id="PROP-OT",
        action="isolate_host",
        target="PLC-SORT01",
    )
    approval_ot = ApprovalResult(
        proposal_id="PROP-OT",
        action="isolate_host",
        target="PLC-SORT01",
        approver="operations_lead",
        status="approved",
        approval_token="APR-ot1234",
    )
    res_ot = executor.execute(proposal_ot, approval_ot)
    assert res_ot.status == "blocked"
    assert "ot" in res_ot.message.lower()

    mock_api_client.execute_action.assert_not_called()


# 8. Bloqueo de ejecución duplicada (Idempotencia)
def test_block_duplicate_execution(
    executor: ContainmentExecutor, mock_api_client: MagicMock
) -> None:
    proposal = ContainmentProposal(
        proposal_id="PROP-DUP",
        action="isolate_host",
        target="WS-HQ-042",
    )
    approval = ApprovalResult(
        proposal_id="PROP-DUP",
        action="isolate_host",
        target="WS-HQ-042",
        approver="analyst_n2",
        status="approved",
        approval_token="APR-dup1234",
    )

    # 1ª ejecución: éxito
    res1 = executor.execute(proposal, approval)
    assert res1.status == "executed"
    assert res1.success is True
    assert mock_api_client.execute_action.call_count == 1

    # 2ª ejecución: debe bloquearse
    res2 = executor.execute(proposal, approval)
    assert res2.status == "blocked"
    assert res2.success is False
    assert "duplicada" in res2.message.lower()
    # No debe haberse llamado a la API una segunda vez
    assert mock_api_client.execute_action.call_count == 1


# 9. Error HTTP de la API SOC
def test_soc_api_http_error(
    executor: ContainmentExecutor, mock_api_client: MagicMock
) -> None:
    proposal = ContainmentProposal(
        proposal_id="PROP-HTTP-ERR",
        action="isolate_host",
        target="WS-HQ-042",
    )
    approval = ApprovalResult(
        proposal_id="PROP-HTTP-ERR",
        action="isolate_host",
        target="WS-HQ-042",
        approver="analyst_n2",
        status="approved",
        approval_token="APR-err1234",
    )
    mock_api_client.execute_action.side_effect = ContainmentHTTPError(
        message="Error HTTP 403: falta aprobación humana",
        status_code=403,
        detail="falta aprobación humana",
    )

    result = executor.execute(proposal, approval)

    assert result.status == "failed"
    assert result.success is False
    assert "403" in result.message
    assert result.error_details == "falta aprobación humana"


# 10. Timeout HTTP
def test_soc_api_timeout_error(
    executor: ContainmentExecutor, mock_api_client: MagicMock
) -> None:
    proposal = ContainmentProposal(
        proposal_id="PROP-TIMEOUT",
        action="isolate_host",
        target="WS-HQ-042",
    )
    approval = ApprovalResult(
        proposal_id="PROP-TIMEOUT",
        action="isolate_host",
        target="WS-HQ-042",
        approver="analyst_n2",
        status="approved",
        approval_token="APR-time1234",
    )
    mock_api_client.execute_action.side_effect = ContainmentTimeoutError(
        "Timeout al ejecutar acción de contención"
    )

    result = executor.execute(proposal, approval)

    assert result.status == "unknown"
    assert result.success is False
    assert "timeout" in result.message.lower()
    assert "no confirmado" in result.message.lower()


# 11. Respuesta inesperada de la API
def test_soc_api_unexpected_response(
    executor: ContainmentExecutor, mock_api_client: MagicMock
) -> None:
    proposal = ContainmentProposal(
        proposal_id="PROP-UNEXP",
        action="purge_email",
        target="bad@phish.example",
    )
    mock_api_client.execute_action.return_value = {
        "status": "partial",
        "result": "error inesperado interno",
    }

    result = executor.execute(proposal)

    assert result.status == "failed"
    assert result.success is False
    assert "no satisfactorio" in result.message.lower()


# 12. Consulta del registro de auditoría
def test_query_containment_log(
    executor: ContainmentExecutor, mock_api_client: MagicMock
) -> None:
    logs = executor.api_client.get_containment_log()

    assert len(logs) == 1
    assert logs[0]["action"] == "isolate_host"
    mock_api_client.get_containment_log.assert_called_once()


# 13. Recuperación de un resultado anterior
def test_retrieve_previous_result(
    executor: ContainmentExecutor, mock_api_client: MagicMock
) -> None:
    proposal = ContainmentProposal(
        proposal_id="PROP-PREV",
        action="block_ioc",
        target="198.51.100.1",
    )
    mock_api_client.execute_action.return_value = {
        "action": "block_ioc",
        "target": "198.51.100.1",
        "result": "ok (simulado)",
    }

    executed = executor.execute(proposal)

    # Recuperar resultado
    retrieved = executor.get_execution_result("PROP-PREV")
    assert retrieved is not None
    assert retrieved.proposal_id == "PROP-PREV"
    assert retrieved.status == "executed"
    assert retrieved.success is True

    # Recuperar resultado inexistente
    assert executor.get_execution_result("NON_EXISTENT") is None


# 14. Protección frente a ejecuciones simultáneas (Concurrencia)
def test_protection_against_concurrent_executions(
    mock_api_client: MagicMock,
) -> None:
    executor = ContainmentExecutor(api_client=mock_api_client)
    proposal = ContainmentProposal(
        proposal_id="PROP-CONC",
        action="isolate_host",
        target="WS-HQ-042",
    )
    approval = ApprovalResult(
        proposal_id="PROP-CONC",
        action="isolate_host",
        target="WS-HQ-042",
        approver="analyst_n2",
        status="approved",
        approval_token="APR-conc1234",
    )

    def run_exec() -> ActionResult:
        return executor.execute(proposal, approval)

    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as pool:
        futures = [pool.submit(run_exec) for _ in range(5)]
        results = [f.result() for f in futures]

    # Exactamente una ejecución debe haber sido enviada a la API
    assert mock_api_client.execute_action.call_count == 1
    executed_count = sum(1 for r in results if r.status == "executed")
    blocked_count = sum(1 for r in results if r.status == "blocked")

    assert executed_count == 1
    assert blocked_count == 4


# 15. Estado desconocido cuando no se puede confirmar el resultado
def test_unknown_state_when_result_unconfirmed(
    executor: ContainmentExecutor, mock_api_client: MagicMock
) -> None:
    proposal = ContainmentProposal(
        proposal_id="PROP-UNCONFIRMED",
        action="disable_user",
        target="adm.test",
    )
    approval = ApprovalResult(
        proposal_id="PROP-UNCONFIRMED",
        action="disable_user",
        target="adm.test",
        approver="analyst_n2",
        status="approved",
        approval_token="APR-unconf1234",
    )
    mock_api_client.execute_action.side_effect = ContainmentTimeoutError("Gateway Timeout")

    res = executor.execute(proposal, approval)
    assert res.status == "unknown"
    assert res.success is False

    # Idempotencia: is_already_executed debe considerarlo registrado para evitar repetición ciega
    assert executor.is_already_executed("PROP-UNCONFIRMED") is True

    # Si se intenta ejecutar de nuevo, se previene por duplicada/incierta
    res2 = executor.execute(proposal, approval)
    assert res2.status == "blocked"
    assert "duplicada" in res2.message.lower()


# Test adicional: Integración con validador de Persona 2 (ApprovalService)
def test_integration_with_approval_service_validator(mock_api_client: MagicMock) -> None:
    mock_approval_service = MagicMock()
    mock_approval_service.validate_approval.return_value = False

    executor = ContainmentExecutor(
        api_client=mock_api_client,
        approval_service=mock_approval_service,
    )

    proposal = ContainmentProposal(
        proposal_id="PROP-P2-VAL",
        action="isolate_host",
        target="WS-01",
    )
    approval = ApprovalResult(
        proposal_id="PROP-P2-VAL",
        action="isolate_host",
        target="WS-01",
        approver="analyst_n2",
        status="approved",
        approval_token="APR-p2-1234",
    )

    result = executor.execute(proposal, approval)

    assert result.status == "blocked"
    assert "servicio de aprobaciones" in result.message.lower()
    mock_approval_service.validate_approval.assert_called_once_with(proposal, approval)
    mock_api_client.execute_action.assert_not_called()
