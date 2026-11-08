"""Tests unitarios para ContainmentAPIClient (Fase 4 - N4).

Verifica la comunicación HTTP, el formateo de peticiones a la API SOC,
la gestión de tokens, códigos de estado, timeouts y respuestas anómalas.
"""
from __future__ import annotations

from unittest.mock import MagicMock
import pytest
import requests

from src.triage.level4.containment_api_client import (
    ContainmentAPIClient,
    ContainmentConnectionError,
    ContainmentHTTPError,
    ContainmentResponseError,
    ContainmentTimeoutError,
)
from src.triage.level4.containment_executor import (
    ApprovalResult,
    ContainmentProposal,
)


@pytest.fixture
def mock_session() -> MagicMock:
    return MagicMock(spec=requests.Session)


@pytest.fixture
def client(mock_session: MagicMock) -> ContainmentAPIClient:
    return ContainmentAPIClient(
        base_url="http://test-soc-api:8000",
        timeout=10.0,
        session=mock_session,
    )


def test_init_invalid_timeout() -> None:
    with pytest.raises(ValueError, match="timeout"):
        ContainmentAPIClient(timeout=0)


def test_execute_action_success(client: ContainmentAPIClient, mock_session: MagicMock) -> None:
    proposal = ContainmentProposal(
        proposal_id="PROP-001",
        action="isolate_host",
        target="WS-HQ-042",
        justification="Infección confirmada por troyano",
        ticket_id="TKT-100",
    )
    approval = ApprovalResult(
        proposal_id="PROP-001",
        action="isolate_host",
        target="WS-HQ-042",
        approver="analyst_n2",
        status="approved",
        approval_token="APR-abcdef1234",
    )

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "timestamp": "2026-11-08T03:00:00Z",
        "action": "isolate_host",
        "target": "WS-HQ-042",
        "justification": "Infección confirmada por troyano",
        "approval_token": "APR-abcdef1234",
        "ticket_id": "TKT-100",
        "result": "ok (simulado)",
    }
    mock_session.post.return_value = mock_resp

    result = client.execute_action(proposal, approval)

    assert result["result"] == "ok (simulado)"
    assert result["target"] == "WS-HQ-042"

    mock_session.post.assert_called_once()
    called_url, called_kwargs = mock_session.post.call_args
    assert called_url[0] == "http://test-soc-api:8000/containment/isolate_host"
    assert called_kwargs["json"] == {
        "target": "WS-HQ-042",
        "justification": "Infección confirmada por troyano",
        "approval_token": "APR-abcdef1234",
        "ticket_id": "TKT-100",
    }


def test_execute_action_without_approval_for_no_approval_action(
    client: ContainmentAPIClient, mock_session: MagicMock
) -> None:
    proposal = {
        "proposal_id": "PROP-002",
        "action": "block_ioc",
        "target": "198.51.100.23",
        "justification": "C2 server detectado",
        "ticket_id": "TKT-101",
    }

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "action": "block_ioc",
        "target": "198.51.100.23",
        "result": "ok (simulado)",
    }
    mock_session.post.return_value = mock_resp

    result = client.execute_action(proposal, approval=None)

    assert result["result"] == "ok (simulado)"
    called_url, called_kwargs = mock_session.post.call_args
    assert called_url[0] == "http://test-soc-api:8000/containment/block_ioc"
    assert called_kwargs["json"]["approval_token"] == ""


def test_execute_action_mismatch_proposal_approval(client: ContainmentAPIClient) -> None:
    proposal = ContainmentProposal(
        proposal_id="PROP-001",
        action="isolate_host",
        target="WS-HQ-042",
    )
    # Aprobación para otro objetivo
    approval = ApprovalResult(
        proposal_id="PROP-001",
        action="isolate_host",
        target="WS-OTHER-999",
        approver="analyst_n2",
        approval_token="APR-1234",
    )

    with pytest.raises(ValueError, match="no coincide"):
        client.execute_action(proposal, approval)


def test_execute_action_http_error_403(
    client: ContainmentAPIClient, mock_session: MagicMock
) -> None:
    proposal = ContainmentProposal(
        proposal_id="PROP-003",
        action="isolate_host",
        target="PLC-SORT01",
    )
    approval = ApprovalResult(
        proposal_id="PROP-003",
        action="isolate_host",
        target="PLC-SORT01",
        approver="n2",
        approval_token="APR-bad",
    )

    mock_resp = MagicMock()
    mock_resp.status_code = 403
    mock_resp.text = "política: el SOC no actúa sobre OT"
    mock_resp.json.return_value = {"detail": "política: el SOC no actúa sobre OT"}
    mock_session.post.return_value = mock_resp

    with pytest.raises(ContainmentHTTPError) as exc_info:
        client.execute_action(proposal, approval)

    assert exc_info.value.status_code == 403
    assert "OT" in exc_info.value.detail


def test_execute_action_http_error_400(
    client: ContainmentAPIClient, mock_session: MagicMock
) -> None:
    proposal = {"action": "invalid_action", "target": "X"}

    mock_resp = MagicMock()
    mock_resp.status_code = 400
    mock_resp.text = "acción no soportada"
    mock_resp.json.return_value = {"detail": "acción no soportada"}
    mock_session.post.return_value = mock_resp

    with pytest.raises(ContainmentHTTPError) as exc_info:
        client.execute_action(proposal)

    assert exc_info.value.status_code == 400


def test_execute_action_timeout(
    client: ContainmentAPIClient, mock_session: MagicMock
) -> None:
    proposal = ContainmentProposal(
        proposal_id="PROP-TIME",
        action="purge_email",
        target="malicious@phishing.example",
    )
    mock_session.post.side_effect = requests.exceptions.Timeout("Connection timed out")

    with pytest.raises(ContainmentTimeoutError) as exc_info:
        client.execute_action(proposal)

    assert isinstance(exc_info.value, TimeoutError)
    assert "Timeout" in str(exc_info.value)


def test_execute_action_connection_error(
    client: ContainmentAPIClient, mock_session: MagicMock
) -> None:
    proposal = ContainmentProposal(
        proposal_id="PROP-CONN",
        action="purge_email",
        target="malicious@phishing.example",
    )
    mock_session.post.side_effect = requests.exceptions.ConnectionError("Refused")

    with pytest.raises(ContainmentConnectionError):
        client.execute_action(proposal)


def test_execute_action_invalid_json(
    client: ContainmentAPIClient, mock_session: MagicMock
) -> None:
    proposal = ContainmentProposal(
        proposal_id="PROP-JSON",
        action="purge_email",
        target="msg-123",
    )
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = "<html>502 Bad Gateway</html>"
    mock_resp.json.side_effect = ValueError("Invalid JSON")
    mock_session.post.return_value = mock_resp

    with pytest.raises(ContainmentResponseError):
        client.execute_action(proposal)


def test_get_containment_log_success(
    client: ContainmentAPIClient, mock_session: MagicMock
) -> None:
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = [
        {"action": "isolate_host", "target": "WS-01", "result": "ok (simulado)"},
        {"action": "block_ioc", "target": "10.0.0.1", "result": "ok (simulado)"},
    ]
    mock_session.get.return_value = mock_resp

    logs = client.get_containment_log()

    assert len(logs) == 2
    assert logs[0]["action"] == "isolate_host"
    mock_session.get.assert_called_once_with(
        "http://test-soc-api:8000/containment/log",
        timeout=10.0,
    )


def test_get_containment_log_error(
    client: ContainmentAPIClient, mock_session: MagicMock
) -> None:
    mock_resp = MagicMock()
    mock_resp.status_code = 500
    mock_resp.text = "Internal Server Error"
    mock_session.get.return_value = mock_resp

    with pytest.raises(ContainmentHTTPError) as exc_info:
        client.get_containment_log()

    assert exc_info.value.status_code == 500
