"""Tests unitarios para ApprovalRepository (Fase 4 - N4).

Verifica la persistencia SQLite, atomicidad, recuperación por ID y propuesta,
prevención de duplicados y filtros por estado.
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import pytest

from src.triage.level4.approval_models import ApprovalResult
from src.triage.level4.approval_repository import ApprovalRepository


@pytest.fixture
def repo(tmp_path: Path) -> ApprovalRepository:
    """Instancia del repositorio sobre archivo SQLite temporal."""
    db_file = tmp_path / "test_approvals.sqlite3"
    return ApprovalRepository(db_path=db_file)


@pytest.fixture
def sample_approval() -> ApprovalResult:
    return ApprovalResult(
        approval_id="APP-TEST-001",
        proposal_id="PROP-101",
        action="isolate_host",
        target="WS-HQ-042",
        status="pending",
        reviewer_id="",
        proposal_hash="hash1234567890ab",
        required_approvers=["N2"],
        requester_id="analyst_n1",
        ticket_id="TKT-001",
    )


def test_init_memory_and_file(tmp_path: Path) -> None:
    # Probar inicialización en memoria
    mem_repo = ApprovalRepository(db_path=":memory:")
    assert mem_repo.is_memory is True
    mem_repo.close()

    # Probar inicialización en disco
    disk_file = tmp_path / "disk.sqlite3"
    disk_repo = ApprovalRepository(db_path=disk_file)
    assert disk_repo.db_path.exists()
    disk_repo.close()


def test_save_and_get(repo: ApprovalRepository, sample_approval: ApprovalResult) -> None:
    saved = repo.save(sample_approval)
    assert saved.approval_id == "APP-TEST-001"

    retrieved = repo.get("APP-TEST-001")
    assert retrieved is not None
    assert retrieved.approval_id == "APP-TEST-001"
    assert retrieved.proposal_id == "PROP-101"
    assert retrieved.action == "isolate_host"
    assert retrieved.target == "WS-HQ-042"
    assert retrieved.status == "pending"
    assert retrieved.proposal_hash == "hash1234567890ab"
    assert retrieved.required_approvers == ["N2"]
    assert retrieved.requester_id == "analyst_n1"
    assert retrieved.ticket_id == "TKT-001"


def test_save_duplicate_raises_error(
    repo: ApprovalRepository, sample_approval: ApprovalResult
) -> None:
    repo.save(sample_approval)
    with pytest.raises(ValueError, match="duplicada"):
        repo.save(sample_approval)


def test_get_nonexistent(repo: ApprovalRepository) -> None:
    assert repo.get("NON_EXISTENT") is None
    assert repo.get("") is None


def test_get_by_proposal(repo: ApprovalRepository) -> None:
    app1 = ApprovalResult(
        approval_id="APP-P1-01",
        proposal_id="PROP-MULTI",
        action="isolate_host",
        target="WS-01",
        status="rejected",
        proposal_hash="h1",
    )
    app2 = ApprovalResult(
        approval_id="APP-P1-02",
        proposal_id="PROP-MULTI",
        action="isolate_host",
        target="WS-01",
        status="approved",
        proposal_hash="h1",
    )
    repo.save(app1)
    repo.save(app2)

    history = repo.get_by_proposal("PROP-MULTI")
    assert len(history) == 2
    ids = {h.approval_id for h in history}
    assert ids == {"APP-P1-01", "APP-P1-02"}

    assert repo.get_by_proposal("PROP-EMPTY") == []


def test_update_existing(repo: ApprovalRepository, sample_approval: ApprovalResult) -> None:
    repo.save(sample_approval)

    sample_approval.status = "approved"
    sample_approval.reviewer_id = "analyst_n2"
    sample_approval.approval_token = "APR-token123"
    sample_approval.decision_timestamp = datetime.now(timezone.utc)
    sample_approval.reason = "Aprobado por SOC N2"

    updated = repo.update(sample_approval)
    assert updated.status == "approved"

    retrieved = repo.get(sample_approval.approval_id)
    assert retrieved is not None
    assert retrieved.status == "approved"
    assert retrieved.reviewer_id == "analyst_n2"
    assert retrieved.approval_token == "APR-token123"
    assert retrieved.reason == "Aprobado por SOC N2"


def test_update_nonexistent_raises_key_error(
    repo: ApprovalRepository, sample_approval: ApprovalResult
) -> None:
    with pytest.raises(KeyError):
        repo.update(sample_approval)


def test_list_by_status_and_list_all(repo: ApprovalRepository) -> None:
    app_pending = ApprovalResult(
        approval_id="APP-PEND",
        proposal_id="P1",
        action="block_ioc",
        target="1.1.1.1",
        status="pending",
        proposal_hash="h",
    )
    app_approved = ApprovalResult(
        approval_id="APP-APPR",
        proposal_id="P2",
        action="block_ioc",
        target="2.2.2.2",
        status="approved",
        proposal_hash="h",
    )
    repo.save(app_pending)
    repo.save(app_approved)

    pending_list = repo.list_by_status("pending")
    assert len(pending_list) == 1
    assert pending_list[0].approval_id == "APP-PEND"

    approved_list = repo.list_by_status("approved")
    assert len(approved_list) == 1
    assert approved_list[0].approval_id == "APP-APPR"

    all_list = repo.list_all()
    assert len(all_list) == 2


def test_persistence_across_separate_instances(tmp_path: Path) -> None:
    db_file = tmp_path / "persistence.sqlite3"

    # Instancia 1 guarda
    repo1 = ApprovalRepository(db_path=db_file)
    app = ApprovalResult(
        approval_id="APP-PERSIST",
        proposal_id="P-PER",
        action="purge_email",
        target="msg-1",
        status="approved",
        proposal_hash="h_per",
    )
    repo1.save(app)
    repo1.close()

    # Instancia 2 recupera
    repo2 = ApprovalRepository(db_path=db_file)
    loaded = repo2.get("APP-PERSIST")
    assert loaded is not None
    assert loaded.approval_id == "APP-PERSIST"
    assert loaded.status == "approved"
    repo2.close()
