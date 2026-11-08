"""Recorrido completo con servicios reales y API oficial en memoria.

Solo el LLM y las identidades son dobles de ensayo. La contención escribe en
un fichero temporal; nunca en el dataset ni en la API usada por la demo visual.
"""
from pathlib import Path

import pytest

from test_level2_integration import ASGITransport, LATRO, IDS, integrated_n1
from src.orchestrator.product_services import ProductServices
from src.triage.level3.incident_report_builder import validate_report
from src.triage.level4.level4_orchestrator import SQLiteResponseStore


@pytest.fixture
def product(integrated_n1, tmp_path, monkeypatch):
    api, store, n1, tickets, investigations, transport, llm = integrated_n1
    if not isinstance(transport, ASGITransport):
        pytest.skip("La contención automatizada solo se prueba con transporte aislado")
    for route in transport.app.routes:
        if getattr(route, "path", "") == "/containment/{action}":
            monkeypatch.setitem(route.endpoint.__globals__, "LOGFILE", str(tmp_path / "containment.jsonl"))
    service = ProductServices(api_url="http://127.0.0.1:1", n1_path=str(store.db_path),
        n2_path=str(tmp_path / "n2.sqlite3"), response_path=str(tmp_path / "response.sqlite3"),
        dataset_root=str(Path(__file__).resolve().parents[1] / "RepositoriDeloitte"), demo_mode=True)
    service.api.session.mount("http://127.0.0.1:1/", ASGITransport(transport.app))
    service.containment.session.mount("http://127.0.0.1:1/", ASGITransport(transport.app))
    return service, n1, llm, transport.app


def test_saved_n1_to_n3_and_authorized_response_survive_reload(product):
    service, n1, llm, app = product
    calls = llm.calls
    tickets = service.correlate(IDS)
    assert llm.calls == calls
    assert len(tickets) == 3  # Cadena, minería e intento independiente.
    incident = next(t for t in tickets if set(t.alert_ids) == LATRO)
    report = service.investigate(incident.ticket_id, before_days=0, after_days=0,
                                 analyst_reason="Prueba de integración explícita")
    validate_report(report)
    assert report.source_ticket_ids == sorted(service.n2.get(incident.ticket_id)["details"]["source_ticket_ids"])
    assert report.timeline and report.scope_analysis.hosts
    assert service.investigate(incident.ticket_id).to_dict() == report.to_dict()
    assert [op["status"] for op in service.responses.list_operations()] == ["completed", "completed"]
    proposals = service.level4.prepare(incident.ticket_id)
    assert proposals and all(p.evidence for p in proposals)
    proposal = next(p for p in proposals if p.action == "isolate_host" and p.target == "WS-BCN-1770")
    with pytest.raises(PermissionError):
        service.level4.execute_approved(proposal.proposal_id)
    with pytest.raises(PermissionError):
        service.decide(proposal.proposal_id, actor="analyst_n1", approved=True, reason="Rol incorrecto")
    assert service.level4.get_state(proposal.proposal_id).status == "pending"
    service.decide(proposal.proposal_id, actor="analyst_n2", approved=True, reason="Autorizar solo esta contención simulada")
    result = service.level4.execute_approved(proposal.proposal_id)
    assert result.success
    assert service.level4.execute_approved(proposal.proposal_id) == result
    reloaded = SQLiteResponseStore(service.responses.db_path)
    assert reloaded.get(proposal.proposal_id).status == "succeeded"
    assert reloaded.load_report(incident.ticket_id).to_dict() == report.to_dict()
    assert "approval_token" not in reloaded.get(proposal.proposal_id).model_dump_json()
    endpoint = next(r.endpoint for r in app.routes if getattr(r, "path", "") == "/containment/log")
    assert len(endpoint()) == 1
    assert all(e.evidence for e in report.timeline)

    # Nueva versión, conservando el informe anterior y su ejecución, para ensayar rechazo.
    revised = report.model_copy(update={"title": report.title + " · fixture de revisión"})
    service.responses.store_report(revised)
    rejected = next(p for p in service.level4.prepare(incident.ticket_id) if p.action == "isolate_host" and p.target == "WS-BCN-1770")
    state = service.decide(rejected.proposal_id, actor="analyst_n2", approved=False, reason="Rechazo explícito de ensayo")
    assert state.status == "rejected"
    with pytest.raises(PermissionError):
        service.level4.execute_approved(rejected.proposal_id)
    with pytest.raises(PermissionError):
        service.decide(rejected.proposal_id, actor="analyst_n2", approved=True, reason="No reabrir")
    assert len(endpoint()) == 1
    assert len(service.responses.list_reports(incident_id=incident.ticket_id)) == 2


def test_n2_source_versions_and_failed_operations_are_explicit(product):
    service, n1, llm, _ = product
    first = service.correlate(sorted(LATRO))[0]
    originals = service.n2.get(first.ticket_id)["details"]["source_ticket_ids"]
    changed = n1.run(sorted(LATRO)[0], reprocess=True)
    second = service.correlate(sorted(LATRO))[0]
    assert first.ticket_id != second.ticket_id
    assert service.n2.get(first.ticket_id)["details"]["source_ticket_ids"] == originals
    assert changed.ticket_id in service.n2.get(second.ticket_id)["details"]["source_ticket_ids"]
    with pytest.raises(ValueError, match="N1"):
        service.correlate(["MISSING-ALERT"])
    assert service.responses.list_operations()[0]["status"] == "failed"


def test_restart_requires_fresh_approval_and_preserves_decisions(product):
    service, _, _, app = product
    incident = service.correlate(sorted(LATRO))[0]
    service.investigate(incident.ticket_id, before_days=0, after_days=0, analyst_reason="Ensayo")
    proposal = next(p for p in service.level4.prepare(incident.ticket_id) if p.action == "isolate_host" and p.target == "WS-BCN-1770")
    service.decide(proposal.proposal_id, actor="analyst_n2", approved=True, reason="Primera aprobación")
    original = service.level4.get_state(proposal.proposal_id).approval.approval_id
    # Instancia nueva: conserva SQLite pero carece de la sesión de tokens.
    restarted = ProductServices(api_url="http://127.0.0.1:1", n1_path=str(service.n1.db_path),
        n2_path=str(service.n2.db_path), response_path=str(service.responses.db_path),
        dataset_root=str(service.references.dataset_root), demo_mode=True)
    restarted.api.session.mount("http://127.0.0.1:1/", ASGITransport(app))
    restarted.containment.session.mount("http://127.0.0.1:1/", ASGITransport(app))
    with pytest.raises(PermissionError):
        restarted.level4.execute_approved(proposal.proposal_id)
    renewed = restarted.decide(proposal.proposal_id, actor="analyst_n2", approved=False, reason="Renovación tras reinicio", restart=True)
    assert renewed.status == "pending" and not renewed.approval.decision_ids
    assert renewed.approval.approval_id != original
    restarted.decide(proposal.proposal_id, actor="analyst_n2", approved=True, reason="Nueva aprobación explícita")
    assert restarted.level4.execute_approved(proposal.proposal_id).success


def test_server_requires_n2_and_the_owner_of_that_target(product, monkeypatch):
    from src.orchestrator.product_services import demo_reviewers
    service, _, _, _ = product
    incident = service.correlate(sorted(LATRO))[0]
    service.investigate(incident.ticket_id, before_days=0, after_days=0, analyst_reason="Ensayo")
    # FS01 no declara propietario en el inventario oficial: permanece manual.
    manual = next(p for p in service.level4.prepare(incident.ticket_id) if p.target == "FS01")
    assert not manual.executable
    # Fixture CMDB complementaria y explícita para verificar doble aprobación.
    original_lookup = service.api.get_asset
    def fixture_asset(key):
        asset = original_lookup(key)
        return {**asset, "owner_upn": "owner.fixture@tarvia.example"} if asset and asset["hostname"] == "FS01" else asset
    monkeypatch.setattr(service.api, "get_asset", fixture_asset)
    proposal = next(p for p in service.level4.prepare(incident.ticket_id)
                    if p.action == "isolate_host" and "service_owner" in p.required_approvals)
    partial = service.decide(proposal.proposal_id, actor="analyst_n2", approved=True, reason="Primera aprobación N2")
    assert partial.status == "pending"
    with pytest.raises(PermissionError):
        service.level4.execute_approved(proposal.proposal_id)
    with pytest.raises(PermissionError):
        service.decide(proposal.proposal_id, actor="director_financiero", approved=True, reason="Responsable de otro servicio")
    actor = next(key for key in demo_reviewers(proposal) if key.startswith("owner:"))
    final = service.decide(proposal.proposal_id, actor=actor, approved=True, reason="Responsable específico de este servidor")
    assert final.status == "approved"
    assert set(final.approval.approved_roles) >= {"N2", "service_owner"}


def _workflow_app(service, view):
    from streamlit.testing.v1 import AppTest
    app = AppTest.from_string(f'''
import streamlit as st
from src.interficie.workflow_views import render_level{view}
render_level{view}(st.session_state.test_product)
''')
    app.session_state["test_product"] = service
    return app.run(timeout=60)


def _widget(widgets, label):
    return next(item for item in widgets if item.label == label)


def test_large_n3_report_reaches_download_and_response_controls(product):
    service, _, _, _ = product
    incident = service.correlate(sorted(LATRO))[0]
    report = service.investigate(incident.ticket_id, before_days=0, after_days=0, analyst_reason="Ensayo")
    # Miles de notas habían bloqueado el renderizado de los botones finales.
    large = report.model_copy(update={"limitations": ["Cobertura parcial de ensayo"] * 3000,
                                      "open_questions": ["Revisión pendiente de ensayo"] * 3000})
    service.responses.store_report(large)
    app = _workflow_app(service, 3)
    assert not app.exception
    assert len(app.get("download_button")) == 1
    assert _widget(app.button, "Abrir respuesta N4")
    assert max(len(frame.value) for frame in app.dataframe) <= 100
    _widget(app.number_input, "Página de limitaciones").set_value(120).run(timeout=60)
    assert not app.exception
    assert _widget(app.number_input, "Página de limitaciones").value == 120


def test_response_selection_and_confirmations_survive_state_transitions(product):
    service, _, _, _ = product
    incident = service.correlate(sorted(LATRO))[0]
    service.investigate(incident.ticket_id, before_days=0, after_days=0, analyst_reason="Ensayo")
    proposal = next(p for p in service.level4.prepare(incident.ticket_id)
                    if p.action == "isolate_host" and p.target == "WS-BCN-1770")
    app = _workflow_app(service, 4)
    _widget(app.selectbox, "Abrir propuesta").set_value(proposal.proposal_id).run()
    _widget(app.selectbox, "Identidad de ensayo").set_value("analyst_n2")
    _widget(app.text_area, "Motivo de la decisión").set_value("Aprobación explícita de ensayo")
    _widget(app.checkbox, "Confirmo esta decisión de ensayo para la acción y el objetivo mostrados").check()
    _widget(app.button, "Aprobar propuesta").click().run(timeout=60)
    assert not app.exception and not app.error
    assert service.level4.get_state(proposal.proposal_id).status == "approved"
    assert _widget(app.selectbox, "Abrir propuesta").value == proposal.proposal_id
    assert not _widget(app.checkbox, "Confirmo esta decisión de ensayo para la acción y el objetivo mostrados").value
    assert _widget(app.button, "Ejecutar acción autorizada").disabled
    _widget(app.checkbox, "Confirmo ejecutar esta acción en la API SOC simulada").check().run()
    assert not _widget(app.button, "Ejecutar acción autorizada").disabled
    _widget(app.text_area, "Motivo de la decisión").set_value("Renovar autorización; exigir votos nuevos")
    _widget(app.checkbox, "Confirmo esta decisión de ensayo para la acción y el objetivo mostrados").check()
    _widget(app.button, "Renovar solicitud y repetir aprobaciones").click().run(timeout=60)
    assert not app.exception and not app.error
    assert _widget(app.selectbox, "Abrir propuesta").value == proposal.proposal_id
    assert service.level4.get_state(proposal.proposal_id).status == "pending"
    assert not _widget(app.checkbox, "Confirmo ejecutar esta acción en la API SOC simulada").value
    assert _widget(app.button, "Ejecutar acción autorizada").disabled
