"""Integración N1 con datos y endpoints oficiales; únicamente el LLM es simulado.

El transporte llama a las funciones de la API oficial en memoria para que pytest
no necesite puertos ni credenciales. La prueba HTTP/IA real se documenta aparte.
"""
import importlib.util
import json
from pathlib import Path
import re
import sqlite3

from fastapi import HTTPException
import pytest

from src.data.reference_repository import ReferenceRepository
from src.data.soc_api_client import SOCAPIClient
from src.data.ticket_repository import TicketRepository
from src.triage.ingestion.imports import import_records
from src.triage.models import Analysis, Finding, LogQuery, PolicySignals, ProposedAction, SearchPlan
from src.triage.output.validation import validate_ticket
from src.triage.triage_orchestrator import create_orchestrator

ROOT = Path(__file__).resolve().parents[1]
DATASET = ROOT / "RepositoriDeloitte"
AUTHORIZED = "ALR-20261005-000301"
MALICIOUS = "ALR-20261006-011826"


@pytest.fixture(scope="module")
def official_api():
    spec = importlib.util.spec_from_file_location("test_official_soc", DATASET / "06_herramientas/mock_soc_api.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def transport(monkeypatch, official_api):
    def get(client, endpoint, params=None, allow_404=False):
        from urllib.parse import unquote
        params = params or {}
        name, _, key = endpoint.strip("/").partition("/")
        key = unquote(key)
        try:
            if name == "alerts":
                return official_api.get_alert(key) if key else official_api.list_alerts(**params)
            if name == "assets":
                return official_api.get_asset(key)
            if name == "users":
                return official_api.get_user(key)
            if name == "changes":
                return official_api.changes(**params)
            if name == "intel":
                return official_api.intel(key)
            if name == "sandbox":
                return official_api.sandbox(key)
            if name == "logs":
                return official_api.search_logs(key, **params)
        except HTTPException as exc:
            if allow_404 and exc.status_code == 404:
                return None
            raise
        raise AssertionError(f"Endpoint inesperado: {endpoint}")
    monkeypatch.setattr(SOCAPIClient, "_get", get)


class ScriptedLLM:
    def __init__(self, mode="malicious", searches=None):
        self.mode, self.searches = mode, searches or []

    def generate_json(self, *, schema, prompt, **kwargs):
        if schema is SearchPlan:
            return SearchPlan(searches=self.searches)
        evidence = json.loads(re.search(r"<untrusted_evidence>\n(.*?)\n</untrusted_evidence>", prompt, re.S)[1])
        context = json.loads(re.search(r"<untrusted_context>\n(.*?)\n</untrusted_context>", prompt, re.S)[1])
        alert = json.loads(re.search(r"<untrusted_alert>\n(.*?)\n</untrusted_alert>", prompt, re.S)[1])
        refs = [e["event_id"] for e in evidence if e.get("event_id") in alert.get("related_events", [])][:1]
        if self.mode == "authorized":
            refs.append(next(c["id"] for c in context["changes"] if c["id"] == "CHG-2026-1031"))
        insufficient = self.mode == "insufficient"
        signals = {key: False for key in PolicySignals.model_fields}
        signals.update(authorized_activity=self.mode == "authorized",
                       malicious_execution=self.mode == "malicious",
                       execution_or_access_confirmed=self.mode == "malicious")
        return Analysis(
            title="Resultado de prueba de integración", summary="Análisis simulado sobre registros oficiales recuperados.",
            verdict="needs_more_info" if insufficient else "benign_true_positive" if self.mode == "authorized" else "true_positive",
            confidence=0.9, findings=[] if insufficient else [Finding(statement="Hallazgo de prueba con referencia recuperada.", evidence_ids=refs)],
            signals=PolicySignals(**signals), proposed_actions=[] if insufficient else [ProposedAction(
                action="review_logs", target="ticket", justification="Revisar las evidencias recuperadas.")],
            open_questions=["Confirmar el alcance de la actividad."] if insufficient else [],
        )


@pytest.fixture
def setup_service(tmp_path, transport):
    store = TicketRepository(tmp_path / "soc.sqlite3")
    api = SOCAPIClient("http://test-soc", store=store)
    service = create_orchestrator(api, store, llm=ScriptedLLM())
    yield api, store, service
    api.close()


@pytest.mark.parametrize("mode,alert_id,expected", [
    ("malicious", MALICIOUS, "true_positive"),
    # SYSTEM y CcmExec son compatibles con SCCM, pero no acreditan svc_sccm.
    ("authorized", AUTHORIZED, "needs_more_info"),
    ("insufficient", AUTHORIZED, "needs_more_info"),
])
def test_end_to_end_verdicts_and_schema(setup_service, mode, alert_id, expected):
    api, store, service = setup_service
    service.investigator.llm = ScriptedLLM(mode)
    events = []
    ticket = service.run(alert_id, on_event=events.append)
    assert ticket.verdict == expected
    assert ticket.executed_actions == []
    assert events[-1]["stage"] == "completed"
    record = store.get(ticket.ticket_id)
    assert validate_ticket(record["details"]["ticket"]) == ticket
    assert record["details"]["runbook_text"]
    assert record["details"]["context"]
    assert record["trace"]
    if mode == "authorized":
        assert any(e.event_id == "CHG-2026-1031" for e in ticket.evidence)
        assert any("cuenta ejecutora" in q for q in ticket.open_questions)
    elif mode == "malicious":
        assert ticket.escalation.escalate
        assert ticket.severity in {"high", "critical"}
    else:
        assert ticket.open_questions and not any(e.event_id for e in ticket.evidence)


def test_persistence_review_idempotence_and_explicit_reprocess(setup_service):
    api, store, service = setup_service
    ticket = service.run(AUTHORIZED)
    store.save_review(ticket.ticket_id, "close", "Revisado por el analista.")
    reopened = TicketRepository(store.db_path)
    assert reopened.get(ticket.ticket_id)["review"]["decision"] == "close"
    assert reopened.get(ticket.ticket_id)["review"]["note"] == "Revisado por el analista."
    assert service.run(AUTHORIZED).ticket_id == ticket.ticket_id
    assert reopened.stats()["tickets"] == 1
    newer = service.run(AUTHORIZED, reprocess=True)
    assert newer.ticket_id != ticket.ticket_id
    assert reopened.stats()["tickets"] == 2
    assert reopened.find_by_alert(AUTHORIZED)["id"] == newer.ticket_id
    assert reopened.get(ticket.ticket_id)["review"]["decision"] == "close"


def test_correlation_retrieves_real_alerts(setup_service, official_api):
    api, store, service = setup_service
    from src.triage.ingestion.entities import extract_entities
    alert = official_api.get_alert(MALICIOUS)
    related = service.correlator.find_related(alert, extract_entities(alert))
    assert related, "status vacío devolvería cero alertas en la API original"
    assert all(a["alert_id"] != MALICIOUS for a in related)


def test_search_windows_and_truncation(setup_service, monkeypatch):
    api, store, service = setup_service
    service.investigator.llm = ScriptedLLM(searches=[LogQuery(
        source="edr_events", query="WS-BCN-1174", reason="Comprobar actividad posterior",
        start="2026-09-01T00:00:00Z", end="2026-12-01T00:00:00Z")])
    original = api.search_logs
    queries = []
    def search(source, **kwargs):
        queries.append(kwargs)
        result = original(source, **kwargs)
        if kwargs["q"].casefold() == "ws-bcn-1174":
            return {**result, "truncated": True}
        return result
    monkeypatch.setattr(api, "search_logs", search)
    ticket = service.run(AUTHORIZED)
    assert any("Consulta incompleta" in q for q in ticket.open_questions)
    assert all(q["desde"] == "2026-10-04T07:56:30.000Z" for q in queries)
    assert all(q["hasta"] == "2026-10-06T07:56:30.000Z" for q in queries)


def test_llm_field_selector_queries_use_literal_soc_api_contract(setup_service):
    api, store, service = setup_service
    raw = SearchPlan(searches=[LogQuery(source="waf", query="src_ip:198.18.11.49", reason="Revisar el origen")])
    plan = service.investigator._sanitize_search_plan(raw)
    assert api.search_logs("waf", q=raw.searches[0].query)["count"] == 0
    result = service.evidence.search(plan)
    assert any(item.event_id == "WAF-0001840" for item in result)
    assert plan.searches[0].query == "198.18.11.49"


def test_import_alerts_and_tickets(setup_service, official_api):
    api, store, service = setup_service
    alert = {**official_api.get_alert(AUTHORIZED), "alert_id": "IMPORTED-TEST-001"}
    data = "\n".join([json.dumps(alert), json.dumps(alert), "invalid", json.dumps({"alert_id": "bad"})]).encode()
    result = import_records(data, kind="alerts", jsonl=True, api=api, store=store, references=service.references)
    assert (result["imported"], result["duplicates"], result["rejected"]) == (1, 1, 2)
    assert api.get_alert(alert["alert_id"]) == alert
    service.investigator.llm = ScriptedLLM("authorized")
    ticket = service.run(alert["alert_id"])
    assert ticket.verdict == "needs_more_info"
    existing = import_records(json.dumps(official_api.get_alert(AUTHORIZED)).encode(), kind="alerts", jsonl=False,
                              api=api, store=store, references=service.references)
    assert existing["duplicates"] == 1
    payload = (DATASET / "01_contexto/ticket_ejemplo.json").read_bytes()
    imported = import_records(payload, kind="tickets", jsonl=False, api=api, store=store, references=service.references)
    assert imported["imported"] == 1
    assert store.get("TKT-EJEMPLO-0001")["details"]["source"] == "imported"
    assert import_records(payload, kind="tickets", jsonl=False, api=api, store=store,
                          references=service.references)["duplicates"] == 1
    bad = json.loads(payload)
    bad["confidence"] = "0.5"  # Pydantic lo convertiría; el contrato oficial debe rechazarlo.
    assert import_records(json.dumps(bad).encode(), kind="tickets", jsonl=False, api=api, store=store,
                          references=service.references)["rejected"] == 1


def test_ten_alert_batch_preserves_successes_when_one_fails(setup_service, official_api, monkeypatch):
    api, store, service = setup_service
    sample = [json.loads(line) for line in (DATASET / "03_alertas/alertas_muestra_desarrollo.jsonl").read_text(encoding="utf-8").splitlines()[:10]]
    ids = [a["alert_id"] for a in sample]
    original = api.get_alert
    def get_alert(alert_id):
        if alert_id == ids[4]:
            raise ConnectionError("Consulta de prueba interrumpida")
        return original(alert_id)
    monkeypatch.setattr(api, "get_alert", get_alert)
    events = []
    tickets = service.run_batch(ids, on_event=events.append)
    assert len(tickets) == 9
    assert store.stats()["tickets"] == 9
    assert len(store.list_attempts()) == 1
    assert store.list_attempts()[0]["alert_id"] == ids[4]
    assert any(e.get("status") == "failed" for e in events)
    monkeypatch.setattr(api, "get_alert", original)
    assert len(service.run_batch(ids)) == 10
    assert store.stats()["tickets"] == 10


@pytest.mark.parametrize("failure", ["api", "llm", "save", "builder"])
def test_controlled_failure_and_retry(setup_service, monkeypatch, failure):
    api, store, service = setup_service
    events = []
    target, name = {"api": (api, "get_alert"), "llm": (service.investigator.llm, "generate_json"),
                    "save": (store, "save"), "builder": (service.tickets, "build")}[failure]
    original = getattr(target, name)
    def fail(*args, **kwargs):
        raise ValueError("Fallo de prueba controlado")
    monkeypatch.setattr(target, name, fail)
    with pytest.raises(ValueError):
        service.run(AUTHORIZED, on_event=events.append)
    assert not store.list_recent()
    assert store.list_attempts()[0]["status"] == "failed"
    assert not any(e["stage"] == "completed" for e in events)
    monkeypatch.setattr(target, name, original)
    assert service.run(AUTHORIZED)
    assert store.list_attempts() == []


def test_missing_llm_credentials(setup_service, monkeypatch):
    api, store, service = setup_service
    monkeypatch.delenv("ORNITH_API_KEY", raising=False)
    with pytest.raises(ValueError, match="ORNITH_API_KEY"):
        create_orchestrator(api, store)


def test_both_legacy_sqlite_formats_are_preserved(tmp_path, monkeypatch):
    import src.data.ticket_repository as module
    monkeypatch.setattr(module, "PROJECT_ROOT", tmp_path)
    with sqlite3.connect(tmp_path / "tickets.sqlite3") as con:
        con.execute("CREATE TABLE tickets (id TEXT PRIMARY KEY, alert_id TEXT, status TEXT, created_at TEXT, details TEXT, trace TEXT, decision TEXT, note TEXT)")
        con.execute("INSERT INTO tickets VALUES ('old-ui','old','new','2026','{}','[]','close','keep')")
    (tmp_path / "data").mkdir()
    with sqlite3.connect(tmp_path / "data/tickets.sqlite3") as con:
        con.execute("CREATE TABLE tickets (id TEXT PRIMARY KEY, alert_id TEXT, status TEXT, created_at TEXT, details TEXT, trace TEXT, review_decision TEXT, review_note TEXT, review_timestamp TEXT)")
        con.execute("INSERT INTO tickets VALUES ('old-data','old2','new','2026','{}','[]','escalate','keep2','2026-11-01')")
    store = TicketRepository()
    assert store.get("old-ui")["review"]["decision"] == "close"
    assert store.get("old-data")["review"]["decision"] == "escalate"
    assert store.stats()["legacy"] == 2
    assert store.processed_alert_ids() == set()
    assert (tmp_path / "data/tickets.sqlite3").exists()


def test_imported_alert_pagination_includes_last_page(setup_service, official_api):
    api, store, service = setup_service
    alert = {**official_api.get_alert(AUTHORIZED), "alert_id": "LOCAL-1"}
    store.import_alert(alert)
    total = len(official_api.ALERTS)
    page = api.list_alerts(limit=2, offset=total - 1)
    assert page["total"] == total + 1
    assert page["items"][-1]["alert_id"] == "LOCAL-1"


def test_change_calendar_uses_madrid_timezone_at_boundary(setup_service, monkeypatch):
    api, store, service = setup_service
    monkeypatch.setattr(api, "get_changes", lambda: [{"id": "CHG-BOUNDARY", "inicio": "2026-10-08 08:00", "fin": "2026-10-08 09:00", "titulo": "Inventario SCCM", "detalle": "svc_sccm ejecuta SCCM", "alcance": "Todos los puestos"}])
    from src.triage.models import EntityKeys
    alert = {"source_product": "EDR", "rule_name": "Inventario SCCM", "entities": {"hosts": ["WS-BCN-1174"], "users": ["svc_sccm"]}}
    inside = service.context.enrich({**alert, "created_at": "2026-10-08T06:30:00Z"}, EntityKeys())
    outside = service.context.enrich({**alert, "created_at": "2026-10-08T08:30:00Z"}, EntityKeys())
    assert inside.changes and not outside.changes


def dashboard_test_app(api, service, store):
    from streamlit.testing.v1 import AppTest
    app = AppTest.from_string('''
import streamlit as st
from src.interficie.dashboard import render_dashboard
render_dashboard(st.session_state.test_api, st.session_state.test_service, st.session_state.test_store)
''')
    app.session_state["test_api"] = api
    app.session_state["test_service"] = service
    app.session_state["test_store"] = store
    return app.run(timeout=60)


def widget_with_label(widgets, label):
    return next(widget for widget in widgets if widget.label == label)


def test_streamlit_investigation_filters_review_and_restart(setup_service):
    api, store, service = setup_service
    service.investigator.llm = ScriptedLLM("authorized")
    app = dashboard_test_app(api, service, store)
    assert not app.exception and not app.error
    assert app.metric[0].value == "11061"
    widget_with_label(app.text_input, "Buscar ID de alerta").set_value(AUTHORIZED).run()
    assert len(app.dataframe[0].value) == 1
    widget_with_label(app.button, "Seleccionar las primeras diez").click().run()
    widget_with_label(app.button, "Investigar selección").click().run(timeout=60)
    assert not app.exception and not app.error
    assert app.metric[0].value == "11060"
    assert store.find_by_alert(AUTHORIZED)
    app.sidebar.radio[0].set_value("Tickets e investigación").run()
    assert not app.exception and not app.error
    assert any("TRIAGE-" in caption.value for caption in app.caption)
    widget_with_label(app.selectbox, "Decisión del analista").set_value("close")
    widget_with_label(app.text_area, "Observaciones del analista").set_value("Revisión desde Streamlit")
    widget_with_label(app.button, "Guardar revisión humana").click().run()
    ticket_id = store.find_by_alert(AUTHORIZED)["id"]
    assert store.get(ticket_id)["review"]["decision"] == "close"
    app = dashboard_test_app(api, service, TicketRepository(store.db_path))
    app.sidebar.radio[0].set_value("Tickets e investigación").run()
    assert not app.exception and not app.error
    assert widget_with_label(app.text_area, "Observaciones del analista").value == "Revisión desde Streamlit"
    app.sidebar.radio[0].set_value("Importar").run()
    assert len(app.get("file_uploader")) == 1


def test_streamlit_shows_controlled_llm_failure(setup_service, monkeypatch):
    api, store, service = setup_service
    def fail(*args, **kwargs):
        raise ValueError("Respuesta LLM inválida")
    monkeypatch.setattr(service.investigator.llm, "generate_json", fail)
    app = dashboard_test_app(api, service, store)
    widget_with_label(app.text_input, "Buscar ID de alerta").set_value(AUTHORIZED).run()
    widget_with_label(app.button, "Seleccionar las primeras diez").click().run()
    widget_with_label(app.button, "Investigar selección").click().run(timeout=60)
    assert not app.exception
    assert not store.list_recent()
    assert app.session_state["batch_results"][0]["Resultado"] == "Fallida"
    assert store.list_attempts()[0]["status"] == "failed"


def test_streamlit_ticket_access_when_api_is_unavailable(setup_service, monkeypatch):
    api, store, service = setup_service
    ticket = service.run(AUTHORIZED)
    import src.interficie.dashboard as dashboard
    def fail(*args):
        raise ConnectionError("API no disponible")
    monkeypatch.setattr(dashboard, "load_alert_index", fail)
    app = dashboard_test_app(api, service, store)
    assert app.warning and not app.exception
    assert app.metric[0].label == "Pendientes locales"
    app.sidebar.radio[0].set_value("Tickets e investigación").run()
    assert not app.exception and not app.error
    assert any(ticket.ticket_id in caption.value for caption in app.caption)
