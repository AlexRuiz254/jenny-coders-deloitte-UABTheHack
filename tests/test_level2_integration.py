"""Integración parcial con dataset/API/SQLite reales y LLM explícitamente simulado.

No es una prueba de IA real ni de red HTTP. El transporte ejecuta FastAPI ASGI
original en memoria. El caso de persistencia N2 requiere importar el módulo de
Persona 3; su incompatibilidad conocida con Python 3.13 se informa como XFAIL.
"""
import asyncio
from collections import Counter
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys
from urllib.parse import unquote, urlsplit

import pytest
import requests
from requests.adapters import BaseAdapter

from src.data.soc_api_client import SOCAPIClient
from src.data.ticket_repository import TicketRepository
from src.triage.level2.incident_decision_service import AlertInvestigationInput, IncidentDecisionService
from src.triage.level2.incident_grouper import IncidentGrouper
from src.triage.level2.level2_orchestrator import Level2Orchestrator
from src.triage.models import Analysis, Finding, PolicySignals, SearchPlan
from src.triage.output.validation import validate_ticket
from src.triage.triage_orchestrator import create_orchestrator

ROOT = Path(__file__).resolve().parents[1]
LATRO = {"ALR-20261009-011790", "ALR-20261009-011791", "ALR-20261009-011792"}
MINER = {"ALR-20261006-011825", "ALR-20261006-011826"}
ISOLATED = "ALR-20261005-000130"
IDS = sorted(LATRO | MINER | {ISOLATED})


class ASGITransport(BaseAdapter):
    def __init__(self, app):
        self.app = app
        self.calls = Counter()

    def send(self, request, **kwargs):
        url = urlsplit(request.url)
        self.calls[unquote(url.path)] += 1
        scope = {
            "type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1",
            "method": request.method, "scheme": url.scheme, "path": unquote(url.path),
            "raw_path": url.path.encode(), "query_string": url.query.encode(), "root_path": "",
            "headers": [(k.lower().encode(), v.encode()) for k, v in request.headers.items()],
            "client": ("127.0.0.1", 0), "server": ("dataset", 80),
        }
        messages = []

        async def receive():
            return {"type": "http.request", "body": b"", "more_body": False}

        async def send(message):
            messages.append(message)

        asyncio.run(self.app(scope, receive, send))
        response = requests.Response()
        response.request, response.url = request, request.url
        start = next(m for m in messages if m["type"] == "http.response.start")
        response.status_code = start["status"]
        response._content = b"".join(m.get("body", b"") for m in messages if m["type"] == "http.response.body")
        return response

    def close(self):
        pass


class ScriptedLLM:
    """Doble de prueba: nunca emite conclusiones de ataque o autorización."""
    def __init__(self):
        self.calls = 0

    def generate_json(self, *, schema, prompt, **kwargs):
        self.calls += 1
        if schema is SearchPlan:
            return SearchPlan(searches=[])
        evidence = json.loads(re.search(r"<untrusted_evidence>\n(.*?)\n</untrusted_evidence>", prompt, re.S)[1])
        refs = [item["event_id"] for item in evidence if item.get("event_id") and item["source"] != "changes"][:3]
        return Analysis(
            title="Prueba de integración con LLM simulado", summary="No es un análisis IA real.",
            verdict="needs_more_info", confidence=.4,
            findings=[Finding(statement="Referencia recuperada del dataset en esta prueba.", evidence_ids=refs)] if refs else [],
            signals=PolicySignals(**{key: False for key in PolicySignals.model_fields}),
            proposed_actions=[], open_questions=["Prueba sin IA real: no concluir malicia ni autorización."],
        )


@pytest.fixture(scope="module")
def integrated_n1(tmp_path_factory):
    spec = importlib.util.spec_from_file_location("phase2_official_api", ROOT / "RepositoriDeloitte/06_herramientas/mock_soc_api.py")
    official = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(official)
    store = TicketRepository(tmp_path_factory.mktemp("n1-phase2") / "n1.sqlite3")
    api = SOCAPIClient("http://dataset", store=store)
    transport = ASGITransport(official.app)
    api.session.mount("http://dataset", transport)
    llm = ScriptedLLM()
    n1 = create_orchestrator(api, store, llm=llm)
    tickets = [n1.run(key) for key in IDS]
    investigations = []
    for ticket in tickets:
        data = store.get(ticket.ticket_id)["details"]
        investigations.append(AlertInvestigationInput.model_validate({
            "alert_id": ticket.alert_ids[0], "alert": data["alert"], "ticket": ticket,
            "analysis": data["analysis"], "context": data["context"],
            "evidence": data["evidence"], "verdict_decision": data["verdict"],
        }))
    yield api, store, n1, tickets, investigations, transport, llm
    api.close()


def test_real_artifacts_groups_and_joint_decision(integrated_n1):
    api, store, n1, tickets, investigations, transport, llm = integrated_n1
    groups = IncidentGrouper().group([i.alert for i in investigations], tickets)
    assert {frozenset(g.alert_ids) for g in groups} == {frozenset(LATRO), frozenset(MINER), frozenset({ISOLATED})}
    assert all(transport.calls[f"/alerts/{key}"] == 1 for key in IDS)
    by_id = {i.alert_id: i for i in investigations}
    for group in groups:
        decision = IncidentDecisionService().decide(group, investigations=[by_id[key] for key in group.alert_ids])
        assert set(decision.alert_ids) == set(group.alert_ids)
        assert decision.verdict_rationale and decision.severity_rationale
        assert decision.escalation is not None
        known = {e.event_id for key in group.alert_ids for e in by_id[key].evidence}
        assert set(decision.key_evidence_ids) <= known
    assert store.stats()["tickets"] == len(IDS)
    before = llm.calls
    assert [n1.run(key).ticket_id for key in IDS] == [ticket.ticket_id for ticket in tickets]
    assert llm.calls == before  # Reutilización real de SQLite, no más respuestas simuladas.


def test_real_missing_alert(integrated_n1):
    api, store, n1, *rest = integrated_n1
    count = store.stats()["tickets"]
    with pytest.raises(LookupError, match="NO-EXISTE"):
        n1.run("NO-EXISTE")
    assert store.stats()["tickets"] == count


def test_shared_repository_rejects_n1_n2_duplicate_scope(integrated_n1):
    api, store, n1, tickets, investigations, *rest = integrated_n1
    merged = tickets[0].model_copy(update={"ticket_id": "INC-CONTRACT-TEST", "alert_ids": IDS})
    with pytest.raises(ValueError, match="ya tiene"):
        store.save({"id": merged.ticket_id, "alert_id": IDS[0],
                    "details": {"ticket": merged.model_dump(mode="json", exclude_none=True)}}, [])


def test_real_n2_ticket_persistence_and_idempotency_if_service_imports(integrated_n1, tmp_path):
    probe = subprocess.run([sys.executable, "-B", "-c",
                            "from src.triage.level2.incident_ticket_service import IncidentTicketService"],
                           capture_output=True, text=True, cwd=ROOT)
    if probe.returncode and "_compat_forward_eval() got multiple values" in probe.stderr:
        pytest.xfail("Bloqueo externo: IncidentTicketService altera ForwardRef de forma incompatible con Python 3.13")
    assert probe.returncode == 0, probe.stderr
    from src.triage.level2.incident_ticket_service import IncidentTicketService
    api, store, n1, source, investigations, transport, llm = integrated_n1
    n2_store = TicketRepository(tmp_path / "n2.sqlite3")
    runner = Level2Orchestrator(triage=n1, api=api, grouper=IncidentGrouper(),
                                decisions=IncidentDecisionService(),
                                tickets=IncidentTicketService(repository=n2_store))
    first = runner.run(IDS)
    second = runner.run(list(reversed(IDS)))
    assert {t.ticket_id for t in first} == {t.ticket_id for t in second}
    assert len(first) == 3 and n2_store.stats()["tickets"] == 3
    assert store.stats()["tickets"] == len(IDS)
    for ticket in first:
        record = n2_store.get(ticket.ticket_id)
        assert validate_ticket(record["details"]["ticket"]) == ticket
        assert record["trace"][0]["source_ticket_ids"]
        assert "Justificación de agrupación" in ticket.summary
        assert ticket.evidence
