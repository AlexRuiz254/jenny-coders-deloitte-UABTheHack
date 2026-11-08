"""Reglas reales de agrupación; no requieren red, IA ni persistencia."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from itertools import permutations
import json
from pathlib import Path
from unittest.mock import patch

import pytest

from src.triage.level2.incident_grouper import IncidentGrouper
from src.triage.level2.incident_decision_service import IncidentGroup
from src.triage.models import Escalation, IntelEntry, Ticket, TicketEvidence
from src.triage.ingestion.entities import extract_indicators


def alert(key, *, hour=0, host="WS-1", user="alice", **entities):
    return {"alert_id": key, "created_at": (
        datetime(2026, 10, 10, tzinfo=timezone.utc) + timedelta(hours=hour)
    ).isoformat(), "entities": {
        "hosts": [host] if host else [], "users": [user] if user else [], **entities,
    }, "related_events": []}


def ticket(item, *, bad=(), events=()):
    return Ticket(
        ticket_id="N1-" + item["alert_id"], alert_ids=[item["alert_id"]],
        title="Fixture", summary="Prueba sin IA", verdict="needs_more_info",
        confidence=.5, severity="medium", recommended_actions=[],
        escalation=Escalation(escalate=False),
        evidence=[TicketEvidence(source="edr_events", event_id=e, finding="Fixture") for e in events],
        enrichment=[IntelEntry(indicator=i, type="domain", source="TIP", result=json.dumps(
            {"value": i, "reputation": "malicious"}
        )) for i in bad],
    )


def groups(items, tickets=None, **kwargs):
    return IncidentGrouper(**kwargs).group(items, tickets or [ticket(a) for a in items])


def test_two_related_alerts_share_a_real_event():
    a, b = alert("A"), alert("B", hour=1, host="OTHER", user="other")
    a["related_events"] = b["related_events"] = ["EDR-123"]
    result = groups([a, b])
    assert [g.alert_ids for g in result] == [["A", "B"]]
    assert isinstance(result[0], IncidentGroup)
    assert "EDR-123" in result[0].correlation_reason
    assert result[0].justification == result[0].correlation_reason


def test_three_alerts_one_chain_with_explainable_links():
    items = [alert("A"), alert("B", hour=1), alert("C", hour=2)]
    items[0]["related_events"] = ["EML-1"]
    items[1]["related_events"] = ["EML-1", "EDR-2"]
    items[2]["related_events"] = ["EDR-2"]
    result = groups(items)
    assert len(result) == 1 and result[0].alert_ids == ["A", "B", "C"]
    assert len(result[0].shared_entities["relations"]) == 2


@pytest.mark.parametrize("entities", [
    {}, {"ips": ["8.8.8.8"]}, {"domains": ["google.com"]},
    {"hashes": ["a" * 64]},
])
def test_superficial_coincidences_do_not_group(entities):
    a, b = alert("A", host="HOST-A", **entities), alert("B", host="HOST-B", **entities)
    assert len(groups([a, b])) == 2


def test_same_host_and_user_alone_are_insufficient():
    assert len(groups([alert("A"), alert("B")])) == 2


def test_shared_background_evidence_does_not_merge_incidents():
    items = [alert("A"), alert("B")]
    assert len(groups(items, [ticket(a, events=["EDR-999"]) for a in items])) == 2


def test_file_hash_host_and_user_form_a_relation():
    items = [alert("A", files=[{"sha256": "a" * 64}]),
             alert("B", hour=1, hashes=["a" * 64])]
    assert len(groups(items)) == 1


def test_hash_requires_victim_and_corroboration():
    items = [alert("A", host=None, files=[{"sha256": "a" * 64}]),
             alert("B", hour=1, host=None, hashes=["a" * 64])]
    assert len(groups(items)) == 2
    assert len(groups(items, [ticket(a, bad=["a" * 64]) for a in items])) == 1


def test_tip_domain_also_requires_host_and_user():
    items = [alert("A", domains=["c2.example"]), alert("B", domains=["c2.example"])]
    assert len(groups(items)) == 2
    assert len(groups(items, [ticket(a, bad=["c2.example"]) for a in items])) == 1
    items[1]["entities"]["hosts"] = ["OTHER"]
    assert len(groups(items, [ticket(a, bad=["c2.example"]) for a in items])) == 2


@pytest.mark.parametrize("field", ["message_id", "session_id", "ai_session"])
def test_explicit_binding_links_observations(field):
    items = [alert("A"), alert("B")]
    for a in items:
        a["evidence"] = {field: "unique-observation-123"}
    assert len(groups(items)) == 1


def test_placeholder_bindings_and_approved_changes_do_not_link():
    for value in [" UNKNOWN ", "-", "...", "ninguno", "(12 cuentas)"]:
        items = [alert("A"), alert("B")]
        for a in items:
            a["evidence"] = {"session_id": value}
            a["entities"]["sessions"] = [value]
            a["related_events"] = ["CHG-123"]
        assert len(groups(items)) == 2


def test_duplicate_alerts_are_deduplicated():
    a = alert("A")
    assert groups([a, deepcopy(a)], [ticket(a), ticket(a)])[0].alert_ids == ["A"]


def test_single_and_empty_inputs():
    assert IncidentGrouper().group([], []) == []
    assert groups([alert("A")])[0].alert_ids == ["A"]


def test_missing_or_unknown_investigations_are_explicit_errors():
    a, b = alert("A"), alert("B")
    with pytest.raises(ValueError, match="Faltan"):
        IncidentGrouper().group([a, b], [ticket(a)])
    with pytest.raises(ValueError, match="desconocida"):
        IncidentGrouper().group([a], [ticket(b)])


def test_conflicting_duplicate_is_rejected():
    a = alert("A")
    with pytest.raises(ValueError, match="contradictorias"):
        groups([a, alert("A", user="other")], [ticket(a)])


def test_time_window_and_no_unbounded_transitive_chain():
    items = [alert("A"), alert("B", hour=20), alert("C", hour=40)]
    for a in items:
        a["related_events"] = ["EDR-1"]
    result = groups(items)
    assert sorted(len(g.alert_ids) for g in result) == [1, 2]
    assert len(groups([items[0], items[2]])) == 2


def test_missing_dates_are_not_fabricated():
    items = [alert("A"), alert("B")]
    items[0].pop("created_at")
    for a in items:
        a["related_events"] = ["EDR-1"]
    assert len(groups(items)) == 2


def test_deterministic_partition_preserves_all_alerts_without_mutation():
    items = [alert("A"), alert("B"), alert("C", user="other")]
    items[0]["related_events"] = items[1]["related_events"] = ["DNS-1"]
    before = deepcopy(items)
    expected = [g.model_dump() for g in groups(items)]
    for order in permutations(items):
        assert [g.model_dump() for g in groups(list(order))] == expected
    assert items == before
    ids = [i for group in expected for i in group["alert_ids"]]
    assert sorted(ids) == ["A", "B", "C"] and len(ids) == len(set(ids))


def test_no_network_or_llm():
    with patch("socket.socket", side_effect=AssertionError("No network")):
        assert len(groups([alert("A"), alert("B")])) == 2


@pytest.mark.parametrize("hours", [0, -1, float("inf"), float("nan")])
def test_invalid_window(hours):
    with pytest.raises(ValueError):
        IncidentGrouper(hours)


def test_real_dataset_latrodectus_chain_has_verifiable_links():
    root = Path(__file__).resolve().parents[1] / "RepositoriDeloitte"
    ids = {"ALR-20261009-011790", "ALR-20261009-011791", "ALR-20261009-011792"}
    items = [a for line in (root / "03_alertas/alertas.jsonl").read_text(encoding="utf-8").splitlines()
             if (a := json.loads(line))["alert_id"] in ids]
    tip = {entry["value"]: entry for line in (root / "05_inteligencia/ti_feed.jsonl").read_text(encoding="utf-8").splitlines()
           if (entry := json.loads(line))}
    sandbox = {entry["sha256"]: entry for line in (root / "05_inteligencia/sandbox_informes.jsonl").read_text(encoding="utf-8").splitlines()
               if (entry := json.loads(line))}
    tickets = [ticket(a) for a in items]  # Solo envoltura de test; no análisis IA.
    for a, t in zip(items, tickets):
        for value in extract_indicators(a):
            if value in tip:
                t.enrichment.append(IntelEntry(indicator=value, type=tip[value]["indicator_type"],
                                               source=tip[value]["source"], result=json.dumps(tip[value])))
            if value in sandbox:
                t.enrichment.append(IntelEntry(indicator=value, type="sha256", source="sandbox",
                                               result=json.dumps(sandbox[value])))
    result = IncidentGrouper().group(items, tickets)
    assert len(result) == 1 and set(result[0].alert_ids) == ids
    assert "6f395de" in result[0].correlation_reason
    assert "aplihartom.com" in result[0].correlation_reason
