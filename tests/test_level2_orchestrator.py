"""Contratos y escenarios N2 con mocks; no representan una investigación real."""
from copy import deepcopy
from types import SimpleNamespace
from unittest.mock import Mock, call, create_autospec
import json
import sys

import pytest

from src.triage.level2.level2_orchestrator import (
    AlertReader, IncidentDecisionService, IncidentGrouper, IncidentTicketService,
    Level2Orchestrator,
)
from src.triage.level2.incident_decision_service import IncidentDecisionResult, IncidentGroup
from src.triage.models import Analysis, Escalation, PolicySignals, Ticket
from src.triage.triage_orchestrator import TriageOrchestrator


def make_ticket(key, ids):
    return Ticket(ticket_id=key, alert_ids=ids, title="Fixture", summary="Sin IA",
                  verdict="needs_more_info", confidence=.5, severity="medium", evidence=[],
                  recommended_actions=[], escalation=Escalation(escalate=False))


def group(ids):
    return IncidentGroup(incident_id="INC-" + "-".join(ids), alert_ids=ids,
                         correlation_reason="Relación de prueba", justification="Relación de prueba")


class Harness:
    def __init__(self, ids=("A", "B"), groups=None):
        self.raw = {i: {"alert_id": i, "created_at": "2026-10-10T12:00:00Z"} for i in ids}
        self.individual = {i: make_ticket("N1-" + i, [i]) for i in ids}
        analysis = Analysis(title="Fixture", summary="Sin IA", verdict="needs_more_info", confidence=.5,
                            findings=[], signals=PolicySignals(**{k: False for k in PolicySignals.model_fields}),
                            proposed_actions=[], open_questions=[])
        self.records = {"N1-" + i: {"details": {"alert": self.raw[i],
                        "analysis": analysis.model_dump(), "context": {}, "evidence": []}} for i in ids}
        self.triage = create_autospec(TriageOrchestrator, instance=True)
        self.api = create_autospec(AlertReader, instance=True)
        self.store = Mock(spec=["get"])
        self.store.get.side_effect = self.records.get
        self.triage.run.side_effect = self.investigate
        self.api.get_alert.side_effect = self.raw.get
        self.grouper = create_autospec(IncidentGrouper, instance=True)
        self.grouper.group.return_value = groups if groups is not None else [group(list(ids))]
        self.decisions = create_autospec(IncidentDecisionService, instance=True)
        self.decisions.decide.side_effect = lambda g, **kwargs: IncidentDecisionResult(
            alert_ids=g.alert_ids, verdict="needs_more_info", confidence=.4,
            verdict_rationale="Razón de veredicto", severity="medium",
            severity_rationale="Razón de severidad", escalation=Escalation(escalate=False),
            open_questions=["Pregunta N2"],
        )
        self.tickets = create_autospec(IncidentTicketService, instance=True)
        self.tickets.build_and_save.side_effect = lambda g, d, t, **kw: make_ticket(g.incident_id, g.alert_ids)
        self.service = Level2Orchestrator(triage=self.triage, api=self.api, store=self.store,
                                          grouper=self.grouper, decisions=self.decisions, tickets=self.tickets)

    def investigate(self, key):
        if key not in self.individual:
            raise LookupError(f"Alerta no encontrada: {key}")
        return self.individual[key]


def test_empty_input():
    h = Harness()
    assert h.service.run([]) == []
    h.triage.run.assert_not_called()
    h.api.get_alert.assert_not_called()


def test_duplicate_ids_only_processed_once():
    h = Harness()
    ids = ["A", "A", "B", "A"]
    assert len(h.service.run(ids)) == 1
    assert h.triage.run.call_args_list == [call("A"), call("B")]
    assert h.store.get.call_count == 2
    h.api.get_alert.assert_not_called()
    assert ids == ["A", "A", "B", "A"]


def test_forwarding_real_method_names_models_and_rationales():
    h = Harness()
    before = deepcopy(h.individual)
    output = h.service.run(["A", "B"])
    h.grouper.group.assert_called_once_with(list(h.raw.values()), list(h.individual.values()))
    args, kwargs = h.decisions.decide.call_args
    assert args[0].alert_ids == ["A", "B"]
    assert [i.alert_id for i in kwargs["investigations"]] == ["A", "B"]
    assert all(i.analysis is not None for i in kwargs["investigations"])
    args, kwargs = h.tickets.build_and_save.call_args
    assert isinstance(args[1], IncidentDecisionResult)
    assert args[1].verdict_rationale == "Razón de veredicto"
    assert args[1].severity_rationale == "Razón de severidad"
    assert args[1].open_questions == ["Pregunta N2"]
    assert args[2] == list(h.individual.values())
    assert kwargs["trace"][0]["source_ticket_ids"] == ["N1-A", "N1-B"]
    assert output[0].ticket_id == "INC-A-B"
    assert h.individual == before


def test_distinct_incidents_get_only_their_members():
    h = Harness(("A", "B", "C"), [group(["C", "A"]), group(["B"])])
    output = h.service.run(["A", "B", "C"])
    assert [t.alert_ids for t in output] == [["C", "A"], ["B"]]
    assert [[i.alert_id for i in c.kwargs["investigations"]] for c in h.decisions.decide.call_args_list] == [["C", "A"], ["B"]]
    assert h.tickets.build_and_save.call_count == 2


@pytest.mark.parametrize("ids", [["A", "A", "B"], ["A", "B", "UNKNOWN"], ["A"], [], ["A", None]])
def test_invalid_group_partition_prevents_decisions_and_saves(ids):
    h = Harness(groups=[SimpleNamespace(incident_id="INC", alert_ids=ids)])
    with pytest.raises(ValueError):
        h.service.run(["A", "B"])
    h.decisions.decide.assert_not_called()
    h.tickets.build_and_save.assert_not_called()


def test_overlap_rejected_before_any_save():
    h = Harness(groups=[group(["A"]), group(["A", "B"])])
    with pytest.raises(ValueError, match="varios"):
        h.service.run(["A", "B"])
    h.tickets.build_and_save.assert_not_called()


def test_duplicate_incident_ids_rejected_before_any_save():
    first, second = group(["A"]), group(["B"])
    second.incident_id = first.incident_id
    h = Harness(groups=[first, second])
    with pytest.raises(ValueError, match="incident_id"):
        h.service.run(["A", "B"])
    h.tickets.build_and_save.assert_not_called()


@pytest.mark.parametrize("ids,kind", [(None, TypeError), ("AB", TypeError), ([""], ValueError), ([1], ValueError)])
def test_invalid_input(ids, kind):
    h = Harness()
    with pytest.raises(kind):
        h.service.run(ids)
    h.triage.run.assert_not_called()


def test_missing_alert_is_explicit_and_no_consolidated_ticket():
    h = Harness()
    with pytest.raises(LookupError, match="UNKNOWN"):
        h.service.run(["UNKNOWN"])
    h.tickets.build_and_save.assert_not_called()


def test_fallback_alert_reader_if_stored_alert_absent():
    h = Harness(("A",))
    del h.records["N1-A"]["details"]["alert"]
    h.service.run(["A"])
    h.api.get_alert.assert_called_once_with("A")


def test_wrong_stored_alert_rejected():
    h = Harness()
    h.records["N1-A"]["details"]["alert"] = {"alert_id": "OTHER"}
    with pytest.raises(ValueError, match="otra alerta"):
        h.service.run(["A"])


def test_missing_artifacts_are_not_reconstructed_from_ticket():
    h = Harness()
    del h.records["N1-A"]["details"]["analysis"]
    with pytest.raises(ValueError, match="incompleta"):
        h.service.run(["A"])
    h.decisions.decide.assert_not_called()


@pytest.mark.parametrize("name", ["triage", "api", "grouper", "decisions", "tickets"])
def test_missing_dependencies(name):
    h = Harness()
    kwargs = {key: getattr(h, key) for key in ["triage", "api", "grouper", "decisions", "tickets", "store"]}
    kwargs[name] = None
    with pytest.raises(TypeError, match=name):
        Level2Orchestrator(**kwargs)


@pytest.mark.parametrize("name,method", [("triage", "run"), ("grouper", "group"),
                                        ("decisions", "decide"), ("tickets", "build_and_save")])
def test_pending_dependency_errors_identify_component(name, method):
    h = Harness()
    error = NotImplementedError("Pendiente")
    getattr(getattr(h, name), method).side_effect = error
    with pytest.raises(NotImplementedError) as caught:
        h.service.run(["A", "B"])
    assert caught.value is error and method in " ".join(error.__notes__)


def test_technical_error_propagates_without_fake_decision():
    h = Harness()
    error = ConnectionError("Proveedor no disponible")
    h.decisions.decide.side_effect = error
    with pytest.raises(ConnectionError) as caught:
        h.service.run(["A", "B"])
    assert caught.value is error
    h.tickets.build_and_save.assert_not_called()


def test_evaluate_all_groups_before_persistence():
    h = Harness(groups=[group(["A"]), group(["B"])])
    first = h.decisions.decide.side_effect(group(["A"]))
    h.decisions.decide.side_effect = [first, RuntimeError("Segundo grupo")]
    with pytest.raises(RuntimeError):
        h.service.run(["A", "B"])
    h.tickets.build_and_save.assert_not_called()


def test_none_decision_rejected():
    h = Harness()
    h.decisions.decide.side_effect = None
    h.decisions.decide.return_value = None
    with pytest.raises(ValueError, match="decisión"):
        h.service.run(["A", "B"])


def test_wrong_decision_scope_rejected():
    h = Harness()
    decision = h.decisions.decide.side_effect(group(["A"]))
    h.decisions.decide.side_effect = None
    h.decisions.decide.return_value = decision
    with pytest.raises(ValueError, match="ajenas"):
        h.service.run(["A", "B"])


def test_group_result_must_be_list():
    h = Harness()
    h.grouper.group.return_value = None
    with pytest.raises(TypeError):
        h.service.run(["A", "B"])


def test_wrong_n1_ticket_scope_rejected():
    h = Harness()
    h.individual["A"].alert_ids = ["OTHER"]
    with pytest.raises(ValueError, match="alert_ids"):
        h.service.run(["A"])


def test_reused_n1_ticket_id_rejected():
    h = Harness()
    h.individual["B"].ticket_id = h.individual["A"].ticket_id
    with pytest.raises(ValueError, match="reutilizó"):
        h.service.run(["A", "B"])


def test_invalid_consolidated_ticket_rejected():
    h = Harness()
    h.tickets.build_and_save.side_effect = None
    h.tickets.build_and_save.return_value = {"fake": True}
    with pytest.raises(TypeError):
        h.service.run(["A", "B"])


def test_returning_individual_ticket_is_not_consolidation():
    h = Harness(("A",))
    h.tickets.build_and_save.side_effect = None
    h.tickets.build_and_save.return_value = h.individual["A"]
    with pytest.raises(ValueError, match="posiblemente N1"):
        h.service.run(["A"])


def test_partial_save_failure_is_not_retried():
    h = Harness(groups=[group(["A"]), group(["B"])])
    h.tickets.build_and_save.side_effect = [make_ticket("INC-A", ["A"]), OSError("Segundo guardado")]
    with pytest.raises(OSError):
        h.service.run(["A", "B"])
    assert h.tickets.build_and_save.call_count == 2


def test_three_alerts_one_incident():
    h = Harness(("A", "B", "C"))
    assert len(h.service.run(["A", "B", "C"])) == 1


def test_two_independent_attacks():
    h = Harness(("A1", "A2", "B1", "B2"), [group(["A1", "A2"]), group(["B1", "B2"])])
    output = h.service.run(["A1", "A2", "B1", "B2"])
    assert len(output) == 2 and output[0].ticket_id != output[1].ticket_id


def test_isolated_alert_keeps_its_incident():
    h = Harness(("A",))
    assert h.service.run(["A"])[0].alert_ids == ["A"]


def test_cli_wires_real_component_factories(monkeypatch, tmp_path, capsys):
    import dotenv
    import src.data.soc_api_client as api_module
    import src.data.ticket_repository as repository_module
    import src.triage.triage_orchestrator as n1_module
    import src.triage.level2.incident_grouper as group_module
    import src.triage.level2.incident_decision_service as decision_module
    import src.triage.level2.incident_ticket_service as ticket_module
    import src.triage.level2.level2_orchestrator as module

    n1_path, n2_path = tmp_path / "n1.sqlite3", tmp_path / "n2.sqlite3"
    n1_store, n2_store, api, n1 = Mock(), Mock(), Mock(), Mock()
    repositories = Mock(side_effect=[n1_store, n2_store])
    api_factory, n1_factory = Mock(return_value=api), Mock(return_value=n1)
    grouper, decisions, tickets = Mock(), Mock(), Mock()
    group_factory, decision_factory = Mock(return_value=grouper), Mock(return_value=decisions)
    ticket_factory = Mock(return_value=tickets)
    runner = Mock()
    output = make_ticket("INC-A", ["A"])
    runner.run.return_value = [output]
    runner_factory = Mock(return_value=runner)
    monkeypatch.setattr(dotenv, "load_dotenv", Mock())
    monkeypatch.setattr(repository_module, "TicketRepository", repositories)
    monkeypatch.setattr(api_module, "SOCAPIClient", api_factory)
    monkeypatch.setattr(n1_module, "create_orchestrator", n1_factory)
    monkeypatch.setattr(group_module, "IncidentGrouper", group_factory)
    monkeypatch.setattr(decision_module, "IncidentDecisionService", decision_factory)
    monkeypatch.setattr(ticket_module, "IncidentTicketService", ticket_factory)
    monkeypatch.setattr(module, "Level2Orchestrator", runner_factory)
    monkeypatch.setattr(sys, "argv", ["n2", "A", "A", "--api-url", "http://soc:8765",
                                      "--n1-db", str(n1_path), "--n2-db", str(n2_path)])
    module._main()
    assert repositories.call_args_list == [call(n1_path), call(n2_path)]
    api_factory.assert_called_once_with("http://soc:8765", store=n1_store)
    ticket_factory.assert_called_once_with(repository=n2_store)
    assert runner_factory.call_args.kwargs == {
        "triage": n1, "api": api, "grouper": grouper, "decisions": decisions, "tickets": tickets,
    }
    runner.run.assert_called_once_with(["A", "A"])
    assert json.loads(capsys.readouterr().out)[0]["ticket_id"] == output.ticket_id
    api.close.assert_called_once()
    n1_store.close.assert_called_once()
    n2_store.close.assert_called_once()


def test_cli_rejects_shared_database_before_creating_files(monkeypatch, tmp_path):
    from src.triage.level2.level2_orchestrator import _main
    path = tmp_path / "same.sqlite3"
    monkeypatch.setattr(sys, "argv", ["n2", "A", "--n1-db", str(path), "--n2-db", str(path)])
    with pytest.raises(SystemExit) as caught:
        _main()
    assert caught.value.code == 2
    assert not path.exists()
