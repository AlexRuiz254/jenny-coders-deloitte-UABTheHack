"""Auditoría de lectura: contratos, procedencia local y resultado HTTP del ensayo.

Ejecutar desde la raíz del repositorio. No llama al LLM ni ejecuta contención.
"""
import csv
import json
from collections import Counter
from pathlib import Path
import sys

import requests

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from src.data.ticket_repository import TicketRepository
from src.triage.level3.incident_report_builder import IncidentReportBuilder
from src.triage.level4.level4_orchestrator import SQLiteResponseStore
from src.triage.output.validation import validate_ticket
from src.triage.time_windows import parse_utc

INCIDENT = "INC-5a04411da2f121ff1cc6-vd2d89109ec56"
ALERTS = [f"ALR-20261009-{value}" for value in ("011790", "011791", "011792")]


def run():
    n1 = TicketRepository(ROOT / "tickets.sqlite3")
    n2 = TicketRepository(ROOT / "tickets_n2.sqlite3")
    responses = SQLiteResponseStore(ROOT / "soc_response.sqlite3")
    report = responses.load_report(INCIDENT)
    assert report is not None
    IncidentReportBuilder().validate(report)
    validate_ticket(n2.get(INCIDENT)["details"]["ticket"])
    records = [n1.find_by_alert(alert) for alert in ALERTS]
    for record in records:
        validate_ticket(record["details"]["ticket"])
    compared, errors, sources = 0, [], {}
    evidence_sets = [*(record["details"]["evidence"] for record in records),
                     [item.model_dump(mode="json") for item in report.evidence]]
    for items in evidence_sets:
        for item in items:
            source, event_id = item["source"], item.get("event_id")
            if not event_id or source == "changes" or item["raw"].get("kind") == "query_summary":
                continue
            if source not in sources:
                file = ROOT / "RepositoriDeloitte/04_logs" / (source + ".jsonl")
                if file.is_file():
                    with file.open(encoding="utf-8") as handle:
                        rows = [json.loads(line) for line in handle if line.strip()]
                else:
                    with file.with_suffix(".csv").open(encoding="utf-8", newline="") as handle:
                        rows = list(csv.DictReader(handle))
                sources[source] = {row["event_id"]: row for row in rows if row.get("event_id")}
            original = sources[source].get(event_id)
            compared += 1
            if original != item["raw"]:
                errors.append(f"Evento distinto o inexistente: {source}/{event_id}")
    for event in report.timeline:
        if not any(parse_utc(event.timestamp) == parse_utc(sources[ref.source][ref.event_id].get("timestamp")
                   or sources[ref.source][ref.event_id].get("eventTime")) for ref in event.evidence
                   if ref.source in sources and ref.event_id in sources[ref.source]):
            errors.append(f"Fecha de cronología sin coincidencia: {event.event_id}")
    session = requests.Session()
    session.trust_env = False
    response = session.get("http://127.0.0.1:8001/containment/log", timeout=30, allow_redirects=False)
    response.raise_for_status()
    public = {"timestamp", "action", "target", "ticket_id", "result", "justification"}
    actions = [{key: value for key, value in row.items() if key in public}
               for row in response.json() if row.get("ticket_id") == INCIDENT]
    states = responses.list_states(incident_id=INCIDENT)
    assert not errors, errors[:10]
    assert len(actions) == 1 and actions[0]["target"] == "WS-BCN-1770"
    result = {
        "incident_id": INCIDENT, "n1_tickets": [record["id"] for record in records],
        "contracts_valid": True, "evidence_comparisons": compared, "provenance_errors": errors,
        "timeline_events": len(report.timeline), "evidence_items": len(report.evidence),
        "report_versions": responses.list_reports(incident_id=INCIDENT),
        "origin": {name: getattr(report.reconstruction, name).model_dump(mode="json")
                   for name in ("patient_zero", "initial_access", "root_cause")},
        "scope": {name: [{"statement": item.statement, "status": item.status,
                          "evidence_count": len(item.evidence)} for item in getattr(report.scope_analysis, name)]
                  for name in ("hosts", "users", "services")},
        "proposal_states": [dict(proposal_id=s.proposal.proposal_id, target=s.proposal.target,
            status=s.status, report_digest=s.proposal.report_digest,
            identity_mode=s.approval.identity_mode if s.approval else None) for s in states],
        "state_counts": dict(Counter(s.status for s in states)), "simulated_api_actions": actions,
        "automated_audit_only": "No sustituye la revisión semántica ni las acciones reales del navegador.",
    }
    (Path(__file__).parent / "evidence_validation.json").write_text(
        json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({key: result[key] for key in ("contracts_valid", "evidence_comparisons",
        "provenance_errors", "timeline_events", "evidence_items", "state_counts")}, ensure_ascii=True))


if __name__ == "__main__":
    run()
