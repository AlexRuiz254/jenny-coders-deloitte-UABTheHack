"""Contrastar salidas guardadas con eventos y consultas del dataset oficial inmutable."""
import argparse
import importlib.util
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from src.triage.output.validation import validate_ticket
from src.triage.time_windows import alert_window, parse_utc


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--iteration", type=int, choices=(1, 2, 3), required=True)
    args = parser.parse_args()
    spec = importlib.util.spec_from_file_location("audit_official_api", ROOT / "RepositoriDeloitte/06_herramientas/mock_soc_api.py")
    official = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(official)
    folder = Path(__file__).parent / f"iteration_{args.iteration}"
    results = []
    for path in sorted(folder.glob("*.record.json")):
        record = json.loads(path.read_text(encoding="utf-8"))
        details = record["details"]
        ticket = validate_ticket(details["ticket"])
        start, end = alert_window(details["alert"])
        errors, events, queries = [], 0, 0
        by_source = {}
        for ev in details["evidence"]:
            source, raw = ev["source"], ev["raw"]
            if source == "changes":
                if raw not in official.CHANGES:
                    errors.append(f"Cambio inexistente: {ev['event_id']}")
            elif ev.get("event_id"):
                if source not in by_source:
                    by_source[source] = {r["event_id"]: r for r in official.logs(source) if r.get("event_id")}
                original = by_source[source].get(ev["event_id"])
                if original != raw:
                    errors.append(f"Evento diferente o inexistente: {ev['event_id']}")
                if not start <= parse_utc(ev["timestamp"]) <= end:
                    errors.append(f"Evento fuera de ventana: {ev['event_id']}")
                events += 1
            elif raw.get("kind") == "query_summary":
                actual = official.search_logs(source, q=raw["q"], desde=raw["desde"], hasta=raw["hasta"], limit=2000)
                if (raw["count"], raw["truncated"]) != (actual["count"], actual["truncated"]):
                    errors.append(f"Consulta no reproducible: {raw['query_id']}")
                queries += 1
        refs = {ev["event_id"] or ev["raw"].get("query_id") for ev in details["evidence"]}
        for finding in details["analysis"]["findings"]:
            if set(finding["evidence_ids"]) - refs:
                errors.append("Hallazgo con referencia inexistente")
        if ticket.verdict != details["verdict"]["verdict"] or ticket.executed_actions:
            errors.append("Decisión distinta de VerdictEngine o contención ejecutada")
        result = {"alert_id": record["alert_id"], "ticket_id": ticket.ticket_id, "events_verified": events,
                  "queries_reproduced": queries, "errors": errors,
                  "note": "Comprueba procedencia y resultados; la coherencia semántica se evalúa por separado."}
        results.append(result)
        print(json.dumps(result, ensure_ascii=False))
    (folder / "evidence_audit.json").write_text(json.dumps(results, ensure_ascii=False, indent=2), encoding="utf-8")
    if any(r["errors"] for r in results):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
