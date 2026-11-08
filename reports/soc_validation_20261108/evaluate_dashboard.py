"""Pulsar widgets reales de Streamlit con API/LLM reales; guardar salidas sin editarlas."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from dotenv import load_dotenv
from streamlit.testing.v1 import AppTest
from src.data.ticket_repository import TicketRepository
from src.triage.output.validation import validate_ticket


def widget(widgets, label):
    return next(w for w in widgets if w.label == label)


def check(app):
    if app.exception or app.error:
        raise RuntimeError(str([e.value for e in [*app.exception, *app.error]]))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--iteration", type=int, choices=(1, 2, 3), required=True)
    args = parser.parse_args()
    load_dotenv(ROOT / ".env")
    os.environ["SOC_API_URL"] = "http://127.0.0.1:8001"
    folder = Path(__file__).parent / f"iteration_{args.iteration}"
    folder.mkdir(exist_ok=True)
    store = TicketRepository(os.getenv("SOC_DB_PATH") or None)
    selection = json.loads((Path(__file__).parent / "selection.json").read_text(encoding="utf-8"))
    manifest = {"route": "Streamlit AppTest: real dashboard widgets, real HTTP SOC API, configured real LLM; no interactive browser",
                "iteration": args.iteration, "tickets": [], "code_sha256": {}}
    for path in [*ROOT.glob("src/**/*.py"), ROOT / "system_src/investigation_system_prompt.md"]:
        manifest["code_sha256"][str(path.relative_to(ROOT))] = hashlib.sha256(path.read_bytes()).hexdigest()
    for alert_id in selection["alerts"]:
        previous = store.find_by_alert(alert_id)
        if args.iteration == 1 and previous:
            raise RuntimeError(f"La alerta seleccionada ya tiene ticket: {alert_id}")
        print(f"START iteration={args.iteration} alert={alert_id}", flush=True)
        app = AppTest.from_file(str(ROOT / "src/interficie/dashboard.py"), default_timeout=900).run()
        check(app)
        if previous:
            app.sidebar.radio[0].set_value("Tickets e investigación").run()
            widget(app.text_input, "Buscar alerta o ticket").set_value(alert_id).run()
            widget(app.selectbox, "Abrir detalle y revisión").set_value(previous["id"]).run()
            widget(app.checkbox, "Crear una nueva investigación conservando la anterior").check().run()
            widget(app.button, "Reprocesar alerta").click().run(timeout=900)
        else:
            widget(app.text_input, "Buscar ID de alerta").set_value(alert_id).run()
            widget(app.multiselect, "Seleccionar alertas para investigar").set_value([alert_id]).run()
            widget(app.button, "Investigar selección").click().run(timeout=900)
        check(app)
        print("RESULT", app.session_state["batch_results"], flush=True)
        record = store.find_by_alert(alert_id)
        if not record or previous and record["id"] == previous["id"]:
            raise RuntimeError(f"No se generó ticket nuevo para {alert_id}")
        ticket = validate_ticket(record["details"]["ticket"])
        app.sidebar.radio[0].set_value("Tickets e investigación").run()
        widget(app.selectbox, "Abrir detalle y revisión").set_value(ticket.ticket_id).run()
        check(app)
        assert any(ticket.ticket_id in caption.value for caption in app.caption)
        assert ticket.executed_actions == []
        assert ticket.verdict == record["details"]["verdict"]["verdict"]
        for suffix, data in (("ticket", ticket.model_dump(mode="json", exclude_none=True)), ("record", record)):
            (folder / f"{alert_id}.{suffix}.json").write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        manifest["tickets"].append({"alert_id": alert_id, "ticket_id": ticket.ticket_id,
                                    "verdict": ticket.verdict, "severity": ticket.severity,
                                    "escalate": ticket.escalation.escalate})
        (folder / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
        print("SAVED", manifest["tickets"][-1], flush=True)


if __name__ == "__main__":
    main()
