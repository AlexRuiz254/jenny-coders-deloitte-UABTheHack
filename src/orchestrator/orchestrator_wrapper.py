"""Entrada anterior: investigar mediante el orquestador único y persistir en SQLite."""
import json
from pathlib import Path
import os

from dotenv import load_dotenv

from src.data.soc_api_client import SOCAPIClient, ensure_local_soc_api
from src.data.ticket_repository import TicketRepository
from src.triage.ingestion.imports import validate_alert
from src.triage.triage_orchestrator import create_orchestrator


class OrchestratorWrapper:
    def process_alert(self, alert_json: str):
        root = Path(__file__).resolve().parents[2]
        load_dotenv(root / ".env")
        store = TicketRepository(os.getenv("SOC_DB_PATH") or None)
        api_url = ensure_local_soc_api(os.getenv("SOC_API_URL") or "http://127.0.0.1:8000")
        api = SOCAPIClient(api_url, store=store)
        try:
            service = create_orchestrator(api, store)
            alert = validate_alert(json.loads(alert_json), service.references)
            if api.get_alert(alert["alert_id"]) is None:
                store.import_alert(alert)
            return service.run(alert["alert_id"]).model_dump(mode="json", exclude_none=True)
        finally:
            api.close()
