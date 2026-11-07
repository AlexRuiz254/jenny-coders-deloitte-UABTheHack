import json
import logging
import os
from pathlib import Path

log_path = os.path.join(Path(__file__).parents[2], ".streamlit", "streamlit.log")
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler(log_path, encoding="utf-8")]
)
class OrchestratorWrapper:

    def __init__(self):
        self.tickets_path = Path(__file__).parents[2] / "data" / "tickets.json"
        logging.debug("[DEBUG] OrchestratorWrapper inicializado – tickets_path=%s", self.tickets_path)
    def _load_tickets(self):
        if self.tickets_path.is_file():
            try:
                with open(self.tickets_path, "r", encoding="utf-8") as f:
                    lines = [json.loads(line) for line in f.readlines() if line.strip()]
                logging.debug("[DEBUG] Cargados %d tickets del archivo", len(lines))
                return lines
            except Exception as e:
                logging.exception("[ERROR] Falló al leer tickets.json")
                return []
        else:
            logging.debug("[DEBUG] tickets.json no existe – se crea nuevo")
            return []
    def _save_ticket(self, ticket):
        """Añade un ticket al archivo JSON‑Lines."""
        try:
            self.tickets_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.tickets_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(ticket, ensure_ascii=False) + "\n")
            logging.debug("[DEBUG] Ticket guardado en %s", self.tickets_path)
        except Exception as e:
            logging.exception("[ERROR] No se pudo escribir el ticket")
    def process_alert(self, alert_json: str):
        logging.debug("[DEBUG] process_alert recibido")
        try:
            alert = json.loads(alert_json)
            logging.debug("[DEBUG] Alert parsed: %s", alert)
        except json.JSONDecodeError as e:
            logging.error("[ERROR] JSON inválido: %s", e)
            return {"error": f"JSON inválido: {e}"}
        import uuid, datetime
        ticket = {
            "id": str(uuid.uuid4()),
            "alert_id": alert.get("alert_id", "UNKNOWN"),
            "status": "new",
            "created_at": datetime.datetime.utcnow().isoformat() + "Z",
            "details": alert,
        }
        logging.debug("[DEBUG] Ticket generado: %s", ticket)
        # Guardar en disco
        self._save_ticket(ticket)
        logging.info("[INFO] Ticket creado – ID: %s", ticket["id"])
        return ticket
