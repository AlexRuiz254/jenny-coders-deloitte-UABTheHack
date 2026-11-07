# src/interficie/api.py
import uuid, datetime, json
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

app = FastAPI(title="Demo Triage API")

# __file__ = …\jenny-coders-deloitte-UABTheHack\src\interficie\api.py
# parents[2] sube dos niveles (interficie → src → proyecto raíz)
DATA_DIR = Path(__file__).resolve().parents[2] / "data"
TICKETS_FILE = DATA_DIR / "tickets.json"

# Aseguramos que la carpeta exista
DATA_DIR.mkdir(parents=True, exist_ok=True)

# -------------------------------------------------
# Modelo de alerta (compatible con Python 3.9)
# -------------------------------------------------
class Alert(BaseModel):
    alert_id: str
    severity: str
    description: Optional[str] = None   # ← usa Optional

# -------------------------------------------------
# crea el ticket
# -------------------------------------------------
@app.post("/process")
def process_alert(alert: Alert):
    ticket = {
        "id": str(uuid.uuid4()),
        "alert_id": alert.alert_id,
        "status": "new",
        "created_at": datetime.datetime.utcnow().isoformat() + "Z",
        "details": alert.dict(),
    }

    try:
        # Append a una nueva línea en formato JSON‑Lines
        with open(TICKETS_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(ticket, ensure_ascii=False) + "\n")
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error al escribir el ticket en {TICKETS_FILE}: {e}"
        )
    return ticket