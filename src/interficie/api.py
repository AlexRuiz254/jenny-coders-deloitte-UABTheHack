# src/interficie/api.py
import uuid, datetime
from pathlib import Path
from typing import Optional, List, Dict, Any

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from .repository import TicketRepository   

repo = TicketRepository()                 

app = FastAPI(title="Demo Triage API")

class Alert(BaseModel):
    alert_id: str
    severity: str
    description: Optional[str] = None   # ← usa Optional

@app.post("/process")
def process_alert(alert: Alert):
    ticket = {
        "id": str(uuid.uuid4()),
        "alert_id": alert.alert_id,
        "status": "new",
        "created_at": datetime.datetime.utcnow().isoformat() + "Z",
        "details": alert.dict(),
    }
    # Guardamos sin traza (por ahora)
    repo.save(ticket, trace=[])
    return ticket


@app.get("/tickets", response_model=List[Dict[str, Any]])
def list_tickets(limit: int = 25):
    """
    Devuelve los `limit` tickets más recientes.
    """
    return repo.list_recent(limit=limit)