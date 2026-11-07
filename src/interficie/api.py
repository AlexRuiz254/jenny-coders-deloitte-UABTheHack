# src/interficie/api.py
import uuid, datetime
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from .repository import SQLiteTicketRepository

repo = SQLiteTicketRepository()

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

    try:
        repo.add(ticket)
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error al escribir el ticket en SQLite: {e}"
        )
    return ticket