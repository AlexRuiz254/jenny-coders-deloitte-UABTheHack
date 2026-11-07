"""Validación de la salida contra el contrato oficial y los modelos del proyecto."""
import json
from functools import lru_cache
from pathlib import Path

from jsonschema import Draft202012Validator

from src.triage.models import Ticket

PROJECT_ROOT = Path(__file__).resolve().parents[3]


@lru_cache(maxsize=1)
def ticket_validator() -> Draft202012Validator:
    path = PROJECT_ROOT / "RepositoriDeloitte/01_contexto/ticket_salida.schema.json"
    return Draft202012Validator(json.loads(path.read_text(encoding="utf-8-sig")))


def validate_ticket(payload: dict) -> Ticket:
    ticket_validator().validate(payload)
    ticket = Ticket.model_validate(payload)
    if not ticket.ticket_id.strip() or not ticket.alert_ids or any(
        not value.strip() for value in ticket.alert_ids
    ):
        raise ValueError("El ticket debe identificar el ticket y al menos una alerta.")
    ticket_validator().validate(ticket.model_dump(mode="json", exclude_none=True))
    return ticket
