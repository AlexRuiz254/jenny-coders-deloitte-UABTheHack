"""Persistencia de tickets y traza local; no existe POST /tickets en la API SOC."""
from typing import Any
from tarvia_soc.models import Ticket

class TicketRepository:
    def __init__(self, db_path: str = "tickets.sqlite3") -> None:
        raise NotImplementedError

    def save(self, ticket: Ticket, trace: list[dict[str, Any]]) -> None:
        """Guardar ticket y operaciones de investigación realizadas."""
        raise NotImplementedError

    def get(self, ticket_id: str) -> dict[str, Any] | None:
        """Recuperar ticket, traza y estado de revisión."""
        raise NotImplementedError

    def list_recent(self, limit: int = 25) -> list[dict[str, Any]]:
        """Listar tickets para el dashboard."""
        raise NotImplementedError

    def save_review(self, ticket_id: str, decision: str, note: str) -> None:
        """Registrar cierre/escalado humano, sin ejecutar contención."""
        raise NotImplementedError
