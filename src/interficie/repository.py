"""Import público anterior; la implementación única está en src.data."""
from src.data.ticket_repository import SQLiteTicketRepository, TicketRepository

__all__ = ["TicketRepository", "SQLiteTicketRepository"]
