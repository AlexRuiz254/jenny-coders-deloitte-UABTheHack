"""Vista Streamlit: solo presentación; no contiene investigación ni política."""
from typing import Any
from tarvia_soc.models import Ticket
from tarvia_soc.data.soc_api_client import SOCAPIClient
from tarvia_soc.data.ticket_repository import TicketRepository
from tarvia_soc.orchestration.triage_orchestrator import TriageOrchestrator

def render_queue(api: SOCAPIClient) -> str | None:
    """Mostrar cola y devolver alert_id seleccionado."""
    raise NotImplementedError

def render_progress(events: list[dict[str, Any]]) -> None:
    """Mostrar consultas y resultados mientras se investiga."""
    raise NotImplementedError

def render_ticket(ticket: Ticket) -> None:
    """Mostrar veredicto, confianza, severidad, evidencias, recomendaciones y JSON."""
    raise NotImplementedError

def render_human_review(ticket: Ticket, store: TicketRepository) -> None:
    """Cerrar/escalar por acción explícita de un humano; registrar la decisión."""
    raise NotImplementedError

def render_dashboard(api: SOCAPIClient, service: TriageOrchestrator,
                     store: TicketRepository) -> None:
    """Conectar las vistas, lanzar run y recuperar tickets guardados."""
    raise NotImplementedError
