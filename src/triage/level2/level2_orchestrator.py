"""Coordinar N2 mediante los contratos propuestos, sin implementar sus servicios.

Contrato mínimo pendiente de IncidentGroup: atributo ``alert_ids: list[str]``.
Los grupos deben particionar todas las alertas recibidas, incluidos los casos
unitarios. evaluate y create_and_save reciben solo los tickets N1 de su grupo.

N1 devuelve Ticket, no RawAlert: se necesita una lectura adicional por ID para
group(). El lector inyectado puede usar una caché compartida con N1; aquí no se
modifica su cliente ni se reconstruyen alertas a partir de tickets incompletos.

N1 puede persistir sus tickets individuales. Solo IncidentTicketService guarda
los consolidados: deberá vincular los ticket_id de origen y distinguir N1/N2
en su persistencia/traza, sin que este orquestador vuelva a guardar ninguno.
No hay transacción global ni reintentos: un fallo no deshace guardados previos.
"""
from __future__ import annotations

from collections.abc import Callable
from typing import Any, Protocol, TYPE_CHECKING

from src.triage.models import RawAlert, Ticket

if TYPE_CHECKING:
    from src.triage.triage_orchestrator import TriageOrchestrator


class AlertReader(Protocol):
    def get_alert(self, alert_id: str) -> RawAlert | None: ...


class IncidentGroup(Protocol):
    alert_ids: list[str]


class IncidentGrouper(Protocol):
    def group(self, alerts: list[RawAlert], tickets: list[Ticket]) -> list[IncidentGroup]: ...


class IncidentDecisionService(Protocol):
    def evaluate(self, group: IncidentGroup, tickets: list[Ticket]) -> Any: ...


class IncidentTicketService(Protocol):
    def create_and_save(
        self, group: IncidentGroup, tickets: list[Ticket], decision: Any
    ) -> Ticket: ...


class Level2Orchestrator:
    def __init__(
        self, *, triage: TriageOrchestrator, api: AlertReader,
        grouper: IncidentGrouper, decisions: IncidentDecisionService,
        tickets: IncidentTicketService,
    ) -> None:
        """Recibir N1 y servicios reales; no construir ni sustituir dependencias."""
        for name, dependency, method in (
            ("triage", triage, "run"), ("api", api, "get_alert"),
            ("grouper", grouper, "group"), ("decisions", decisions, "evaluate"),
            ("tickets", tickets, "create_and_save"),
        ):
            if dependency is None or not callable(getattr(dependency, method, None)):
                raise TypeError(f"Falta la dependencia obligatoria {name}.{method}")
        self.triage = triage
        self.api = api
        self.grouper = grouper
        self.decisions = decisions
        self.tickets = tickets

    @staticmethod
    def _call(component: str, operation: Callable[..., Any], *args: Any) -> Any:
        try:
            return operation(*args)
        except NotImplementedError as exc:
            exc.add_note(f"Dependencia N2 pendiente: {component}.")
            raise

    @staticmethod
    def _check_ticket(value: Ticket, alert_ids: list[str], component: str) -> Ticket:
        if not isinstance(value, Ticket):
            raise TypeError(f"{component} debe devolver un Ticket válido")
        if not value.ticket_id.strip():
            raise ValueError(f"{component} devolvió un ticket_id vacío")
        if (len(value.alert_ids) != len(set(value.alert_ids))
                or set(value.alert_ids) != set(alert_ids)):
            raise ValueError(f"{component} devolvió alert_ids distintos de {alert_ids!r}")
        return value

    @staticmethod
    def _check_groups(
        groups: list[IncidentGroup], known_ids: set[str],
    ) -> list[tuple[IncidentGroup, list[str]]]:
        if not isinstance(groups, list):
            raise TypeError("IncidentGrouper.group debe devolver una lista de grupos")
        seen: set[str] = set()
        validated = []
        for number, group in enumerate(groups, start=1):
            ids = getattr(group, "alert_ids", None)
            if (not isinstance(ids, list) or not ids
                    or any(not isinstance(item, str) or not item.strip() for item in ids)):
                raise ValueError(f"El grupo {number} debe exponer alert_ids: list[str] no vacía")
            members = set(ids)
            if len(members) != len(ids):
                raise ValueError(f"El grupo {number} contiene IDs duplicados")
            if members - known_ids:
                raise ValueError(f"El grupo {number} contiene IDs desconocidos: {sorted(members - known_ids)}")
            if members & seen:
                raise ValueError(f"Alertas asignadas a varios incidentes: {sorted(members & seen)}")
            seen.update(members)
            validated.append((group, ids.copy()))
        if seen != known_ids:
            raise ValueError(f"Alertas sin grupo de incidente: {sorted(known_ids - seen)}")
        return validated

    def run(self, alert_ids: list[str]) -> list[Ticket]:
        """Investigar IDs únicos, validar grupos y delegar decisión y consolidación."""
        if not isinstance(alert_ids, list):
            raise TypeError("alert_ids debe ser una lista de cadenas")
        if any(not isinstance(item, str) or not item.strip() for item in alert_ids):
            raise ValueError("Cada alert_id debe ser una cadena no vacía")
        unique_ids = list(dict.fromkeys(alert_ids))
        if not unique_ids:
            return []

        # Comprobar existencia antes de iniciar investigaciones con efectos N1.
        alerts = []
        for alert_id in unique_ids:
            alert = self._call("AlertReader.get_alert", self.api.get_alert, alert_id)
            if alert is None:
                raise LookupError(f"Alerta no encontrada: {alert_id}")
            if not isinstance(alert, dict) or alert.get("alert_id") != alert_id:
                raise ValueError(f"AlertReader.get_alert devolvió otra alerta para {alert_id!r}")
            alerts.append(alert)

        individual = []
        by_alert: dict[str, Ticket] = {}
        source_ticket_ids: set[str] = set()
        for alert_id in unique_ids:
            ticket = self._call("TriageOrchestrator.run", self.triage.run, alert_id)
            ticket = self._check_ticket(ticket, [alert_id], "TriageOrchestrator.run")
            if ticket.ticket_id in source_ticket_ids:
                raise ValueError("N1 reutilizó un ticket_id para alertas distintas")
            source_ticket_ids.add(ticket.ticket_id)
            individual.append(ticket)
            by_alert[alert_id] = ticket

        groups = self._call("IncidentGrouper.group", self.grouper.group, alerts, individual)
        validated = self._check_groups(groups, set(unique_ids))

        # Validar y evaluar todos los grupos antes de pedir guardados consolidados.
        evaluated = []
        for group, ids in validated:
            members = [by_alert[alert_id] for alert_id in ids]
            decision = self._call(
                "IncidentDecisionService.evaluate", self.decisions.evaluate, group, members
            )
            if decision is None:
                raise ValueError("IncidentDecisionService.evaluate no devolvió una decisión")
            evaluated.append((group, ids, members, decision))

        consolidated = []
        saved_ids: set[str] = set()
        for group, ids, members, decision in evaluated:
            ticket = self._call(
                "IncidentTicketService.create_and_save", self.tickets.create_and_save,
                group, members, decision,
            )
            ticket = self._check_ticket(ticket, ids, "IncidentTicketService.create_and_save")
            if ticket.ticket_id in saved_ids:
                raise ValueError("IncidentTicketService reutilizó un ticket_id entre incidentes")
            saved_ids.add(ticket.ticket_id)
            consolidated.append(ticket)
        return consolidated
