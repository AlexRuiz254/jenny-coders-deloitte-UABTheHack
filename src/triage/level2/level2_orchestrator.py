"""Coordinar los contratos reales N2: decide y build_and_save.

N1 guarda y reutiliza sus investigaciones. Se leen sus artefactos persistidos,
sin reconstruir análisis a partir de tickets ni repetir consultas de alertas.
Solo el servicio de tickets persiste N2. Para repetir el pipeline se utiliza un
repositorio separado: N2 distingue los niveles, pero la caché actual de N1 aún
devuelve el último ticket por alerta sin filtrar N1/N2.
No hay transacción global: los guardados anteriores no se deshacen al fallar.
"""
from __future__ import annotations

from collections.abc import Callable
from typing import Any, Protocol, TYPE_CHECKING

from src.triage.models import RawAlert, Ticket
from src.triage.level2.incident_decision_service import (
    AlertInvestigationInput, IncidentDecisionResult, IncidentGroup,
)

if TYPE_CHECKING:
    from src.triage.triage_orchestrator import TriageOrchestrator


class AlertReader(Protocol):
    def get_alert(self, alert_id: str) -> RawAlert | None: ...


class IncidentGrouper(Protocol):
    def group(self, alerts: list[RawAlert], tickets: list[Ticket]) -> list[IncidentGroup]: ...


class IncidentDecisionService(Protocol):
    def decide(self, incident_group: IncidentGroup, *,
               investigations: list[AlertInvestigationInput]) -> IncidentDecisionResult: ...


class IncidentTicketService(Protocol):
    def build_and_save(
        self, group: IncidentGroup, decision: IncidentDecisionResult, investigations: list[Ticket],
        *, trace: list[dict],
    ) -> Ticket: ...


class Level2Orchestrator:
    def __init__(
        self, *, triage: TriageOrchestrator, api: AlertReader,
        grouper: IncidentGrouper, decisions: IncidentDecisionService,
        tickets: IncidentTicketService, store: Any = None,
    ) -> None:
        """Recibir N1 y servicios reales; no construir ni sustituir dependencias."""
        for name, dependency, method in (
            ("triage", triage, "run"), ("api", api, "get_alert"),
            ("grouper", grouper, "group"), ("decisions", decisions, "decide"),
            ("tickets", tickets, "build_and_save"),
        ):
            if dependency is None or not callable(getattr(dependency, method, None)):
                raise TypeError(f"Falta la dependencia obligatoria {name}.{method}")
        self.triage = triage
        self.api = api
        self.grouper = grouper
        self.decisions = decisions
        self.tickets = tickets
        self.store = store if store is not None else getattr(triage, "store", None)

    @staticmethod
    def _call(component: str, operation: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        try:
            return operation(*args, **kwargs)
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
        incident_ids: set[str] = set()
        validated = []
        for number, group in enumerate(groups, start=1):
            incident_id = getattr(group, "incident_id", None)
            if not isinstance(incident_id, str) or not incident_id.strip() or incident_id in incident_ids:
                raise ValueError("Cada grupo debe tener un incident_id no vacío y único")
            incident_ids.add(incident_id)
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
            raw_alerts = getattr(group, "alerts", [])
            if raw_alerts and (
                any(not isinstance(item, dict) for item in raw_alerts)
                or {item.get("alert_id") for item in raw_alerts} != members
            ):
                raise ValueError("Las alertas originales del grupo no coinciden con sus alert_ids")
            seen.update(members)
            validated.append((group, ids.copy()))
        if seen != known_ids:
            raise ValueError(f"Alertas sin grupo de incidente: {sorted(known_ids - seen)}")
        return validated

    def _investigation(self, alert_id: str, ticket: Ticket) -> AlertInvestigationInput:
        record = self._call("TicketRepository.get", self.store.get, ticket.ticket_id)
        details = record.get("details", {}) if isinstance(record, dict) else {}
        if not isinstance(details, dict):
            raise ValueError(f"Artefactos N1 inválidos para {alert_id}")
        required = {"analysis", "context", "evidence"}
        if not required <= details.keys():
            raise ValueError(f"Investigación N1 incompleta para {alert_id}: faltan {sorted(required - details.keys())}")
        alert = details.get("alert")
        if alert is None:
            alert = self._call("AlertReader.get_alert", self.api.get_alert, alert_id)
        if alert is None:
            raise LookupError(f"Alerta no encontrada: {alert_id}")
        if not isinstance(alert, dict) or alert.get("alert_id") != alert_id:
            raise ValueError(f"Investigación de otra alerta para {alert_id!r}")
        if details["analysis"] is None or details["context"] is None:
            raise ValueError(f"Faltan análisis/contexto N1 de {alert_id}")
        return AlertInvestigationInput.model_validate({
            "alert_id": alert_id, "alert": alert, "ticket": ticket,
            "analysis": details["analysis"], "context": details["context"],
            "evidence": details["evidence"], "verdict_decision": details.get("verdict"),
            "related_alerts": details.get("related_alerts", []),
        })

    def run(self, alert_ids: list[str]) -> list[Ticket]:
        """Investigar IDs únicos, validar grupos y delegar decisión y consolidación."""
        if not isinstance(alert_ids, list):
            raise TypeError("alert_ids debe ser una lista de cadenas")
        if any(not isinstance(item, str) or not item.strip() for item in alert_ids):
            raise ValueError("Cada alert_id debe ser una cadena no vacía")
        unique_ids = list(dict.fromkeys(alert_ids))
        if not unique_ids:
            return []

        if self.store is None or not callable(getattr(self.store, "get", None)):
            raise TypeError("Se requiere el repositorio N1 (store.get) para recuperar las investigaciones")
        # N1 comprueba la existencia y reutiliza resultados guardados. La alerta
        # original está en sus artefactos: no se hace un segundo GET por defecto.
        alerts = []
        individual = []
        by_alert: dict[str, Ticket] = {}
        investigations: dict[str, AlertInvestigationInput] = {}
        source_ticket_ids: set[str] = set()
        for alert_id in unique_ids:
            ticket = self._call("TriageOrchestrator.run", self.triage.run, alert_id)
            ticket = self._check_ticket(ticket, [alert_id], "TriageOrchestrator.run")
            if ticket.ticket_id in source_ticket_ids:
                raise ValueError("N1 reutilizó un ticket_id para alertas distintas")
            source_ticket_ids.add(ticket.ticket_id)
            individual.append(ticket)
            by_alert[alert_id] = ticket
            investigation = self._investigation(alert_id, ticket)
            investigations[alert_id] = investigation
            alerts.append(investigation.alert)

        groups = self._call("IncidentGrouper.group", self.grouper.group, alerts, individual)
        validated = self._check_groups(groups, set(unique_ids))

        # Validar y evaluar todos los grupos antes de pedir guardados consolidados.
        evaluated = []
        for group, ids in validated:
            members = [investigations[alert_id] for alert_id in ids]
            decision = self._call(
                "IncidentDecisionService.decide", self.decisions.decide, group,
                investigations=members,
            )
            if decision is None:
                raise ValueError("IncidentDecisionService.decide no devolvió una decisión")
            decision = IncidentDecisionResult.model_validate(decision)
            if set(decision.alert_ids) != set(ids) or len(decision.alert_ids) != len(ids):
                raise ValueError("La decisión N2 contiene alertas ajenas al grupo")
            evaluated.append((group, ids, members, decision))

        consolidated = []
        saved_ids: set[str] = set()
        for group, ids, members, decision in evaluated:
            # El servicio real acepta IncidentDecisionResult sin reconstruirlo.
            source_tickets = [by_alert[alert_id] for alert_id in ids]
            trace = [{"stage": "consolidate_incident", "incident_id": group.incident_id,
                      "source_ticket_ids": [ticket.ticket_id for ticket in source_tickets],
                      "correlation_reason": group.correlation_reason,
                      "decision": decision.model_dump(mode="json")}]
            ticket = self._call(
                "IncidentTicketService.build_and_save", self.tickets.build_and_save,
                group, decision, source_tickets, trace=trace,
            )
            ticket = self._check_ticket(ticket, ids, "IncidentTicketService.build_and_save")
            if ticket.ticket_id != group.incident_id:
                raise ValueError("El servicio devolvió otro ticket (posiblemente N1), no el incidente solicitado")
            if ticket.ticket_id in saved_ids:
                raise ValueError("IncidentTicketService reutilizó un ticket_id entre incidentes")
            saved_ids.add(ticket.ticket_id)
            consolidated.append(ticket)
        return consolidated


def _main() -> None:
    """Ejecutar N2 desde Python con API, LLM y SQLite reales, sin servicios falsos."""
    import argparse
    import json
    from pathlib import Path

    from dotenv import load_dotenv
    from src.data.soc_api_client import SOCAPIClient
    from src.data.ticket_repository import TicketRepository
    from src.triage.triage_orchestrator import create_orchestrator
    from src.triage.level2.incident_grouper import IncidentGrouper as Grouper
    from src.triage.level2.incident_decision_service import IncidentDecisionService as Decisions
    from src.triage.level2.incident_ticket_service import IncidentTicketService as Tickets

    root = Path(__file__).resolve().parents[3]
    parser = argparse.ArgumentParser(description="Triaje N2: investigar, agrupar, decidir y guardar incidentes")
    parser.add_argument("alert_ids", nargs="+")
    parser.add_argument("--api-url", default="http://127.0.0.1:8001")
    parser.add_argument("--n1-db", type=Path, default=root / "tickets.sqlite3")
    parser.add_argument("--n2-db", type=Path, default=root / "tickets_n2.sqlite3")
    parser.add_argument("--dataset-root", type=Path, default=root / "RepositoriDeloitte")
    parser.add_argument("--window-hours", type=float, default=24)
    args = parser.parse_args()
    if args.n1_db.resolve() == args.n2_db.resolve():
        parser.error("N1 y N2 requieren bases distintas: la caché N1 no filtra por nivel")

    load_dotenv(root / ".env")
    grouper = Grouper(window_hours=args.window_hours)
    n1_store = TicketRepository(args.n1_db)
    n2_store = TicketRepository(args.n2_db)
    api = SOCAPIClient(args.api_url, store=n1_store)
    try:
        n1 = create_orchestrator(api, n1_store, dataset_root=args.dataset_root)
        service = Level2Orchestrator(
            triage=n1, api=api, grouper=grouper, decisions=Decisions(),
            tickets=Tickets(repository=n2_store),
        )
        result = service.run(args.alert_ids)
        print(json.dumps([ticket.model_dump(mode="json", exclude_none=True) for ticket in result],
                         ensure_ascii=False, indent=2))
    finally:
        api.close()
        n1_store.close()
        n2_store.close()


if __name__ == "__main__":
    _main()
