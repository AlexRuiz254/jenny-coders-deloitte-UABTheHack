"""Punto único de entrada; coordina pasos, iteraciones y resultados."""
from collections.abc import Callable
from datetime import datetime, timezone
from time import perf_counter
from typing import Any
from src.triage.models import Ticket
from src.data.soc_api_client import SOCAPIClient
from src.data.reference_repository import ReferenceRepository
from src.interficie.repository import SQLiteTicketRepository
from src.triage.ingestion.entities import extract_entities, extract_indicators
from src.triage.investigation.runbook_registry import RunbookRegistry
from src.triage.investigation.context_enricher import ContextEnricher
from src.triage.investigation.intel_enricher import IntelEnricher
from src.triage.investigation.evidence_collector import EvidenceCollector
from src.triage.investigation.alert_correlator import AlertCorrelator
from src.triage.investigation.investigation_agent import InvestigationAgent
from src.triage.decision.verdict_engine import VerdictEngine
from src.triage.decision.severity_calculator import SeverityCalculator
from src.triage.decision.escalation_engine import EscalationEngine
from src.triage.decision.action_recommender import ActionRecommender
from src.triage.output.ticket_builder import TicketBuilder

class TriageOrchestrator:
    def __init__(self, *, api: SOCAPIClient,
                 references: ReferenceRepository,
                 runbooks: RunbookRegistry,
                 context: ContextEnricher,
                 intel: IntelEnricher,
                 evidence: EvidenceCollector,
                 correlator: AlertCorrelator,
                 investigator: InvestigationAgent,
                 verdicts: VerdictEngine,
                 severity: SeverityCalculator,
                 escalation: EscalationEngine,
                 actions: ActionRecommender,
                 tickets: TicketBuilder,
                 store: SQLiteTicketRepository) -> None:
        """Recibir dependencias; ninguna lógica de negocio aquí."""
        self.api = api
        self.references = references
        self.runbooks = runbooks
        self.context = context
        self.intel = intel
        self.evidence = evidence
        self.correlator = correlator
        self.investigator = investigator
        self.verdicts = verdicts
        self.severity = severity
        self.escalation = escalation
        self.actions = actions
        self.tickets = tickets
        self.store = store
        for name in (
            "api", "references", "runbooks", "context", "intel", "evidence",
            "correlator", "investigator", "verdicts", "severity", "escalation",
            "actions", "tickets", "store",
        ):
            if getattr(self, name) is None:
                raise ValueError(f"Falta la dependencia obligatoria: {name}")

    def run(self, alert_id: str,
            on_event: Callable[[dict[str, Any]], None] | None = None) -> Ticket:
        """Alerta → runbook → contexto/intel/logs/correlación → IA → política → ticket."""
        started = perf_counter()
        trace: list[dict[str, Any]] = []

        def emit(stage: str) -> None:
            # Cada etapa anuncia su inicio; completed solo se emite tras guardar.
            event = {"alert_id": alert_id, "stage": stage}
            trace.append(event)
            if on_event is not None:
                on_event(event.copy())

        def call(stage: str, operation: Callable[..., Any],
                 *args: Any, **kwargs: Any) -> Any:
            emit(stage)
            try:
                return operation(*args, **kwargs)
            except NotImplementedError as exc:
                component = getattr(operation, "__qualname__", stage)
                exc.add_note(
                    f"Dependencia pendiente: {component}; "
                    f"etapa {stage}, alerta {alert_id}."
                )
                raise

        # Alerta, identificadores y procedimiento de investigación.
        alert = call("get_alert", self.api.get_alert, alert_id)
        if alert is None:
            raise LookupError(f"Alerta no encontrada: {alert_id}")

        entities = call("extract_entities", extract_entities, alert)
        indicators = call("extract_indicators", extract_indicators, alert)

        runbook_id = alert.get("runbook")
        if not runbook_id:
            raise ValueError(f"La alerta {alert_id} no contiene un runbook")
        runbook_text = call("load_runbook", self.runbooks.get_text, runbook_id)
        strategy = call("get_strategy", self.runbooks.get_strategy, runbook_id)
        plan = call("build_plan", strategy.build_plan, alert)

        # Enriquecimiento y evidencias iniciales, sin decisiones de incidente.
        context = call("enrich_context", self.context.enrich, alert, entities)
        intel = call("enrich_intel", self.intel.enrich, indicators)
        initial_evidence = call(
            "collect_related_events", self.evidence.collect_related_events, alert
        )
        related_alerts = call(
            "find_related_alerts", self.correlator.find_related, alert, entities
        )

        # El investigador planifica; el colector ejecuta las consultas.
        searches = call(
            "plan_searches", self.investigator.plan_searches,
            alert=alert, runbook_text=runbook_text, plan=plan,
            context=context, evidence=initial_evidence
        )
        additional_evidence = call("search_evidence", self.evidence.search, searches)
        evidence = [*initial_evidence, *additional_evidence]

        analysis = call(
            "analyze", self.investigator.analyze,
            alert=alert, runbook_text=runbook_text, context=context,
            intel=intel, evidence=evidence, related_alerts=related_alerts
        )

        # Aplicar los motores existentes a los resultados del investigador.
        verdict = call(
            "decide_verdict", self.verdicts.decide,
            analysis=analysis, evidence=evidence, context=context
        )
        severity = call(
            "calculate_severity", self.severity.calculate,
            alert=alert, context=context, analysis=analysis, verdict=verdict
        )
        escalation = call(
            "decide_escalation", self.escalation.decide,
            analysis=analysis, verdict=verdict, severity=severity,
            related_alerts=related_alerts
        )
        actions = call(
            "recommend_actions", self.actions.recommend,
            analysis=analysis, context=context, verdict=verdict, severity=severity
        )

        # El constructor produce el ticket; el repositorio lo persiste.
        ticket = call(
            "build_ticket", self.tickets.build,
            alert=alert, related_alerts=related_alerts, context=context,
            analysis=analysis, verdict=verdict, severity=severity,
            escalation=escalation, actions=actions, evidence=evidence,
            intel=intel, triage_seconds=perf_counter() - started
        )
        ticket = Ticket.model_validate(ticket)
        # Adaptar el Ticket al sobre del repositorio, sin perder su JSON ni la traza.
        record = {
            "id": ticket.ticket_id,
            "alert_id": alert["alert_id"],
            "status": "new",  # Estado de revisión, independiente del veredicto.
            "created_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "details": {
                "ticket": ticket.model_dump(mode="json", exclude_none=True),
                "trace": trace,
            },
        }
        # add serializa la traza tras anunciar save_ticket y confirma el commit.
        # Si falla, el error se propaga sin anunciar completed ni devolver ticket.
        call("save_ticket", self.store.add, record)
        emit("completed")
        return ticket

    def run_batch(self, alert_ids: list[str],
                  on_event: Callable[[dict[str, Any]], None] | None = None) -> list[Ticket]:
        """Procesar en orden; propagar el primer error sin inventar tickets."""
        return [self.run(alert_id, on_event=on_event) for alert_id in alert_ids]


def _main() -> None:
    """Conectar componentes reales para ejecutar una alerta desde la terminal."""
    import argparse
    from pathlib import Path

    from src.triage.llm import LLMClient

    parser = argparse.ArgumentParser(description="Ejecutar el triaje SOC de una alerta")
    parser.add_argument("alert_id")
    parser.add_argument("--api-url", default="http://localhost:8000")
    parser.add_argument(
        "--dataset-root", type=Path,
        default=Path(__file__).resolve().parents[2] / "RepositoriDeloitte"
    )
    parser.add_argument(
        "--db-path", help="Ruta SQLite; por defecto se usa data/tickets.db del proyecto"
    )
    args = parser.parse_args()

    api = SOCAPIClient(base_url=args.api_url)
    try:
        references = ReferenceRepository(args.dataset_root)
        store = SQLiteTicketRepository(db_path=args.db_path)
        service = TriageOrchestrator(
            api=api, references=references,
            runbooks=RunbookRegistry(args.dataset_root / "01_contexto" / "runbooks"),
            context=ContextEnricher(api, references), intel=IntelEnricher(api),
            evidence=EvidenceCollector(api), correlator=AlertCorrelator(api),
            investigator=InvestigationAgent(LLMClient()), verdicts=VerdictEngine(),
            severity=SeverityCalculator(), escalation=EscalationEngine(),
            actions=ActionRecommender(), tickets=TicketBuilder(), store=store
        )
        ticket = service.run(args.alert_id)
        print(ticket.model_dump_json(exclude_none=True, indent=2))
    finally:
        api.close()


if __name__ == "__main__":
    _main()
