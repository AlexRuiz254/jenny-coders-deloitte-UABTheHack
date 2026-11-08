"""Punto único de entrada; coordina pasos, iteraciones y resultados."""
from collections.abc import Callable
from datetime import datetime, timezone
from time import perf_counter
from typing import Any
import logging
from src.triage.models import ContextSnapshot, Evidence, SearchPlan, Ticket
from src.data.soc_api_client import SOCAPIClient
from src.data.reference_repository import ReferenceRepository
from src.data.ticket_repository import SQLiteTicketRepository, utc_now
from src.triage.output.validation import validate_ticket
from src.triage.time_windows import alert_window, api_time, parse_utc
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

logger = logging.getLogger(__name__)

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
            on_event: Callable[[dict[str, Any]], None] | None = None,
            *, reprocess: bool = False) -> Ticket:
        """Persistir resultados o fallos; un reprocesamiento explícito crea otra versión."""
        existing = self.store.find_by_alert(alert_id)
        if existing and not reprocess:
            if on_event:
                on_event({"alert_id": alert_id, "stage": "already_processed", "status": "completed"})
            return validate_ticket(existing["details"]["ticket"])
        trace: list[dict[str, Any]] = []
        try:
            self.store.record_attempt(alert_id, "running", "start", trace)
            ticket = self._run(alert_id, on_event, trace, reprocess)
        except Exception as exc:
            stage = trace[-1]["stage"] if trace else "start"
            # No guardar respuestas completas del proveedor, prompts ni cabeceras.
            message = f"{stage}: {type(exc).__name__}. " + str(exc).split("\n", 1)[0][:240]
            event = {"alert_id": alert_id, "stage": stage, "status": "failed", "message": message}
            trace.append(event)
            logger.error("Triaje fallido de %s en %s (%s)", alert_id, stage, type(exc).__name__)
            try:
                self.store.record_attempt(alert_id, "failed", stage, trace, message)
            except Exception:
                logger.exception("No se pudo registrar el fallo de %s", alert_id)
            if on_event:
                on_event(event.copy())
            raise
        # Un fallo al registrar el estado auxiliar no invalida un ticket ya confirmado.
        try:
            self.store.record_attempt(alert_id, "completed", "completed", trace)
        except Exception:
            logger.exception("No se pudo actualizar el estado auxiliar de %s", alert_id)
        return ticket

    def _run(self, alert_id: str, on_event, trace: list[dict], reprocess: bool) -> Ticket:
        """Alerta → runbook → contexto/intel/logs/correlación → IA → política → ticket."""
        started = perf_counter()
        def emit(stage: str, status: str = "started", **details: Any) -> None:
            event = {"alert_id": alert_id, "stage": stage, "status": status,
                     "timestamp": utc_now(), **details}
            trace.append(event)
            if on_event is not None:
                try:
                    on_event(event.copy())
                except Exception:
                    logger.error("No se pudo mostrar el progreso de %s", alert_id)

        def call(stage: str, operation: Callable[..., Any],
                 *args: Any, **kwargs: Any) -> Any:
            emit(stage)
            result = operation(*args, **kwargs)
            count = len(result) if isinstance(result, list) else None
            details = {"count": count} if count is not None else {}
            if isinstance(result, list):
                details["truncated"] = any(isinstance(item, Evidence) and item.raw.get("truncated") for item in result)
                if result and isinstance(result[0], Evidence):
                    details["count"] = sum(bool(item.event_id) for item in result)
            emit(stage, "completed", **details)
            return result

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
        evidence = list(initial_evidence)
        looked_up = self.investigator._known_identifiers(alert, context, [])
        call("enrich_discovered", self._enrich_discovered, alert, context, evidence, looked_up)
        searches = call(
            "plan_searches", self.investigator.plan_searches,
            alert=alert, runbook_text=runbook_text, plan=plan,
            context=context, evidence=evidence
        )
        # La API compara fechas como texto: siempre enviar UTC con milisegundos.
        start, end = alert_window(alert)
        for search in searches.searches:
            query_start = max(start, parse_utc(search.start)) if search.start else start
            query_end = min(end, parse_utc(search.end)) if search.end else end
            if query_start > query_end:
                raise ValueError("La búsqueda del investigador queda fuera de la ventana de ±24 horas.")
            search.start, search.end = api_time(query_start), api_time(query_end)
        additional_evidence = call("search_evidence", self.evidence.search, searches)
        for item in additional_evidence:
            if item not in evidence:
                evidence.append(item)
        new_context = call("enrich_discovered", self._enrich_discovered,
                           alert, context, evidence, looked_up)
        pending = self.investigator._assess_runbook_coverage(alert, plan, context, evidence)
        if new_context and any(row.get("query") for row in pending):
            second = call(
                "plan_followup_searches", self.investigator.plan_searches,
                alert=alert, runbook_text=runbook_text, plan=plan,
                context=context, evidence=evidence)
            # Tampoco repetir consultas truncadas en la segunda y última ronda.
            attempted = {(s.source, s.query.casefold(), s.start, s.end) for s in searches.searches}
            second = self.investigator._sanitize_search_plan(second, alert=alert, context=context, evidence=evidence)
            second = SearchPlan(searches=[s for s in second.searches
                                         if (s.source, s.query.casefold(), s.start, s.end) not in attempted])
            if second.searches:
                for item in call("search_followup_evidence", self.evidence.search, second):
                    if item not in evidence:
                        evidence.append(item)
                searches.searches.extend(second.searches)
                call("enrich_discovered", self._enrich_discovered, alert, context, evidence, looked_up)
        diagnostics = getattr(self.investigator, "search_diagnostics", {})
        # Guardar la cobertura realmente recuperada, en lugar de la última intención de búsqueda.
        final_coverage = self.investigator._assess_runbook_coverage(alert, plan, context, evidence)
        diagnostics = {**diagnostics, "checks": [{k: v for k, v in row.items() if k != "query"} for row in final_coverage]}
        emit("investigation_coverage", "completed", **diagnostics)
        # El constructor ya sabe vincular Evidence: incluir la autorización real,
        # sin cambiar su contrato ni convertirla en un evento de log inventado.
        evidence.extend(Evidence(source="changes", event_id=change["id"], raw=change)
                        for change in context.changes if change.get("id"))

        analysis = call(
            "analyze", self.investigator.analyze,
            alert=alert, runbook_text=runbook_text, context=context,
            intel=intel, evidence=evidence, related_alerts=related_alerts
        )
        for row in final_coverage:
            if row["status"] == "pending":
                question = f"Comprobación pendiente del runbook: {row['check']}"
                if row.get("identifier"):
                    question += f" ({row['source']}: {row['identifier']})"
                question += ". " + row.get("limitation", "Sin consulta completa para el identificador y la ventana requeridos.")
                if question not in analysis.open_questions:
                    analysis.open_questions.append(question)
        for item in evidence:
            if item.raw.get("truncated"):
                question = f"Consulta incompleta en {item.source}: {item.raw.get('q', '')}. Se alcanzó el límite de la API."
                if question not in analysis.open_questions:
                    analysis.open_questions.append(question)
                analysis.signals.blocked_before_effect = False

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
        ticket = call("validate_ticket", validate_ticket,
                      Ticket.model_validate(ticket).model_dump(mode="json", exclude_none=True))
        # Adaptar el Ticket al sobre del repositorio, sin perder su JSON ni la traza.
        record = {
            "id": ticket.ticket_id,
            "alert_id": alert["alert_id"],
            "status": "new",  # Estado de revisión, independiente del veredicto.
            "created_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "details": {
                "ticket": ticket.model_dump(mode="json", exclude_none=True),
                "source": "generated", "alert": alert,
                "runbook_id": runbook_id, "runbook_text": runbook_text,
                "context": context.model_dump(mode="json"),
                "search_plan": searches.model_dump(mode="json"),
                "search_diagnostics": diagnostics,
                "analysis": analysis.model_dump(mode="json"),
                "verdict": verdict.model_dump(mode="json"),
                "related_alerts": related_alerts,
                "evidence": [item.model_dump(mode="json") for item in evidence],
            },
        }
        call("save_ticket", self.store.save, record, trace, allow_reprocess=reprocess)
        emit("completed", "completed", ticket_id=ticket.ticket_id)
        return ticket

    def _enrich_discovered(self, alert, context, evidence, looked_up) -> bool:
        """Ampliar contexto con campos estructurados; recordar también consultas fallidas."""
        known = self.investigator._known_identifiers({}, ContextSnapshot(), evidence)
        groups = {"host": "hosts", "user": "users", "ip": "ips"}
        extra = {}
        for kind, group in groups.items():
            candidates = sorted(known[kind] - looked_up[kind])
            if kind == "user":
                # El normalizador unifica UPN corporativo, TARVIA\usuario y username.
                candidates = extract_entities({"entities": {group: candidates}}).users
                previous = extract_entities({"entities": {group: sorted(looked_up[kind])}}).users
                candidates = [value for value in candidates if value not in previous]
            extra[group] = candidates[:50]
            if len(candidates) > 50:
                context.missing_lookups.append(f"{group}:enriquecimiento limitado a 50 entidades nuevas")
            looked_up[kind].update(extra[group])
        if not any(extra.values()):
            return False
        enriched = self.context.enrich(
            {**alert, "entities": extra, "evidence": {}},
            extract_entities({"entities": extra}))
        changed = False
        for field in ContextSnapshot.model_fields:
            current = getattr(context, field)
            for row in getattr(enriched, field):
                keys = {"assets": ("asset_id", "hostname", "ip"), "users": ("user_id", "upn", "username"),
                        "changes": ("id",), "services": ("servicio",)}.get(field, ())
                key_field = next((key for key in keys if isinstance(row, dict) and row.get(key)), None)
                duplicate = key_field and isinstance(row, dict) and row.get(key_field) and any(
                    isinstance(previous, dict) and previous.get(key_field) == row[key_field] for previous in current)
                if not duplicate and row not in current:
                    current.append(row)
                    changed |= field != "missing_lookups"
        # Un activo resuelto por IP puede descubrir también su hostname, y viceversa.
        resolved = self.investigator._known_identifiers({}, context, [])
        for kind in groups:
            looked_up[kind].update(resolved[kind])
        return changed

    def run_batch(self, alert_ids: list[str],
                  on_event: Callable[[dict[str, Any]], None] | None = None) -> list[Ticket]:
        """Procesar secuencialmente; conservar éxitos y comunicar cada fallo al callback."""
        tickets = []
        for alert_id in dict.fromkeys(alert_ids):
            try:
                tickets.append(self.run(alert_id, on_event=on_event))
            except Exception:
                continue  # run ya registra el fallo y emite su evento.
        return tickets


def create_orchestrator(api: SOCAPIClient, store: SQLiteTicketRepository,
                        dataset_root=None, llm=None) -> TriageOrchestrator:
    """Cableado único de los componentes reales para consola e interfaz."""
    import os
    from pathlib import Path
    from src.triage.llm import LLMClient

    root = Path(dataset_root) if dataset_root else Path(__file__).resolve().parents[2] / "RepositoriDeloitte"
    references = ReferenceRepository(root)
    return TriageOrchestrator(
        api=api, references=references, runbooks=RunbookRegistry(root / "01_contexto/runbooks"),
        context=ContextEnricher(api, references), intel=IntelEnricher(api),
        evidence=EvidenceCollector(api), correlator=AlertCorrelator(api),
        investigator=InvestigationAgent(llm or LLMClient(model=os.getenv("ORNITH_MODEL") or "uncensored")),
        verdicts=VerdictEngine(), severity=SeverityCalculator(), escalation=EscalationEngine(),
        actions=ActionRecommender(), tickets=TicketBuilder(), store=store,
    )


def _main() -> None:
    """Conectar componentes reales para ejecutar una alerta desde la terminal."""
    import argparse
    from pathlib import Path

    parser = argparse.ArgumentParser(description="Ejecutar el triaje SOC de una alerta")
    parser.add_argument("alert_id")
    parser.add_argument("--api-url", default="http://localhost:8000")
    parser.add_argument(
        "--dataset-root", type=Path,
        default=Path(__file__).resolve().parents[2] / "RepositoriDeloitte"
    )
    parser.add_argument(
        "--db-path", help="Ruta SQLite; por defecto tickets.sqlite3 del proyecto"
    )
    args = parser.parse_args()

    from dotenv import load_dotenv
    load_dotenv(Path(__file__).resolve().parents[2] / ".env")
    store = SQLiteTicketRepository(db_path=args.db_path)
    api = SOCAPIClient(base_url=args.api_url, store=store)
    try:
        service = create_orchestrator(api, store, args.dataset_root)
        ticket = service.run(args.alert_id)
        print(ticket.model_dump_json(exclude_none=True, indent=2))
    finally:
        api.close()


if __name__ == "__main__":
    _main()
