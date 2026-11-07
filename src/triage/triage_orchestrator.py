"""Punto único de entrada; coordina pasos, iteraciones y resultados."""
from collections.abc import Callable
from typing import Any
from tarvia_soc.models import Ticket
from tarvia_soc.data.soc_api_client import SOCAPIClient
from tarvia_soc.data.reference_repository import ReferenceRepository
from tarvia_soc.data.ticket_repository import TicketRepository
from tarvia_soc.investigation.runbook_registry import RunbookRegistry
from tarvia_soc.investigation.context_enricher import ContextEnricher
from tarvia_soc.investigation.intel_enricher import IntelEnricher
from tarvia_soc.investigation.evidence_collector import EvidenceCollector
from tarvia_soc.investigation.alert_correlator import AlertCorrelator
from tarvia_soc.investigation.investigation_agent import InvestigationAgent
from tarvia_soc.decision.verdict_engine import VerdictEngine
from tarvia_soc.decision.severity_calculator import SeverityCalculator
from tarvia_soc.decision.escalation_engine import EscalationEngine
from tarvia_soc.decision.action_recommender import ActionRecommender
from tarvia_soc.output.ticket_builder import TicketBuilder

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
                 store: TicketRepository) -> None:
        """Recibir dependencias; ninguna lógica de negocio aquí."""
        raise NotImplementedError

    def run(self, alert_id: str,
            on_event: Callable[[dict[str, Any]], None] | None = None) -> Ticket:
        """Alerta → runbook → contexto/intel/logs/correlación → IA → política → ticket."""
        raise NotImplementedError

    def run_batch(self, alert_ids: list[str],
                  on_event: Callable[[dict[str, Any]], None] | None = None) -> list[Ticket]:
        """Procesar las 10 alertas de la demo sin hardcodear identificadores."""
        raise NotImplementedError
