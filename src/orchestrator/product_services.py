"""Composición del producto N1–N4; la interfaz no implementa los motores SOC."""
from __future__ import annotations

from contextvars import ContextVar
from pathlib import Path
from uuid import uuid4

import requests

from src.data.reference_repository import ReferenceRepository
from src.data.soc_api_client import SOCAPIClient
from src.data.ticket_repository import TicketRepository, utc_now
from src.triage.investigation.evidence_collector import EvidenceCollector
from src.triage.level2.incident_decision_service import IncidentDecisionService
from src.triage.level2.incident_grouper import IncidentGrouper
from src.triage.level2.incident_ticket_service import IncidentTicketService
from src.triage.level2.level2_orchestrator import Level2Orchestrator
from src.triage.level3.attack_reconstructor import AttackReconstructor
from src.triage.level3.incident_report_builder import IncidentReportBuilder
from src.triage.level3.investigation_expander import InvestigationExpander
from src.triage.level3.level3_orchestrator import Level3Orchestrator
from src.triage.level3.scope_analyzer import ScopeAnalyzer
from src.triage.level4.approval_repository import ApprovalRepository
from src.triage.level4.approval_service import ApprovalService
from src.triage.level4.containment_api_client import ContainmentAPIClient
from src.triage.level4.level4_orchestrator import HumanDecision, Level4Orchestrator, SQLiteResponseStore
from src.triage.level4.response_planner import ResponsePlanner
from src.triage.output.validation import validate_ticket

DEMO_REVIEWERS = {
    "analyst_n1": "Analista N1 · simulado",
    "analyst_n2": "Analista N2 · simulado",
    "director_ecommerce": "Responsable de E-commerce · simulado",
    "director_financiero": "Responsable de Finanzas · simulado",
    "director_tecnologia": "Responsable de Tecnología · simulado",
    "dpo": "Responsable de datos / DPO · simulado",
    "directora_operaciones": "Responsable de Operaciones / negocio · simulado",
}
_DEMO_ACTOR = ContextVar("tarvia_demo_reviewer", default=None)


def demo_reviewers(proposal):
    reviewers = dict(DEMO_REVIEWERS)
    owner = (proposal.target_snapshot.get("asset") or {}).get("owner_upn")
    if owner and "service_owner" in proposal.required_approvals:
        reviewers["owner:" + owner.casefold()] = f"Responsable del servicio · {owner} · simulado"
    return reviewers


def _verify_demo_actor(decision, proposal) -> bool:
    if decision.actor != _DEMO_ACTOR.get() or decision.actor not in demo_reviewers(proposal):
        return False
    if decision.actor.startswith("owner:"):
        owner = (proposal.target_snapshot.get("asset") or {}).get("owner_upn", "")
        return decision.actor == "owner:" + owner.casefold()
    if decision.actor in {"analyst_n1", "analyst_n2", "directora_operaciones"}:
        return True
    responsible = (proposal.target_snapshot.get("service") or {}).get("responsable", "")
    allowed = {
        "director_ecommerce": {"Directora de E-commerce"},
        "director_financiero": {"Director Financiero"},
        "director_tecnologia": {"Director de Tecnología"}, "dpo": {"DPO"},
    }
    return responsible in allowed.get(decision.actor, set())


class _SavedTriage:
    def __init__(self, store):
        self.store = store

    def run(self, alert_id):
        record = self.store.find_by_alert(alert_id)
        if not record or any(record["details"].get(key) is None for key in ("analysis", "context", "evidence", "alert")):
            raise ValueError(f"{alert_id}: investigar en N1 antes de correlacionar; un ticket importado sin investigación no basta")
        return validate_ticket(record["details"]["ticket"])


class ProductServices:
    def __init__(self, *, api_url: str, n1_path: str, n2_path: str, response_path: str,
                 dataset_root: str, demo_mode: bool = False):
        paths = [Path(value).resolve() for value in (n1_path, n2_path, response_path)]
        if len(set(paths)) != 3:
            raise ValueError("N1, N2 y respuesta requieren rutas de persistencia distintas")
        self.demo_mode = demo_mode
        self.n1, self.n2 = TicketRepository(paths[0]), TicketRepository(paths[1])
        self.responses = SQLiteResponseStore(paths[2])
        self.api = SOCAPIClient(api_url, store=self.n1)
        self.api.session.trust_env = False
        self.api.session.max_redirects = 0
        self.references = ReferenceRepository(Path(dataset_root))
        self.planner = ResponsePlanner(api=self.api, references=self.references)
        if demo_mode:
            session = requests.Session()
            session.trust_env = False
            session.max_redirects = 0
            self.containment = ContainmentAPIClient(api_url, session=session)
            self.level4 = Level4Orchestrator.with_soc_services(
                planner=self.planner, store=self.responses,
                approval_service=ApprovalService(repository=ApprovalRepository(paths[2])),
                api_client=self.containment, verify_actor=_verify_demo_actor, identity_mode="demo_simulated")
        else:
            self.level4 = Level4Orchestrator(report_loader=self.responses.load_report,
                                           planner=self.planner, store=self.responses)

    def _operation(self, level, target, operation, on_event):
        record = {"operation_id": str(uuid4()), "level": level, "target": target,
                  "status": "running", "started_at": utc_now(), "events": []}
        self.responses.save_operation(record)

        def progress(event):
            record["events"].append({**event, "timestamp": utc_now()})
            self.responses.save_operation(record)
            if on_event:
                on_event(event)
        try:
            result = operation(progress)
        except Exception as exc:
            record.update(status="failed", error_type=type(exc).__name__, finished_at=utc_now())
            self.responses.save_operation(record)
            raise
        record.update(status="completed", finished_at=utc_now())
        self.responses.save_operation(record)
        return result

    def correlate(self, alert_ids: list[str], *, window_hours=24, on_event=None):
        service = Level2Orchestrator(triage=_SavedTriage(self.n1), api=self.api,
            grouper=IncidentGrouper(window_hours), decisions=IncidentDecisionService(),
            tickets=IncidentTicketService(repository=self.n2))
        return self._operation("N2", alert_ids, lambda progress: service.run(alert_ids, on_event=progress), on_event)

    def investigate(self, incident_id: str, *, before_days=7, after_days=2, new_version=False,
                    analyst_reason="", on_event=None):
        previous = self.responses.load_report(incident_id)
        if previous is not None and not new_version:
            return previous
        record = self.n2.get(incident_id)
        if record is None:
            raise LookupError("Selecciona un incidente N2 guardado")
        ticket = validate_ticket(record["details"]["ticket"])
        if not ticket.escalation.escalate:
            if not analyst_reason.strip():
                raise ValueError("El incidente no está escalado: justificar explícitamente la investigación avanzada")
            self.n2.save_review(incident_id, "continue_investigation", analyst_reason.strip())
        expander = InvestigationExpander(api=self.api, collector=EvidenceCollector(self.api),
            n1_store=self.n1, n2_store=self.n2, before_days=before_days, after_days=after_days,
            max_window_days=31, max_queries=48, max_additional_events=2000)
        service = Level3Orchestrator(n1_store=self.n1, n2_store=self.n2, expander=expander,
            reconstructor=AttackReconstructor(),
            scope_analyzer=ScopeAnalyzer(references=self.references, dataset_root=self.references.dataset_root),
            report_builder=IncidentReportBuilder())

        def run(progress):
            report = service.run(incident_id, on_event=progress)
            self.responses.store_report(report)
            progress({"stage": "report_saved", "incident_id": incident_id})
            return report
        return self._operation("N3", incident_id, run, on_event)

    def decide(self, proposal_id, *, actor, approved, reason, restart=False):
        if not self.demo_mode:
            raise PermissionError("No hay autenticación real configurada; las decisiones solo están disponibles en modo demostración")
        proposal = self.level4.get_state(proposal_id).proposal
        if actor not in demo_reviewers(proposal) or not reason.strip():
            raise ValueError("Seleccionar una identidad de ensayo y escribir un motivo")
        if actor.startswith("owner:"):
            self.level4.approvals.service.policy.user_roles[actor.casefold()] = "service_owner"
        decision = HumanDecision(decision_id="DEMO-" + str(uuid4()), actor=actor, approved=approved,
                                 reason="ENSAYO · identidad simulada: " + reason.strip())
        context = _DEMO_ACTOR.set(actor)
        try:
            return (self.level4.restart_approval(proposal_id, decision) if restart else
                    self.level4.record_decision(proposal_id, decision))
        finally:
            _DEMO_ACTOR.reset(context)
