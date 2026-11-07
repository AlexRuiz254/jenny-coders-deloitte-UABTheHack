"""Contratos de datos. Solo modelos Pydantic: no contienen implementación de triaje."""
from __future__ import annotations

from typing import Any, Literal
from pydantic import BaseModel, Field

RawAlert = dict[str, Any]  # Las 11.061 alertas usan el mismo formato principal
Verdict = Literal["true_positive", "benign_true_positive", "false_positive", "needs_more_info"]
Severity = Literal["informational", "low", "medium", "high", "critical"]
LogSource = Literal[
    "proxy", "dns", "edr_events", "idp_signins", "waf", "email",
    "ecom_auth", "firewall", "email_clicks", "vpn", "ai_gateway",
    "ecom_account", "cloudtrail", "sql_audit", "dlp", "idp_audit",
    "cicd_builds", "ad_events",
]

class EntityKeys(BaseModel):
    """Identificadores extraídos de entities; sin transformar la alerta original."""
    hosts: list[str] = Field(default_factory=list)
    users: list[str] = Field(default_factory=list)
    ips: list[str] = Field(default_factory=list)
    domains: list[str] = Field(default_factory=list)
    urls: list[str] = Field(default_factory=list)
    hashes: list[str] = Field(default_factory=list)
    sessions: list[str] = Field(default_factory=list)
    customers: list[str] = Field(default_factory=list)

class ContextSnapshot(BaseModel):
    assets: list[dict[str, Any]] = Field(default_factory=list)
    users: list[dict[str, Any]] = Field(default_factory=list)
    changes: list[dict[str, Any]] = Field(default_factory=list)
    services: list[dict[str, Any]] = Field(default_factory=list)
    network_zones: list[dict[str, Any]] = Field(default_factory=list)
    missing_lookups: list[str] = Field(default_factory=list)

class IntelEntry(BaseModel):
    indicator: str
    type: str
    source: str
    result: str

class Evidence(BaseModel):
    source: str
    event_id: str | None = None
    timestamp: str | None = None
    raw: dict[str, Any] = Field(default_factory=dict)

class InvestigationPlan(BaseModel):
    runbook_id: str
    required_checks: list[str]
    suggested_sources: list[LogSource]

class LogQuery(BaseModel):
    source: LogSource
    query: str
    reason: str
    start: str | None = None
    end: str | None = None

class SearchPlan(BaseModel):
    """Salida estructurada del LLM para planificar búsquedas adicionales."""
    searches: list[LogQuery]

class Finding(BaseModel):
    statement: str
    evidence_ids: list[str]

class PolicySignals(BaseModel):
    """Afirmaciones del LLM que hay que contrastar con las evidencias."""
    execution_or_access_confirmed: bool
    blocked_before_effect: bool
    privileged_or_vip: bool
    sensitive_or_payment_data: bool
    malicious_execution: bool
    credentials_compromised: bool
    persistence: bool
    personal_data_exposure: bool
    financial_fraud: bool
    attack_chain: bool
    authorized_activity: bool

class ProposedAction(BaseModel):
    action: str
    target: str
    justification: str

class Analysis(BaseModel):
    """Salida Pydantic del LLM; NO es el ticket final ni una decisión validada."""
    title: str
    verdict: Verdict
    confidence: float = Field(ge=0, le=1)
    summary: str
    findings: list[Finding]
    signals: PolicySignals
    proposed_actions: list[ProposedAction]
    open_questions: list[str]

class VerdictDecision(BaseModel):
    verdict: Verdict
    confidence: float = Field(ge=0, le=1)
    rationale: str

class SeverityDecision(BaseModel):
    severity: Severity
    rationale: str

class Escalation(BaseModel):
    escalate: bool
    to: str | None = None
    reason: str | None = None

class TicketEvidence(BaseModel):
    source: str
    event_id: str | None = None
    finding: str

class TicketAction(BaseModel):
    action: str
    target: str
    requires_approval: bool
    justification: str | None = None

class Ticket(BaseModel):
    """Coincide con los campos exigidos/permitidos por ticket_salida.schema.json."""
    ticket_id: str
    alert_ids: list[str]
    title: str
    verdict: Verdict
    confidence: float = Field(ge=0, le=1)
    severity: Severity
    summary: str
    evidence: list[TicketEvidence]
    recommended_actions: list[TicketAction]
    escalation: Escalation
    # Campos opcionales definidos en el esquema oficial
    severity_rationale: str | None = None
    affected: dict[str, list[Any]] = Field(default_factory=dict)
    enrichment: list[IntelEntry] = Field(default_factory=list)
    mitre: list[str] = Field(default_factory=list)
    executed_actions: list[dict[str, Any]] = Field(default_factory=list)
    open_questions: list[str] = Field(default_factory=list)
    triage_seconds: float | None = None
