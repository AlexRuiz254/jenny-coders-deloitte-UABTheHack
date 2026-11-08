"""Servicio de decisión consolidada de incidentes para SOC Nivel 2 (N2).

Este módulo recibe un incidente agrupado (`IncidentGroup`) junto con las alertas
originales y los artefactos de investigación individual producidos en Nivel 1
(análisis, contextos, evidencias y tickets/decisiones previas) y genera tres
decisiones consolidadas reutilizando los motores oficiales de N1:

1. Veredicto global (`VerdictEngine`).
2. Severidad global (`SeverityCalculator`).
3. Decisión de escalado (`EscalationEngine`).

Contratos de integración:
- Entrada de Persona 1 / Persona 4: `IncidentGroup` (o diccionario/objeto
  equivalente con `alert_ids` / `alerts`) más las investigaciones individuales
  (`AlertInvestigationInput` o colecciones de `alerts`, `analyses`, `contexts`,
  `evidence`, `tickets`).
- Salida para Persona 3 / Persona 4: `IncidentDecisionResult` con los campos
  consolidados (`alert_ids`, `verdict`, `confidence`, `verdict_rationale`,
  `severity`, `severity_rationale`, `escalation`, `key_evidence_ids`,
  `open_questions`).
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime, timedelta, timezone, tzinfo
import re
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from pydantic import BaseModel, ConfigDict, Field

import src.triage.decision.verdict_engine as _verdict_engine_mod
from src.triage.decision.escalation_engine import EscalationEngine
from src.triage.decision.severity_calculator import (
    CRITICALITIES,
    SEVERITY_LEVELS,
    SeverityCalculator,
)
from src.triage.decision.verdict_engine import VerdictEngine


class _MadridFallbackTz(tzinfo):
    """Fallback para `Europe/Madrid` (CET/CEST) en entornos Windows sin paquete `tzdata`."""

    @staticmethod
    def _last_sunday(year: int, month: int) -> datetime:
        day = 31
        while True:
            dt = datetime(year, month, day, 1, 0, tzinfo=timezone.utc)
            if dt.weekday() == 6:
                return dt
            day -= 1

    def _is_dst(self, dt: datetime | None) -> bool:
        if dt is None:
            return False
        year = dt.year
        start = self._last_sunday(year, 3)
        end = self._last_sunday(year, 10)
        utc_naive = dt.replace(tzinfo=timezone.utc)
        return start <= utc_naive < end

    def utcoffset(self, dt: datetime | None) -> timedelta:
        return timedelta(hours=2 if self._is_dst(dt) else 1)

    def dst(self, dt: datetime | None) -> timedelta:
        return timedelta(hours=1 if self._is_dst(dt) else 0)

    def tzname(self, dt: datetime | None) -> str:
        return "CEST" if self._is_dst(dt) else "CET"


def _safe_zoneinfo(key: str) -> tzinfo:
    try:
        return ZoneInfo(key)
    except ZoneInfoNotFoundError:
        if key == "Europe/Madrid":
            return _MadridFallbackTz()
        return timezone.utc


try:
    ZoneInfo("Europe/Madrid")
except ZoneInfoNotFoundError:
    _verdict_engine_mod.ZoneInfo = _safe_zoneinfo  # type: ignore[assignment]
from src.triage.models import (
    Analysis,
    ContextSnapshot,
    Escalation,
    Evidence,
    Finding,
    PolicySignals,
    RawAlert,
    Severity,
    SeverityDecision,
    Ticket,
    Verdict,
    VerdictDecision,
)


_STORE_TOKEN_RE = re.compile(
    r"(?:^|[-_])(T\d{2,3}|TIENDA[-_]?\d+|STORE[-_]?\d+)(?:$|[-_])",
    re.IGNORECASE,
)
_POS_HOST_RE = re.compile(
    r"^(?:POS|TPV)[-_]?([A-Z0-9]+?)(?:[-_]\d+)?$",
    re.IGNORECASE,
)
_CRITICALITY_TO_RANK: dict[str, int] = {
    "low": 0,
    "medium": 1,
    "high": 2,
    "critical": 3,
}
_CRITICALITY_RANK_TO_LABEL: dict[int, str] = {
    0: "baja",
    1: "media",
    2: "alta",
    3: "crítica",
}


class AlertInvestigationInput(BaseModel):
    """Artefactos de la investigación individual de N1 para una alerta del grupo."""

    model_config = ConfigDict(extra="allow")

    alert_id: str = ""
    alert: RawAlert = Field(default_factory=dict)
    analysis: Analysis | None = None
    context: ContextSnapshot = Field(default_factory=ContextSnapshot)
    evidence: list[Evidence] = Field(default_factory=list)
    ticket: Ticket | dict[str, Any] | None = None
    verdict_decision: VerdictDecision | None = None
    severity_decision: SeverityDecision | None = None
    escalation_decision: Escalation | None = None
    related_alerts: list[RawAlert] = Field(default_factory=list)


class IncidentGroup(BaseModel):
    """Contrato de agrupación de incidente recibido desde Persona 1 / Persona 4."""

    model_config = ConfigDict(extra="allow")

    incident_id: str = ""
    group_id: str = ""
    alert_ids: list[str] = Field(default_factory=list)
    alerts: list[RawAlert] = Field(default_factory=list)
    correlation_reason: str = ""
    shared_entities: dict[str, Any] = Field(default_factory=dict)
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    investigations: list[AlertInvestigationInput] = Field(default_factory=list)


class IncidentDecisionResult(BaseModel):
    """Contrato de salida consolidado de N2 para Persona 3 (Ticket) y Persona 4 (Orquestador)."""

    model_config = ConfigDict(extra="forbid")

    alert_ids: list[str] = Field(default_factory=list)
    verdict: Verdict
    confidence: float = Field(ge=0.0, le=1.0)
    verdict_rationale: str
    severity: Severity
    severity_rationale: str
    escalation: Escalation
    key_evidence_ids: list[str] = Field(default_factory=list)
    open_questions: list[str] = Field(default_factory=list)

    @property
    def verdict_decision(self) -> VerdictDecision:
        """Vista compatible con `VerdictDecision` de N1 para consumidores que la requieran."""
        return VerdictDecision(
            verdict=self.verdict,
            confidence=self.confidence,
            rationale=self.verdict_rationale,
        )

    @property
    def severity_decision(self) -> SeverityDecision:
        """Vista compatible con `SeverityDecision` de N1 para consumidores que la requieran."""
        return SeverityDecision(
            severity=self.severity,
            rationale=self.severity_rationale,
        )


# Alias semántico por si Persona 3 o Persona 4 importan `IncidentDecision`.
IncidentDecision = IncidentDecisionResult
N1InvestigationResult = AlertInvestigationInput


class _NormalizedAlertItem:
    """Contenedor interno normalizado para cada alerta que integra el incidente."""

    def __init__(
        self,
        alert_id: str,
        alert: RawAlert,
        analysis: Analysis | None,
        context: ContextSnapshot,
        evidence: list[Evidence],
        ticket: Ticket | dict[str, Any] | None = None,
        verdict_decision: VerdictDecision | None = None,
        severity_decision: SeverityDecision | None = None,
        escalation_decision: Escalation | None = None,
        related_alerts: list[RawAlert] | None = None,
    ) -> None:
        self.alert_id = alert_id
        self.alert = alert
        self.analysis = analysis
        self.context = context
        self.evidence = evidence
        self.ticket = ticket
        self.verdict_decision = verdict_decision
        self.severity_decision = severity_decision
        self.escalation_decision = escalation_decision
        self.related_alerts = related_alerts or []


class IncidentDecisionService:
    """Servicio de Nivel 2 que consolida veredicto, severidad y escalado de un incidente."""

    def __init__(
        self,
        verdict_engine: VerdictEngine | None = None,
        severity_calculator: SeverityCalculator | None = None,
        escalation_engine: EscalationEngine | None = None,
    ) -> None:
        self.verdict_engine = (
            verdict_engine if verdict_engine is not None else VerdictEngine()
        )
        self.severity_calculator = (
            severity_calculator
            if severity_calculator is not None
            else SeverityCalculator()
        )
        self.escalation_engine = (
            escalation_engine
            if escalation_engine is not None
            else EscalationEngine()
        )

    def decide(
        self,
        incident_group: IncidentGroup | dict[str, Any] | Any | None = None,
        alerts: (
            Sequence[RawAlert]
            | Sequence[AlertInvestigationInput | dict[str, Any] | Any]
            | None
        ) = None,
        tickets: (
            Sequence[Ticket | dict[str, Any]]
            | Mapping[str, Ticket | dict[str, Any]]
            | None
        ) = None,
        analyses: (
            Sequence[Analysis | dict[str, Any]]
            | Mapping[str, Analysis | dict[str, Any]]
            | None
        ) = None,
        contexts: (
            Sequence[ContextSnapshot | dict[str, Any]]
            | Mapping[str, ContextSnapshot | dict[str, Any]]
            | ContextSnapshot
            | dict[str, Any]
            | None
        ) = None,
        evidence: (
            Sequence[Evidence | dict[str, Any]]
            | Sequence[Sequence[Evidence | dict[str, Any]]]
            | Mapping[str, Sequence[Evidence | dict[str, Any]]]
            | None
        ) = None,
        investigations: (
            Sequence[AlertInvestigationInput | dict[str, Any] | Any]
            | Mapping[str, AlertInvestigationInput | dict[str, Any] | Any]
            | None
        ) = None,
        *,
        verdicts: (
            Sequence[VerdictDecision | dict[str, Any]]
            | Mapping[str, VerdictDecision | dict[str, Any]]
            | None
        ) = None,
        severities: (
            Sequence[SeverityDecision | dict[str, Any]]
            | Mapping[str, SeverityDecision | dict[str, Any]]
            | None
        ) = None,
        escalations: (
            Sequence[Escalation | dict[str, Any]]
            | Mapping[str, Escalation | dict[str, Any]]
            | None
        ) = None,
        **kwargs: Any,
    ) -> IncidentDecisionResult:
        """Determinar veredicto, severidad y escalado global para el incidente agrupado."""
        items, alert_ids, group_meta = self._normalize_inputs(
            incident_group=incident_group,
            alerts=alerts,
            tickets=tickets,
            analyses=analyses,
            contexts=contexts,
            evidence=evidence,
            investigations=investigations,
            verdicts=verdicts,
            severities=severities,
            escalations=escalations,
            extra_kwargs=kwargs,
        )

        # 1. Evaluar cada alerta con VerdictEngine de N1 y consolidar veredicto global.
        verdict_decision, per_alert_verdicts, n2_issues = self._decide_global_verdict(
            items=items,
            alert_ids=alert_ids,
            group_meta=group_meta,
        )

        # 2. Calcular la severidad global reutilizando SeverityCalculator de N1.
        severity_decision = self._decide_global_severity(
            items=items,
            per_alert_verdicts=per_alert_verdicts,
            global_verdict=verdict_decision,
        )

        # 3. Determinar el escalado global reutilizando EscalationEngine de N1.
        escalation_decision = self._decide_global_escalation(
            items=items,
            per_alert_verdicts=per_alert_verdicts,
            global_verdict=verdict_decision,
            global_severity=severity_decision,
        )

        # 4. Recopilar referencias a evidencias clave y preguntas abiertas sin duplicados.
        key_evidence_ids = self._collect_key_evidence_ids(
            items=items,
            per_alert_verdicts=per_alert_verdicts,
            global_verdict=verdict_decision,
        )
        open_questions = self._collect_open_questions(
            items=items,
            n2_issues=n2_issues,
        )

        return IncidentDecisionResult(
            alert_ids=alert_ids,
            verdict=verdict_decision.verdict,
            confidence=verdict_decision.confidence,
            verdict_rationale=verdict_decision.rationale,
            severity=severity_decision.severity,
            severity_rationale=severity_decision.rationale,
            escalation=escalation_decision,
            key_evidence_ids=key_evidence_ids,
            open_questions=open_questions,
        )

    # ------------------------------------------------------------------
    # Normalización de entradas (Persona 1 / N1 / Persona 4)
    # ------------------------------------------------------------------

    def _normalize_inputs(
        self,
        *,
        incident_group: Any,
        alerts: Any,
        tickets: Any,
        analyses: Any,
        contexts: Any,
        evidence: Any,
        investigations: Any,
        verdicts: Any,
        severities: Any,
        escalations: Any,
        extra_kwargs: dict[str, Any],
    ) -> tuple[list[_NormalizedAlertItem], list[str], dict[str, Any]]:
        """Unificar las entradas del grupo y los resultados individuales de N1."""
        if incident_group is None:
            incident_group = extra_kwargs.get("group") or extra_kwargs.get("incident")
        if investigations is None:
            investigations = (
                extra_kwargs.get("n1_results")
                or extra_kwargs.get("investigation_results")
                or extra_kwargs.get("results")
            )
        if tickets is None:
            tickets = extra_kwargs.get("n1_tickets")
        if contexts is None and "context" in extra_kwargs:
            contexts = extra_kwargs["context"]

        # Si el segundo argumento posicional (`alerts`) es en realidad una lista de
        # `AlertInvestigationInput` o objetos de investigación, reasignarlo.
        if (
            investigations is None
            and isinstance(alerts, Sequence)
            and not isinstance(alerts, (str, bytes))
            and alerts
            and self._looks_like_investigation_item(alerts[0])
        ):
            investigations = alerts
            alerts = None

        group_meta = self._extract_group_metadata(incident_group)
        if alerts is None and group_meta.get("alerts"):
            alerts = group_meta["alerts"]
        if investigations is None and group_meta.get("investigations"):
            investigations = group_meta["investigations"]
        if tickets is None and group_meta.get("tickets"):
            tickets = group_meta["tickets"]
        if analyses is None and group_meta.get("analyses"):
            analyses = group_meta["analyses"]
        if contexts is None and group_meta.get("contexts"):
            contexts = group_meta["contexts"]
        if evidence is None and group_meta.get("evidence"):
            evidence = group_meta["evidence"]

        inv_list = self._coerce_investigation_list(investigations)
        alert_list = [self._coerce_raw_alert(a) for a in (alerts or [])]
        ticket_map, ticket_list = self._index_tickets(tickets)
        analysis_map, analysis_list = self._index_models(analyses, Analysis)
        context_map, context_list, shared_context = self._index_contexts(contexts)
        evidence_map, evidence_per_index, shared_evidence = self._index_evidence(
            evidence
        )
        verdict_map, verdict_list = self._index_models(verdicts, VerdictDecision)
        severity_map, severity_list = self._index_models(severities, SeverityDecision)
        escalation_map, escalation_list = self._index_models(escalations, Escalation)

        # Determinar el orden canónico de alert_ids del incidente.
        ordered_ids: list[str] = []
        for aid in group_meta.get("alert_ids", []):
            if isinstance(aid, str) and aid.strip() and aid not in ordered_ids:
                ordered_ids.append(aid.strip())
        for raw_alert in alert_list:
            aid = str(raw_alert.get("alert_id") or "").strip()
            if aid and aid not in ordered_ids:
                ordered_ids.append(aid)
        for inv in inv_list:
            aid = str(
                inv.alert_id or (inv.alert.get("alert_id") if inv.alert else "")
            ).strip()
            if aid and aid not in ordered_ids:
                ordered_ids.append(aid)
        for t_aid in ticket_map:
            if t_aid and t_aid not in ordered_ids:
                ordered_ids.append(t_aid)

        alert_by_id: dict[str, RawAlert] = {}
        for raw_alert in alert_list:
            aid = str(raw_alert.get("alert_id") or "").strip()
            if aid and aid not in alert_by_id:
                alert_by_id[aid] = raw_alert

        inv_by_id: dict[str, AlertInvestigationInput] = {}
        for idx, inv in enumerate(inv_list):
            aid = str(
                inv.alert_id or (inv.alert.get("alert_id") if inv.alert else "")
            ).strip()
            if not aid and idx < len(ordered_ids):
                aid = ordered_ids[idx]
            if not aid:
                aid = f"ALERT-{idx + 1}"
                if aid not in ordered_ids:
                    ordered_ids.append(aid)
            inv_by_id[aid] = inv

        if not ordered_ids:
            max_len = max(
                len(alert_list),
                len(inv_list),
                len(analysis_list),
                len(ticket_list),
            )
            ordered_ids = [f"ALERT-{i + 1}" for i in range(max_len)]

        items: list[_NormalizedAlertItem] = []
        for idx, aid in enumerate(ordered_ids):
            inv = inv_by_id.get(aid)
            if inv is None and idx < len(inv_list) and not inv_list[idx].alert_id:
                inv = inv_list[idx]

            raw_alert = alert_by_id.get(aid)
            if raw_alert is None and inv is not None and inv.alert:
                raw_alert = dict(inv.alert)
            if raw_alert is None and idx < len(alert_list):
                raw_alert = dict(alert_list[idx])
            if raw_alert is None:
                raw_alert = {"alert_id": aid}
            elif not raw_alert.get("alert_id"):
                raw_alert = {**raw_alert, "alert_id": aid}

            ticket = inv.ticket if (inv and inv.ticket is not None) else ticket_map.get(aid)
            if ticket is None and idx < len(ticket_list):
                ticket = ticket_list[idx]

            analysis = inv.analysis if (inv and inv.analysis is not None) else analysis_map.get(aid)
            if analysis is None and idx < len(analysis_list):
                analysis = analysis_list[idx]
            if analysis is None and ticket is not None:
                analysis = self._analysis_from_ticket(ticket)

            context = (
                inv.context
                if (inv and not self._is_empty_context(inv.context))
                else context_map.get(aid)
            )
            if context is None and idx < len(context_list):
                context = context_list[idx]
            if context is None and shared_context is not None:
                context = shared_context
            if context is None:
                context = ContextSnapshot()

            if inv is not None and inv.evidence:
                ev_list = list(inv.evidence)
            elif aid in evidence_map:
                ev_list = list(evidence_map[aid])
            elif idx < len(evidence_per_index):
                ev_list = list(evidence_per_index[idx])
            elif shared_evidence:
                ev_list = list(shared_evidence)
            else:
                ev_list = self._evidence_from_ticket(ticket)

            v_dec = (
                inv.verdict_decision
                if (inv and inv.verdict_decision is not None)
                else verdict_map.get(aid)
            )
            if v_dec is None and idx < len(verdict_list):
                v_dec = verdict_list[idx]

            s_dec = (
                inv.severity_decision
                if (inv and inv.severity_decision is not None)
                else severity_map.get(aid)
            )
            if s_dec is None and idx < len(severity_list):
                s_dec = severity_list[idx]

            e_dec = (
                inv.escalation_decision
                if (inv and inv.escalation_decision is not None)
                else escalation_map.get(aid)
            )
            if e_dec is None and idx < len(escalation_list):
                e_dec = escalation_list[idx]

            rel_alerts = list(inv.related_alerts) if (inv and inv.related_alerts) else []

            items.append(
                _NormalizedAlertItem(
                    alert_id=aid,
                    alert=raw_alert,
                    analysis=analysis,
                    context=context,
                    evidence=ev_list,
                    ticket=ticket,
                    verdict_decision=v_dec,
                    severity_decision=s_dec,
                    escalation_decision=e_dec,
                    related_alerts=rel_alerts,
                )
            )

        return items, ordered_ids, group_meta

    # ------------------------------------------------------------------
    # 1. Motor de Veredicto Consolidado (N2)
    # ------------------------------------------------------------------

    def _decide_global_verdict(
        self,
        *,
        items: list[_NormalizedAlertItem],
        alert_ids: list[str],
        group_meta: dict[str, Any],
    ) -> tuple[VerdictDecision, dict[str, VerdictDecision], list[str]]:
        """Consolidar el veredicto global del incidente reutilizando `VerdictEngine`."""
        n2_issues: list[str] = []
        per_alert_verdicts: dict[str, VerdictDecision] = {}

        if not items:
            issue = (
                "No se han recibido alertas ni resultados de investigación N1 para "
                "el incidente agrupado."
            )
            n2_issues.append(issue)
            return (
                VerdictDecision(
                    verdict="needs_more_info",
                    confidence=0.0,
                    rationale=(
                        "Información insuficiente: el incidente no contiene alertas "
                        "ni análisis N1 verificables."
                    ),
                ),
                per_alert_verdicts,
                n2_issues,
            )

        missing_analysis_ids: list[str] = []
        for item in items:
            if item.analysis is None:
                missing_analysis_ids.append(item.alert_id)
                per_alert_verdicts[item.alert_id] = VerdictDecision(
                    verdict="needs_more_info",
                    confidence=0.0,
                    rationale=(
                        f"La alerta {item.alert_id} carece de análisis individual de N1."
                    ),
                )
                continue

            # Reutilizar siempre el motor VerdictEngine de N1 para validar cada alerta.
            validated = self.verdict_engine.decide(
                item.analysis,
                item.evidence,
                item.context,
                alert=item.alert,
            )
            # Si además se verifican restricciones de alcance/activo/origen en N2 para BTP:
            if item.analysis.verdict == "benign_true_positive":
                scope_ok, scope_problem = self._verify_n2_authorization_scope(
                    item.alert,
                    item.analysis,
                    item.evidence,
                    item.context,
                )
                if not scope_ok:
                    n2_issues.append(f"[{item.alert_id}] {scope_problem}")
                    validated = VerdictDecision(
                        verdict="needs_more_info",
                        confidence=max(0.0, round(validated.confidence - 0.20, 2)),
                        rationale=(
                            f"No se acepta benign_true_positive en {item.alert_id}: "
                            f"{scope_problem} {validated.rationale}"
                        ),
                    )
            per_alert_verdicts[item.alert_id] = validated

        if missing_analysis_ids:
            n2_issues.append(
                "Faltan investigaciones individuales de N1 para las alertas: "
                + ", ".join(missing_analysis_ids)
                + "."
            )

        # Detectar contradicciones cruzadas entre alertas y evidencias del incidente.
        contradictions, tainted_alert_ids = self._detect_cross_alert_contradictions(
            items=items,
            per_alert_verdicts=per_alert_verdicts,
            group_meta=group_meta,
        )
        n2_issues.extend(contradictions)

        # Si una alerta estaba marcada como true_positive pero depende de evidencias
        # contradichas o inválidas en el cruce N2, degradarla a needs_more_info.
        for tainted_id in tainted_alert_ids:
            prev = per_alert_verdicts.get(tainted_id)
            if prev is not None and prev.verdict != "needs_more_info":
                per_alert_verdicts[tainted_id] = VerdictDecision(
                    verdict="needs_more_info",
                    confidence=max(0.0, round(prev.confidence - 0.25, 2)),
                    rationale=(
                        f"Evidencia contradictoria en el incidente para {tainted_id}. "
                        f"{prev.rationale}"
                    ),
                )

        tp_ids = [
            aid
            for aid, dec in per_alert_verdicts.items()
            if dec.verdict == "true_positive"
        ]
        btp_ids = [
            aid
            for aid, dec in per_alert_verdicts.items()
            if dec.verdict == "benign_true_positive"
        ]
        fp_ids = [
            aid
            for aid, dec in per_alert_verdicts.items()
            if dec.verdict == "false_positive"
        ]
        nmi_ids = [
            aid
            for aid, dec in per_alert_verdicts.items()
            if dec.verdict == "needs_more_info"
        ]

        correlation_unfounded = bool(group_meta.get("correlation_valid") is False)
        if correlation_unfounded:
            n2_issues.append(
                "La relación entre las alertas del grupo ha sido marcada como no fundamentada."
            )

        # Regla 1: True Positive confirmado en al menos una alerta (sin contradicción
        # que invalide la actividad maliciosa y con relación fundamentada).
        if tp_ids and not correlation_unfounded:
            tp_confidences = [per_alert_verdicts[aid].confidence for aid in tp_ids]
            base_conf = max(tp_confidences)
            penalty = 0.05 * len(nmi_ids) + 0.05 * len(contradictions)
            confidence = max(0.0, min(1.0, round(base_conf - penalty, 2)))

            parts = [
                f"Incidente clasificado como true_positive: actividad maliciosa "
                f"confirmada con evidencias verificables en {', '.join(tp_ids)}."
            ]
            if btp_ids:
                parts.append(
                    "Autorización parcial detectada: las alertas "
                    f"{', '.join(btp_ids)} corresponden a actividad autorizada "
                    "(benign_true_positive), pero no eximen ni ocultan el compromiso "
                    f"confirmado en {', '.join(tp_ids)}."
                )
            if fp_ids:
                parts.append(
                    f"Las alertas {', '.join(fp_ids)} fueron descartadas individualmente "
                    "como false_positive, manteniéndose el veredicto global de compromiso."
                )
            if nmi_ids:
                parts.append(
                    f"Las alertas {', '.join(nmi_ids)} requieren información adicional "
                    "para completar el alcance secundario."
                )
                for aid in nmi_ids:
                    parts.append(f"[{aid}] Actividad declarada autorizada o pendiente de verificación: "
                                 f"{per_alert_verdicts[aid].rationale}")
            for aid in tp_ids:
                parts.append(f"[{aid}] {per_alert_verdicts[aid].rationale}")
            for aid in btp_ids:
                parts.append(f"[{aid}] {per_alert_verdicts[aid].rationale}")

            return (
                VerdictDecision(
                    verdict="true_positive",
                    confidence=confidence,
                    rationale=" ".join(parts),
                ),
                per_alert_verdicts,
                n2_issues,
            )

        # Regla 2: Si existen contradicciones, alertas en needs_more_info o falta de
        # análisis sin ningún true_positive confirmado -> needs_more_info.
        if contradictions or nmi_ids or missing_analysis_ids or correlation_unfounded:
            all_confs = [dec.confidence for dec in per_alert_verdicts.values()]
            base_conf = min(all_confs) if all_confs else 0.0
            if contradictions:
                base_conf = max(0.0, round(base_conf - 0.15 * len(contradictions), 2))

            parts = [
                "Incidente clasificado como needs_more_info: no es posible confirmar "
                "ni descartar el incidente de forma concluyente."
            ]
            if contradictions:
                parts.append(
                    "Se detectaron contradicciones entre alertas o evidencias: "
                    + " ".join(contradictions)
                )
            if nmi_ids:
                parts.append(
                    f"Alertas con evidencias o verificaciones insuficientes: {', '.join(nmi_ids)}."
                )
            if btp_ids and nmi_ids:
                parts.append(
                    f"Aunque {', '.join(btp_ids)} presenta actividad autorizada, "
                    "no todas las actividades relevantes del grupo están explicadas."
                )
            for aid in alert_ids:
                if aid in per_alert_verdicts:
                    parts.append(f"[{aid}] {per_alert_verdicts[aid].rationale}")

            return (
                VerdictDecision(
                    verdict="needs_more_info",
                    confidence=max(0.0, min(1.0, round(base_conf, 2))),
                    rationale=" ".join(parts),
                ),
                per_alert_verdicts,
                n2_issues,
            )

        # Regla 3: Benign True Positive (todas las actividades relevantes ocurrieron
        # y están explicadas por cambios/mantenimientos/flujos autorizados verificados).
        if btp_ids and len(btp_ids) + len(fp_ids) == len(alert_ids):
            confs = [per_alert_verdicts[aid].confidence for aid in btp_ids]
            confidence = max(0.0, min(1.0, round(min(confs), 2)))
            parts = [
                "Incidente clasificado como benign_true_positive: todas las actividades "
                f"relevantes del grupo ({', '.join(btp_ids)}) están respaldadas y "
                "explicadas por un cambio, mantenimiento o actividad autorizada "
                "cuyo activo, horario, origen y alcance coinciden."
            ]
            if fp_ids:
                parts.append(
                    f"Las alertas restantes ({', '.join(fp_ids)}) corresponden a "
                    "false_positive sin actividad maliciosa."
                )
            for aid in btp_ids:
                parts.append(f"[{aid}] {per_alert_verdicts[aid].rationale}")

            return (
                VerdictDecision(
                    verdict="benign_true_positive",
                    confidence=confidence,
                    rationale=" ".join(parts),
                ),
                per_alert_verdicts,
                n2_issues,
            )

        # Regla 4: False Positive (todas las alertas del incidente descartadas con pruebas).
        if fp_ids and len(fp_ids) == len(alert_ids):
            confs = [per_alert_verdicts[aid].confidence for aid in fp_ids]
            confidence = max(0.0, min(1.0, round(min(confs), 2)))
            parts = [
                "Incidente clasificado como false_positive: todas las alertas del "
                f"grupo ({', '.join(fp_ids)}) han sido descartadas mediante "
                "evidencias verificables."
            ]
            for aid in fp_ids:
                parts.append(f"[{aid}] {per_alert_verdicts[aid].rationale}")

            return (
                VerdictDecision(
                    verdict="false_positive",
                    confidence=confidence,
                    rationale=" ".join(parts),
                ),
                per_alert_verdicts,
                n2_issues,
            )

        # Fallback defensivo ante cualquier combinación no cubierta.
        return (
            VerdictDecision(
                verdict="needs_more_info",
                confidence=0.0,
                rationale=(
                    "No se dispone de elementos suficientes para confirmar o descartar "
                    "el incidente."
                ),
            ),
            per_alert_verdicts,
            n2_issues,
        )

    def _verify_n2_authorization_scope(
        self,
        alert: RawAlert,
        analysis: Analysis,
        evidence: list[Evidence],
        context: ContextSnapshot,
    ) -> tuple[bool, str]:
        """Verificar que el cambio autorizado coincida también en activo, origen y alcance."""
        if not context.changes:
            return False, "No existen cambios autorizados en el contexto para respaldar la actividad."

        changes_by_id = {
            str(ch.get("id", "")).strip(): ch
            for ch in context.changes
            if isinstance(ch, dict) and str(ch.get("id", "")).strip()
        }
        referenced_changes = [
            changes_by_id[ref]
            for finding in analysis.findings
            for ref in finding.evidence_ids
            if ref in changes_by_id
        ]
        if not referenced_changes:
            return False, "Ningún hallazgo cita un identificador de cambio válido del contexto."

        alert_hosts = self._extract_alert_host_tokens(alert)
        alert_ips = self._extract_alert_ip_tokens(alert)

        for change in referenced_changes:
            # Comprobar activos/hosts explícitos si el registro del cambio los declara.
            explicit_assets: set[str] = set()
            for field in ("activos", "assets", "hosts", "activo", "hostname", "target"):
                val = change.get(field)
                if isinstance(val, str) and val.strip():
                    for token in re.split(r"[,;\s]+", val.strip()):
                        if token:
                            explicit_assets.add(token.casefold())
                elif isinstance(val, Sequence) and not isinstance(val, (str, bytes)):
                    for item in val:
                        if isinstance(item, str) and item.strip():
                            explicit_assets.add(item.strip().casefold())

            if explicit_assets and alert_hosts:
                if not (explicit_assets & alert_hosts):
                    return (
                        False,
                        f"El activo de la alerta ({sorted(alert_hosts)}) no coincide "
                        f"con el alcance del cambio {change.get('id')} ({sorted(explicit_assets)}).",
                    )

            # Comprobar origen explícito si el cambio declara `origen` / `origin` / `source_ip`.
            explicit_origins: set[str] = set()
            for field in ("origen", "origin", "source_ip", "source_host"):
                val = change.get(field)
                if isinstance(val, str) and val.strip():
                    explicit_origins.add(val.strip().casefold())
            if explicit_origins and (alert_hosts or alert_ips):
                all_tokens = alert_hosts | alert_ips
                if not (explicit_origins & all_tokens):
                    return (
                        False,
                        f"El origen observado ({sorted(all_tokens)}) no coincide con "
                        f"el origen autorizado en el cambio {change.get('id')} "
                        f"({sorted(explicit_origins)}).",
                    )

        return True, ""

    def _detect_cross_alert_contradictions(
        self,
        *,
        items: list[_NormalizedAlertItem],
        per_alert_verdicts: dict[str, VerdictDecision],
        group_meta: dict[str, Any],
    ) -> tuple[list[str], set[str]]:
        """Detectar contradicciones entre evidencias o análisis de distintas alertas."""
        contradictions: list[str] = []
        tainted_alerts: set[str] = set()

        # 1. Mismo event_id con contenido de Evidence distinto entre alertas.
        events_by_id: dict[str, tuple[str, Evidence]] = {}
        ambiguous_event_ids: set[str] = set()
        for item in items:
            for ev in item.evidence:
                eid = (ev.event_id or "").strip()
                if not eid:
                    continue
                prev = events_by_id.get(eid)
                if prev is not None and prev[1] != ev:
                    ambiguous_event_ids.add(eid)
                    contradictions.append(
                        f"El evento {eid} presenta contenido contradictorio entre "
                        f"{prev[0]} y {item.alert_id}."
                    )
                else:
                    events_by_id[eid] = (item.alert_id, ev)

        if ambiguous_event_ids:
            for item in items:
                if item.analysis is None:
                    continue
                cited = {
                    ref
                    for finding in item.analysis.findings
                    for ref in finding.evidence_ids
                }
                if cited & ambiguous_event_ids:
                    tainted_alerts.add(item.alert_id)

        # 2. Dos alertas citan el mismo event_id pero una afirma true_positive /
        # benign_true_positive y otra afirma false_positive sobre la misma prueba.
        verdicts_by_event: dict[str, list[tuple[str, str]]] = {}
        for item in items:
            if item.analysis is None:
                continue
            eff_verdict = per_alert_verdicts[item.alert_id].verdict
            prop_verdict = item.analysis.verdict
            for finding in item.analysis.findings:
                for eid in finding.evidence_ids:
                    verdicts_by_event.setdefault(eid, []).append(
                        (item.alert_id, eff_verdict or prop_verdict)
                    )

        for eid, pairs in verdicts_by_event.items():
            verdict_set = {v for _, v in pairs}
            if "false_positive" in verdict_set and (
                "true_positive" in verdict_set or "benign_true_positive" in verdict_set
            ):
                involved = sorted({aid for aid, _ in pairs})
                contradictions.append(
                    f"Contradicción directa sobre la evidencia {eid}: las alertas "
                    f"{', '.join(involved)} emiten veredictos incompatibles "
                    f"({sorted(verdict_set)}) sobre el mismo evento."
                )
                tainted_alerts.update(involved)

        # 3. Contradicción de señales sobre la misma entidad/evento cuando no hay
        # eventos diferenciados (p. ej. una alerta afirma que todo fue bloqueado sin
        # efecto y falso positivo, y otra afirma ejecución maliciosa sin evidencias propias).
        for item in items:
            if item.analysis is None:
                continue
            v_dec = per_alert_verdicts[item.alert_id]
            if v_dec.verdict == "true_positive":
                valid_ev_ids = {
                    ev.event_id
                    for ev in item.evidence
                    if ev.event_id and ev.event_id.strip() and ev.event_id not in ambiguous_event_ids
                }
                cited_valid = [
                    ref
                    for finding in item.analysis.findings
                    for ref in finding.evidence_ids
                    if ref in valid_ev_ids
                ]
                if not cited_valid:
                    contradictions.append(
                        f"La alerta {item.alert_id} propone true_positive pero no "
                        "dispone de evidencias verificables no ambiguas."
                    )
                    tainted_alerts.add(item.alert_id)

        # Deduplicar mensajes conservando orden.
        return list(dict.fromkeys(contradictions)), tainted_alerts

    # ------------------------------------------------------------------
    # 2. Motor de Severidad Global (N2)
    # ------------------------------------------------------------------

    def _decide_global_severity(
        self,
        *,
        items: list[_NormalizedAlertItem],
        per_alert_verdicts: dict[str, VerdictDecision],
        global_verdict: VerdictDecision,
    ) -> SeverityDecision:
        """Calcular la severidad consolidada reutilizando `SeverityCalculator`."""
        if not items:
            return SeverityDecision(
                severity="low",
                rationale=(
                    "Sin alertas válidas en el incidente; se asigna severidad low "
                    "de forma conservadora hasta recibir datos."
                ),
            )

        # Si el incidente global es benign_true_positive, reutilizar directamente
        # SeverityCalculator (la política SOC fija informational o low).
        if global_verdict.verdict == "benign_true_positive":
            consolidated_alert = self._build_consolidated_alert(items)
            consolidated_context = self._merge_contexts([i.context for i in items])
            consolidated_analysis = self._build_consolidated_analysis(
                items, global_verdict.verdict
            )
            decision = self.severity_calculator.calculate(
                consolidated_alert,
                consolidated_context,
                consolidated_analysis,
                global_verdict,
            )
            return SeverityDecision(
                severity=decision.severity,
                rationale=(
                    f"{decision.rationale} Actividad autorizada verificada para "
                    f"{len(items)} alerta(s) del incidente."
                ),
            )

        # Seleccionar las alertas relevantes para el impacto activo del incidente:
        # En un incidente true_positive con parte autorizada (BTP) o FP, las alertas
        # BTP/FP explicadas no deben inflar ni amortiguar la severidad del ataque real.
        relevant_items = self._select_severity_relevant_items(
            items=items,
            per_alert_verdicts=per_alert_verdicts,
            global_verdict=global_verdict.verdict,
        )

        # Evaluar también las severidades individuales con SeverityCalculator para trazabilidad.
        individual_severities: list[tuple[str, SeverityDecision]] = []
        for item in relevant_items:
            analysis = item.analysis or self._empty_analysis()
            v_dec = per_alert_verdicts.get(item.alert_id, global_verdict)
            if item.severity_decision is not None:
                individual_severities.append((item.alert_id, item.severity_decision))
            else:
                try:
                    ind_sev = self.severity_calculator.calculate(
                        item.alert,
                        item.context,
                        analysis,
                        v_dec,
                    )
                    individual_severities.append((item.alert_id, ind_sev))
                except ValueError:
                    pass

        consolidated_context = self._merge_contexts([i.context for i in relevant_items])
        affected_stores = self._extract_affected_stores(
            relevant_items, consolidated_context
        )
        affected_hosts = self._extract_affected_hosts(
            relevant_items, consolidated_context
        )
        affected_services = self._extract_affected_services(consolidated_context)

        consolidated_alert = self._build_consolidated_alert(
            relevant_items,
            extra_context=consolidated_context,
        )
        consolidated_analysis = self._build_consolidated_analysis(
            relevant_items,
            global_verdict.verdict,
        )

        # Enriquecer la representación de activos en el contexto consolidado cuando
        # existen servicios críticos de negocio o múltiples tiendas afectadas para que
        # SeverityCalculator cruce la matriz con la criticidad real conjunta.
        effective_context, scope_notes = self._prepare_effective_severity_context(
            alert=consolidated_alert,
            context=consolidated_context,
            affected_stores=affected_stores,
            affected_hosts=affected_hosts,
            affected_services=affected_services,
            global_verdict=global_verdict.verdict,
        )

        base_decision = self.severity_calculator.calculate(
            consolidated_alert,
            effective_context,
            consolidated_analysis,
            global_verdict,
        )

        final_severity: Severity = base_decision.severity
        extra_rationale: list[str] = list(scope_notes)

        # Si hay múltiples tiendas afectadas (≥2 tiendas) en un incidente activo
        # (true_positive o needs_more_info) y el resultado aún quedó por debajo de
        # high (p. ej. alertas low/medium sin ajuste previo), reflejar el alcance
        # multitienda con un máximo de +1 nivel según la política SOC.
        if (
            len(affected_stores) >= 2
            and global_verdict.verdict in ("true_positive", "needs_more_info")
            and SEVERITY_LEVELS.index(final_severity) < SEVERITY_LEVELS.index("high")
        ):
            idx = min(
                len(SEVERITY_LEVELS) - 1, SEVERITY_LEVELS.index(final_severity) + 1
            )
            final_severity = SEVERITY_LEVELS[idx]
            extra_rationale.append(
                f"Ajuste de alcance N2 (+1 -> {final_severity}): impacto operativo "
                f"distribuido en {len(affected_stores)} tiendas ({', '.join(affected_stores)})."
            )

        # Explicar explícitamente que el volumen de alertas no infla la severidad por sí mismo.
        if len(items) > 1:
            extra_rationale.append(
                f"Evaluación consolidada sobre {len(items)} alertas (no se aplica media "
                "simple ni incremento automático por volumen de alertas)."
            )
        if affected_hosts:
            extra_rationale.append(
                f"Sistemas afectados considerados ({len(affected_hosts)}): "
                + ", ".join(affected_hosts[:8])
                + ("..." if len(affected_hosts) > 8 else "")
                + "."
            )
        if affected_services:
            extra_rationale.append(
                "Servicios de negocio afectados: " + ", ".join(affected_services) + "."
            )

        rationale = " ".join([base_decision.rationale, *extra_rationale]).strip()
        return SeverityDecision(severity=final_severity, rationale=rationale)

    def _select_severity_relevant_items(
        self,
        *,
        items: list[_NormalizedAlertItem],
        per_alert_verdicts: dict[str, VerdictDecision],
        global_verdict: Verdict,
    ) -> list[_NormalizedAlertItem]:
        """Filtrar alertas que determinan la severidad activa del incidente."""
        if global_verdict == "true_positive":
            tp_only = [
                item
                for item in items
                if per_alert_verdicts.get(item.alert_id) is not None
                and per_alert_verdicts[item.alert_id].verdict == "true_positive"
            ]
            if tp_only:
                return tp_only
        if global_verdict == "needs_more_info":
            active = [
                item
                for item in items
                if per_alert_verdicts.get(item.alert_id) is None
                or per_alert_verdicts[item.alert_id].verdict
                not in ("benign_true_positive", "false_positive")
            ]
            if active:
                return active
        return items

    def _prepare_effective_severity_context(
        self,
        *,
        alert: RawAlert,
        context: ContextSnapshot,
        affected_stores: list[str],
        affected_hosts: list[str],
        affected_services: list[str],
        global_verdict: Verdict,
    ) -> tuple[ContextSnapshot, list[str]]:
        """Preparar el contexto consolidado reflejando criticidad de negocio y alcance multitienda."""
        notes: list[str] = []
        assets = [dict(a) for a in context.assets if isinstance(a, dict)]

        # Calcular la mayor criticidad registrada entre todos los activos y servicios del contexto.
        highest_rank = 0
        for asset in assets:
            crit = str(asset.get("criticality", "")).strip().casefold()
            if crit in CRITICALITIES:
                highest_rank = max(
                    highest_rank, _CRITICALITY_TO_RANK[CRITICALITIES[crit]]
                )

        for service in context.services:
            if not isinstance(service, dict):
                continue
            scrit = str(
                service.get("criticidad") or service.get("criticality") or ""
            ).strip().casefold()
            if scrit in CRITICALITIES:
                srv_rank = _CRITICALITY_TO_RANK[CRITICALITIES[scrit]]
                if srv_rank > highest_rank:
                    highest_rank = srv_rank
                    notes.append(
                        f"Criticidad elevada a {_CRITICALITY_RANK_TO_LABEL[highest_rank]} "
                        f"por el servicio de negocio '{service.get('servicio', 'desconocido')}'."
                    )

        # Si hay múltiples tiendas afectadas (≥2) en un incidente no benigno/no FP,
        # el alcance operativo conjunto en red de tiendas equivale al menos a criticidad alta
        # (o crítica si hay ≥3 tiendas o servicios de pago TPV implicados).
        if len(affected_stores) >= 2 and global_verdict in (
            "true_positive",
            "needs_more_info",
        ):
            has_pos = any(
                "tpv" in str(a.get("type", "")).casefold()
                or str(a.get("hostname", "")).upper().startswith(("POS-", "TPV-"))
                for a in assets
            ) or any(h.upper().startswith(("POS-", "TPV-")) for h in affected_hosts)
            target_rank = 3 if (len(affected_stores) >= 3 or has_pos) else 2
            if target_rank > highest_rank:
                highest_rank = target_rank
            notes.append(
                f"Alcance multitienda detectado ({len(affected_stores)} tiendas afectadas: "
                f"{', '.join(affected_stores)}); se considera el impacto operativo conjunto "
                f"(criticidad efectiva {_CRITICALITY_RANK_TO_LABEL[highest_rank]})."
            )

        # Asegurar que el activo más crítico esté enlazado con las entidades de la alerta
        # consolidada para que `SeverityCalculator._get_criticality` lo seleccione.
        target_label = _CRITICALITY_RANK_TO_LABEL[highest_rank]
        primary_host = None
        hosts_in_alert = (alert.get("entities") or {}).get("hosts") or []
        if hosts_in_alert:
            first = hosts_in_alert[0]
            primary_host = (
                first.get("hostname") or first.get("asset_id") or first.get("ip")
                if isinstance(first, dict)
                else str(first)
            )
        if not primary_host:
            primary_host = affected_hosts[0] if affected_hosts else "INCIDENT-SCOPE"
            alert.setdefault("entities", {}).setdefault("hosts", []).append(
                {"hostname": primary_host}
            )

        if highest_rank > 0:
            assets.append(
                {
                    "asset_id": primary_host,
                    "hostname": primary_host,
                    "criticality": target_label,
                }
            )

        return (
            ContextSnapshot(
                assets=assets,
                users=list(context.users),
                services=list(context.services),
                network_zones=list(context.network_zones),
                changes=list(context.changes),
                missing_lookups=list(context.missing_lookups),
            ),
            notes,
        )

    # ------------------------------------------------------------------
    # 3. Motor de Escalado Global (N2)
    # ------------------------------------------------------------------

    def _decide_global_escalation(
        self,
        *,
        items: list[_NormalizedAlertItem],
        per_alert_verdicts: dict[str, VerdictDecision],
        global_verdict: VerdictDecision,
        global_severity: SeverityDecision,
    ) -> Escalation:
        """Determinar la decisión de escalado global reutilizando `EscalationEngine`."""
        relevant_items = self._select_severity_relevant_items(
            items=items,
            per_alert_verdicts=per_alert_verdicts,
            global_verdict=global_verdict.verdict,
        )
        consolidated_analysis = self._build_consolidated_analysis(
            relevant_items,
            global_verdict.verdict,
        )
        all_alerts = [item.alert for item in items]

        # Delegar la decisión principal en el motor oficial `EscalationEngine` de N1.
        base_escalation = self.escalation_engine.decide(
            consolidated_analysis,
            global_verdict,
            global_severity,
            all_alerts,
        )

        # Si el incidente global es false_positive o benign_true_positive, no escala.
        if global_verdict.verdict in ("false_positive", "benign_true_positive"):
            return base_escalation

        # Combinar motivos adicionales de las alertas activas sin duplicarlos.
        combined_reasons: list[str] = []
        if base_escalation.reason:
            combined_reasons.append(base_escalation.reason.strip())

        for item in relevant_items:
            v_dec = per_alert_verdicts.get(item.alert_id, global_verdict)
            if v_dec.verdict in ("false_positive", "benign_true_positive"):
                continue
            ind_esc = item.escalation_decision
            if ind_esc is not None and ind_esc.escalate and ind_esc.reason:
                reason_text = ind_esc.reason.strip()
                if reason_text and reason_text not in combined_reasons:
                    combined_reasons.append(reason_text)

        # Verificar afectación a red OT o propagación multitienda/multisistema para
        # documentarlo en el motivo de escalado conforme a `politica_soc.md`.
        merged_context = self._merge_contexts([i.context for i in relevant_items])
        has_ot = self._has_ot_scope(merged_context)
        stores = self._extract_affected_stores(relevant_items, merged_context)
        services = self._extract_affected_services(merged_context)

        escalate = base_escalation.escalate
        to = base_escalation.to

        if has_ot and global_verdict.verdict in ("true_positive", "needs_more_info"):
            if not escalate:
                escalate = True
                to = "N2 de guardia" if global_severity.severity == "critical" else "N2"
            ot_note = (
                "Afectación en zona LOGISTICS-OT: según política SOC, no ejecutar "
                "contención directa y coordinar con el Responsable de Operaciones."
            )
            if ot_note not in combined_reasons:
                combined_reasons.append(ot_note)

        if escalate:
            if len(stores) >= 2:
                store_note = (
                    f"Propagación del incidente a {len(stores)} tiendas "
                    f"({', '.join(stores)})."
                )
                if store_note not in combined_reasons:
                    combined_reasons.append(store_note)
            if services:
                srv_note = (
                    "Servicios de negocio afectados: " + ", ".join(services) + "."
                )
                if srv_note not in combined_reasons:
                    combined_reasons.append(srv_note)

        deduped_reason = self._deduplicate_sentences(combined_reasons)
        return Escalation(
            escalate=escalate,
            to=to if escalate else "",
            reason=deduped_reason,
        )

    # ------------------------------------------------------------------
    # Construcción de artefactos consolidados y extracción de entidades
    # ------------------------------------------------------------------

    def _build_consolidated_alert(
        self,
        items: list[_NormalizedAlertItem],
        *,
        extra_context: ContextSnapshot | None = None,
    ) -> RawAlert:
        """Construir una alerta sintética con la mayor severidad de regla y todas las entidades."""
        highest_rule_sev: Severity = "informational"
        for item in items:
            raw_sev = item.alert.get("severity", "informational")
            if raw_sev in SEVERITY_LEVELS:
                if SEVERITY_LEVELS.index(raw_sev) > SEVERITY_LEVELS.index(highest_rule_sev):
                    highest_rule_sev = raw_sev

        hosts: list[Any] = []
        ips: list[str] = []
        users: list[Any] = []
        for item in items:
            entities = item.alert.get("entities") or {}
            if not isinstance(entities, dict):
                continue
            for h in entities.get("hosts") or []:
                if h not in hosts:
                    hosts.append(h)
            for ip in entities.get("ips") or []:
                if isinstance(ip, str) and ip not in ips:
                    ips.append(ip)
            for u in entities.get("users") or []:
                if u not in users:
                    users.append(u)

        if extra_context is not None:
            for asset in extra_context.assets:
                if not isinstance(asset, dict):
                    continue
                hostname = asset.get("hostname") or asset.get("asset_id")
                ip = asset.get("ip")
                if hostname and {"hostname": hostname} not in hosts and hostname not in hosts:
                    hosts.append({"hostname": hostname, "ip": ip} if ip else {"hostname": hostname})
                if isinstance(ip, str) and ip and ip not in ips:
                    ips.append(ip)

        return {
            "alert_id": ",".join(item.alert_id for item in items),
            "severity": highest_rule_sev,
            "entities": {
                "hosts": hosts,
                "ips": ips,
                "users": users,
            },
        }

    def _build_consolidated_analysis(
        self,
        items: list[_NormalizedAlertItem],
        global_verdict: Verdict,
    ) -> Analysis:
        """Consolidar los `Analysis` y `PolicySignals` de las alertas relevantes."""
        analyses = [item.analysis for item in items if item.analysis is not None]
        if not analyses:
            return self._empty_analysis(verdict=global_verdict)

        if global_verdict in ("false_positive", "benign_true_positive"):
            signals = PolicySignals(
                execution_or_access_confirmed=False,
                privileged_or_vip=False,
                sensitive_or_payment_data=False,
                blocked_before_effect=(
                    global_verdict == "false_positive"
                    and all(a.signals.blocked_before_effect for a in analyses)
                ),
                authorized_activity=(global_verdict == "benign_true_positive"),
                malicious_execution=False,
                credentials_compromised=False,
                persistence=False,
                personal_data_exposure=False,
                financial_fraud=False,
                attack_chain=False,
            )
        else:
            exec_confirmed = any(
                a.signals.execution_or_access_confirmed or a.signals.malicious_execution
                for a in analyses
            )
            priv_or_vip = any(a.signals.privileged_or_vip for a in analyses) or (
                self._has_privileged_or_vip_user(items)
            )
            sens_or_pay = any(
                a.signals.sensitive_or_payment_data
                or a.signals.personal_data_exposure
                or a.signals.financial_fraud
                for a in analyses
            )
            # Solo se aplica blocked_before_effect (-1) si TODAS las alertas fueron
            # bloqueadas antes de producir efecto y no hay actividad posterior confirmada.
            all_blocked = (
                all(a.signals.blocked_before_effect for a in analyses)
                and not exec_confirmed
                and not any(
                    a.signals.credentials_compromised
                    or a.signals.persistence
                    or a.signals.personal_data_exposure
                    or a.signals.financial_fraud
                    for a in analyses
                )
            )
            distinct_rules = {
                str(item.alert.get("rule_id") or "").strip()
                for item in items
                if str(item.alert.get("rule_id") or "").strip()
            }
            multi_stage_chain = (
                global_verdict == "true_positive"
                and len(items) >= 2
                and (len(distinct_rules) >= 2 or exec_confirmed)
            )
            signals = PolicySignals(
                execution_or_access_confirmed=exec_confirmed,
                privileged_or_vip=priv_or_vip,
                sensitive_or_payment_data=sens_or_pay,
                blocked_before_effect=all_blocked,
                authorized_activity=all(a.signals.authorized_activity for a in analyses),
                malicious_execution=any(a.signals.malicious_execution for a in analyses),
                credentials_compromised=any(
                    a.signals.credentials_compromised for a in analyses
                ),
                persistence=any(a.signals.persistence for a in analyses),
                personal_data_exposure=any(
                    a.signals.personal_data_exposure for a in analyses
                ),
                financial_fraud=any(a.signals.financial_fraud for a in analyses),
                attack_chain=any(a.signals.attack_chain for a in analyses)
                or multi_stage_chain,
            )

        findings: list[Finding] = []
        for a in analyses:
            for f in a.findings:
                if f not in findings:
                    findings.append(f)

        open_q: list[str] = []
        for a in analyses:
            for q in a.open_questions:
                if q not in open_q:
                    open_q.append(q)

        avg_conf = round(sum(a.confidence for a in analyses) / len(analyses), 2)
        return Analysis(
            title=analyses[0].title,
            verdict=global_verdict,
            confidence=max(0.0, min(1.0, avg_conf)),
            summary=" ".join(a.summary for a in analyses if a.summary).strip()
            or "Incidente consolidado N2.",
            findings=findings,
            signals=signals,
            proposed_actions=[],
            open_questions=open_q,
        )

    def _collect_key_evidence_ids(
        self,
        *,
        items: list[_NormalizedAlertItem],
        per_alert_verdicts: dict[str, VerdictDecision],
        global_verdict: VerdictDecision,
    ) -> list[str]:
        """Recopilar IDs de evidencias clave verificables sin duplicar objetos completos."""
        available_ids: set[str] = set()
        for item in items:
            for ev in item.evidence:
                if ev.event_id and ev.event_id.strip():
                    available_ids.add(ev.event_id.strip())
            for ch in item.context.changes:
                if isinstance(ch, dict) and ch.get("id"):
                    available_ids.add(str(ch["id"]).strip())
            if isinstance(item.ticket, Ticket):
                for tev in item.ticket.evidence:
                    if tev.event_id and tev.event_id.strip():
                        available_ids.add(tev.event_id.strip())
            elif isinstance(item.ticket, dict):
                for tev in item.ticket.get("evidence") or []:
                    if isinstance(tev, dict) and tev.get("event_id"):
                        available_ids.add(str(tev["event_id"]).strip())

        # Priorizar las evidencias de alertas con el mismo veredicto que el global
        # (especialmente true_positive en incidentes mixtos).
        prioritized_items = sorted(
            items,
            key=lambda it: (
                0
                if (
                    per_alert_verdicts.get(it.alert_id) is not None
                    and per_alert_verdicts[it.alert_id].verdict == global_verdict.verdict
                )
                else 1
            ),
        )

        key_ids: list[str] = []
        for item in prioritized_items:
            if item.analysis is not None:
                for finding in item.analysis.findings:
                    for ref in finding.evidence_ids:
                        clean_ref = ref.strip()
                        if clean_ref and clean_ref in available_ids and clean_ref not in key_ids:
                            key_ids.append(clean_ref)
            if isinstance(item.ticket, Ticket):
                for tev in item.ticket.evidence:
                    # Los resúmenes de consultas no son eventos y no llevan event_id.
                    clean_ref = (tev.event_id or "").strip()
                    if clean_ref and clean_ref not in key_ids:
                        key_ids.append(clean_ref)

        # Si no hubo referencias en findings pero sí evidencias válidas en los items,
        # conservar sus event_id como trazabilidad mínima.
        if not key_ids:
            for item in prioritized_items:
                for ev in item.evidence:
                    clean_ref = (ev.event_id or "").strip()
                    if clean_ref and clean_ref not in key_ids:
                        key_ids.append(clean_ref)

        return key_ids

    def _collect_open_questions(
        self,
        *,
        items: list[_NormalizedAlertItem],
        n2_issues: list[str],
    ) -> list[str]:
        """Unificar preguntas abiertas de N1 y las incidencias detectadas en N2."""
        questions: list[str] = []
        for issue in n2_issues:
            clean = issue.strip()
            if clean and clean not in questions:
                questions.append(clean)

        for item in items:
            if item.analysis is not None:
                for q in item.analysis.open_questions:
                    clean = q.strip()
                    if clean and clean not in questions:
                        questions.append(clean)
            if isinstance(item.ticket, Ticket):
                for q in item.ticket.open_questions:
                    clean = q.strip()
                    if clean and clean not in questions:
                        questions.append(clean)
            elif isinstance(item.ticket, dict):
                for q in item.ticket.get("open_questions") or []:
                    if isinstance(q, str) and q.strip() and q.strip() not in questions:
                        questions.append(q.strip())

        return questions

    # ------------------------------------------------------------------
    # Utilidades privadas de extracción y coerción
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_affected_stores(
        items: list[_NormalizedAlertItem],
        context: ContextSnapshot,
    ) -> list[str]:
        """Identificar tiendas únicas afectadas a partir de zonas, activos y hosts."""
        stores: list[str] = []

        def add_store(val: str) -> None:
            clean = val.strip().upper()
            if clean and clean not in stores:
                stores.append(clean)

        for zone in context.network_zones:
            if not isinstance(zone, dict):
                continue
            for field in ("tienda_id", "store_id", "codigo_tienda", "tienda", "store"):
                if zone.get(field):
                    add_store(str(zone[field]))
            if str(zone.get("zona", "")).upper() == "STORES" and zone.get("cidr"):
                if not any(zone.get(f) for f in ("tienda_id", "store_id", "tienda")):
                    add_store(f"STORES:{zone['cidr']}")

        for asset in context.assets:
            if not isinstance(asset, dict):
                continue
            for field in ("tienda_id", "store_id", "tienda", "store"):
                if asset.get(field):
                    add_store(str(asset[field]))
            hostname = str(asset.get("hostname") or asset.get("asset_id") or "").strip()
            match = _STORE_TOKEN_RE.search(hostname)
            if match:
                add_store(match.group(1))
            else:
                pos_match = _POS_HOST_RE.match(hostname)
                if pos_match:
                    add_store(pos_match.group(1))

        for item in items:
            entities = item.alert.get("entities") or {}
            if not isinstance(entities, dict):
                continue
            for h in entities.get("hosts") or []:
                hostname = (
                    str(h.get("hostname") or h.get("asset_id") or "")
                    if isinstance(h, dict)
                    else str(h)
                ).strip()
                match = _STORE_TOKEN_RE.search(hostname)
                if match:
                    add_store(match.group(1))
                else:
                    pos_match = _POS_HOST_RE.match(hostname)
                    if pos_match:
                        add_store(pos_match.group(1))

        return stores

    @staticmethod
    def _extract_affected_hosts(
        items: list[_NormalizedAlertItem],
        context: ContextSnapshot,
    ) -> list[str]:
        """Extraer lista deduplicada de sistemas/hosts afectados en el incidente."""
        hosts: list[str] = []

        def add_host(val: str) -> None:
            clean = val.strip()
            if clean and clean.upper() not in {h.upper() for h in hosts}:
                hosts.append(clean)

        for asset in context.assets:
            if isinstance(asset, dict):
                name = asset.get("hostname") or asset.get("asset_id") or asset.get("ip")
                if name:
                    add_host(str(name))

        for item in items:
            entities = item.alert.get("entities") or {}
            if not isinstance(entities, dict):
                continue
            for h in entities.get("hosts") or []:
                if isinstance(h, dict):
                    name = h.get("hostname") or h.get("asset_id") or h.get("ip")
                    if name:
                        add_host(str(name))
                elif isinstance(h, str):
                    add_host(h)

        return hosts

    @staticmethod
    def _extract_affected_services(context: ContextSnapshot) -> list[str]:
        """Extraer nombres de servicios de negocio afectados del contexto."""
        services: list[str] = []
        for srv in context.services:
            if isinstance(srv, dict):
                name = srv.get("servicio") or srv.get("name") or srv.get("business_service")
                if name and str(name) not in services:
                    services.append(str(name))
        for asset in context.assets:
            if isinstance(asset, dict):
                name = asset.get("business_service")
                if name and str(name) not in services:
                    services.append(str(name))
        return services

    @staticmethod
    def _has_ot_scope(context: ContextSnapshot) -> bool:
        """Comprobar si algún activo o zona del incidente pertenece a LOGISTICS-OT."""
        for asset in context.assets:
            if isinstance(asset, dict) and str(asset.get("zone", "")).upper() == "LOGISTICS-OT":
                return True
        for zone in context.network_zones:
            if isinstance(zone, dict) and str(zone.get("zona", "")).upper() == "LOGISTICS-OT":
                return True
        return False

    @staticmethod
    def _has_privileged_or_vip_user(items: list[_NormalizedAlertItem]) -> bool:
        """Detectar cuentas privilegiadas (`adm.*`, `privileged`) o VIP en el contexto."""
        for item in items:
            for user in item.context.users:
                if not isinstance(user, dict):
                    continue
                if user.get("vip") is True or user.get("privileged") is True:
                    return True
                uname = str(user.get("username") or user.get("upn") or "").casefold()
                role = str(user.get("role") or user.get("rol") or "").casefold()
                if uname.startswith("adm.") or "vip" in role or "directiv" in role or "ciso" in role:
                    return True
        return False

    @staticmethod
    def _extract_alert_host_tokens(alert: RawAlert) -> set[str]:
        tokens: set[str] = set()
        entities = alert.get("entities") or {}
        if not isinstance(entities, dict):
            return tokens
        for h in entities.get("hosts") or []:
            if isinstance(h, str) and h.strip():
                tokens.add(h.strip().casefold())
            elif isinstance(h, dict):
                for k in ("hostname", "asset_id", "ip"):
                    if h.get(k):
                        tokens.add(str(h[k]).strip().casefold())
        return tokens

    @staticmethod
    def _extract_alert_ip_tokens(alert: RawAlert) -> set[str]:
        tokens: set[str] = set()
        entities = alert.get("entities") or {}
        if not isinstance(entities, dict):
            return tokens
        for ip in entities.get("ips") or []:
            if isinstance(ip, str) and ip.strip():
                tokens.add(ip.strip().casefold())
            elif isinstance(ip, dict) and ip.get("ip"):
                tokens.add(str(ip["ip"]).strip().casefold())
        return tokens

    @staticmethod
    def _merge_contexts(contexts: Sequence[ContextSnapshot]) -> ContextSnapshot:
        """Combinar múltiples `ContextSnapshot` sin duplicar registros."""
        merged = ContextSnapshot()
        for ctx in contexts:
            if ctx is None:
                continue
            for a in ctx.assets:
                if a not in merged.assets:
                    merged.assets.append(a)
            for u in ctx.users:
                if u not in merged.users:
                    merged.users.append(u)
            for s in ctx.services:
                if s not in merged.services:
                    merged.services.append(s)
            for z in ctx.network_zones:
                if z not in merged.network_zones:
                    merged.network_zones.append(z)
            for c in ctx.changes:
                if c not in merged.changes:
                    merged.changes.append(c)
            for m in ctx.missing_lookups:
                if m not in merged.missing_lookups:
                    merged.missing_lookups.append(m)
        return merged

    @staticmethod
    def _deduplicate_sentences(chunks: Sequence[str]) -> str:
        """Combinar motivos de escalado evitando frases duplicadas."""
        seen: set[str] = set()
        result: list[str] = []
        for chunk in chunks:
            for sentence in re.split(r"(?<=[.])\s+", chunk.strip()):
                clean = sentence.strip()
                if not clean:
                    continue
                key = clean.casefold().rstrip(".")
                if key not in seen:
                    seen.add(key)
                    result.append(clean if clean.endswith(".") else f"{clean}.")
        return " ".join(result)

    @staticmethod
    def _empty_signals(**overrides: bool) -> PolicySignals:
        defaults = {
            "execution_or_access_confirmed": False,
            "blocked_before_effect": False,
            "privileged_or_vip": False,
            "sensitive_or_payment_data": False,
            "malicious_execution": False,
            "credentials_compromised": False,
            "persistence": False,
            "personal_data_exposure": False,
            "financial_fraud": False,
            "attack_chain": False,
            "authorized_activity": False,
        }
        defaults.update(overrides)
        return PolicySignals(**defaults)

    @classmethod
    def _empty_analysis(cls, verdict: Verdict = "needs_more_info") -> Analysis:
        return Analysis(
            title="Investigación consolidada N2",
            verdict=verdict,
            confidence=0.0,
            summary="Sin análisis individual disponible.",
            findings=[],
            signals=cls._empty_signals(),
            proposed_actions=[],
            open_questions=[],
        )

    @staticmethod
    def _is_empty_context(ctx: ContextSnapshot | None) -> bool:
        if ctx is None:
            return True
        return not (
            ctx.assets
            or ctx.users
            or ctx.services
            or ctx.network_zones
            or ctx.changes
            or ctx.missing_lookups
        )

    @staticmethod
    def _looks_like_investigation_item(obj: Any) -> bool:
        if isinstance(obj, AlertInvestigationInput):
            return True
        if isinstance(obj, dict):
            return "analysis" in obj or ("alert" in obj and ("evidence" in obj or "context" in obj))
        return hasattr(obj, "analysis") and hasattr(obj, "alert")

    @classmethod
    def _extract_group_metadata(cls, incident_group: Any) -> dict[str, Any]:
        if incident_group is None:
            return {}
        if isinstance(incident_group, BaseModel):
            data = incident_group.model_dump()
            # Preservar objetos originales para no perder instancias Pydantic anidadas.
            for field in (
                "alerts",
                "investigations",
                "tickets",
                "analyses",
                "contexts",
                "evidence",
            ):
                if hasattr(incident_group, field):
                    data[field] = getattr(incident_group, field)
            return data
        if isinstance(incident_group, dict):
            return dict(incident_group)
        if isinstance(incident_group, (list, tuple)) and incident_group:
            if all(isinstance(x, str) for x in incident_group):
                return {"alert_ids": list(incident_group)}
            if all(isinstance(x, dict) and "alert_id" in x for x in incident_group):
                return {"alerts": list(incident_group)}
        meta: dict[str, Any] = {}
        for attr in (
            "incident_id",
            "group_id",
            "alert_ids",
            "alerts",
            "investigations",
            "tickets",
            "analyses",
            "contexts",
            "evidence",
            "correlation_reason",
            "correlation_valid",
            "confidence",
        ):
            if hasattr(incident_group, attr):
                meta[attr] = getattr(incident_group, attr)
        return meta

    @classmethod
    def _coerce_investigation_list(
        cls, investigations: Any
    ) -> list[AlertInvestigationInput]:
        if not investigations:
            return []
        items = (
            list(investigations.values())
            if isinstance(investigations, Mapping)
            else list(investigations)
        )
        result: list[AlertInvestigationInput] = []
        for item in items:
            if isinstance(item, AlertInvestigationInput):
                result.append(item)
            elif isinstance(item, BaseModel):
                result.append(
                    AlertInvestigationInput.model_validate(item.model_dump())
                )
            elif isinstance(item, dict):
                result.append(AlertInvestigationInput.model_validate(item))
            else:
                payload = {
                    k: getattr(item, k)
                    for k in (
                        "alert_id",
                        "alert",
                        "analysis",
                        "context",
                        "evidence",
                        "ticket",
                        "verdict_decision",
                        "severity_decision",
                        "escalation_decision",
                        "related_alerts",
                    )
                    if hasattr(item, k)
                }
                result.append(AlertInvestigationInput.model_validate(payload))
        return result

    @staticmethod
    def _coerce_raw_alert(alert: Any) -> RawAlert:
        if isinstance(alert, dict):
            return dict(alert)
        if isinstance(alert, BaseModel):
            return alert.model_dump()
        return {"alert_id": str(alert)}

    @staticmethod
    def _index_tickets(
        tickets: Any,
    ) -> tuple[dict[str, Ticket | dict[str, Any]], list[Ticket | dict[str, Any]]]:
        by_id: dict[str, Ticket | dict[str, Any]] = {}
        as_list: list[Ticket | dict[str, Any]] = []
        if not tickets:
            return by_id, as_list
        if isinstance(tickets, Mapping):
            for k, v in tickets.items():
                by_id[str(k)] = v
                as_list.append(v)
            return by_id, as_list
        for t in tickets:
            as_list.append(t)
            if isinstance(t, Ticket) and t.alert_ids:
                for aid in t.alert_ids:
                    by_id.setdefault(aid, t)
            elif isinstance(t, dict):
                for aid in t.get("alert_ids") or []:
                    by_id.setdefault(str(aid), t)
                if t.get("alert_id"):
                    by_id.setdefault(str(t["alert_id"]), t)
        return by_id, as_list

    @staticmethod
    def _index_models(
        collection: Any, model_cls: type[BaseModel]
    ) -> tuple[dict[str, Any], list[Any]]:
        by_id: dict[str, Any] = {}
        as_list: list[Any] = []
        if not collection:
            return by_id, as_list

        def coerce(val: Any) -> Any:
            if isinstance(val, model_cls):
                return val
            if isinstance(val, dict):
                return model_cls.model_validate(val)
            return val

        if isinstance(collection, Mapping):
            for k, v in collection.items():
                obj = coerce(v)
                by_id[str(k)] = obj
                as_list.append(obj)
            return by_id, as_list

        for v in collection:
            as_list.append(coerce(v))
        return by_id, as_list

    @staticmethod
    def _index_contexts(
        contexts: Any,
    ) -> tuple[dict[str, ContextSnapshot], list[ContextSnapshot], ContextSnapshot | None]:
        by_id: dict[str, ContextSnapshot] = {}
        as_list: list[ContextSnapshot] = []
        if contexts is None:
            return by_id, as_list, None
        if isinstance(contexts, ContextSnapshot):
            return by_id, as_list, contexts
        if isinstance(contexts, dict) and any(
            k in contexts
            for k in ("assets", "users", "services", "network_zones", "changes")
        ):
            return by_id, as_list, ContextSnapshot.model_validate(contexts)
        if isinstance(contexts, Mapping):
            for k, v in contexts.items():
                ctx = (
                    v
                    if isinstance(v, ContextSnapshot)
                    else ContextSnapshot.model_validate(v)
                )
                by_id[str(k)] = ctx
                as_list.append(ctx)
            return by_id, as_list, None
        for v in contexts:
            ctx = (
                v
                if isinstance(v, ContextSnapshot)
                else ContextSnapshot.model_validate(v)
            )
            as_list.append(ctx)
        return by_id, as_list, None

    @staticmethod
    def _index_evidence(
        evidence: Any,
    ) -> tuple[dict[str, list[Evidence]], list[list[Evidence]], list[Evidence]]:
        by_id: dict[str, list[Evidence]] = {}
        per_idx: list[list[Evidence]] = []
        flat: list[Evidence] = []
        if not evidence:
            return by_id, per_idx, flat

        def coerce_ev(item: Any) -> Evidence:
            if isinstance(item, Evidence):
                return item
            if isinstance(item, dict):
                return Evidence.model_validate(item)
            return item

        if isinstance(evidence, Mapping):
            for k, seq in evidence.items():
                ev_list = [coerce_ev(x) for x in (seq or [])]
                by_id[str(k)] = ev_list
                per_idx.append(ev_list)
            return by_id, per_idx, flat

        seq = list(evidence)
        if seq and isinstance(seq[0], (list, tuple)):
            for sub in seq:
                per_idx.append([coerce_ev(x) for x in sub])
            return by_id, per_idx, flat

        flat = [coerce_ev(x) for x in seq]
        return by_id, per_idx, flat

    @classmethod
    def _analysis_from_ticket(cls, ticket: Ticket | dict[str, Any]) -> Analysis | None:
        """Reconstruir un `Analysis` mínimo si solo se proporcionó un `Ticket` de N1."""
        if isinstance(ticket, dict):
            try:
                ticket = Ticket.model_validate(ticket)
            except Exception:
                return None
        if not isinstance(ticket, Ticket):
            return None
        findings = [
            Finding(statement=tev.finding, evidence_ids=[tev.event_id])
            for tev in ticket.evidence
            if tev.event_id
        ]
        return Analysis(
            title=ticket.title,
            verdict=ticket.verdict,
            confidence=ticket.confidence,
            summary=ticket.summary,
            findings=findings,
            signals=cls._empty_signals(
                execution_or_access_confirmed=(ticket.verdict == "true_positive"),
                authorized_activity=(ticket.verdict == "benign_true_positive"),
            ),
            proposed_actions=[],
            open_questions=list(ticket.open_questions),
        )

    @staticmethod
    def _evidence_from_ticket(ticket: Ticket | dict[str, Any] | None) -> list[Evidence]:
        """Extraer objetos `Evidence` desde un `Ticket` si no se pasaron por separado."""
        if ticket is None:
            return []
        if isinstance(ticket, dict):
            raw_ev = ticket.get("evidence") or []
            return [
                Evidence(
                    source=str(e.get("source", "ticket")),
                    event_id=str(e.get("event_id", "")),
                    raw={"finding": str(e.get("finding", ""))},
                )
                for e in raw_ev
                if isinstance(e, dict) and e.get("event_id")
            ]
        if isinstance(ticket, Ticket):
            return [
                Evidence(
                    source=tev.source,
                    event_id=tev.event_id,
                    raw={"finding": tev.finding},
                )
                for tev in ticket.evidence
                if tev.event_id
            ]
        return []
