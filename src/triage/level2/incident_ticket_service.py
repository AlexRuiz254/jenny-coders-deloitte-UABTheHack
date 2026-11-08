from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple, Union
from uuid import uuid4

from pydantic import BaseModel, Field

from src.triage.models import (
    Escalation,
    Evidence,
    IntelEntry,
    RawAlert,
    Severity,
    Ticket,
    TicketAction,
    TicketEvidence,
    Verdict,
)
from src.triage.output.ticket_builder import TicketBuilder
from src.triage.output.validation import validate_ticket

try:
    from src.data.ticket_repository import TicketRepository
except Exception:
    try:
        from src.interficie.repository import TicketRepository  # type: ignore
    except Exception:
        TicketRepository = None  # type: ignore

logger = logging.getLogger("tarvia_soc.level2.incident_ticket_service")

class IncidentTicketServiceError(Exception):
    """Clase base para errores en el servicio de tickets de incidentes."""
    pass


class EmptyGroupError(IncidentTicketServiceError, ValueError):
    """El grupo de incidentes está vacío o no contiene identificadores de alerta válidos."""
    pass

class MissingInvestigationError(IncidentTicketServiceError, ValueError):
    """Faltan investigaciones individuales N1 para una o más alertas del grupo."""
    pass

class IncompleteDecisionError(IncidentTicketServiceError, ValueError):
    """La decisión N2 está incompleta o carece de campos obligatorios (veredicto, severidad)."""
    pass

class TicketBuildError(IncidentTicketServiceError, RuntimeError):
    """Error durante la construcción, consolidación o validación del ticket."""
    pass

class PersistenceError(IncidentTicketServiceError, RuntimeError):
    """Error durante la persistencia del ticket en el repositorio."""
    pass


class IncidentGroup(BaseModel):
    """Grupo de alertas correladas pertenecientes a un mismo incidente.

    Permite instanciación con lista de diccionarios `alerts`, lista de `alert_ids`,
    o ambos.
    """
    incident_id: Optional[str] = None
    alerts: List[Dict[str, Any]] = Field(default_factory=list)
    alert_ids: List[str] = Field(default_factory=list)
    title: Optional[str] = None
    justification: Optional[str] = None
    group_rationale: Optional[str] = None
    created_at: Optional[str] = None

    def resolved_alert_ids(self) -> List[str]:
        """Obtener la lista deduplicada y ordenada de IDs de alerta del grupo."""
        ids: List[str] = []
        for aid in self.alert_ids:
            if aid and aid.strip() and aid.strip() not in ids:
                ids.append(aid.strip())
        for alert in self.alerts:
            if isinstance(alert, dict):
                aid = alert.get("alert_id")
            else:
                aid = getattr(alert, "alert_id", None)
            if aid and aid.strip() and aid.strip() not in ids:
                ids.append(aid.strip())
        return ids


class IncidentDecision(BaseModel):
    """Decisiones tomadas por el módulo de decisiones N2 para el incidente."""
    verdict: Verdict
    severity: Severity
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    escalation: Union[Escalation, Dict[str, Any], bool] = Field(
        default_factory=lambda: Escalation(escalate=False)
    )
    justification: Optional[str] = None
    rationale: Optional[str] = None
    verdict_rationale: Optional[str] = None
    severity_rationale: Optional[str] = None
    title: Optional[str] = None
    recommended_actions: List[Union[TicketAction, Dict[str, Any]]] = Field(default_factory=list)
    actions: List[Union[TicketAction, Dict[str, Any]]] = Field(default_factory=list)
    key_evidence_ids: List[str] = Field(default_factory=list)
    open_questions: List[str] = Field(default_factory=list)


class N1Investigation(BaseModel):
    """Estructura normalizada para los resultados de investigación N1 de una alerta."""
    alert_id: Optional[str] = None
    ticket: Optional[Union[Ticket, Dict[str, Any]]] = None
    alert: Optional[Dict[str, Any]] = None
    analysis: Optional[Any] = None
    evidence: List[Any] = Field(default_factory=list)
    affected: Dict[str, List[Any]] = Field(default_factory=dict)
    enrichment: List[Union[IntelEntry, Dict[str, Any]]] = Field(default_factory=list)
    mitre: List[str] = Field(default_factory=list)
    recommended_actions: List[Union[TicketAction, Dict[str, Any]]] = Field(default_factory=list)
    open_questions: List[str] = Field(default_factory=list)
    triage_seconds: Optional[float] = None
    summary: Optional[str] = None


class IncidentTicketService:
    """Convierte alertas agrupadas (IncidentGroup) y decisiones N2 en un único Ticket consolidado."""

    def __init__(
        self,
        ticket_builder: Optional[TicketBuilder] = None,
        repository: Optional[Any] = None,
        *,
        builder: Optional[TicketBuilder] = None,
        store: Optional[Any] = None,
    ) -> None:
        """Inicializar el servicio recibiendo dependencias reutilizables."""
        self.ticket_builder = ticket_builder or builder
        if self.ticket_builder is None:
            self.ticket_builder = TicketBuilder()

        self.repository = repository or store
        if self.repository is None and TicketRepository is not None:
            try:
                self.repository = TicketRepository()
            except Exception as exc:
                logger.warning("No se pudo instanciar TicketRepository por defecto: %s", exc)


    def create_and_save(
        self,
        group: Any,
        tickets: List[Ticket],
        decision: Any,
        *,
        trace: Optional[List[Dict[str, Any]]] = None,
        reprocess: bool = False,
    ) -> Ticket:
        """Crear y persistir el ticket consolidado N2 (Protocolo Level2Orchestrator)."""
        return self.build_and_save(
            group=group,
            decision=decision,
            investigations=tickets,
            trace=trace,
            reprocess=reprocess,
        )

    def build_and_save(
        self,
        group: Union[IncidentGroup, Dict[str, Any], Any],
        decision: Union[IncidentDecision, Dict[str, Any], Any],
        investigations: Optional[Union[Dict[str, Any], List[Any], Any]] = None,
        *,
        trace: Optional[List[Dict[str, Any]]] = None,
        reprocess: bool = False,
        allow_missing_investigations: bool = False,
    ) -> Ticket:
        """Construir el ticket de incidente N2 y persistirlo en el repositorio.

        Garantiza idempotencia: si el incidente ya ha sido procesado como N2 y reprocess=False,
        recupera el ticket existente sin crear duplicados y sin confundirlo con tickets N1.
        """
        # Si los argumentos posicionales vienen invertidos (group, tickets, decision)
        if isinstance(decision, list) and not isinstance(investigations, (list, dict)) and investigations is not None:
            decision, investigations = investigations, decision

        incident_id, alert_ids, group_justification, _ = self._extract_group_info(group)

        # Validación: Grupo no vacío
        if not alert_ids:
            raise EmptyGroupError(
                "Fase de validación de grupo: El grupo de incidentes está vacío o no contiene alertas válidas."
            )

        # Control de idempotencia previo: verificar si ya existe un ticket N2 consolidado para este incidente
        if not reprocess and self.repository is not None:
            existing = self._find_existing_ticket(incident_id, alert_ids)
            if existing is not None:
                logger.info("El incidente N2 %s ya fue procesado; recuperando ticket existente.", incident_id)
                return existing

        # Construir y validar el ticket consolidado
        ticket, source_ticket_ids = self._build_with_metadata(
            group=group,
            decision=decision,
            investigations=investigations,
            allow_missing_investigations=allow_missing_investigations,
        )

        # Persistir en el repositorio asegurando marcas explícitas de N2
        self._persist_ticket(
            ticket=ticket,
            incident_id=incident_id,
            group_justification=group_justification,
            decision=decision,
            source_ticket_ids=source_ticket_ids,
            trace=trace or [],
            reprocess=reprocess,
        )

        return ticket

    def build(
        self,
        group: Union[IncidentGroup, Dict[str, Any], Any],
        decision: Union[IncidentDecision, Dict[str, Any], Any],
        investigations: Optional[Union[Dict[str, Any], List[Any], Any]] = None,
        *,
        allow_missing_investigations: bool = False,
    ) -> Ticket:
        """Construir y validar el Ticket consolidado sin guardarlo en el repositorio."""
        ticket, _ = self._build_with_metadata(
            group=group,
            decision=decision,
            investigations=investigations,
            allow_missing_investigations=allow_missing_investigations,
        )
        return ticket

    def _build_with_metadata(
        self,
        group: Union[IncidentGroup, Dict[str, Any], Any],
        decision: Union[IncidentDecision, Dict[str, Any], Any],
        investigations: Optional[Union[Dict[str, Any], List[Any], Any]] = None,
        *,
        allow_missing_investigations: bool = False,
    ) -> Tuple[Ticket, List[str]]:
        """Construir el Ticket consolidado y recopilar los source_ticket_ids de N1."""
        incident_id, alert_ids, group_justification, group_title = self._extract_group_info(group)

        if not alert_ids:
            raise EmptyGroupError(
                "Fase de validación de grupo: El grupo de incidentes está vacío o no contiene alertas válidas."
            )

        norm_decision = self._normalize_decision(decision)

        # Recolección y validación de investigaciones N1
        inv_map, missing_alerts = self._collect_investigations(alert_ids, investigations)
        if missing_alerts:
            if not allow_missing_investigations:
                raise MissingInvestigationError(
                    f"Fase de investigación N1: Faltan investigaciones para las alertas: {missing_alerts}. "
                    "No se pueden inventar datos en el triaje de incidentes."
                )

        # Extraer los ticket_id individuales de N1 para vincularlos en la trazabilidad N2
        source_ticket_ids: List[str] = []
        for inv in inv_map.values():
            if inv.ticket:
                tid = getattr(inv.ticket, "ticket_id", None) or (
                    inv.ticket.get("ticket_id") if isinstance(inv.ticket, dict) else None
                )
                if tid and tid not in source_ticket_ids:
                    source_ticket_ids.append(tid)

        # Consolidación de información individual
        consolidated_evidence = self._consolidate_evidence(inv_map)
        consolidated_affected = self._consolidate_affected(inv_map, group)
        consolidated_intel = self._consolidate_intel(inv_map)
        consolidated_actions = self._consolidate_actions(norm_decision, inv_map)
        consolidated_mitre = self._consolidate_mitre(inv_map, group)
        consolidated_questions = self._consolidate_questions(inv_map, missing_alerts, norm_decision)
        total_seconds = self._calculate_total_seconds(inv_map)

        # Construcción de título y resumen consolidados
        title = (
            norm_decision.title
            or group_title
            or f"Incidente N2 {incident_id}: {norm_decision.verdict.replace('_', ' ').title()} "
            f"({len(alert_ids)} alertas)"
        )

        summary = self._consolidate_summary(
            incident_id=incident_id,
            alert_ids=alert_ids,
            group_justification=group_justification,
            decision=norm_decision,
            inv_map=inv_map,
        )

        severity_rationale = (
            norm_decision.severity_rationale
            or norm_decision.rationale
            or norm_decision.justification
            or f"Severidad {norm_decision.severity} determinada por motor de decisión N2 para el incidente {incident_id}."
        )

        # Formatear escalation para cumplir estrictamente con ticket_salida.schema.json
        esc_dict: Dict[str, Any] = {"escalate": bool(norm_decision.escalation.escalate)}
        if norm_decision.escalation.to is not None:
            esc_dict["to"] = str(norm_decision.escalation.to)
        elif norm_decision.escalation.escalate:
            esc_dict["to"] = "SOC N3"
        if norm_decision.escalation.reason is not None:
            esc_dict["reason"] = str(norm_decision.escalation.reason)

        # Construcción y validación estricta del modelo Ticket
        try:
            ticket_payload: Dict[str, Any] = {
                "ticket_id": incident_id,
                "alert_ids": alert_ids,
                "title": title,
                "verdict": norm_decision.verdict,
                "confidence": norm_decision.confidence,
                "severity": norm_decision.severity,
                "severity_rationale": severity_rationale,
                "summary": summary,
                "evidence": [e.model_dump(mode="json", exclude_none=True) if hasattr(e, "model_dump") else {k: v for k, v in e.items() if v is not None} for e in consolidated_evidence],
                "recommended_actions": [a.model_dump(mode="json", exclude_none=True) if hasattr(a, "model_dump") else {k: v for k, v in a.items() if v is not None} for a in consolidated_actions],
                "escalation": esc_dict,
                "affected": consolidated_affected,
                "enrichment": [i.model_dump(mode="json", exclude_none=True) if hasattr(i, "model_dump") else {k: v for k, v in i.items() if v is not None} for i in consolidated_intel],
                "mitre": consolidated_mitre,
                "executed_actions": [],
                "open_questions": consolidated_questions,
            }
            if total_seconds is not None:
                ticket_payload["triage_seconds"] = total_seconds

            ticket = validate_ticket(ticket_payload)
            return ticket, source_ticket_ids
        except Exception as exc:
            raise TicketBuildError(
                f"Fase de construcción: Error en la validación del ticket consolidado para {incident_id}: {exc}"
            ) from exc

    def _extract_group_info(
        self, group: Any
    ) -> Tuple[str, List[str], Optional[str], Optional[str]]:
        """Extraer incident_id, alert_ids únicos, justificación y título del grupo."""
        if group is None:
            raise EmptyGroupError("Fase de validación de grupo: El grupo recibido es None.")

        if isinstance(group, IncidentGroup):
            alert_ids = group.resolved_alert_ids()
            incident_id = group.incident_id or (f"INC-{alert_ids[0]}" if alert_ids else f"INC-{uuid4().hex[:8].upper()}")
            justification = group.justification or group.group_rationale
            title = group.title
            return incident_id, alert_ids, justification, title

        if isinstance(group, dict):
            raw_ids = list(group.get("alert_ids") or [])
            for alert in group.get("alerts") or []:
                if isinstance(alert, dict) and alert.get("alert_id"):
                    raw_ids.append(alert["alert_id"])
                elif hasattr(alert, "alert_id") and getattr(alert, "alert_id"):
                    raw_ids.append(getattr(alert, "alert_id"))
            alert_ids = list(dict.fromkeys(a.strip() for a in raw_ids if a and str(a).strip()))
            incident_id = group.get("incident_id") or group.get("id") or (f"INC-{alert_ids[0]}" if alert_ids else f"INC-{uuid4().hex[:8].upper()}")
            justification = group.get("justification") or group.get("group_rationale")
            title = group.get("title")
            return str(incident_id), alert_ids, justification, title

        # Soporte para protocolos / objetos duck-typed
        raw_ids = list(getattr(group, "alert_ids", []))
        for alert in getattr(group, "alerts", []):
            aid = alert.get("alert_id") if isinstance(alert, dict) else getattr(alert, "alert_id", None)
            if aid:
                raw_ids.append(aid)
        alert_ids = list(dict.fromkeys(a.strip() for a in raw_ids if a and str(a).strip()))
        incident_id = getattr(group, "incident_id", getattr(group, "id", None))
        if not incident_id or not str(incident_id).strip():
            incident_id = f"INC-{alert_ids[0]}" if alert_ids else f"INC-{uuid4().hex[:8].upper()}"
        justification = getattr(group, "justification", getattr(group, "group_rationale", None))
        title = getattr(group, "title", None)
        return str(incident_id), alert_ids, justification, title

    def _normalize_decision(self, decision: Any) -> IncidentDecision:
        """Normalizar y validar campos obligatorios de la decisión N2."""
        if decision is None:
            raise IncompleteDecisionError("Fase de decisión N2: La decisión recibida es None.")

        if isinstance(decision, IncidentDecision):
            return decision

        if isinstance(decision, dict):
            verdict = decision.get("verdict")
            severity = decision.get("severity")
            if not verdict or not severity:
                raise IncompleteDecisionError(
                    "Fase de decisión N2: Faltan campos obligatorios en decision ('verdict' y 'severity')."
                )
            confidence = float(decision.get("confidence", 1.0))
            raw_esc = decision.get("escalation", False)
            if isinstance(raw_esc, bool):
                escalation = Escalation(escalate=raw_esc)
            elif isinstance(raw_esc, dict):
                escalation = Escalation(**raw_esc)
            elif isinstance(raw_esc, Escalation):
                escalation = raw_esc
            else:
                escalation = Escalation(escalate=False)

            actions = decision.get("recommended_actions") or decision.get("actions") or []
            return IncidentDecision(
                verdict=verdict,
                severity=severity,
                confidence=confidence,
                escalation=escalation,
                justification=decision.get("justification"),
                rationale=decision.get("rationale"),
                verdict_rationale=decision.get("verdict_rationale"),
                severity_rationale=decision.get("severity_rationale"),
                title=decision.get("title"),
                recommended_actions=actions,
                open_questions=list(decision.get("open_questions") or []),
            )

        # Soporte para IncidentDecisionResult u objetos duck-typed
        verdict = getattr(decision, "verdict", None)
        severity = getattr(decision, "severity", None)
        if not verdict or not severity:
            raise IncompleteDecisionError(
                "Fase de decisión N2: Objeto de decisión carece de atributos requeridos ('verdict', 'severity')."
            )
        confidence = float(getattr(decision, "confidence", 1.0))
        raw_esc = getattr(decision, "escalation", False)
        if isinstance(raw_esc, bool):
            escalation = Escalation(escalate=raw_esc)
        elif isinstance(raw_esc, dict):
            escalation = Escalation(**raw_esc)
        elif isinstance(raw_esc, Escalation):
            escalation = raw_esc
        else:
            escalation = Escalation(escalate=False)

        actions = getattr(decision, "recommended_actions", getattr(decision, "actions", []))
        rationale = getattr(decision, "verdict_rationale", getattr(decision, "rationale", None))
        justification = getattr(decision, "justification", rationale)
        severity_rationale = getattr(decision, "severity_rationale", None)
        open_questions = list(getattr(decision, "open_questions", []))

        return IncidentDecision(
            verdict=verdict,
            severity=severity,
            confidence=confidence,
            escalation=escalation,
            justification=justification,
            rationale=rationale,
            verdict_rationale=rationale,
            severity_rationale=severity_rationale,
            title=getattr(decision, "title", None),
            recommended_actions=actions,
            open_questions=open_questions,
        )

    def _collect_investigations(
        self, alert_ids: List[str], investigations: Any
    ) -> Tuple[Dict[str, N1Investigation], List[str]]:
        """Indexar investigaciones N1 por alert_id y detectar alertas faltantes."""
        inv_map: Dict[str, N1Investigation] = {}
        if investigations is None:
            return inv_map, list(alert_ids)

        if isinstance(investigations, dict):
            for key, val in investigations.items():
                norm = self._to_n1_investigation(val, default_alert_id=str(key))
                aid = norm.alert_id or str(key)
                inv_map[aid] = norm
        elif isinstance(investigations, (list, tuple, set)):
            for idx, item in enumerate(investigations):
                norm = self._to_n1_investigation(item)
                aid = norm.alert_id
                if not aid and idx < len(alert_ids):
                    aid = alert_ids[idx]
                    norm.alert_id = aid
                if aid:
                    inv_map[aid] = norm
        else:
            norm = self._to_n1_investigation(investigations)
            if norm.alert_id:
                inv_map[norm.alert_id] = norm

        missing = [aid for aid in alert_ids if aid not in inv_map]
        return inv_map, missing

    def _to_n1_investigation(self, item: Any, default_alert_id: Optional[str] = None) -> N1Investigation:
        """Convertir cualquier formato de investigación (Ticket, dict, Analysis) a N1Investigation."""
        if isinstance(item, N1Investigation):
            if default_alert_id and not item.alert_id:
                item.alert_id = default_alert_id
            return item

        if isinstance(item, Ticket):
            aid = item.alert_ids[0] if item.alert_ids else default_alert_id
            return N1Investigation(
                alert_id=aid,
                ticket=item,
                evidence=list(item.evidence),
                affected=dict(item.affected),
                enrichment=list(item.enrichment),
                mitre=list(item.mitre),
                recommended_actions=list(item.recommended_actions),
                open_questions=list(item.open_questions),
                triage_seconds=item.triage_seconds,
                summary=item.summary,
            )

        if isinstance(item, dict):
            if "ticket_id" in item and "alert_ids" in item:
                try:
                    t = Ticket.model_validate(item)
                    return self._to_n1_investigation(t, default_alert_id=default_alert_id)
                except Exception:
                    pass

            if "ticket" in item and isinstance(item["ticket"], (Ticket, dict)):
                t_val = item["ticket"]
                if isinstance(t_val, dict):
                    t_val = Ticket.model_validate(t_val)
                res = self._to_n1_investigation(t_val, default_alert_id=default_alert_id)
                if "alert" in item and isinstance(item["alert"], dict):
                    res.alert = item["alert"]
                return res

            aid = item.get("alert_id") or default_alert_id
            return N1Investigation(
                alert_id=aid,
                alert=item.get("alert"),
                analysis=item.get("analysis"),
                evidence=list(item.get("evidence") or []),
                affected=dict(item.get("affected") or {}),
                enrichment=list(item.get("enrichment") or item.get("intel") or []),
                mitre=list(item.get("mitre") or []),
                recommended_actions=list(item.get("recommended_actions") or item.get("actions") or []),
                open_questions=list(item.get("open_questions") or []),
                triage_seconds=item.get("triage_seconds"),
                summary=item.get("summary"),
            )

        aid = getattr(item, "alert_id", default_alert_id)
        if hasattr(item, "ticket"):
            t = getattr(item, "ticket")
            return self._to_n1_investigation(t, default_alert_id=aid)

        return N1Investigation(
            alert_id=aid,
            evidence=list(getattr(item, "evidence", [])),
            affected=dict(getattr(item, "affected", {})),
            enrichment=list(getattr(item, "enrichment", getattr(item, "intel", []))),
            mitre=list(getattr(item, "mitre", [])),
            recommended_actions=list(getattr(item, "recommended_actions", getattr(item, "actions", []))),
            open_questions=list(getattr(item, "open_questions", [])),
            triage_seconds=getattr(item, "triage_seconds", None),
            summary=getattr(item, "summary", None),
        )

    def _consolidate_evidence(self, inv_map: Dict[str, N1Investigation]) -> List[TicketEvidence]:
        """Consolidar evidencias de todas las investigaciones sin duplicados."""
        consolidated: List[TicketEvidence] = []
        seen: Set[Tuple[str, Optional[str], str]] = set()

        for aid, inv in inv_map.items():
            for raw_ev in inv.evidence:
                source = getattr(raw_ev, "source", None) or (raw_ev.get("source") if isinstance(raw_ev, dict) else None) or "unknown"
                event_id = getattr(raw_ev, "event_id", None) or (raw_ev.get("event_id") if isinstance(raw_ev, dict) else None)
                finding = getattr(raw_ev, "finding", None) or (raw_ev.get("finding") if isinstance(raw_ev, dict) else None)
                if not finding:
                    finding = f"Evidencia observada en alerta {aid}"

                key = (str(source), str(event_id) if event_id is not None else None, str(finding))
                if key not in seen:
                    seen.add(key)
                    consolidated.append(
                        TicketEvidence(
                            source=source,
                            event_id=event_id,
                            finding=finding,
                        )
                    )

        return consolidated

    def _consolidate_affected(
        self, inv_map: Dict[str, N1Investigation], group: Any
    ) -> Dict[str, List[Any]]:
        """Consolidar activos, usuarios, servicios y entidades afectadas sin duplicados."""
        affected: Dict[str, List[Any]] = {}

        def add_item(category: str, item: Any) -> None:
            if not item:
                return
            target_list = affected.setdefault(category, [])
            if item not in target_list:
                target_list.append(item)

        for _, inv in inv_map.items():
            for category, items in inv.affected.items():
                if isinstance(items, (list, tuple, set)):
                    for it in items:
                        add_item(category, it)
                else:
                    add_item(category, items)

            if inv.alert and isinstance(inv.alert, dict) and "entities" in inv.alert:
                for cat, ents in (inv.alert.get("entities") or {}).items():
                    if isinstance(ents, list):
                        for e in ents:
                            add_item(cat, e)
                    elif ents:
                        add_item(cat, ents)

        alerts_in_group = getattr(group, "alerts", []) if not isinstance(group, dict) else group.get("alerts", [])
        for a in alerts_in_group:
            if isinstance(a, dict) and "entities" in a:
                for cat, ents in (a.get("entities") or {}).items():
                    if isinstance(ents, list):
                        for e in ents:
                            add_item(cat, e)
                    elif ents:
                        add_item(cat, ents)

        return affected

    def _consolidate_intel(self, inv_map: Dict[str, N1Investigation]) -> List[IntelEntry]:
        """Consolidar información de inteligencia (IOCs y feeds) sin duplicados."""
        consolidated: List[IntelEntry] = []
        seen: Set[Tuple[str, str, str, str]] = set()

        for _, inv in inv_map.items():
            for item in inv.enrichment:
                if isinstance(item, IntelEntry):
                    entry = item
                elif isinstance(item, dict):
                    entry = IntelEntry(
                        indicator=item.get("indicator", ""),
                        type=item.get("type", "unknown"),
                        source=item.get("source", "unknown"),
                        result=item.get("result", ""),
                    )
                else:
                    continue

                key = (entry.indicator, entry.type, entry.source, entry.result)
                if key not in seen and entry.indicator:
                    seen.add(key)
                    consolidated.append(entry)

        return consolidated

    def _consolidate_actions(
        self, decision: IncidentDecision, inv_map: Dict[str, N1Investigation]
    ) -> List[TicketAction]:
        """Consolidar acciones recomendadas N2 y N1, evitando duplicaciones de (action, target)."""
        consolidated: List[TicketAction] = []
        seen: Set[Tuple[str, str]] = set()

        all_actions = list(decision.recommended_actions or decision.actions or [])
        for _, inv in inv_map.items():
            all_actions.extend(inv.recommended_actions)

        for raw_act in all_actions:
            if isinstance(raw_act, TicketAction):
                act = raw_act
            elif isinstance(raw_act, dict):
                act = TicketAction(
                    action=raw_act.get("action", "review"),
                    target=raw_act.get("target", "ticket"),
                    requires_approval=bool(raw_act.get("requires_approval", False)),
                    justification=raw_act.get("justification"),
                )
            else:
                act = TicketAction(
                    action=getattr(raw_act, "action", "review"),
                    target=getattr(raw_act, "target", "ticket"),
                    requires_approval=bool(getattr(raw_act, "requires_approval", False)),
                    justification=getattr(raw_act, "justification", None),
                )

            key = (act.action, act.target)
            if key not in seen:
                seen.add(key)
                consolidated.append(act)

        if not consolidated:
            consolidated.append(
                TicketAction(
                    action="review_incident",
                    target="ticket",
                    requires_approval=False,
                    justification="Revisión analítica del incidente consolidado N2",
                )
            )

        return consolidated

    def _consolidate_mitre(
        self, inv_map: Dict[str, N1Investigation], group: Any
    ) -> List[str]:
        """Consolidar identificadores MITRE ATT&CK únicos de todas las fuentes."""
        mitre_ids: List[str] = []

        def add_technique(tid: Any) -> None:
            if tid and isinstance(tid, str):
                s = tid.strip()
                if s and s not in mitre_ids:
                    mitre_ids.append(s)

        for _, inv in inv_map.items():
            for m in inv.mitre:
                add_technique(m)
            if inv.alert and isinstance(inv.alert, dict):
                m_obj = inv.alert.get("mitre")
                if isinstance(m_obj, dict):
                    add_technique(m_obj.get("technique_id"))
                elif isinstance(m_obj, str):
                    add_technique(m_obj)

        alerts_in_group = getattr(group, "alerts", []) if not isinstance(group, dict) else group.get("alerts", [])
        for a in alerts_in_group:
            if isinstance(a, dict):
                m_obj = a.get("mitre")
                if isinstance(m_obj, dict):
                    add_technique(m_obj.get("technique_id"))
                elif isinstance(m_obj, str):
                    add_technique(m_obj)

        return mitre_ids

    def _consolidate_questions(
        self,
        inv_map: Dict[str, N1Investigation],
        missing_alerts: List[str],
        decision: Optional[IncidentDecision] = None,
    ) -> List[str]:
        """Consolidar preguntas abiertas de N1, N2 y registrar alertas sin investigación si aplica."""
        questions: List[str] = []

        if decision and decision.open_questions:
            for q in decision.open_questions:
                if q and q not in questions:
                    questions.append(q)

        for _, inv in inv_map.items():
            for q in inv.open_questions:
                if q and q not in questions:
                    questions.append(q)

        for aid in missing_alerts:
            q = f"Alerta {aid} incluida en el grupo pero sin investigación N1 disponible; requiere revisión manual."
            if q not in questions:
                questions.append(q)

        return questions

    def _calculate_total_seconds(self, inv_map: Dict[str, N1Investigation]) -> Optional[float]:
        """Calcular tiempo total de procesamiento agregando los tiempos de N1."""
        total = 0.0
        has_time = False
        for _, inv in inv_map.items():
            if inv.triage_seconds is not None:
                total += float(inv.triage_seconds)
                has_time = True
        return total if has_time else None

    def _consolidate_summary(
        self,
        incident_id: str,
        alert_ids: List[str],
        group_justification: Optional[str],
        decision: IncidentDecision,
        inv_map: Dict[str, N1Investigation],
    ) -> str:
        """Sintetizar la justificación de agrupación, el veredicto N2 y hallazgos N1."""
        parts: List[str] = []

        verdict_str = decision.verdict.replace("_", " ").upper()
        verdict_note = decision.justification or decision.rationale or "Sin justificación adicional"
        parts.append(
            f"Incidente {incident_id} consolidado con {len(alert_ids)} alertas. "
            f"Veredicto N2: {verdict_str} (Severidad: {decision.severity.upper()}). "
            f"Justificación del veredicto: {verdict_note}."
        )

        if group_justification:
            parts.append(f"Justificación de agrupación: {group_justification}")

        n1_summaries = []
        for aid in alert_ids:
            inv = inv_map.get(aid)
            if inv and inv.summary:
                n1_summaries.append(f"• [{aid}]: {inv.summary}")
        if n1_summaries:
            parts.append("Resumen de investigaciones N1 agrupadas:\n" + "\n".join(n1_summaries))

        return "\n\n".join(parts)

    def _is_n2_incident_ticket(
        self,
        record: Dict[str, Any],
        incident_id: str,
        alert_ids: List[str],
    ) -> bool:
        """Verificar si un registro del repositorio es estrictamente un ticket de incidente N2.

        Distingue inequívocamente entre tickets individuales de N1 y tickets consolidados de N2,
        incluso si ambos niveles comparten la misma base de datos o repositorio.
        """
        if not isinstance(record, dict):
            return False

        details = record.get("details")
        if not isinstance(details, dict):
            return False

        ticket_data = details.get("ticket")
        if not isinstance(ticket_data, dict):
            return False

        # 1. Regla de exclusión: Descartar explícitamente cualquier ticket N1
        # Los tickets N1 se caracterizan por origen 'generated' con runbook_id/runbook_text
        # y carecen de las marcas explícitas de nivel N2
        is_explicit_n2 = (
            details.get("level") == "N2"
            or details.get("tier") == "N2"
            or details.get("type") == "incident"
            or details.get("is_incident") is True
        )

        is_n1_origin = (
            details.get("level") == "N1"
            or details.get("tier") == "N1"
            or (
                details.get("source") == "generated"
                and ("runbook_id" in details or "runbook_text" in details)
                and not is_explicit_n2
            )
        )
        if is_n1_origin:
            return False

        # 2. Regla de correspondencia de identificador de incidente
        rec_id = str(record.get("id") or "")
        rec_incident_id = str(details.get("incident_id") or "")
        rec_ticket_id = str(ticket_data.get("ticket_id") or "")

        matches_incident_id = (
            rec_id == incident_id
            or rec_incident_id == incident_id
            or rec_ticket_id == incident_id
        )

        # Si no tiene marcas explícitas N2 ni coincide con el incident_id, se descarta
        if not (is_explicit_n2 or matches_incident_id):
            return False

        # 3. Regla de correspondencia de alertas agrupadas
        rec_alert_ids = ticket_data.get("alert_ids") or details.get("grouped_alert_ids")
        if not isinstance(rec_alert_ids, list):
            return False

        # Las alertas del ticket guardado deben coincidir exactamente con el grupo N2
        return set(rec_alert_ids) == set(alert_ids)

    def _find_existing_ticket(self, incident_id: str, alert_ids: List[str]) -> Optional[Ticket]:
        """Buscar exclusivamente un ticket consolidado N2 previo para este incidente.

        Nunca devuelve tickets individuales de N1 aunque compartan alert_id.
        """
        if self.repository is None:
            return None

        # 1. Búsqueda directa por ID de incidente
        if hasattr(self.repository, "get"):
            try:
                record = self.repository.get(incident_id)
                if record and self._is_n2_incident_ticket(record, incident_id, alert_ids):
                    ticket_data = record["details"]["ticket"]
                    return validate_ticket(ticket_data)
            except Exception as exc:
                logger.debug("Excepción al buscar ticket por incident_id %s: %s", incident_id, exc)

        # 2. Búsqueda por alert_id SOLO aceptando registros de nivel N2
        if hasattr(self.repository, "find_by_alert"):
            for aid in alert_ids:
                try:
                    record = self.repository.find_by_alert(aid)
                    if record and self._is_n2_incident_ticket(record, incident_id, alert_ids):
                        ticket_data = record["details"]["ticket"]
                        return validate_ticket(ticket_data)
                except Exception as exc:
                    logger.debug("Excepción al buscar ticket por alert_id %s: %s", aid, exc)

        # 3. Búsqueda en lista reciente
        if hasattr(self.repository, "list_recent"):
            try:
                recent = self.repository.list_recent(limit=50)
                for record in recent:
                    if self._is_n2_incident_ticket(record, incident_id, alert_ids):
                        ticket_data = record["details"]["ticket"]
                        return validate_ticket(ticket_data)
            except Exception as exc:
                logger.debug("Excepción al listar tickets recientes: %s", exc)

        return None

    def _persist_ticket(
        self,
        ticket: Ticket,
        incident_id: str,
        group_justification: Optional[str],
        decision: Any,
        source_ticket_ids: List[str],
        trace: List[Dict[str, Any]],
        reprocess: bool,
    ) -> None:
        """Persistir el ticket consolidado N2 en el repositorio configurado."""
        if self.repository is None:
            logger.warning("No hay repositorio configurado para persistir el ticket %s", incident_id)
            return

        primary_alert_id = ticket.alert_ids[0] if ticket.alert_ids else incident_id

        # Enriquecer la traza con el hito de consolidación N2
        n2_trace = list(trace)
        n2_trace.append({
            "stage": "n2_incident_consolidation",
            "level": "N2",
            "incident_id": incident_id,
            "alert_ids": ticket.alert_ids,
            "source_ticket_ids": source_ticket_ids,
            "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        })

        # Estructura del registro explícitamente marcada como N2
        record = {
            "id": ticket.ticket_id,
            "alert_id": primary_alert_id,
            "status": "new",
            "created_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "details": {
                "ticket": ticket.model_dump(mode="json", exclude_none=True),
                "level": "N2",
                "tier": "N2",
                "type": "incident",
                "is_incident": True,
                "incident_id": incident_id,
                "grouped_alert_ids": ticket.alert_ids,
                "source_ticket_ids": source_ticket_ids,
                "group_justification": group_justification,
                "decision_verdict": getattr(decision, "verdict", None),
                "decision_severity": getattr(decision, "severity", None),
                "decision_rationale": (
                    getattr(decision, "verdict_rationale", None)
                    or getattr(decision, "rationale", None)
                    or getattr(decision, "justification", None)
                ),
                "trace": n2_trace,
            },
        }

        try:
            if hasattr(self.repository, "save"):
                try:
                    # Siempre allow_reprocess=True en N2 para permitir persistir incidentes
                    # cuyas alertas individuales ya hayan sido guardadas en N1 en el mismo repositorio
                    self.repository.save(record, n2_trace, allow_reprocess=True)
                except TypeError:
                    self.repository.save(record, n2_trace)
            elif hasattr(self.repository, "add"):
                self.repository.add(record)
            else:
                raise AttributeError("El repositorio no implementa save(...) ni add(...)")
        except Exception as exc:
            raise PersistenceError(
                f"Fase de persistencia: Falló el almacenamiento del ticket {incident_id} en el repositorio: {exc}"
            ) from exc
