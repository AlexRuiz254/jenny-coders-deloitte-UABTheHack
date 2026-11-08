"""Investigación N3 acotada, sin IA, decisiones ni escrituras.

Contrato provisional: expand(incident, tickets) -> InvestigationBundle.
incident admite el Ticket consolidado N2, IncidentGroup, registro SQLite N2
o su ID (con n2_store). tickets admite Ticket N1, AlertInvestigationInput o
registros SQLite N1. Pasar investigaciones completas evita lecturas adicionales;
con tickets se recuperan sus artefactos mediante n1_store.get(ticket_id).

Los repositorios son los actuales TicketRepository; nunca se usa find_by_alert,
porque no distingue niveles. No se ejecutan N1/N2 ni se persiste un informe.
Las coincidencias de búsquedas son candidatos, no conclusiones de ataque.
"""
from __future__ import annotations

from datetime import datetime, timedelta
import json
import math
from typing import Any

from pydantic import BaseModel, Field

from src.data.soc_api_client import SOCAPIClient
from src.triage.ingestion.entities import extract_entities, extract_indicators
from src.triage.investigation.evidence_collector import EvidenceCollector
from src.triage.level2.incident_decision_service import AlertInvestigationInput, IncidentGroup
from src.triage.level2.incident_grouper import IncidentGrouper
from src.triage.models import ContextSnapshot, EntityKeys, Evidence, LogQuery, SearchPlan, Ticket
from src.triage.time_windows import alert_window, api_time, parse_utc


class InvestigationBundle(BaseModel):
    """Entrada de reconstruct(bundle), assess(bundle) y del futuro informe N3.

    alert_ids es el alcance original N2; related_alert_ids solo propone vínculos.
    investigations conserva análisis/contexto N1; las evidencias mantienen raw.
    events contiene eventos (no metadatos), ordenados por UTC, sin fecha al final.
    window contiene start/end UTC inclusivos. searches registra source/query,
    start/end, status (complete/truncated/unavailable/reused) y count si existe.
    related_incidents contiene incident_id, alert_ids, vínculos estructurados,
    justificación y fechas de las alertas; no supone una fusión ni causalidad.
    No es el informe_incidente oficial: no calcula origen, alcance ni impacto.
    """

    incident_id: str
    alert_ids: list[str]
    related_alert_ids: list[str] = Field(default_factory=list)
    incident_ticket: Ticket | None = None
    source_tickets: list[Ticket] = Field(default_factory=list)
    investigations: list[AlertInvestigationInput] = Field(default_factory=list)
    alerts: list[dict[str, Any]] = Field(default_factory=list)
    contexts: dict[str, ContextSnapshot] = Field(default_factory=dict)
    entities: EntityKeys = Field(default_factory=EntityKeys)
    original_evidence: list[Evidence] = Field(default_factory=list)
    additional_evidence: list[Evidence] = Field(default_factory=list)
    events: list[Evidence] = Field(default_factory=list)
    related_incidents: list[dict[str, Any]] = Field(default_factory=list)
    consulted_sources: list[str] = Field(default_factory=list)
    searches: list[dict[str, Any]] = Field(default_factory=list)
    window: dict[str, str]
    limitations: list[str] = Field(default_factory=list)


class InvestigationExpander:
    def __init__(
        self, *, api: SOCAPIClient, collector: EvidenceCollector,
        n1_store: Any = None, n2_store: Any = None,
        before_days: float = 3, after_days: float = 1,
        max_window_days: float = 31, max_queries: int = 48,
        max_incidents: int = 100, max_additional_events: int = 10000,
        sources: list[str] | None = None,
    ) -> None:
        """Inyectar API/colector y, opcionalmente, repositorios SQLite N1/N2.

        sources limita las búsquedas ampliadas; las referencias originales se
        resuelven en su fuente real. max_queries cuenta ambas clases de consulta
        de logs. max_incidents acota registros SQLite, incluidos los de otro nivel
        si el repositorio es compartido. No hay caché entre llamadas a expand.
        """
        for name, value in (("before_days", before_days), ("after_days", after_days),
                            ("max_window_days", max_window_days)):
            if not math.isfinite(value) or value < 0:
                raise ValueError(f"{name} debe ser finito y no negativo")
        if max_window_days == 0:
            raise ValueError("max_window_days debe ser mayor que cero")
        if before_days + after_days > max_window_days:
            raise ValueError("La ventana configurada supera max_window_days")
        for name, value in (("max_queries", max_queries), ("max_incidents", max_incidents),
                            ("max_additional_events", max_additional_events)):
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise ValueError(f"{name} debe ser un entero positivo")
        for dependency, method in ((api, "get_alert"), (collector, "search"),
                                   (collector, "collect_related_events")):
            if not callable(getattr(dependency, method, None)):
                raise TypeError(f"Falta la dependencia obligatoria {method}")
        for store, methods in ((n1_store, ("get",)), (n2_store, ("get", "list_recent"))):
            if store is not None and any(not callable(getattr(store, method, None)) for method in methods):
                raise TypeError(f"Repositorio incompatible: se requiere {methods}")
        allowed = set(EvidenceCollector.SOURCES.values())
        selected = sorted(allowed) if sources is None else list(dict.fromkeys(sources))
        if not selected or set(selected) - allowed:
            raise ValueError("sources debe contener fuentes reales de EvidenceCollector")
        self.api, self.collector = api, collector
        self.n1_store, self.n2_store = n1_store, n2_store
        self.before = timedelta(days=before_days)
        self.after = timedelta(days=after_days)
        self.max_window = timedelta(days=max_window_days)
        self.max_queries, self.max_incidents = max_queries, max_incidents
        self.max_additional_events = max_additional_events
        self.sources = selected

    @staticmethod
    def _is_n2(record: dict) -> bool:
        details = record.get("details", {})
        return (details.get("level") == "N2" or details.get("tier") == "N2"
                or details.get("is_incident") is True or details.get("type") == "incident")

    def _incident(self, incident: Ticket | IncidentGroup | dict[str, Any] | str
                  ) -> tuple[str, list[str], Ticket | None]:
        if isinstance(incident, str):
            if self.n2_store is None:
                raise TypeError("Un incident_id requiere n2_store.get")
            record = self.n2_store.get(incident)
            if record is None:
                raise LookupError(f"Incidente N2 no encontrado: {incident}")
            identity, ids, ticket = self._incident(record)
            if identity != incident:
                raise ValueError("El repositorio devolvió otro incidente")
            return identity, ids, ticket
        if isinstance(incident, dict):
            if "details" in incident:
                if not self._is_n2(incident):
                    raise ValueError("El registro no está marcado como incidente N2")
                incident = Ticket.model_validate(incident["details"]["ticket"])
            elif "ticket_id" in incident:
                incident = Ticket.model_validate(incident)
            else:
                incident = IncidentGroup.model_validate(incident)
        if isinstance(incident, Ticket):
            identity, ids, ticket = incident.ticket_id, incident.alert_ids, incident
        elif isinstance(incident, IncidentGroup):
            identity, ids, ticket = incident.incident_id, incident.alert_ids, None
        else:
            raise TypeError("incident debe ser un Ticket N2, IncidentGroup o registro/ID N2")
        if (not identity.strip() or not ids or len(ids) != len(set(ids))
                or any(not item.strip() for item in ids)):
            raise ValueError("El incidente requiere ID y alert_ids no vacíos y únicos")
        return identity, sorted(ids), ticket.model_copy(deep=True) if ticket else None

    def _investigation(self, value: Ticket | AlertInvestigationInput | dict[str, Any],
                       limitations: list[str], *, fetch: bool) -> AlertInvestigationInput:
        if isinstance(value, AlertInvestigationInput):
            result = value.model_copy(deep=True)
        else:
            record = value if isinstance(value, dict) and "details" in value else None
            ticket = Ticket.model_validate(record["details"]["ticket"] if record else value)
            if len(ticket.alert_ids) != 1:
                raise ValueError("Se requiere un ticket N1 individual por alerta")
            if record is None and self.n1_store is not None:
                record = self.n1_store.get(ticket.ticket_id)
                if record is None:
                    raise LookupError(f"Investigación N1 no encontrada: {ticket.ticket_id}")
            if record is not None and self._is_n2(record):
                raise ValueError(f"Se recibió un registro N2 como investigación N1: {ticket.ticket_id}")
            details = record["details"] if record else {}
            if record and Ticket.model_validate(details["ticket"]) != ticket:
                raise ValueError(f"El ticket y sus artefactos N1 no coinciden: {ticket.ticket_id}")
            alert_id = ticket.alert_ids[0]
            alert = details.get("alert")
            if alert is None:
                if not fetch:
                    raise LookupError(f"Falta la alerta persistida de {alert_id}")
                alert = self.api.get_alert(alert_id)
                if alert is None:
                    raise LookupError(f"Alerta no encontrada: {alert_id}")
            for field in ("analysis", "context", "evidence"):
                if field not in details:
                    limitations.append(f"{alert_id}: no se dispone del artefacto N1 {field}.")
            result = AlertInvestigationInput.model_validate({
                "alert_id": alert_id, "alert": alert, "ticket": ticket,
                "analysis": details.get("analysis"), "context": details.get("context", {}),
                "evidence": details.get("evidence", []),
                "verdict_decision": details.get("verdict"),
                "related_alerts": details.get("related_alerts", []),
            })
        if result.alert.get("alert_id") != result.alert_id:
            raise ValueError("Los artefactos N1 pertenecen a otra alerta")
        if result.ticket is None:
            raise ValueError("La investigación requiere su Ticket N1 individual")
        result.ticket = Ticket.model_validate(result.ticket)
        if result.ticket.alert_ids != [result.alert_id]:
            raise ValueError("La investigación requiere su Ticket N1 individual")
        if result.analysis is None:
            limitations.append(f"{result.alert_id}: análisis N1 no disponible; no se reconstruye a partir del ticket.")
        return result.model_copy(deep=True)

    @staticmethod
    def _metadata(item: Evidence) -> bool:
        return (item.event_id is None and "truncated" in item.raw
                and "q" in item.raw and not item.timestamp)

    @staticmethod
    def _deduplicate(items: list[Evidence], limitations: list[str]) -> list[Evidence]:
        result: dict[tuple[str, str], Evidence] = {}
        for item in items:
            key = (item.source, item.event_id or json.dumps(item.raw, sort_keys=True, ensure_ascii=False))
            previous = result.get(key)
            if previous is not None and previous != item:
                # No descartar versiones contradictorias de un evento silenciosamente.
                limitations.append(f"Versiones distintas de {item.source}/{item.event_id}; se conservan ambas.")
                key = (item.source, json.dumps(item.model_dump(), sort_keys=True, ensure_ascii=False))
            result[key] = item
        return [result[key] for key in sorted(result)]

    @staticmethod
    def _instant(item: Evidence) -> datetime | None:
        value = item.timestamp or item.raw.get("timestamp") or item.raw.get("eventTime")
        return parse_utc(value) if value else None

    @staticmethod
    def _entities(alerts: list[dict], evidence: list[Evidence], tickets: list[Ticket]) -> EntityKeys:
        inputs = [extract_entities(alert) for alert in alerts]
        inputs.extend(extract_entities({"entities": ticket.affected}) for ticket in tickets)
        for item in evidence:
            if InvestigationExpander._metadata(item):
                continue
            row = item.raw
            identity = row.get("userIdentity") or {}
            if not isinstance(identity, dict):
                identity = {}
            raw = {
                "hosts": [row.get(key) for key in ("hostname", "src_host", "client_host", "runner")],
                "users": [row.get(key) for key in ("user", "user_upn", "actor_upn", "subject")],
                "sessions": [row.get("session_id"), identity.get("accessKeyId")],
                "customers": [row.get("customer_id")],
                "cloud": {"identity": identity.get("userName") or identity.get("arn")},
            }
            keys = extract_entities({"entities": raw})
            # El helper N1 valida IP, dominio, URL y hash en campos estructurados.
            indicators = extract_indicators({"evidence": row})
            for indicator in indicators:
                for group in ("ips", "domains", "urls", "hashes"):
                    parsed = extract_entities({"entities": {group: [indicator]}})
                    getattr(keys, group).extend(getattr(parsed, group))
            # Para investigación interna conservar también IP privadas del evento.
            keys.ips.extend(extract_entities({"entities": {"ips": [
                row.get(key) for key in ("ip", "src_ip", "dst_ip", "sourceIPAddress", "assigned_ip")
            ]}}).ips)
            inputs.append(keys)
        return EntityKeys(**{key: sorted({value for item in inputs for value in getattr(item, key)})
                             for key in EntityKeys.model_fields})

    @staticmethod
    def _uncovered(start: datetime, end: datetime, source: str, term: str,
                   original: list[Evidence]) -> list[tuple[datetime, datetime]]:
        """Reutilizar solo cobertura documentada, completa y de la misma consulta."""
        intervals = [(start, end)]
        for item in original:
            row = item.raw
            if (not InvestigationExpander._metadata(item) or item.source != source
                    or row.get("q", "").casefold() != term.casefold()
                    or row.get("truncated") is not False
                    or not row.get("desde") or not row.get("hasta")):
                continue
            try:
                a, b = parse_utc(row["desde"]), parse_utc(row["hasta"])
            except (ValueError, TypeError, AttributeError):
                continue  # Metadatos inválidos no prueban cobertura.
            if a > b:
                continue
            remaining = []
            for left, right in intervals:
                if b < left or a > right:
                    remaining.append((left, right))
                else:
                    if left < a:
                        remaining.append((left, a - timedelta(milliseconds=1)))
                    if b < right:
                        remaining.append((b + timedelta(milliseconds=1), right))
            intervals = [(a, b) for a, b in remaining if a <= b]
        return intervals

    def _relations(self, incident_id: str, ids: list[str], investigations: list[AlertInvestigationInput],
                   start: datetime, end: datetime, limitations: list[str]) -> list[dict]:
        if self.n2_store is None:
            limitations.append("Sin n2_store: no se han comparado otros incidentes N2.")
            return []
        if self.n1_store is None:
            limitations.append("Sin n1_store: no se pueden recuperar los artefactos de otros incidentes N2.")
            return []
        records = self.n2_store.list_recent(limit=self.max_incidents + 1, offset=0)
        if len(records) > self.max_incidents:
            limitations.append(f"Comparación limitada a {self.max_incidents} registros recientes de SQLite.")
        result = []
        grouper = IncidentGrouper(window_hours=max((end - start).total_seconds() / 3600, .001))
        for record in records[:self.max_incidents]:
            if not self._is_n2(record):
                continue
            other_id, other_ids, _ = self._incident(record)
            if other_id == incident_id:
                continue
            if set(ids) & set(other_ids):
                limitations.append(f"{other_id}: comparte alertas originales; no se propone como incidente independiente.")
                continue
            source_ids = record["details"].get("source_ticket_ids")
            if not source_ids:
                limitations.append(f"{other_id}: faltan source_ticket_ids N1 para justificar relaciones.")
                continue
            candidates = []
            for source_id in sorted(set(source_ids)):
                source = self.n1_store.get(source_id)
                if source is None or not source.get("details", {}).get("alert"):
                    limitations.append(f"{other_id}: falta investigación N1 {source_id}.")
                    break
                candidates.append(self._investigation(source, limitations, fetch=False))
            if {item.alert_id for item in candidates} != set(other_ids):
                continue
            try:
                times = [parse_utc(item.alert["created_at"]) for item in candidates]
            except (KeyError, ValueError, TypeError, AttributeError):
                limitations.append(f"{other_id}: fechas de alertas inválidas; relación no evaluada.")
                continue
            if max(times) < start or min(times) > end:
                continue
            members = investigations + candidates
            groups = grouper.group([item.alert for item in members], [item.ticket for item in members])
            in_window = {item.alert_id for item, instant in zip(candidates, times) if start <= instant <= end}
            links = [link for group in groups for link in group.shared_entities.get("relations", [])
                     if set(link["alert_ids"]) & set(ids) and set(link["alert_ids"]) & in_window]
            if links:
                result.append({
                    "incident_id": other_id, "alert_ids": other_ids,
                    "source_ticket_ids": sorted(source_ids), "relations": links,
                    "justification": "; ".join(link["reason"] for link in links),
                    "start": api_time(min(times)), "end": api_time(max(times)),
                })
        return sorted(result, key=lambda item: item["incident_id"])

    def expand(self, incident: Ticket | IncidentGroup | dict[str, Any] | str,
               tickets: list[Ticket | AlertInvestigationInput | dict[str, Any]]) -> InvestigationBundle:
        """Reutilizar N1, ampliar logs y proponer relaciones sin cambiar el incidente.

        Errores SQLite, programación y HTTP se propagan. Una desconexión de logs
        deja un bundle parcial explícito; una dependencia pendiente se propaga.
        SOCAPIClient oculta el 404 de fuentes: vacío y fuente ausente no se pueden
        distinguir. EvidenceCollector fija limit=2000; la API no permite offset.
        """
        limitations: list[str] = []
        incident_id, ids, consolidated = self._incident(incident)
        if not isinstance(tickets, list):
            raise TypeError("tickets debe ser una lista de investigaciones/tickets N1")
        investigations = [self._investigation(value, limitations, fetch=True) for value in tickets]
        if len(investigations) != len(ids) or {item.alert_id for item in investigations} != set(ids):
            raise ValueError("Se requiere exactamente una investigación N1 por alerta del incidente")
        investigations.sort(key=lambda item: item.alert_id)
        alerts = [item.alert for item in investigations]
        times = []
        for alert in alerts:
            try:
                times.append(parse_utc(alert["created_at"]))
            except (KeyError, ValueError, TypeError, AttributeError) as exc:
                raise ValueError(f"Fecha created_at inválida en {alert['alert_id']}") from exc
        if max(times) - min(times) + self.before + self.after > self.max_window:
            raise ValueError("La ventana de investigación supera max_window_days; reduzca el alcance")
        originals = self._deduplicate([e for item in investigations for e in item.evidence], limitations)
        source_tickets = [item.ticket for item in investigations]
        searches: list[dict] = []
        extra: list[Evidence] = []
        query_count = 0
        disconnected = False

        # Resolver únicamente referencias originales cuyo evento aún no tenemos.
        seen = {(item.source, item.event_id) for item in originals if item.event_id}
        for alert in alerts:
            for event_id in dict.fromkeys(alert.get("related_events", []) or []):
                source = EvidenceCollector.SOURCES.get(event_id.split("-", 1)[0].upper())
                if source is None:
                    limitations.append(f"Referencia sin fuente conocida: {event_id}.")
                    continue
                if (source, event_id) in seen or disconnected:
                    continue
                if query_count >= self.max_queries:
                    limitations.append("Límite de consultas alcanzado; quedan referencias sin recuperar.")
                    continue
                a, b = alert_window(alert)
                query = {"source": source, "query": event_id, "start": api_time(a), "end": api_time(b)}
                query_count += 1
                try:
                    rows = self.collector.collect_related_events({**alert, "related_events": [event_id]})
                except ConnectionError as exc:
                    searches.append({**query, "status": "unavailable", "error": str(exc)})
                    limitations.append(f"Logs no disponibles: {exc}")
                    disconnected = True
                    continue
                seen.add((source, event_id))
                found = [item for item in rows if not self._metadata(item)]
                originals.extend(found)
                truncated = any(item.raw.get("truncated") for item in rows if self._metadata(item))
                searches.append({**query, "status": "truncated" if truncated else "complete", "count": len(found)})
                if not found:
                    limitations.append(f"No se recuperó la referencia {source}/{event_id}.")
                if truncated:
                    limitations.append(f"Consulta truncada de referencia {source}/{event_id}.")

        # Las fechas proceden de alertas y eventos, nunca del reloj del sistema.
        originals = self._deduplicate(originals, limitations)
        for item in originals:
            if self._metadata(item):
                continue
            try:
                instant = self._instant(item)
            except (ValueError, TypeError, AttributeError):
                instant = None
            if instant is None:
                limitations.append(f"Evento sin fecha válida: {item.source}/{item.event_id}.")
            else:
                times.append(instant)
        start, end = min(times) - self.before, max(times) + self.after
        if end - start > self.max_window:
            raise ValueError("La ventana de investigación supera max_window_days; reduzca el alcance")
        entities = self._entities(alerts, originals, source_tickets)
        # Alternar categorías evita que muchos IOC consuman todo el presupuesto
        # antes de investigar equipos y usuarios del propio incidente.
        categories = [getattr(entities, key) for key in (
            "hashes", "sessions", "hosts", "users", "customers", "domains", "urls", "ips"
        )]
        terms = list(dict.fromkeys(values[index] for index in range(max(map(len, categories)))
                                   for values in categories if index < len(values)))
        # La API compara q sin distinguir mayúsculas, incluso dentro de URLs.
        terms = list({term.casefold(): term for term in terms}.values())
        if not terms:
            limitations.append("No hay identificadores válidos para ampliar búsquedas de logs.")

        # Consultas de texto literal: la API no soporta DSL, offset ni operadores.
        pending = ((source, term, a, b) for term in terms for source in self.sources
                   for a, b in self._uncovered(start, end, source, term, originals))
        known_values = {json.dumps(item.model_dump(), sort_keys=True, ensure_ascii=False) for item in originals}
        for source, term, a, b in pending:
            if disconnected or len(extra) >= self.max_additional_events:
                break
            if query_count >= self.max_queries:
                limitations.append(f"Límite de {self.max_queries} consultas alcanzado; cobertura parcial.")
                break
            query_count += 1
            query = {"source": source, "query": term, "start": api_time(a), "end": api_time(b)}
            try:
                rows = self.collector.search(SearchPlan(searches=[LogQuery(
                    source=source, query=term, start=api_time(a), end=api_time(b),
                    reason="Ampliación N3 por identificador observado; no implica malicia",
                )]))
            except ConnectionError as exc:
                searches.append({**query, "status": "unavailable", "error": str(exc)})
                limitations.append(f"Logs no disponibles: {exc}")
                disconnected = True
                break
            metadata = [item for item in rows if self._metadata(item)]
            truncated = any(item.raw.get("truncated") for item in metadata)
            searches.append({**query, "status": "truncated" if truncated else "complete",
                             "count": sum(not self._metadata(item) for item in rows)})
            if truncated:
                limitations.append(f"{source}/{term}: resultados truncados a 2000; la API no ofrece paginación de logs.")
            for item in rows:
                if self._metadata(item):
                    continue
                try:
                    instant = self._instant(item)
                except (ValueError, TypeError, AttributeError):
                    instant = None
                if instant is None:
                    limitations.append(f"Evento adicional sin fecha válida: {item.source}/{item.event_id}.")
                elif not start <= instant <= end:
                    limitations.append(f"Evento fuera de ventana descartado: {item.source}/{item.event_id}.")
                    continue
                value = json.dumps(item.model_dump(), sort_keys=True, ensure_ascii=False)
                if value in known_values:
                    continue
                if len(extra) >= self.max_additional_events:
                    limitations.append(f"Límite de {self.max_additional_events} eventos adicionales alcanzado.")
                    break
                extra.append(item.model_copy(deep=True))
                known_values.add(value)
        # Registrar cobertura N1 reutilizada sin presentar esos metadatos como eventos.
        for item in originals:
            if self._metadata(item):
                searches.append({"source": item.source, "query": item.raw["q"],
                                 "start": item.raw.get("desde"), "end": item.raw.get("hasta"),
                                 "status": "reused", "count": item.raw.get("count"),
                                 "truncated": item.raw.get("truncated")})
                if item.raw.get("truncated"):
                    limitations.append(f"La investigación N1 ya tenía resultados truncados en {item.source}.")
        if len(extra) >= self.max_additional_events:
            limitations.append(f"Límite de {self.max_additional_events} eventos adicionales alcanzado; cobertura parcial.")
        additional = self._deduplicate(extra, limitations)
        events = [item for item in self._deduplicate(originals + additional, limitations)
                  if not self._metadata(item)]

        def order(item: Evidence) -> tuple:
            try:
                instant = self._instant(item)
            except (ValueError, TypeError, AttributeError):
                instant = None
            return (instant is None, api_time(instant) if instant else "", item.source,
                    item.event_id or "", json.dumps(item.raw, sort_keys=True, ensure_ascii=False))

        events.sort(key=order)
        relations = self._relations(incident_id, ids, investigations, start, end, limitations)
        limitations.extend([
            "Las búsquedas por subcadena pueden devolver actividad no relacionada; no prueban causalidad.",
            "SOCAPIClient no distingue logs vacíos de fuente con HTTP 404; no es prueba de ausencia de ataque.",
            "Solo se comparan incidentes N2 persistidos; no se descubren ni investigan automáticamente nuevas alertas.",
        ])
        return InvestigationBundle(
            incident_id=incident_id, alert_ids=ids, incident_ticket=consolidated,
            source_tickets=source_tickets, investigations=investigations, alerts=alerts,
            contexts={item.alert_id: item.context for item in investigations},
            entities=self._entities(alerts, events, source_tickets),
            original_evidence=originals, additional_evidence=additional, events=events,
            related_incidents=relations,
            related_alert_ids=sorted({key for item in relations for key in item["alert_ids"]}),
            consulted_sources=sorted({item.source for item in originals} | {q["source"] for q in searches}),
            searches=searches, window={"start": api_time(start), "end": api_time(end)},
            limitations=list(dict.fromkeys(limitations)),
        )
