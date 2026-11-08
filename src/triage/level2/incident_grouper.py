"""Agrupación conservadora N2 basada en referencias estructuradas, sin red ni IA.

Una coincidencia de usuario, equipo, IP o dominio nunca basta por sí sola.
Las confianzas son etiquetas heurísticas de relación, no probabilidades de ataque.
Se reutilizan el extractor N1 y el IncidentGroup existente de Persona 2.
"""
from datetime import timedelta
from hashlib import sha256
import json
import math
import re

from src.triage.ingestion.entities import extract_entities
from src.triage.investigation.evidence_collector import EvidenceCollector
from src.triage.level2.incident_decision_service import IncidentGroup
from src.triage.models import RawAlert, Ticket
from src.triage.time_windows import parse_utc


class IncidentGrouper:
    def __init__(self, window_hours: float = 24) -> None:
        if not math.isfinite(window_hours) or window_hours <= 0:
            raise ValueError("window_hours debe ser finito y mayor que cero")
        self.window = timedelta(hours=window_hours)

    @staticmethod
    def _bindings(value: object) -> set[str]:
        """Solo identificadores explícitos; nunca buscar dentro de texto libre."""
        result = set()
        if isinstance(value, dict):
            for key, item in value.items():
                if key in {"message_id", "session_id", "ai_session"}:
                    if (isinstance(item, str) and item.strip()
                            and any(char.isalnum() for char in item)
                            and not item.strip().startswith("(")
                            and item.strip().casefold() not in {
                                "unknown", "none", "null", "n/a", "desconocido", "ninguno",
                            }):
                        result.add(f"{key}:{item.strip()}")
                elif key == "sessions":
                    for session in item if isinstance(item, list) else []:
                        if (isinstance(session, str) and session.strip()
                                and any(char.isalnum() for char in session)
                                and not session.strip().startswith("(")
                                and session.strip().casefold() not in {
                                    "unknown", "none", "null", "n/a", "desconocido", "ninguno",
                                }):
                            result.add(f"session_id:{session.strip()}")
                if isinstance(item, (dict, list)):
                    result.update(IncidentGrouper._bindings(item))
        elif isinstance(value, list):
            for item in value:
                result.update(IncidentGrouper._bindings(item))
        return result

    @staticmethod
    def _facts(alert: RawAlert, ticket: Ticket) -> dict:
        keys = extract_entities(alert)
        events = set()
        for event_id in alert.get("related_events", []) or []:
            if (isinstance(event_id, str) and re.fullmatch(r"[A-Z]+-\d+", event_id)
                    and event_id.split("-", 1)[0] in EvidenceCollector.SOURCES):
                events.add(event_id)
        seed_events = set(events)
        for evidence in ticket.evidence:
            if evidence.source in EvidenceCollector.SOURCES.values() and evidence.event_id:
                events.add(evidence.event_id)
        corroborated = set()
        for entry in ticket.enrichment:
            try:
                record = json.loads(entry.result)
            except (ValueError, TypeError):
                continue
            if not isinstance(record, dict):
                continue
            # Usar resultados estructurados de TIP/sandbox, no juicios del LLM.
            indicator = entry.indicator.casefold()
            if (record.get("reputation") == "malicious"
                    and str(record.get("value", "")).casefold() == indicator):
                corroborated.add(indicator)
            if (record.get("verdict") == "malicious"
                    and str(record.get("sha256", "")).casefold() == indicator):
                corroborated.add(indicator)
        try:
            instant = parse_utc(alert.get("created_at", ""))
        except (ValueError, TypeError, AttributeError):
            instant = None
        return {
            "time": instant, "events": events,
            "seed_events": seed_events,
            "bindings": IncidentGrouper._bindings(alert.get("entities", {}))
            | IncidentGrouper._bindings(alert.get("evidence", {})),
            "hosts": set(keys.hosts), "users": set(keys.users),
            "customers": set(keys.customers), "hashes": set(keys.hashes),
            "network": set(keys.domains) | set(keys.urls), "corroborated": corroborated,
        }

    def _relation(self, left: dict, right: dict) -> tuple[float, str, dict] | None:
        if (left["time"] is None or right["time"] is None
                or abs(left["time"] - right["time"]) > self.window):
            return None
        shared = {key: sorted(left[key] & right[key]) for key in (
            "events", "bindings", "hosts", "users", "customers", "hashes", "network",
        )}
        anchored = sorted(set(shared["events"]) & (left["seed_events"] | right["seed_events"]))
        if anchored:
            return .98, "Mismo evento vinculado a una alerta original", {"event_ids": anchored}
        if shared["bindings"]:
            return .95, "Mismo mensaje o sesión explícita", {"bindings": shared["bindings"]}
        victim = shared["hosts"] or shared["users"] or shared["customers"]
        known = left["corroborated"] | right["corroborated"]
        supported_hashes = [value for value in shared["hashes"] if value in known]
        if shared["hashes"] and victim and (
            supported_hashes or (shared["hosts"] and shared["users"])
        ):
            return .90, "Mismo fichero y víctima, corroborados por TIP/sandbox o equipo y usuario", {
                "hashes": supported_hashes or shared["hashes"],
                "hosts": shared["hosts"], "users": shared["users"],
                "customers": shared["customers"],
            }
        network = [value for value in shared["network"] if value.casefold() in known]
        if network and shared["hosts"] and shared["users"]:
            return .85, "Mismo IOC malicioso de TIP en el mismo equipo y usuario", {
                "indicators": network, "hosts": shared["hosts"], "users": shared["users"],
            }
        return None

    def group(self, alerts: list[RawAlert], tickets: list[Ticket]) -> list[IncidentGroup]:
        """Particionar entradas sin perder IDs; justificar cada unión verificable.

        La ventana limita también la duración total del grupo: una secuencia de
        coincidencias no puede extender un incidente indefinidamente.
        AlertCorrelator ya aporta candidatos a N1, pero sus coincidencias amplias
        no son prueba de incidente. Aquí se usan solo las entradas, sin volver a
        consultarlo ni realizar nuevas lecturas de la API.
        """
        by_id: dict[str, RawAlert] = {}
        for alert in alerts:
            if not isinstance(alert, dict) or not isinstance(alert.get("alert_id"), str) or not alert["alert_id"].strip():
                raise ValueError("Cada alerta debe contener un alert_id válido")
            alert_id = alert["alert_id"]
            if alert_id in by_id and by_id[alert_id] != alert:
                raise ValueError(f"Versiones contradictorias de la alerta {alert_id}")
            by_id[alert_id] = alert
        by_ticket = {}
        for ticket in tickets:
            if not isinstance(ticket, Ticket) or len(ticket.alert_ids) != 1:
                raise ValueError("Se requiere un Ticket N1 individual por alerta")
            alert_id = ticket.alert_ids[0]
            if alert_id not in by_id:
                raise ValueError(f"Ticket de alerta desconocida: {alert_id}")
            if alert_id in by_ticket and by_ticket[alert_id] != ticket:
                raise ValueError(f"Investigaciones contradictorias de {alert_id}")
            by_ticket[alert_id] = ticket
        if set(by_id) != set(by_ticket):
            raise ValueError(f"Faltan investigaciones N1: {sorted(set(by_id) - set(by_ticket))}")
        ids = sorted(by_id)
        facts = {key: self._facts(by_id[key], by_ticket[key]) for key in ids}
        edges = []
        for index, left in enumerate(ids):
            for right in ids[index + 1:]:
                relation = self._relation(facts[left], facts[right])
                if relation:
                    score, reason, proof = relation
                    edges.append((score, left, right, reason, proof))
        edges.sort(key=lambda edge: (-edge[0], edge[1], edge[2]))
        owners = {key: key for key in ids}
        components = {key: {key} for key in ids}
        links: dict[str, list[dict]] = {key: [] for key in ids}
        for score, left, right, reason, proof in edges:
            a, b = owners[left], owners[right]
            if a == b:
                continue
            members = components[a] | components[b]
            times = [facts[key]["time"] for key in members]
            if max(times) - min(times) > self.window:
                continue
            root, other = sorted((a, b))
            components[root] = members
            links[root] = links[a] + links[b] + [{
                "alert_ids": [left, right], "reason": reason,
                "confidence": score, "evidence": proof,
            }]
            del components[other]
            del links[other]
            for key in members:
                owners[key] = root
        result = []
        for members in sorted(components.values(), key=lambda items: sorted(items)):
            ordered = sorted(members)
            relations = links[owners[ordered[0]]]
            reason = "; ".join(
                f"{' / '.join(link['alert_ids'])}: {link['reason']} {json.dumps(link['evidence'], ensure_ascii=False, sort_keys=True)}"
                for link in relations
            ) or "Alerta individual: no hay evidencias suficientes de relación dentro de la ventana."
            incident_id = "INC-" + sha256(json.dumps(ordered).encode()).hexdigest()[:20]
            result.append(IncidentGroup(
                incident_id=incident_id, group_id=incident_id, alert_ids=ordered,
                alerts=[by_id[key] for key in ordered], correlation_reason=reason,
                justification=reason, shared_entities={"relations": relations},
                confidence=min(link["confidence"] for link in relations) if relations else None,
            ))
        return result
