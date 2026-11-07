"""Importaciones JSON/JSONL con validación por registro y sin tocar los datasets."""
from datetime import datetime
import json
import logging

from src.data.ticket_repository import utc_now
from src.triage.output.validation import validate_ticket

logger = logging.getLogger(__name__)


def validate_alert(payload: dict, references) -> dict:
    if not isinstance(payload, dict):
        raise ValueError("La alerta debe ser un objeto JSON.")
    for key in ("alert_id", "created_at", "source_product", "rule_id", "rule_name", "severity", "status", "runbook"):
        if not isinstance(payload.get(key), str) or not payload[key].strip():
            raise ValueError(f"Falta un texto válido en {key}.")
    instant = datetime.fromisoformat(payload["created_at"].replace("Z", "+00:00"))
    if instant.tzinfo is None:
        raise ValueError("created_at debe incluir zona horaria.")
    if payload["severity"] not in {"informational", "low", "medium", "high", "critical"}:
        raise ValueError("Severidad no válida.")
    if payload["status"] != "new":
        raise ValueError("La importación de pendientes requiere status=new.")
    if not isinstance(payload.get("entities"), dict) or not isinstance(payload.get("evidence", {}), dict):
        raise ValueError("entities y evidence deben ser objetos.")
    for key in ("hosts", "users", "ips", "domains", "urls", "files", "hashes", "sessions", "customers", "processes"):
        items = payload["entities"].get(key, [])
        if not isinstance(items, list) or any(not isinstance(item, (str, dict)) for item in items):
            raise ValueError(f"entities.{key} debe ser una lista de textos u objetos.")
    if "cloud" in payload["entities"] and not isinstance(payload["entities"]["cloud"], dict):
        raise ValueError("entities.cloud debe ser un objeto.")
    events = payload.get("related_events")
    if not isinstance(events, list) or any(not isinstance(item, str) or not item.strip() for item in events):
        raise ValueError("related_events debe ser una lista de identificadores.")
    rule = references.get_rule(payload["rule_id"])
    if rule is None or rule["runbook"] != payload["runbook"]:
        raise ValueError("La regla y el runbook no coinciden con el catálogo oficial.")
    # La API compara fechas textualmente: normalizar las importadas al mismo formato.
    from src.triage.time_windows import api_time
    return {**payload, "created_at": api_time(instant)}


def import_records(data: bytes, *, kind: str, jsonl: bool, store, api, references) -> dict:
    summary = {"imported": 0, "duplicates": 0, "rejected": 0, "errors": []}
    try:
        content = data.decode("utf-8-sig")
        if jsonl:
            entries = [(number, line) for number, line in enumerate(content.splitlines(), 1) if line.strip()]
        else:
            parsed = json.loads(content)
            entries = list(enumerate(parsed if isinstance(parsed, list) else [parsed], 1))
    except (UnicodeError, ValueError):
        return {**summary, "rejected": 1, "errors": ["El archivo no contiene JSON UTF-8 válido."]}
    for number, entry in entries:
        try:
            payload = json.loads(entry) if jsonl else entry
            if kind == "alerts":
                alert = validate_alert(payload, references)
                alert_id = alert["alert_id"]
                if store.get_imported_alert(alert_id) or store.find_by_alert(alert_id) or api.get_alert(alert_id):
                    summary["duplicates"] += 1
                    continue
                inserted = store.import_alert(alert)
                summary["imported" if inserted else "duplicates"] += 1
            elif kind == "tickets":
                ticket = validate_ticket(payload)
                if store.get(ticket.ticket_id) or any(store.find_by_alert(a) for a in ticket.alert_ids):
                    summary["duplicates"] += 1
                    continue
                store.save({"id": ticket.ticket_id, "alert_id": ticket.alert_ids[0],
                            "created_at": utc_now(), "details": {
                                "ticket": ticket.model_dump(mode="json", exclude_none=True),
                                "source": "imported",
                            }}, trace=[])
                summary["imported"] += 1
            else:
                raise ValueError("Tipo de importación desconocido.")
        except Exception as exc:
            logger.warning("Importación rechazada en registro %s (%s)", number, type(exc).__name__)
            summary["rejected"] += 1
            if isinstance(exc, ConnectionError):
                reason = "API SOC no disponible; no se pudo comprobar si la alerta ya existe. Reintentar."
            else:
                reason = str(exc).split("\n", 1)[0][:200]
            summary["errors"].append(f"Registro {number}: {reason}")
    return summary
