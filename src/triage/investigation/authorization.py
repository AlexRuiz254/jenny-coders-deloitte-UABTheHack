"""Comprobar el cambio contra su actividad, no contra toda la investigación."""
from datetime import datetime
from ipaddress import ip_address
import re
from zoneinfo import ZoneInfo

from src.triage.models import ContextSnapshot, Evidence, Finding
from src.triage.time_windows import parse_utc
from src.triage.investigation.context_enricher import ContextEnricher


def check_authorization(findings: list[Finding], evidence: list[Evidence],
                        context: ContextSnapshot) -> tuple[bool, str]:
    local = ZoneInfo("Europe/Madrid")
    reasons = []
    for change in context.changes:
        change_id = change.get("id")
        # Solo los eventos vinculados al cambio en el mismo hallazgo.
        refs = {ref for finding in findings if change_id in finding.evidence_ids
                for ref in finding.evidence_ids}
        events = [ev for ev in evidence if ev.event_id in refs and ev.source != "changes"]
        if not events:
            continue
        detail = str(change.get("detalle", ""))
        title = str(change.get("titulo", "")).casefold()
        if "sccm" in title:
            events = [ev for ev in events if ev.source == "edr_events"
                      and ev.raw.get("event_type") == "process_start"
                      and str(ev.raw.get("parent_name", "")).casefold() == "ccmexec.exe"
                      and str(ev.raw.get("process_name", "")).casefold() == "powershell.exe"
                      and isinstance(ev.raw.get("details"), dict)
                      and "get-ciminstance win32_product" in str(ev.raw["details"].get("decoded", "")).casefold()
                      and "\\ccm\\inventory\\" in str(ev.raw["details"].get("decoded", "")).casefold()]
        if not events:
            reasons.append(f"{change_id}: falta el evento de la actividad autorizada.")
            continue
        if any(not isinstance(ev.timestamp or ev.raw.get("timestamp"), str) for ev in events):
            reasons.append(f"{change_id}: falta un timestamp válido de la actividad.")
            continue
        try:
            start, end = [datetime.fromisoformat(change[key]) for key in ("inicio", "fin")]
            start = start.replace(tzinfo=local) if start.tzinfo is None else start
            end = end.replace(tzinfo=local) if end.tzinfo is None else end
            times = [parse_utc(ev.timestamp or ev.raw["timestamp"]).astimezone(local) for ev in events]
            hours = re.search(r"(\d{1,2}:\d{2})\s*[-–]\s*(\d{1,2}:\d{2})", detail)
            in_window = start <= end and all(start <= t <= end for t in times)
            if hours:
                first, last = [datetime.strptime(h, "%H:%M").time() for h in hours.groups()]
                in_window &= all(first <= t.time() <= last if first <= last else
                                 t.time() >= first or t.time() <= last for t in times)
        except (KeyError, TypeError, ValueError):
            reasons.append(f"{change_id}: faltan fechas válidas de la actividad o del cambio.")
            continue
        if not in_window:
            reasons.append(f"{change_id}: la actividad evaluada está fuera de la ventana autorizada.")
            continue
        hosts = {str(ev.raw[field]).casefold() for ev in events
                 for field in ("hostname", "host", "client_host") if ev.raw.get(field)}
        assets = [a for a in context.assets if str(a.get("hostname", "")).casefold() in hosts]
        scope = str(change.get("alcance", ""))
        if scope.casefold() == "todos los puestos":
            scope_ok = bool(hosts) and len(assets) == len(hosts) and all(
                a.get("business_service") == "Puesto de trabajo" for a in assets)
        elif scope.casefold() == "servidores windows":
            scope_ok = bool(assets) and all("windows server" in a.get("os", "").casefold() for a in assets)
        elif scope.casefold() == "todas las redes salvo ot":
            scope_ok = bool(assets) and all(a.get("zone") and a["zone"] != "LOGISTICS-OT" for a in assets)
        else:
            scope_ok = bool(hosts) and all(ContextEnricher._scope_matches(scope, [host]) for host in hosts)
            if not scope_ok and scope.casefold() == "correo":
                scope_ok = all(ev.source in {"email", "dlp"} for ev in events)
        if not scope_ok:
            reasons.append(f"{change_id}: alcance de la actividad sin comprobar.")
            continue
        accounts = re.findall(r"\b(?:svc_[\w.-]+|ext\.[\w.-]+)\b", detail, re.I)
        if accounts:
            users = {str(ev.raw.get("user", ev.raw.get("user_upn", ""))).casefold()
                     .rsplit("\\", 1)[-1].removesuffix("@tarvia.example") for ev in events}
            if not users or not users <= {a.casefold() for a in accounts}:
                reasons.append(f"{change_id}: ventana y alcance compatibles; falta vincular la cuenta ejecutora al mecanismo autorizado.")
                continue
        origin = re.search(r"\b(?:IPs? origen|origen|desde)\s+(\d{1,3}(?:\.\d{1,3}){3})(?:-(\d{1,3}))?\b", detail, re.I)
        if origin:
            try:
                first = ip_address(origin[1])
                last = ip_address(origin[1].rsplit(".", 1)[0] + "." + origin[2]) if origin[2] else first
                sources = [ip_address(ev.raw["src_ip"]) for ev in events]
                if last < first or not all(first <= ip <= last for ip in sources):
                    continue
            except (KeyError, TypeError, ValueError):
                continue
        return True, f"Cambio {change_id}: actividad vinculada, ventana local, alcance y condiciones explícitas comprobados; revisar condiciones en texto libre."
    return False, " ".join(dict.fromkeys(reasons)) or "No se ha vinculado la actividad a un cambio autorizado verificable."
