"""Recoge eventos referenciados y consultas adicionales a 18 fuentes de logs."""
import json

from src.triage.models import Evidence, RawAlert, SearchPlan
from src.data.soc_api_client import SOCAPIClient
from src.triage.time_windows import alert_window, api_time

class EvidenceCollector:
    SOURCES = {
        "PRX": "proxy", "DNS": "dns", "EDR": "edr_events",
        "SIGN": "idp_signins", "WAF": "waf", "EML": "email",
        "ECA": "ecom_auth", "FW": "firewall", "CLK": "email_clicks",
        "VPN": "vpn", "AIG": "ai_gateway", "ECO": "ecom_account",
        "CT": "cloudtrail", "SQL": "sql_audit", "DLP": "dlp",
        "AUD": "idp_audit", "CI": "cicd_builds", "ADE": "ad_events",
    }

    def __init__(self, api: SOCAPIClient) -> None:
        self.api = api

    @staticmethod
    def _event(source: str, row: dict) -> Evidence:
        return Evidence(
            source=source,
            event_id=row.get("event_id"),
            timestamp=row.get("timestamp") or row.get("eventTime"),
            raw=row
        )

    def collect_related_events(self, alert: RawAlert) -> list[Evidence]:
        """Resolver prefijos EDR/EML/CT/... y comprobar event_id exacto."""
        evidence = []
        seen = set()
        start, end = alert_window(alert)
        for event_id in alert.get("related_events", []):
            source = self.SOURCES.get(event_id.split("-", 1)[0].upper())
            if source is None or (source, event_id) in seen:
                continue
            seen.add((source, event_id))
            result = self.api.search_logs(source, q=event_id, desde=api_time(start),
                                          hasta=api_time(end), limit=2000)
            for row in result.get("items", []):
                # La API busca subcadenas: nunca aceptar un ID solo parecido.
                if row.get("event_id") == event_id:
                    evidence.append(self._event(source, row))
                    break
            if result.get("truncated"):
                evidence.append(Evidence(source=source, raw={
                    "q": event_id, "count": result.get("count"),
                    "truncated": result["truncated"]
                }))
        return evidence

    def search(self, plan: SearchPlan) -> list[Evidence]:
        """Ejecutar búsquedas, deduplicar, controlar límites y truncamientos."""
        evidence = []
        seen_events = set()
        seen_queries = set()
        for query in plan.searches:
            key = (query.source, query.query, query.start, query.end)
            if key in seen_queries:
                continue
            seen_queries.add(key)
            result = self.api.search_logs(
                query.source, q=query.query,
                desde=query.start or "", hasta=query.end or "", limit=2000
            )
            for row in result.get("items", []):
                identity = row.get("event_id") or json.dumps(
                    row, sort_keys=True, ensure_ascii=False
                )
                event_key = (query.source, identity)
                if event_key not in seen_events:
                    seen_events.add(event_key)
                    evidence.append(self._event(query.source, row))
            # Evidence no tiene campos count/truncated. Conservarlos en raw
            # como resumen de consulta, sin asignarle un event_id ficticio.
            metadata = {field: result[field] for field in ("count", "truncated") if field in result}
            if metadata:
                evidence.append(Evidence(source=query.source, raw={
                    "q": query.query, "desde": query.start or "",
                    "hasta": query.end or "", **metadata
                }))
        return evidence
