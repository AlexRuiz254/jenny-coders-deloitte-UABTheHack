"""Inteligencia interna TIP, GeoIP y sandbox; OSINT externa opcional para futuro."""
import json
import re
from ipaddress import ip_address
from urllib.parse import urlsplit

from src.triage.models import IntelEntry
from src.data.soc_api_client import SOCAPIClient

class IntelEnricher:
    def __init__(self, api: SOCAPIClient) -> None:
        self.api = api

    def enrich(self, indicators: list[str]) -> list[IntelEntry]:
        """Consultar indicadores disponibles; ausencia de IOC != benigno."""
        entries = []
        seen = set()
        for indicator in indicators:
            value = indicator.strip()
            if not value:
                continue
            try:
                value = str(ip_address(value))
                kind = "ip"
            except ValueError:
                if re.fullmatch(r"[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64}", value):
                    kind = {32: "md5", 40: "sha1", 64: "sha256"}[len(value)]
                    value = value.lower()
                elif "://" in value:
                    parsed = urlsplit(value)
                    if not parsed.netloc:
                        continue
                    kind = "url"
                else:
                    value = value.rstrip(".").lower()
                    if not re.fullmatch(r"[a-z0-9_-]+(?:\.[a-z0-9_-]+)+", value):
                        continue
                    kind = "domain"
            if value in seen:
                continue
            seen.add(value)
            intel = self.api.get_intel(value) or {}
            for field, source in (("tip", "TIP"), ("geo", "GeoIP")):
                record = intel.get(field)
                if record:
                    entries.append(IntelEntry(
                        indicator=value,
                        type=record.get("indicator_type", kind),
                        source=record.get("source") or source,
                        result=json.dumps(record, ensure_ascii=False, sort_keys=True)
                    ))
            if kind == "sha256":
                sandbox = self.api.get_sandbox(value)
                if sandbox:
                    entries.append(IntelEntry(
                        indicator=value, type=kind, source="sandbox",
                        result=json.dumps(sandbox, ensure_ascii=False, sort_keys=True)
                    ))
        return entries
