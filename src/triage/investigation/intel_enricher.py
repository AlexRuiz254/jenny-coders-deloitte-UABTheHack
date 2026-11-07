"""Inteligencia interna TIP, GeoIP y sandbox; OSINT externa opcional para futuro."""
from tarvia_soc.models import IntelEntry
from tarvia_soc.data.soc_api_client import SOCAPIClient

class IntelEnricher:
    def __init__(self, api: SOCAPIClient) -> None:
        raise NotImplementedError

    def enrich(self, indicators: list[str]) -> list[IntelEntry]:
        """Consultar indicadores disponibles; ausencia de IOC != benigno."""
        raise NotImplementedError
