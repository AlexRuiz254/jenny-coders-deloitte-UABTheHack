"""Correlación básica de N1: otras alertas en ±24 h y entidades compartidas."""
from tarvia_soc.models import RawAlert, EntityKeys
from tarvia_soc.data.soc_api_client import SOCAPIClient

class AlertCorrelator:
    def __init__(self, api: SOCAPIClient) -> None:
        raise NotImplementedError

    def find_related(self, alert: RawAlert, entities: EntityKeys,
                     window_hours: int = 24) -> list[RawAlert]:
        """Paginar alertas; no agrupar únicamente por compartir IP."""
        raise NotImplementedError
