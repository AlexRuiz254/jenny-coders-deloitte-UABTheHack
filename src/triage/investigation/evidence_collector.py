"""Recoge eventos referenciados y consultas adicionales a 18 fuentes de logs."""
from tarvia_soc.models import Evidence, RawAlert, SearchPlan
from tarvia_soc.data.soc_api_client import SOCAPIClient

class EvidenceCollector:
    def __init__(self, api: SOCAPIClient) -> None:
        raise NotImplementedError

    def collect_related_events(self, alert: RawAlert) -> list[Evidence]:
        """Resolver prefijos EDR/EML/CT/... y comprobar event_id exacto."""
        raise NotImplementedError

    def search(self, plan: SearchPlan) -> list[Evidence]:
        """Ejecutar búsquedas, deduplicar, controlar límites y truncamientos."""
        raise NotImplementedError
