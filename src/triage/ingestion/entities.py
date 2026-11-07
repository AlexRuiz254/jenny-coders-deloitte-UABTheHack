"""Dos helpers de extracción; no se necesita AlertNormalizer para el dataset."""
from tarvia_soc.models import RawAlert, EntityKeys

def extract_entities(alert: RawAlert) -> EntityKeys:
    """Leer las distintas formas de entities: listas, cloud y ai_session."""
    raise NotImplementedError

def extract_indicators(alert: RawAlert) -> list[str]:
    """Seleccionar IP públicas, dominios, URL y hashes de alerta/evidencias."""
    raise NotImplementedError
