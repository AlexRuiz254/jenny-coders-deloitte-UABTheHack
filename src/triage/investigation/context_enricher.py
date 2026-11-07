"""Contexto de activo/usuario/cambios y criticidad de negocio."""
from tarvia_soc.models import RawAlert, EntityKeys, ContextSnapshot
from tarvia_soc.data.soc_api_client import SOCAPIClient
from tarvia_soc.data.reference_repository import ReferenceRepository

class ContextEnricher:
    def __init__(self, api: SOCAPIClient, references: ReferenceRepository) -> None:
        raise NotImplementedError

    def enrich(self, alert: RawAlert, entities: EntityKeys) -> ContextSnapshot:
        """Resolver activos/usuarios/vulnerabilidades/servicios/zonas/cambios/RRHH."""
        raise NotImplementedError
