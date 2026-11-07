"""Acceso a contexto que la API no expone directamente como endpoint."""
from pathlib import Path
from typing import Any

class ReferenceRepository:
    def __init__(self, dataset_root: Path) -> None:
        """Ruta a 01_contexto y 02_inventario del ZIP original."""
        raise NotImplementedError

    def get_policy(self) -> str:
        """Leer politica_soc.md."""
        raise NotImplementedError

    def get_company_context(self) -> str:
        """Leer empresa_tarvia.md."""
        raise NotImplementedError

    def get_rule(self, rule_id: str) -> dict[str, str] | None:
        """Consultar catálogo y comprobar consistencia de rule_id/runbook."""
        raise NotImplementedError

    def get_business_service(self, service: str) -> dict[str, Any] | None:
        """Buscar en servicios_negocio.csv."""
        raise NotImplementedError

    def get_network_zone(self, ip: str) -> dict[str, Any] | None:
        """Buscar CIDR en zonas_red.csv."""
        raise NotImplementedError

    def get_store(self, ip: str) -> dict[str, Any] | None:
        """Buscar CIDR de tiendas monitorizadas en tiendas.csv."""
        raise NotImplementedError
