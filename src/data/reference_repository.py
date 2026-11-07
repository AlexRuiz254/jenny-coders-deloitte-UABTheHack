"""Acceso a contexto que la API no expone directamente como endpoint."""
from pathlib import Path
from typing import Any
import csv
from ipaddress import ip_address, ip_network

class ReferenceRepository:
    def __init__(self, dataset_root: Path) -> None:
        """Ruta a 01_contexto y 02_inventario del ZIP original."""
        self.dataset_root = Path(dataset_root)

    def _read_text(self, name: str) -> str:
        try:
            return (self.dataset_root / "01_contexto" / name).read_text(
                encoding="utf-8-sig"
            )
        except FileNotFoundError:
            return ""

    def _read_csv(self, folder: str, name: str) -> list[dict[str, str]]:
        try:
            with (self.dataset_root / folder / name).open(
                encoding="utf-8-sig", newline=""
            ) as stream:
                return list(csv.DictReader(stream))
        except FileNotFoundError:
            return []

    def _find_network(self, ip: str, name: str, column: str) -> dict | None:
        try:
            address = ip_address(ip)
        except ValueError:
            return None
        matches = []
        for row in self._read_csv("02_inventario", name):
            try:
                network = ip_network(row[column], strict=False)
            except (KeyError, ValueError):
                continue
            if address in network:
                matches.append((network.prefixlen, row))
        return max(matches, key=lambda item: item[0])[1] if matches else None

    def get_policy(self) -> str:
        """Leer politica_soc.md."""
        return self._read_text("politica_soc.md")

    def get_company_context(self) -> str:
        """Leer empresa_tarvia.md."""
        return self._read_text("empresa_tarvia.md")

    def get_rule(self, rule_id: str) -> dict[str, str] | None:
        """Consultar catálogo y comprobar consistencia de rule_id/runbook."""
        for row in self._read_csv("01_contexto", "catalogo_casos_de_uso.csv"):
            if row["rule_id"].casefold() != rule_id.strip().casefold():
                continue
            runbook = row.get("runbook", "")
            # No devolver una regla que apunte a un runbook inexistente.
            if not runbook or Path(runbook).name != runbook:
                return None
            path = self.dataset_root / "01_contexto" / "runbooks" / f"{runbook}.md"
            return row if path.is_file() else None
        return None

    def get_business_service(self, service: str) -> dict[str, Any] | None:
        """Buscar en servicios_negocio.csv."""
        key = service.strip().casefold()
        if not key:
            return None
        rows = self._read_csv("02_inventario", "servicios_negocio.csv")
        for row in rows:
            if row["servicio"].casefold() == key:
                return row
        # La CMDB añade una aclaración de facturación al servicio de e-commerce.
        matches = [row for row in rows if key.startswith(row["servicio"].casefold() + " (")]
        return matches[0] if len(matches) == 1 else None

    def get_network_zone(self, ip: str) -> dict[str, Any] | None:
        """Buscar CIDR en zonas_red.csv."""
        return self._find_network(ip, "zonas_red.csv", "cidr")

    def get_store(self, ip: str) -> dict[str, Any] | None:
        """Buscar CIDR de tiendas monitorizadas en tiendas.csv."""
        return self._find_network(ip, "tiendas.csv", "red")
