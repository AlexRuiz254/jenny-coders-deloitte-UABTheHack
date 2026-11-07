"""Cliente HTTP de los endpoints GET realmente existentes en mock_soc_api.py."""
from typing import Any
from tarvia_soc.models import LogSource, RawAlert

class SOCAPIClient:
    def __init__(self, base_url: str = "http://localhost:8000") -> None:
        """Preparar la sesión HTTP; no importar mock_soc_api.py."""
        raise NotImplementedError

    def list_alerts(self, *, status: str = "new", limit: int = 50,
                    offset: int = 0, desde: str = "", hasta: str = "",
                    rule_id: str = "") -> dict[str, Any]:
        """GET /alerts; gestionar paginación fuera o dentro del servicio que lo use."""
        raise NotImplementedError

    def get_alert(self, alert_id: str) -> RawAlert:
        """GET /alerts/{alert_id}."""
        raise NotImplementedError

    def get_asset(self, key: str) -> dict[str, Any] | None:
        """GET /assets/{key}; un 404 significa activo desconocido."""
        raise NotImplementedError

    def get_user(self, key: str) -> dict[str, Any] | None:
        """GET /users/{key}; incluye eventos RRHH."""
        raise NotImplementedError

    def search_logs(self, source: LogSource, *, q: str = "",
                    desde: str = "", hasta: str = "",
                    limit: int = 200) -> dict[str, Any]:
        """GET /logs/{source}; preservar count/truncated/items."""
        raise NotImplementedError

    def get_intel(self, indicator: str) -> dict[str, Any]:
        """GET /intel/{indicator}; TIP y GeoIP."""
        raise NotImplementedError

    def get_sandbox(self, sha256: str) -> dict[str, Any] | None:
        """GET /sandbox/{sha256}; 404 no significa benigno."""
        raise NotImplementedError

    def get_changes(self, q: str = "") -> list[dict[str, Any]]:
        """GET /changes?q=...; no basta una coincidencia textual para autorizar."""
        raise NotImplementedError
