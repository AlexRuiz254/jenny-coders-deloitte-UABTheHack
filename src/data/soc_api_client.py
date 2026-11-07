from typing import Any
from urllib.parse import quote

import requests
from tarvia_soc.models import LogSource, RawAlert


class SOCAPIClient:

    def __init__(
        self,
        base_url: str = "http://localhost:8000",
        timeout: float = 30
    ) -> None:
        """Preparar sesión HTTP sin importar mock_soc_api.py."""

        if timeout <= 0:
            raise ValueError("timeout debe ser mayor que 0")

        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.session = requests.Session()

    def _get(
        self,
        endpoint: str,
        params: dict | None = None,
        allow_404: bool = False
    ) -> Any:
        """Realizar una petición GET y devolver su JSON."""

        try:
            response = self.session.get(
                f"{self.base_url}{endpoint}",
                params=params,
                timeout=self.timeout
            )

            if allow_404 and response.status_code == 404:
                return None

            response.raise_for_status()
            return response.json()

        except requests.exceptions.Timeout as exc:
            raise ConnectionError(
                f"Timeout al consultar {endpoint}"
            ) from exc

        except requests.exceptions.ConnectionError as exc:
            raise ConnectionError(
                f"No se pudo conectar con la API SOC: {self.base_url}"
            ) from exc

        except requests.exceptions.HTTPError as exc:
            raise RuntimeError(
                f"Error HTTP al consultar {endpoint}: "
                f"{exc.response.status_code}"
            ) from exc

    @staticmethod
    def _encode(value: str) -> str:
        """Codificar parámetros de ruta."""
        return quote(str(value), safe="")

    def list_alerts(
        self, *, status: str = "new", limit: int = 50,
        offset: int = 0, desde: str = "", hasta: str = "",
        rule_id: str = ""
    ) -> dict[str, Any]:
        """GET /alerts."""

        if not 1 <= limit <= 500:
            raise ValueError("limit debe estar entre 1 y 500")

        if offset < 0:
            raise ValueError("offset no puede ser negativo")

        return self._get("/alerts", {
            "status": status,
            "limit": limit,
            "offset": offset,
            "desde": desde,
            "hasta": hasta,
            "rule_id": rule_id
        })

    def get_alert(self, alert_id: str) -> RawAlert:
        """GET /alerts/{alert_id}."""

        return self._get(
            f"/alerts/{self._encode(alert_id)}"
        )

    def get_asset(self, key: str) -> dict[str, Any] | None:
        """GET /assets/{key}; 404 devuelve None."""

        return self._get(
            f"/assets/{self._encode(key)}",
            allow_404=True
        )

    def get_user(self, key: str) -> dict[str, Any] | None:
        """GET /users/{key}; 404 devuelve None."""

        return self._get(
            f"/users/{self._encode(key)}",
            allow_404=True
        )

    def search_logs(
        self, source: LogSource, *,
        q: str = "", desde: str = "",
        hasta: str = "", limit: int = 200
    ) -> dict[str, Any]:
        """GET /logs/{source}; conserva count/truncated/items."""

        if not 1 <= limit <= 2000:
            raise ValueError("limit debe estar entre 1 y 2000")

        return self._get(
            f"/logs/{self._encode(source)}",
            {
                "q": q,
                "desde": desde,
                "hasta": hasta,
                "limit": limit
            }
        )

    def get_intel(self, indicator: str) -> dict[str, Any]:
        """GET /intel/{indicator}."""

        return self._get(
            f"/intel/{self._encode(indicator)}"
        )

    def get_sandbox(self, sha256: str) -> dict[str, Any] | None:
        """GET /sandbox/{sha256}; 404 devuelve None."""

        return self._get(
            f"/sandbox/{self._encode(sha256)}",
            allow_404=True
        )

    def get_changes(self, q: str = "") -> list[dict[str, Any]]:
        """GET /changes?q=..."""

        return self._get(
            "/changes",
            {"q": q}
        )

    def close(self) -> None:
        """Cerrar conexiones HTTP."""
        self.session.close()
