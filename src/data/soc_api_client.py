import atexit
from pathlib import Path
import socket
import subprocess
import sys
import threading
import time
from typing import Any
from urllib.parse import quote, urlsplit

import requests
from src.triage.models import LogSource, RawAlert

PROJECT_ROOT = Path(__file__).resolve().parents[2]
_LOCAL_API_LOCK = threading.Lock()
_LOCAL_API_STATE: dict[str, Any] = sys.modules.setdefault("_tarvia_local_soc_api", {})


def is_soc_api_healthy(base_url: str, timeout: float = 1.5) -> bool:
    """Comprobar que base_url responde en GET /alerts con el esquema JSON esperado."""
    try:
        resp = requests.get(
            f"{base_url.rstrip('/')}/alerts",
            params={"limit": 1},
            timeout=timeout,
        )
        if resp.status_code != 200:
            return False
        payload = resp.json()
        return (
            isinstance(payload, dict)
            and isinstance(payload.get("items"), list)
            and isinstance(payload.get("total"), int)
        )
    except Exception:
        return False


def _is_port_free(host: str, port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.3)
        return sock.connect_ex((host, port)) != 0


def ensure_local_soc_api(
    raw_url: str = "http://127.0.0.1:8000",
    *,
    avoid_port: int | None = None,
    auto_start: bool = True,
) -> str:
    """Validar y arrancar automáticamente run_server.py cuando la API SOC es local."""
    url = (raw_url or "http://127.0.0.1:8000").strip().rstrip("/")
    parts = urlsplit(url)
    if parts.scheme not in {"http", "https"} or (parts.hostname or "").lower() not in {"127.0.0.1", "localhost", "::1"}:
        return url

    port = parts.port or (443 if parts.scheme == "https" else 80)
    if (avoid_port is not None and port == avoid_port) or 8501 <= port <= 8510:
        port = 8000 if avoid_port != 8000 else 8001

    candidate = f"http://127.0.0.1:{port}"
    if is_soc_api_healthy(candidate):
        return candidate

    cached_url = _LOCAL_API_STATE.get("url")
    if isinstance(cached_url, str) and is_soc_api_healthy(cached_url, timeout=0.8):
        return cached_url

    for fallback_port in (8000, 8001):
        if fallback_port != avoid_port and fallback_port != port:
            fallback_url = f"http://127.0.0.1:{fallback_port}"
            if is_soc_api_healthy(fallback_url, timeout=0.8):
                return fallback_url

    if not auto_start:
        return candidate

    server_script = PROJECT_ROOT / "run_server.py"
    mock_api = PROJECT_ROOT / "RepositoriDeloitte/06_herramientas/mock_soc_api.py"
    if not server_script.is_file() or not mock_api.is_file():
        return candidate

    with _LOCAL_API_LOCK:
        if is_soc_api_healthy(candidate, timeout=0.8):
            return candidate
        spawn_port = port
        if not _is_port_free("127.0.0.1", spawn_port):
            spawn_port = next(
                (p for p in (8000, 8001, 8002, 8003) if p != avoid_port and _is_port_free("127.0.0.1", p)),
                spawn_port,
            )
        spawn_url = f"http://127.0.0.1:{spawn_port}"
        if is_soc_api_healthy(spawn_url, timeout=0.5):
            _LOCAL_API_STATE["url"] = spawn_url
            return spawn_url

        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        proc = subprocess.Popen(
            [sys.executable, str(server_script), "--port", str(spawn_port)],
            cwd=str(PROJECT_ROOT),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=creationflags,
        )
        _LOCAL_API_STATE["process"] = proc
        atexit.register(lambda p=proc: p.terminate() if p.poll() is None else None)

        deadline = time.monotonic() + 12.0
        while time.monotonic() < deadline:
            if is_soc_api_healthy(spawn_url, timeout=1.0):
                _LOCAL_API_STATE["url"] = spawn_url
                return spawn_url
            if proc.poll() is not None:
                break
            time.sleep(0.2)
    return candidate


class SOCAPIClient:

    def __init__(
        self,
        base_url: str = "http://localhost:8000",
        timeout: float = 30,
        store=None,
    ) -> None:
        """Preparar sesión HTTP sin importar mock_soc_api.py."""

        if timeout <= 0:
            raise ValueError("timeout debe ser mayor que 0")

        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.store = store
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

        except ValueError as exc:
            raise ConnectionError(
                f"Respuesta no JSON al consultar {endpoint} en {self.base_url}"
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

        page = self._get("/alerts", {
            "status": status,
            "limit": limit,
            "offset": offset,
            "desde": desde,
            "hasta": hasta,
            "rule_id": rule_id
        })
        if (
            not isinstance(page, dict)
            or not isinstance(page.get("items"), list)
            or not isinstance(page.get("total"), int)
        ):
            raise ConnectionError(
                f"Respuesta de catálogo inválida en {self.base_url}/alerts"
            )
        if self.store is None:
            return page
        local = self.store.list_imported_alerts(status=status, rule_id=rule_id,
                                                 desde=desde, hasta=hasta)
        remote_total = page["total"]
        local_start = max(0, offset - remote_total)
        remaining = limit - len(page["items"])
        return {"total": remote_total + len(local),
                "items": [*page["items"], *local[local_start:local_start + remaining]]}

    def get_alert(self, alert_id: str) -> RawAlert | None:
        """GET /alerts/{alert_id}; 404 devuelve None."""

        local = self.store.get_imported_alert(alert_id) if self.store is not None else None
        if local is not None:
            return local
        return self._get(
            f"/alerts/{self._encode(alert_id)}",
            allow_404=True
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

        result = self._get(
            f"/logs/{self._encode(source)}",
            {
                "q": q,
                "desde": desde,
                "hasta": hasta,
                "limit": limit
            },
            allow_404=True
        )
        return result if result is not None else {
            "count": 0, "truncated": False, "items": []
        }

    def get_intel(self, indicator: str) -> dict[str, Any] | None:
        """GET /intel/{indicator}; 404 devuelve None."""

        return self._get(
            f"/intel/{self._encode(indicator)}",
            allow_404=True
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
