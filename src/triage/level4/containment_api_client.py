"""Cliente HTTP para interactuar con la API SOC simulada en Fase 4 (N4).

Encapsula exclusivamente las peticiones HTTP relativas a contención y consulta
de auditoría, gestionando códigos de estado, timeouts y respuestas de la API.
"""
from __future__ import annotations

import logging
from typing import Any, Optional
from urllib.parse import quote

import requests

logger = logging.getLogger(__name__)


class ContainmentAPIError(Exception):
    """Excepción base para errores de comunicación con la API de contención."""
    pass


class ContainmentConnectionError(ContainmentAPIError):
    """Fallo de conexión o red con la API SOC."""
    pass


class ContainmentTimeoutError(ContainmentAPIError, TimeoutError):
    """Timeout durante la ejecución de la petición de contención."""
    pass


class ContainmentHTTPError(ContainmentAPIError):
    """Respuesta con código de error HTTP (4xx o 5xx) de la API SOC."""

    def __init__(
        self,
        message: str,
        status_code: int,
        detail: str = "",
        response_data: Optional[dict[str, Any]] = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.detail = detail
        self.response_data = response_data or {}


class ContainmentResponseError(ContainmentAPIError):
    """Respuesta inesperada o malformada de la API SOC."""
    pass


def _extract_field(obj: Any, name: str, default: Any = None) -> Any:
    """Extraer un atributo o clave con soporte para dicts y modelos."""
    if obj is None:
        return default
    if isinstance(obj, dict):
        return obj.get(name, default)
    return getattr(obj, name, default)


class ContainmentAPIClient:
    """Cliente HTTP dedicado a los endpoints de contención de la API SOC."""

    def __init__(
        self,
        base_url: str = "http://localhost:8000",
        timeout: float = 30.0,
        session: Optional[requests.Session] = None,
    ) -> None:
        """Inicializar cliente HTTP con URL base y timeout configurables."""
        if timeout <= 0:
            raise ValueError("timeout debe ser un valor mayor que 0")

        self.base_url = str(base_url).rstrip("/")
        self.timeout = float(timeout)
        self.session = session or requests.Session()

    def execute_action(
        self,
        proposal: Any,
        approval: Any = None,
    ) -> dict[str, Any]:
        """Enviar la petición de contención a la API SOC simulada.

        Parámetros:
        * proposal: propuesta de contención (ContainmentProposal o dict).
        * approval: autorización humana (ApprovalResult o dict).

        Devuelve:
        * dict con la respuesta estructurada de la API (200 OK).

        Lanza:
        * ContainmentTimeoutError: si se supera el timeout.
        * ContainmentConnectionError: si no se puede conectar.
        * ContainmentHTTPError: si la API devuelve un código de error (400, 403, 500...).
        * ContainmentResponseError: si la respuesta no tiene formato JSON válido.
        * ValueError: si la autorización no corresponde a la propuesta.
        """
        if proposal is None:
            raise ValueError("proposal es obligatoria y no puede ser None")

        action = _extract_field(proposal, "action")
        target = _extract_field(proposal, "target")
        justification = _extract_field(proposal, "justification", "") or ""
        ticket_id = _extract_field(proposal, "ticket_id", "") or ""
        proposal_id = _extract_field(proposal, "proposal_id")

        if not action or not str(action).strip():
            raise ValueError("La propuesta debe incluir una acción ('action') válida")
        if not target or not str(target).strip():
            raise ValueError("La propuesta debe incluir un objetivo ('target') válido")

        action_str = str(action).strip()
        target_str = str(target).strip()

        # Extraer token de aprobación y verificar correspondencia
        approval_token = ""
        if approval is not None:
            app_prop_id = _extract_field(approval, "proposal_id")
            if proposal_id and app_prop_id and str(proposal_id) != str(app_prop_id):
                raise ValueError(
                    f"La autorización corresponde a la propuesta '{app_prop_id}', "
                    f"no a '{proposal_id}'"
                )

            app_action = _extract_field(approval, "action")
            if app_action and str(app_action).strip().lower() != action_str.lower():
                raise ValueError(
                    f"La acción de la autorización ('{app_action}') no coincide "
                    f"con la propuesta ('{action_str}')"
                )

            app_target = _extract_field(approval, "target")
            if app_target and str(app_target).strip().lower() != target_str.lower():
                raise ValueError(
                    f"El objetivo de la autorización ('{app_target}') no coincide "
                    f"con la propuesta ('{target_str}')"
                )

            approval_token = str(_extract_field(approval, "approval_token", "") or "").strip()

        # Construir cuerpo de la petición acorde a Action en mock_soc_api.py
        payload = {
            "target": target_str,
            "justification": str(justification),
            "approval_token": approval_token,
            "ticket_id": str(ticket_id),
        }

        url = f"{self.base_url}/containment/{quote(action_str, safe='')}"

        try:
            response = self.session.post(url, json=payload, timeout=self.timeout)
        except requests.exceptions.Timeout as exc:
            raise ContainmentTimeoutError(
                f"Timeout al ejecutar acción de contención '{action_str}' sobre '{target_str}'"
            ) from exc
        except requests.exceptions.ConnectionError as exc:
            raise ContainmentConnectionError(
                f"No se pudo conectar con la API SOC en {self.base_url}: {exc}"
            ) from exc
        except requests.exceptions.RequestException as exc:
            raise ContainmentConnectionError(
                f"Fallo de comunicación HTTP al consultar {url}: {exc}"
            ) from exc

        # Gestionar errores HTTP
        if response.status_code != 200:
            detail = ""
            error_data: dict[str, Any] = {}
            try:
                error_data = response.json()
                detail = error_data.get("detail", response.text)
            except Exception:
                detail = response.text or f"Código de estado {response.status_code}"

            raise ContainmentHTTPError(
                f"Error HTTP {response.status_code} al ejecutar '{action_str}': {detail}",
                status_code=response.status_code,
                detail=str(detail),
                response_data=error_data,
            )

        # Interpretar respuesta 200 OK
        try:
            data = response.json()
        except Exception as exc:
            raise ContainmentResponseError(
                f"La API devolvió una respuesta con JSON no interpretable: {response.text[:200]}"
            ) from exc

        if not isinstance(data, dict):
            raise ContainmentResponseError(
                f"La API devolvió un tipo de datos inesperado ({type(data).__name__}), se esperaba dict"
            )

        return data

    def get_containment_log(self) -> list[dict[str, Any]]:
        """Consultar el registro de operaciones de contención de la API SOC."""
        url = f"{self.base_url}/containment/log"

        try:
            response = self.session.get(url, timeout=self.timeout)
        except requests.exceptions.Timeout as exc:
            raise ContainmentTimeoutError(
                f"Timeout al consultar el registro de contenciones en {url}"
            ) from exc
        except requests.exceptions.ConnectionError as exc:
            raise ContainmentConnectionError(
                f"No se pudo conectar con la API SOC en {self.base_url}: {exc}"
            ) from exc
        except requests.exceptions.RequestException as exc:
            raise ContainmentConnectionError(
                f"Fallo de comunicación HTTP al consultar {url}: {exc}"
            ) from exc

        if response.status_code != 200:
            raise ContainmentHTTPError(
                f"Error HTTP {response.status_code} al obtener log de contención: {response.text}",
                status_code=response.status_code,
                detail=response.text,
            )

        try:
            data = response.json()
        except Exception as exc:
            raise ContainmentResponseError(
                f"La API devolvió un log con JSON no interpretable: {response.text[:200]}"
            ) from exc

        if not isinstance(data, list):
            raise ContainmentResponseError(
                f"Se esperaba una lista de registros, pero la API devolvió {type(data).__name__}"
            )

        return data

    def close(self) -> None:
        """Cerrar la sesión HTTP."""
        self.session.close()
