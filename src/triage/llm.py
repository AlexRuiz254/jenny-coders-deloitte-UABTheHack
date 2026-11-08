"""Cliente HTTP para conectar con la API de Ornith y validar salidas con Pydantic."""
from __future__ import annotations

import json
import math
import os
import re
import time
from pathlib import Path
from typing import Any, TypeVar

import requests
from pydantic import BaseModel, ValidationError

StructuredT = TypeVar("StructuredT", bound=BaseModel)

DEFAULT_ORNITH_API_URL = "https://api.ornith.cc/v1"
DEFAULT_ORNITH_MODEL = "uncensored"
DEFAULT_TIMEOUT_SECONDS = 120.0
DEFAULT_MAX_RETRIES = 2
DEFAULT_RETRY_DELAY_SECONDS = 0.5


class LLMClient:
    """Cliente reutilizable para generar texto y JSON estructurado con la API de Ornith."""

    def __init__(
        self,
        model: str = DEFAULT_ORNITH_MODEL,
        api_key: str | None = None,
    ) -> None:
        if not isinstance(model, str) or not model.strip():
            raise ValueError("El nombre del modelo no puede estar vacío.")

        # Las credenciales solo se reciben por configuración, nunca en el código.
        resolved_api_key = (
            api_key if api_key is not None else os.getenv("ORNITH_API_KEY")
        )
        if not resolved_api_key or not resolved_api_key.strip():
            raise ValueError(
                "No se ha configurado la API key de Ornith. "
                "Proporciona api_key al constructor o define la variable de entorno ORNITH_API_KEY."
            )

        self.model: str = model.strip()
        self.base_url: str = (
            os.getenv("ORNITH_API_URL") or DEFAULT_ORNITH_API_URL
        ).strip().rstrip("/")
        self.timeout = float(os.getenv("ORNITH_TIMEOUT_SECONDS") or DEFAULT_TIMEOUT_SECONDS)
        if not math.isfinite(self.timeout) or self.timeout <= 0:
            raise ValueError("ORNITH_TIMEOUT_SECONDS debe ser un número positivo y finito.")
        self.reasoning_effort = (os.getenv("ORNITH_REASONING_EFFORT") or "").strip()
        if self.reasoning_effort and self.reasoning_effort not in {"none", "low", "medium", "high"}:
            raise ValueError("ORNITH_REASONING_EFFORT debe ser none, low, medium o high.")
        self.max_retries: int = DEFAULT_MAX_RETRIES
        self.retry_delay: float = DEFAULT_RETRY_DELAY_SECONDS

        self.session: requests.Session = requests.Session()
        self.session.headers.update(
            {
                "Authorization": f"Bearer {resolved_api_key.strip()}",
                "Content-Type": "application/json",
            }
        )

    def generate_text(
        self,
        *,
        system_prompt: str | Path,
        prompt: str,
    ) -> str:
        """Envía una consulta de texto leyendo system_prompt desde un archivo y devuelve el contenido generado."""
        system_content = self._load_system_prompt(system_prompt)
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": [
                {
                    "role": "system",
                    "content": system_content,
                },
                {
                    "role": "user",
                    "content": prompt,
                },
            ],
        }
        return self._request_completion(payload)

    def generate_json(
        self,
        *,
        system_prompt: str | Path,
        prompt: str,
        schema: type[StructuredT],
    ) -> StructuredT:
        """Genera una respuesta JSON estructurada leyendo system_prompt desde un archivo y validando con Pydantic."""
        if not isinstance(schema, type) or not issubclass(schema, BaseModel):
            raise TypeError("El parámetro 'schema' debe ser una subclase de pydantic.BaseModel.")

        system_content = self._load_system_prompt(system_prompt)
        json_schema = schema.model_json_schema()
        base_system_instructions = self._build_json_system_prompt(
            system_prompt=system_content,
            json_schema=json_schema,
        )

        last_error: Exception | None = None
        feedback_prompt = prompt

        for attempt in range(2):
            payload: dict[str, Any] = {
                "model": self.model,
                "messages": [
                    {
                        "role": "system",
                        "content": base_system_instructions,
                    },
                    {
                        "role": "user",
                        "content": feedback_prompt,
                    },
                ],
                "response_format": {
                    "type": "json_object",
                },
            }

            raw_content = self._request_completion(payload)
            cleaned_content = self._clean_json_text(raw_content)

            try:
                parsed_json = json.loads(cleaned_content)
                if not isinstance(parsed_json, dict):
                    raise ValueError(
                        f"Se esperaba un objeto JSON (dict), pero se recibió {type(parsed_json).__name__}."
                    )
                result = schema.model_validate(parsed_json)
                return result
            except json.JSONDecodeError as exc:
                last_error = exc
                error_details = (
                    f"El contenido devuelto no es un JSON válido (error de sintaxis en línea {exc.lineno}, "
                    f"columna {exc.colno}: {exc.msg})."
                )
            except ValidationError as exc:
                last_error = exc
                error_details = self._format_validation_error(exc)
            except ValueError as exc:
                last_error = exc
                error_details = str(exc)

            if attempt == 0:
                feedback_prompt = (
                    f"{prompt}\n\n"
                    "CORRECCIÓN REQUERIDA EN SEGUNDO INTENTO:\n"
                    "Tu respuesta anterior no cumplió con el esquema JSON obligatorio.\n"
                    f"Detalle de los errores detectados: {error_details}\n"
                    "Devuelve exclusivamente un objeto JSON válido que corrija todos los campos "
                    "y tipos indicados, sin texto adicional ni bloques Markdown."
                )

        raise ValueError(
            f"La respuesta del modelo no cumple el esquema Pydantic '{schema.__name__}' "
            f"tras 2 intentos. Último error: {last_error}"
        ) from last_error

    @staticmethod
    def _clean_json_text(raw_content: str) -> str:
        """Elimina bloques <think>...</think> o cercas Markdown externas si el gateway los incluye."""
        cleaned = re.sub(
            r"^\s*<think>.*?</think>\s*",
            "",
            raw_content,
            flags=re.DOTALL | re.IGNORECASE,
        ).strip()
        fenced = re.match(
            r"^```(?:json)?\s*(.*?)\s*```$",
            cleaned,
            flags=re.DOTALL | re.IGNORECASE,
        )
        if fenced:
            return fenced.group(1).strip()
        return cleaned

    @staticmethod
    def _load_system_prompt(system_prompt: str | Path) -> str:
        """Lee y valida el contenido del archivo de system_prompt."""
        path = Path(system_prompt)
        if not path.is_file():
            raise FileNotFoundError(
                f"No se encontró el archivo de system_prompt en la ruta: {path}"
            )
        content = path.read_text(encoding="utf-8").strip()
        if not content:
            raise ValueError(
                f"El archivo de system_prompt está vacío: {path}"
            )
        return content

    @staticmethod
    def _build_json_system_prompt(
        *,
        system_prompt: str,
        json_schema: dict[str, Any],
    ) -> str:
        """Construye las instrucciones del sistema incorporando el JSON Schema requerido."""
        schema_str = json.dumps(json_schema, ensure_ascii=False, indent=2)
        instructions = (
            f"{system_prompt.strip()}\n\n"
            "INSTRUCCIONES DE FORMATO JSON ESTRICTO:\n"
            "- Debes devolver exclusivamente un objeto JSON válido.\n"
            "- Debes incluir todos los campos obligatorios definidos en el esquema.\n"
            "- Debes respetar estrictamente los tipos de datos y restricciones de cada campo.\n"
            "- No añadas explicaciones, comentarios ni texto fuera del objeto JSON.\n"
            "- No utilices bloques Markdown ni etiquetas de código (como ```json).\n"
            "- No inventes valores que no estén respaldados por la información proporcionada.\n\n"
            "ESQUEMA JSON REQUERIDO:\n"
            f"{schema_str}"
        )
        return instructions

    @staticmethod
    def _format_validation_error(exc: ValidationError) -> str:
        """Resume qué campos y tipos han fallado en la validación Pydantic."""
        issues: list[str] = []
        for err in exc.errors():
            loc = ".".join(str(part) for part in err.get("loc", ())) or "<raíz>"
            msg = err.get("msg", "valor inválido")
            err_type = err.get("type", "unknown")
            issues.append(f"campo '{loc}' ({err_type}): {msg}")
        return "; ".join(issues)

    def _request_completion(self, payload: dict[str, Any]) -> str:
        """Ejecuta la llamada POST /chat/completions contra Ornith y extrae choices[0].message.content."""
        url = f"{self.base_url}/chat/completions"
        if self.reasoning_effort:
            payload = {**payload, "reasoning_effort": self.reasoning_effort}

        for attempt in range(self.max_retries + 1):
            try:
                response = self.session.post(
                    url,
                    json=payload,
                    timeout=self.timeout,
                )
            except requests.exceptions.Timeout as exc:
                raise TimeoutError(
                    "Tiempo de espera agotado (timeout) al comunicarse con la API de Ornith."
                ) from exc
            except requests.exceptions.ConnectionError as exc:
                raise ConnectionError(
                    f"No se pudo conectar con la API de Ornith en {self.base_url}."
                ) from exc
            except requests.exceptions.RequestException as exc:
                raise RuntimeError(
                    "Error de red al realizar la petición a la API de Ornith."
                ) from exc

            status_code = getattr(response, "status_code", 200)
            if isinstance(status_code, int) and status_code in (429, 503):
                if attempt < self.max_retries:
                    if self.retry_delay > 0:
                        time.sleep(self.retry_delay)
                    continue

            self._check_http_status(response)

            try:
                data = response.json()
            except (ValueError, json.JSONDecodeError) as exc:
                raise ValueError(
                    "La respuesta HTTP de Ornith no contiene un cuerpo JSON válido."
                ) from exc

            return self._extract_message_content(data)

        raise RuntimeError("Se agotaron los reintentos al consultar la API de Ornith.")

    @staticmethod
    def _check_http_status(response: requests.Response) -> None:
        """Valida el código de estado HTTP y lanza errores descriptivos sin exponer credenciales."""
        status_code = getattr(response, "status_code", None)

        if isinstance(status_code, int):
            if status_code == 400:
                raise RuntimeError(
                    "Error HTTP 400 en Ornith: petición o parámetros incorrectos."
                )
            if status_code == 401:
                raise RuntimeError(
                    "Error HTTP 401 en Ornith: API key inexistente o incorrecta."
                )
            if status_code == 402:
                raise RuntimeError(
                    "Error HTTP 402 en Ornith: saldo insuficiente en la cuenta."
                )
            if status_code == 404:
                raise RuntimeError(
                    "Error HTTP 404 en el servidor de IA: revisa ORNITH_API_URL y ORNITH_MODEL. "
                    "El modelo debe coincidir con uno de los identificadores de GET /models."
                )
            if status_code == 429:
                raise RuntimeError(
                    "Error HTTP 429 en Ornith: límite de peticiones o concurrencia excedido."
                )
            if status_code == 503:
                raise RuntimeError(
                    "Error HTTP 503 en Ornith: modelo temporalmente no disponible."
                )
            if status_code >= 400:
                raise RuntimeError(
                    f"Error HTTP {status_code} al consultar la API de Ornith."
                )

        try:
            response.raise_for_status()
        except requests.exceptions.HTTPError as exc:
            code = getattr(exc.response, "status_code", "desconocido")
            raise RuntimeError(
                f"Error HTTP {code} al consultar la API de Ornith."
            ) from exc

    @staticmethod
    def _extract_message_content(data: Any) -> str:
        """Extrae y valida choices[0].message.content de la respuesta de Ornith."""
        if not isinstance(data, dict):
            raise ValueError("Respuesta mal formada de Ornith: el cuerpo raíz no es un objeto JSON.")

        choices = data.get("choices")
        if not isinstance(choices, list) or not choices:
            raise ValueError("Respuesta mal formada de Ornith: falta la lista 'choices' o está vacía.")

        first_choice = choices[0]
        if not isinstance(first_choice, dict):
            raise ValueError("Respuesta mal formada de Ornith: 'choices[0]' no es un objeto.")

        message = first_choice.get("message")
        if not isinstance(message, dict):
            raise ValueError("Respuesta mal formada de Ornith: falta el objeto 'message' en 'choices[0]'.")

        content = message.get("content")
        if not isinstance(content, str) or not content.strip():
            raise ValueError("Respuesta vacía de Ornith: 'choices[0].message.content' está vacío o ausente.")

        return content
