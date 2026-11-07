"""Contrato para conectar con OpenAI SDK + Pydantic Structured Outputs."""
from typing import TypeVar
from pydantic import BaseModel

StructuredT = TypeVar("StructuredT", bound=BaseModel)

class LLMClient:
    def __init__(self, model: str, api_key: str | None = None) -> None:
        """Crear OpenAI(api_key=...). Leer OPENAI_API_KEY si no se proporciona."""
        raise NotImplementedError

    def generate_text(self, *, system_prompt: str, prompt: str) -> str:
        """Usar el SDK oficial (Responses API) para texto libre."""
        raise NotImplementedError

    def generate_json(self, *, system_prompt: str, prompt: str,
                      schema: type[StructuredT]) -> StructuredT:
        """Usar client.responses.parse(..., text_format=schema) y Pydantic."""
        raise NotImplementedError
