"""Pruebas unitarias para LLMClient utilizando mocks HTTP."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
import requests

import src  # noqa: F401 - Registra el alias tarvia_soc -> src.triage
from src.triage.llm import DEFAULT_ORNITH_API_URL, LLMClient
from src.triage.models import Analysis, LogQuery, SearchPlan


@pytest.mark.parametrize("value", ["0", "-1", "nan", "inf"])
def test_configured_timeout_must_be_positive_and_finite(monkeypatch, value):
    monkeypatch.setenv("ORNITH_TIMEOUT_SECONDS", value)
    with pytest.raises(ValueError, match="ORNITH_TIMEOUT_SECONDS"):
        LLMClient(api_key="test-key")


def test_configured_timeout_is_used(monkeypatch):
    monkeypatch.setenv("ORNITH_TIMEOUT_SECONDS", "90")
    assert LLMClient(api_key="test-key").timeout == 90


@pytest.mark.parametrize("effort", ["", "none"])
def test_reasoning_configuration_is_optional_and_forwarded(monkeypatch, system_prompt_file, effort):
    monkeypatch.setenv("ORNITH_REASONING_EFFORT", effort)
    client = LLMClient(api_key="test-key")
    with patch.object(client.session, "post", return_value=_make_mock_response(content="OK")) as post:
        assert client.generate_text(system_prompt=system_prompt_file, prompt="Prueba") == "OK"
    payload = post.call_args.kwargs["json"]
    if effort:
        assert payload["reasoning_effort"] == effort
    else:
        assert "reasoning_effort" not in payload


def test_invalid_reasoning_configuration_is_rejected(monkeypatch):
    monkeypatch.setenv("ORNITH_REASONING_EFFORT", "invalid")
    with pytest.raises(ValueError, match="ORNITH_REASONING_EFFORT"):
        LLMClient(api_key="test-key")


@pytest.fixture()
def system_prompt_file(tmp_path: Path) -> Path:
    """Crea un archivo temporal con las instrucciones de sistema para las pruebas."""
    prompt_path = tmp_path / "system_prompt.md"
    prompt_path.write_text("Eres un analista SOC N1.", encoding="utf-8")
    return prompt_path


def _make_mock_response(
    content: str | None = "Respuesta de prueba",
    status_code: int = 200,
    raw_json: Any = None,
) -> MagicMock:
    """Construye un objeto Mock que simula requests.Response."""
    response = MagicMock(spec=requests.Response)
    response.status_code = status_code

    if raw_json is not None:
        response.json.return_value = raw_json
    elif content is not None:
        response.json.return_value = {
            "id": "chatcmpl-test",
            "object": "chat.completion",
            "choices": [
                {
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": content,
                    },
                    "finish_reason": "stop",
                }
            ],
        }
    else:
        response.json.return_value = {"choices": [{"message": {"content": ""}}]}

    if status_code >= 400:
        http_err = requests.exceptions.HTTPError(response=response)
        response.raise_for_status.side_effect = http_err
    else:
        response.raise_for_status.return_value = None

    return response


def _valid_analysis_dict() -> dict[str, Any]:
    """Devuelve un diccionario válido según el modelo Pydantic Analysis."""
    return {
        "title": "Ejecución sospechosa de PowerShell en host corporativo",
        "verdict": "true_positive",
        "confidence": 0.92,
        "summary": "Se confirmó ejecución de comando codificado con conexión a C2 externo.",
        "findings": [
            {
                "statement": "Proceso powershell.exe ejecutó payload en base64.",
                "evidence_ids": ["EDR-1001", "PROXY-2002"],
            }
        ],
        "signals": {
            "execution_or_access_confirmed": True,
            "blocked_before_effect": False,
            "privileged_or_vip": False,
            "sensitive_or_payment_data": False,
            "malicious_execution": True,
            "credentials_compromised": False,
            "persistence": True,
            "personal_data_exposure": False,
            "financial_fraud": False,
            "attack_chain": True,
            "authorized_activity": False,
        },
        "proposed_actions": [
            {
                "action": "isolate_host",
                "target": "WKST-042",
                "justification": "Ejecución maliciosa y persistencia confirmadas.",
            }
        ],
        "open_questions": ["¿Se exfiltraron archivos antes del aislamiento?"],
    }


# 1. Inicialización del cliente
def test_client_initialization_with_explicit_api_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ORNITH_API_KEY", raising=False)
    monkeypatch.delenv("ORNITH_API_URL", raising=False)

    client = LLMClient(model="uncensored", api_key="ornith-test-key-123")

    assert client.model == "uncensored"
    assert client.base_url == DEFAULT_ORNITH_API_URL
    assert isinstance(client.session, requests.Session)
    assert client.session.headers["Authorization"] == "Bearer ornith-test-key-123"
    assert client.session.headers["Content-Type"] == "application/json"
    assert client.timeout > 0


# 2. Lectura de API key desde variables de entorno
def test_client_reads_api_key_and_url_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ORNITH_API_KEY", "env-secret-key-999")
    monkeypatch.setenv("ORNITH_API_URL", "https://api.ornith.cc/v1/")

    client = LLMClient(model="uncensored")

    assert client.session.headers["Authorization"] == "Bearer env-secret-key-999"
    assert client.base_url == "https://api.ornith.cc/v1"


def test_client_raises_error_when_api_key_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ORNITH_API_KEY", raising=False)

    with pytest.raises(ValueError, match="ORNITH_API_KEY"):
        LLMClient(model="uncensored")


# 3. Generación correcta de texto leyendo system_prompt desde ruta de archivo
def test_generate_text_success(system_prompt_file: Path) -> None:
    client = LLMClient(model="uncensored", api_key="test-key")
    mock_resp = _make_mock_response(content="Resumen del incidente SOC N1.")

    with patch.object(client.session, "post", return_value=mock_resp) as mock_post:
        result = client.generate_text(
            system_prompt=str(system_prompt_file),
            prompt="Resume la alerta ALT-001.",
        )

    assert isinstance(result, str)
    assert result == "Resumen del incidente SOC N1."
    mock_post.assert_called_once_with(
        "https://api.ornith.cc/v1/chat/completions",
        json={
            "model": "uncensored",
            "messages": [
                {"role": "system", "content": "Eres un analista SOC N1."},
                {"role": "user", "content": "Resume la alerta ALT-001."},
            ],
        },
        timeout=client.timeout,
    )


def test_missing_system_prompt_file_raises_file_not_found(tmp_path: Path) -> None:
    client = LLMClient(model="uncensored", api_key="test-key")
    nonexistent = tmp_path / "no_existe.md"

    with pytest.raises(FileNotFoundError):
        client.generate_text(system_prompt=nonexistent, prompt="Hola")


# 4. Generación correcta de JSON
def test_generate_json_returns_pydantic_instance(system_prompt_file: Path) -> None:
    client = LLMClient(model="uncensored", api_key="test-key")
    payload_dict = {
        "searches": [
            {
                "source": "edr_events",
                "query": "host:WKST-042",
                "reason": "Verificar árbol de procesos en el endpoint afectado.",
                "start": "2026-10-15T08:00:00Z",
                "end": "2026-10-15T10:00:00Z",
            }
        ]
    }
    mock_resp = _make_mock_response(content=json.dumps(payload_dict))

    with patch.object(client.session, "post", return_value=mock_resp):
        result = client.generate_json(
            system_prompt=system_prompt_file,
            prompt="Alerta en WKST-042.",
            schema=SearchPlan,
        )

    assert isinstance(result, SearchPlan)
    assert len(result.searches) == 1
    assert isinstance(result.searches[0], LogQuery)
    assert result.searches[0].source == "edr_events"
    assert result.searches[0].query == "host:WKST-042"


# 5. Comprobación de que se utiliza response_format=json_object
def test_generate_json_uses_json_object_response_format(system_prompt_file: Path) -> None:
    client = LLMClient(model="uncensored", api_key="test-key")
    payload_dict = {"searches": []}
    mock_resp = _make_mock_response(content=json.dumps(payload_dict))

    with patch.object(client.session, "post", return_value=mock_resp) as mock_post:
        client.generate_json(
            system_prompt=system_prompt_file,
            prompt="Usuario",
            schema=SearchPlan,
        )

    sent_payload = mock_post.call_args.kwargs["json"]
    assert "response_format" in sent_payload
    assert sent_payload["response_format"] == {"type": "json_object"}


# 6. Comprobación de que se incluye el JSON Schema Pydantic en las instrucciones
def test_generate_json_includes_pydantic_json_schema_in_instructions(tmp_path: Path) -> None:
    prompt_file = tmp_path / "instrucciones_soc.txt"
    prompt_file.write_text("Instrucción base del SOC.", encoding="utf-8")

    client = LLMClient(model="uncensored", api_key="test-key")
    payload_dict = {"searches": []}
    mock_resp = _make_mock_response(content=json.dumps(payload_dict))

    with patch.object(client.session, "post", return_value=mock_resp) as mock_post:
        client.generate_json(
            system_prompt=prompt_file,
            prompt="Consulta del analista.",
            schema=SearchPlan,
        )

    sent_payload = mock_post.call_args.kwargs["json"]
    system_content = sent_payload["messages"][0]["content"]
    expected_schema = SearchPlan.model_json_schema()

    assert "Instrucción base del SOC." in system_content
    assert "SearchPlan" in system_content
    for prop_name in expected_schema.get("properties", {}):
        assert prop_name in system_content
    assert "Markdown" in system_content


# 7. Validación de todos los campos del modelo recibido
def test_generate_json_validates_all_fields_of_analysis_model(system_prompt_file: Path) -> None:
    client = LLMClient(model="uncensored", api_key="test-key")
    analysis_data = _valid_analysis_dict()
    mock_resp = _make_mock_response(content=json.dumps(analysis_data))

    with patch.object(client.session, "post", return_value=mock_resp):
        analysis = client.generate_json(
            system_prompt=system_prompt_file,
            prompt="Evidencias recopiladas...",
            schema=Analysis,
        )

    assert isinstance(analysis, Analysis)
    assert analysis.title == analysis_data["title"]
    assert analysis.verdict == "true_positive"
    assert analysis.confidence == 0.92
    assert analysis.summary == analysis_data["summary"]
    assert len(analysis.findings) == 1
    assert analysis.findings[0].evidence_ids == ["EDR-1001", "PROXY-2002"]
    assert analysis.signals.malicious_execution is True
    assert analysis.signals.persistence is True
    assert analysis.signals.authorized_activity is False
    assert len(analysis.proposed_actions) == 1
    assert analysis.proposed_actions[0].action == "isolate_host"
    assert analysis.open_questions == ["¿Se exfiltraron archivos antes del aislamiento?"]


# 8. Respuesta JSON mal formada
def test_generate_json_raises_on_malformed_json_after_retry(system_prompt_file: Path) -> None:
    client = LLMClient(model="uncensored", api_key="test-key")
    bad_resp_1 = _make_mock_response(content="{json mal formado sin cerrar")
    bad_resp_2 = _make_mock_response(content="Sigue sin ser un JSON válido")

    with patch.object(client.session, "post", side_effect=[bad_resp_1, bad_resp_2]) as mock_post:
        with pytest.raises(ValueError, match="no cumple el esquema Pydantic"):
            client.generate_json(
                system_prompt=system_prompt_file,
                prompt="Usuario",
                schema=SearchPlan,
            )

    assert mock_post.call_count == 2


# 9. Respuesta con campos obligatorios ausentes
def test_generate_json_raises_when_required_fields_missing_after_retry(system_prompt_file: Path) -> None:
    client = LLMClient(model="uncensored", api_key="test-key")
    incomplete_json = json.dumps({"title": "Solo título, faltan campos obligatorios"})
    resp_1 = _make_mock_response(content=incomplete_json)
    resp_2 = _make_mock_response(content=incomplete_json)

    with patch.object(client.session, "post", side_effect=[resp_1, resp_2]) as mock_post:
        with pytest.raises(ValueError, match="Analysis"):
            client.generate_json(
                system_prompt=system_prompt_file,
                prompt="Analiza la alerta",
                schema=Analysis,
            )

    assert mock_post.call_count == 2


# 10. API key incorrecta (HTTP 401)
def test_invalid_api_key_raises_401_without_leaking_key(system_prompt_file: Path) -> None:
    secret_key = "ornith-super-secret-key-do-not-leak"
    client = LLMClient(model="uncensored", api_key=secret_key)
    resp_401 = _make_mock_response(status_code=401)

    with patch.object(client.session, "post", return_value=resp_401):
        with pytest.raises(RuntimeError) as exc_info:
            client.generate_text(system_prompt=system_prompt_file, prompt="Prompt")

    error_msg = str(exc_info.value)
    assert "401" in error_msg
    assert secret_key not in error_msg


# 11. Saldo insuficiente (HTTP 402)
def test_insufficient_balance_raises_402(system_prompt_file: Path) -> None:
    client = LLMClient(model="uncensored", api_key="test-key")
    resp_402 = _make_mock_response(status_code=402)

    with patch.object(client.session, "post", return_value=resp_402):
        with pytest.raises(RuntimeError, match="402"):
            client.generate_text(system_prompt=system_prompt_file, prompt="Prompt")


# 12. Timeout
def test_timeout_raises_timeout_error(system_prompt_file: Path) -> None:
    client = LLMClient(model="uncensored", api_key="test-key")

    with patch.object(
        client.session,
        "post",
        side_effect=requests.exceptions.Timeout("Read timed out"),
    ):
        with pytest.raises(TimeoutError, match="timeout"):
            client.generate_text(system_prompt=system_prompt_file, prompt="Prompt")


# 13. Segundo intento cuando falla la validación JSON
def test_generate_json_succeeds_on_second_attempt_after_validation_failure(system_prompt_file: Path) -> None:
    client = LLMClient(model="uncensored", api_key="test-key")

    # Primer intento: falta 'verdict', 'signals', etc. y 'confidence' fuera de rango
    invalid_first_attempt = json.dumps(
        {
            "title": "Intento incompleto",
            "confidence": 1.5,
        }
    )
    valid_second_attempt = json.dumps(_valid_analysis_dict())

    resp_1 = _make_mock_response(content=invalid_first_attempt)
    resp_2 = _make_mock_response(content=valid_second_attempt)

    with patch.object(client.session, "post", side_effect=[resp_1, resp_2]) as mock_post:
        result = client.generate_json(
            system_prompt=system_prompt_file,
            prompt="Datos de la alerta...",
            schema=Analysis,
        )

    assert isinstance(result, Analysis)
    assert result.verdict == "true_positive"
    assert mock_post.call_count == 2

    # Comprobar que en el segundo intento se indicó qué campos fallaron
    second_call_payload = mock_post.call_args_list[1].kwargs["json"]
    second_user_prompt = second_call_payload["messages"][1]["content"]
    assert "CORRECCIÓN REQUERIDA" in second_user_prompt
    assert "verdict" in second_user_prompt
    assert "confidence" in second_user_prompt


# Pruebas adicionales de robustez (429/503 con reintento y respuesta vacía)
def test_transient_429_and_503_retries_and_recovers(system_prompt_file: Path) -> None:
    client = LLMClient(model="uncensored", api_key="test-key")
    client.retry_delay = 0.0

    resp_429 = _make_mock_response(status_code=429)
    resp_503 = _make_mock_response(status_code=503)
    resp_200 = _make_mock_response(content="Respuesta tras reintentos")

    with patch.object(client.session, "post", side_effect=[resp_429, resp_503, resp_200]) as mock_post:
        text = client.generate_text(system_prompt=system_prompt_file, prompt="Hola")

    assert text == "Respuesta tras reintentos"
    assert mock_post.call_count == 3


def test_empty_response_raises_value_error(system_prompt_file: Path) -> None:
    client = LLMClient(model="uncensored", api_key="test-key")
    empty_resp = _make_mock_response(content="   ")

    with patch.object(client.session, "post", return_value=empty_resp):
        with pytest.raises(ValueError, match="vacía"):
            client.generate_text(system_prompt=system_prompt_file, prompt="Hola")


def test_generate_json_accepts_markdown_fences_and_think_blocks(system_prompt_file: Path) -> None:
    client = LLMClient(model="uncensored", api_key="test-key")
    fenced_content = (
        "<think>Analizando contexto SOC N1...</think>\n"
        "```json\n"
        + json.dumps(_valid_analysis_dict())
        + "\n```"
    )
    mock_resp = _make_mock_response(content=fenced_content)

    with patch.object(client.session, "post", return_value=mock_resp) as mock_post:
        result = client.generate_json(
            system_prompt=system_prompt_file,
            prompt="Evidencias recopiladas...",
            schema=Analysis,
        )

    assert isinstance(result, Analysis)
    assert result.verdict == "true_positive"
    assert mock_post.call_count == 1
