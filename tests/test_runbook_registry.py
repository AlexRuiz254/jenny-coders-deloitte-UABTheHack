"""Pruebas unitarias para RunbookRegistry utilizando directorios temporales."""
from __future__ import annotations

from pathlib import Path

import pytest

import src  # noqa: F401 - Registra el alias tarvia_soc -> src.triage
from src.triage.investigation.runbook_registry import RunbookRegistry
from src.triage.investigation.strategies.ai_security import AISecurityStrategy
from src.triage.investigation.strategies.base import BaseRunbookStrategy
from src.triage.investigation.strategies.cloud import CloudStrategy
from src.triage.investigation.strategies.dlp import DLPStrategy
from src.triage.investigation.strategies.ecommerce import EcommerceStrategy
from src.triage.investigation.strategies.identity import IdentityStrategy
from src.triage.investigation.strategies.malware import MalwareStrategy
from src.triage.investigation.strategies.network import NetworkStrategy
from src.triage.investigation.strategies.ot import OTStrategy
from src.triage.investigation.strategies.phishing import PhishingStrategy
from src.triage.investigation.strategies.supply_chain import SupplyChainStrategy

EXPECTED_RUNBOOK_IDS = [f"RB-{i:02d}" for i in range(1, 11)]

EXPECTED_STRATEGY_MAPPING: dict[str, type[BaseRunbookStrategy]] = {
    "RB-01": PhishingStrategy,
    "RB-02": MalwareStrategy,
    "RB-03": IdentityStrategy,
    "RB-04": DLPStrategy,
    "RB-05": EcommerceStrategy,
    "RB-06": CloudStrategy,
    "RB-07": AISecurityStrategy,
    "RB-08": OTStrategy,
    "RB-09": NetworkStrategy,
    "RB-10": SupplyChainStrategy,
}


@pytest.fixture()
def temp_runbooks_dir(tmp_path: Path) -> Path:
    """Crea un directorio temporal con los 10 archivos Markdown de runbooks en UTF-8."""
    rb_dir = tmp_path / "runbooks"
    rb_dir.mkdir(parents=True, exist_ok=True)

    for rb_id in EXPECTED_RUNBOOK_IDS:
        content = (
            f"# {rb_id} Procedimiento de triaje\n"
            f"**Identificador:** {rb_id}\n\n"
            "## Comprobaciones\n"
            f"- Verificar evidencias asociadas a {rb_id} con acentos (áéíóúñ).\n"
        )
        (rb_dir / f"{rb_id}.md").write_text(content, encoding="utf-8")

    return rb_dir


# 1. El constructor acepta una ruta válida
def test_constructor_accepts_valid_directory(temp_runbooks_dir: Path) -> None:
    registry = RunbookRegistry(temp_runbooks_dir)
    assert registry.runbooks_dir == temp_runbooks_dir.resolve()


# 2. El constructor detecta un directorio inexistente
def test_constructor_raises_on_nonexistent_directory(tmp_path: Path) -> None:
    nonexistent_dir = tmp_path / "carpeta_que_no_existe"
    with pytest.raises(FileNotFoundError, match="no existe"):
        RunbookRegistry(nonexistent_dir)


# 3. Se comprueba que existen los diez archivos Markdown
def test_constructor_verifies_all_ten_markdown_files_exist(temp_runbooks_dir: Path) -> None:
    registry = RunbookRegistry(temp_runbooks_dir)
    for rb_id in EXPECTED_RUNBOOK_IDS:
        assert (registry.runbooks_dir / f"{rb_id}.md").is_file()
        assert isinstance(registry.get_text(rb_id), str)


# 4. get_text("RB-01") devuelve el contenido correcto
def test_get_text_rb01_returns_exact_content(temp_runbooks_dir: Path) -> None:
    expected_content = (temp_runbooks_dir / "RB-01.md").read_text(encoding="utf-8")
    registry = RunbookRegistry(temp_runbooks_dir)

    text = registry.get_text("RB-01")
    assert text == expected_content


# 5. Los diez identificadores devuelven su Markdown correspondiente
def test_all_ten_identifiers_return_their_markdown(temp_runbooks_dir: Path) -> None:
    registry = RunbookRegistry(temp_runbooks_dir)

    for rb_id in EXPECTED_RUNBOOK_IDS:
        expected = (temp_runbooks_dir / f"{rb_id}.md").read_text(encoding="utf-8")
        actual = registry.get_text(rb_id)
        assert actual == expected
        assert f"# {rb_id} Procedimiento de triaje" in actual


# 6. Un identificador inexistente genera una excepción
@pytest.mark.parametrize("invalid_id", ["RB-00", "RB-11", "RB-99", "", "UNKNOWN", "rb-01"])
def test_invalid_identifier_raises_exception(temp_runbooks_dir: Path, invalid_id: str) -> None:
    registry = RunbookRegistry(temp_runbooks_dir)

    with pytest.raises(ValueError, match="inválido"):
        registry.get_text(invalid_id)

    with pytest.raises(ValueError, match="inválido"):
        registry.get_strategy(invalid_id)


# 7. get_strategy("RB-01") devuelve una instancia de PhishingStrategy
def test_get_strategy_rb01_returns_phishing_strategy_instance(temp_runbooks_dir: Path) -> None:
    registry = RunbookRegistry(temp_runbooks_dir)
    strategy = registry.get_strategy("RB-01")

    assert isinstance(strategy, PhishingStrategy)


# 8. Comprobar los diez mapeos de estrategias
@pytest.mark.parametrize(("runbook_id", "expected_cls"), list(EXPECTED_STRATEGY_MAPPING.items()))
def test_all_ten_strategy_mappings(
    temp_runbooks_dir: Path,
    runbook_id: str,
    expected_cls: type[BaseRunbookStrategy],
) -> None:
    registry = RunbookRegistry(temp_runbooks_dir)
    strategy = registry.get_strategy(runbook_id)

    assert type(strategy) is expected_cls


# 9. Una estrategia devuelve un objeto que hereda de BaseRunbookStrategy
@pytest.mark.parametrize("runbook_id", EXPECTED_RUNBOOK_IDS)
def test_strategy_inherits_from_base_runbook_strategy(
    temp_runbooks_dir: Path,
    runbook_id: str,
) -> None:
    registry = RunbookRegistry(temp_runbooks_dir)
    strategy = registry.get_strategy(runbook_id)

    assert isinstance(strategy, BaseRunbookStrategy)


# 10. Un identificador malicioso como ../../README.md no permite acceder a archivos externos
@pytest.mark.parametrize(
    "malicious_id",
    [
        "../../README.md",
        "../../README",
        "../secret",
        "..\\..\\README.md",
        "/etc/passwd",
        "RB-01/../../README.md",
    ],
)
def test_path_traversal_identifier_is_rejected(
    temp_runbooks_dir: Path,
    malicious_id: str,
) -> None:
    # Crear un archivo externo en el directorio padre temporal para intentar acceder a él
    secret_file = temp_runbooks_dir.parent / "README.md"
    secret_file.write_text("CONTENIDO EXTERNO CONFIDENCIAL", encoding="utf-8")

    registry = RunbookRegistry(temp_runbooks_dir)

    with pytest.raises(ValueError, match="inválido"):
        registry.get_text(malicious_id)

    with pytest.raises(ValueError, match="inválido"):
        registry.get_strategy(malicious_id)


# 11. Si falta un archivo Markdown, se produce un error comprensible
def test_missing_markdown_file_raises_descriptive_error(temp_runbooks_dir: Path) -> None:
    (temp_runbooks_dir / "RB-07.md").unlink()

    with pytest.raises(FileNotFoundError, match="RB-07.md"):
        RunbookRegistry(temp_runbooks_dir)
