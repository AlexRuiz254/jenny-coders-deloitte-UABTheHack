"""Usa alert['runbook'] directamente; NO recalcula el runbook desde la regla."""
from __future__ import annotations

from pathlib import Path

from tarvia_soc.investigation.strategies.ai_security import AISecurityStrategy
from tarvia_soc.investigation.strategies.base import BaseRunbookStrategy
from tarvia_soc.investigation.strategies.cloud import CloudStrategy
from tarvia_soc.investigation.strategies.dlp import DLPStrategy
from tarvia_soc.investigation.strategies.ecommerce import EcommerceStrategy
from tarvia_soc.investigation.strategies.identity import IdentityStrategy
from tarvia_soc.investigation.strategies.malware import MalwareStrategy
from tarvia_soc.investigation.strategies.network import NetworkStrategy
from tarvia_soc.investigation.strategies.ot import OTStrategy
from tarvia_soc.investigation.strategies.phishing import PhishingStrategy
from tarvia_soc.investigation.strategies.supply_chain import SupplyChainStrategy


class RunbookRegistry:
    """Registro encargado de cargar los 10 runbooks Markdown y asociar su estrategia Python."""

    _STRATEGY_MAP: dict[str, type[BaseRunbookStrategy]] = {
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

    def __init__(self, runbooks_dir: Path) -> None:
        if runbooks_dir is None:
            raise ValueError("La ruta 'runbooks_dir' no puede ser None.")

        resolved_dir = Path(runbooks_dir).resolve()
        if not resolved_dir.exists() or not resolved_dir.is_dir():
            raise FileNotFoundError(
                f"El directorio de runbooks no existe o no es un directorio válido: {runbooks_dir}"
            )

        self.runbooks_dir: Path = resolved_dir
        self._texts: dict[str, str] = self._load_runbooks()

    def _load_runbooks(self) -> dict[str, str]:
        """Valida la presencia de los 10 archivos Markdown y carga su contenido en UTF-8."""
        loaded: dict[str, str] = {}
        missing_files: list[str] = []

        for runbook_id, strategy_cls in self._STRATEGY_MAP.items():
            if not issubclass(strategy_cls, BaseRunbookStrategy):
                raise TypeError(
                    f"La estrategia {strategy_cls.__name__} asociada a {runbook_id} "
                    "no hereda de BaseRunbookStrategy."
                )

            filename = f"{runbook_id}.md"
            file_path = (self.runbooks_dir / filename).resolve()

            if file_path.parent != self.runbooks_dir or not file_path.is_file():
                missing_files.append(filename)
                continue

            try:
                content = file_path.read_text(encoding="utf-8")
            except OSError as exc:
                raise OSError(
                    f"Error al leer el archivo de runbook '{filename}': {exc}"
                ) from exc

            loaded[runbook_id] = content

        if missing_files:
            missing_list = ", ".join(missing_files)
            raise FileNotFoundError(
                f"Faltan archivos de runbook obligatorios en {self.runbooks_dir}: {missing_list}"
            )

        return loaded

    def _validate_runbook_id(self, runbook_id: str) -> str:
        """Comprueba que el identificador pertenece estrictamente al conjunto permitido RB-01..RB-10."""
        if not isinstance(runbook_id, str) or runbook_id not in self._STRATEGY_MAP:
            allowed = ", ".join(self._STRATEGY_MAP.keys())
            raise ValueError(
                f"Identificador de runbook inválido o no permitido: {runbook_id!r}. "
                f"Valores válidos: {allowed}."
            )
        return runbook_id

    def get_text(self, runbook_id: str) -> str:
        """Leer RB-01.md ... RB-10.md usando el ID presente en la alerta."""
        valid_id = self._validate_runbook_id(runbook_id)
        return self._texts[valid_id]

    def get_strategy(self, runbook_id: str) -> BaseRunbookStrategy:
        """Seleccionar UNA de las diez estrategias (no diez agentes LLM)."""
        valid_id = self._validate_runbook_id(runbook_id)
        strategy_cls = self._STRATEGY_MAP[valid_id]
        return strategy_cls()
