"""Usa alert['runbook'] directamente; NO recalcula el runbook desde la regla."""
from pathlib import Path
from tarvia_soc.investigation.strategies.base import BaseRunbookStrategy

class RunbookRegistry:
    def __init__(self, runbooks_dir: Path) -> None:
        raise NotImplementedError

    def get_text(self, runbook_id: str) -> str:
        """Leer RB-01.md ... RB-10.md usando el ID presente en la alerta."""
        raise NotImplementedError

    def get_strategy(self, runbook_id: str) -> BaseRunbookStrategy:
        """Seleccionar UNA de las diez estrategias (no diez agentes LLM)."""
        raise NotImplementedError
