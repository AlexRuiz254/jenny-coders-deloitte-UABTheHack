"""Contrato de las estrategias de runbook; solo describen comprobaciones."""
from abc import ABC, abstractmethod
from tarvia_soc.models import RawAlert, InvestigationPlan

class BaseRunbookStrategy(ABC):
    @abstractmethod
    def build_plan(self, alert: RawAlert) -> InvestigationPlan:
        """Seleccionar checks y fuentes según las particularidades de la regla."""
        raise NotImplementedError
