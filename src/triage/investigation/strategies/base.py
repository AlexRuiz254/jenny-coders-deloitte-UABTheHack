"""Contrato de las estrategias de runbook; solo describen comprobaciones."""
from abc import ABC, abstractmethod

from tarvia_soc.models import InvestigationPlan, RawAlert


class BaseRunbookStrategy(ABC):

    @abstractmethod
    def build_plan(self, alert: RawAlert) -> InvestigationPlan:
        """
        Generar el plan de investigación específico del runbook
        al que pertenece la estrategia.
        """
        raise NotImplementedError
