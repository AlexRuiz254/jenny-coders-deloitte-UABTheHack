"""Pruebas unitarias para el contrato abstracto BaseRunbookStrategy."""
from __future__ import annotations

from abc import ABC
import inspect

import pytest

import src  # noqa: F401 - Registra el alias tarvia_soc -> src.triage
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
from tarvia_soc.models import InvestigationPlan, RawAlert

ALL_STRATEGIES: list[type[BaseRunbookStrategy]] = [
    PhishingStrategy,
    MalwareStrategy,
    IdentityStrategy,
    DLPStrategy,
    EcommerceStrategy,
    CloudStrategy,
    AISecurityStrategy,
    OTStrategy,
    NetworkStrategy,
    SupplyChainStrategy,
]


class _IncompleteStrategy(BaseRunbookStrategy):
    """Subclase de prueba que no implementa build_plan()."""


class _DummyStrategy(BaseRunbookStrategy):
    """Estrategia concreta de prueba que implementa build_plan()."""

    def build_plan(self, alert: RawAlert) -> InvestigationPlan:
        return InvestigationPlan(
            runbook_id=str(alert.get("runbook", "RB-02")),
            required_checks=[
                "check_process_tree",
                "check_file_signature",
                "check_hash_reputation",
            ],
            suggested_sources=["edr_events", "proxy", "dns"],
        )


# 1. Comprobar que BaseRunbookStrategy es una clase abstracta
def test_base_runbook_strategy_is_abstract_class() -> None:
    assert issubclass(BaseRunbookStrategy, ABC)
    assert inspect.isabstract(BaseRunbookStrategy)
    assert "build_plan" in BaseRunbookStrategy.__abstractmethods__


# 2. Comprobar que no se puede instanciar directamente
def test_cannot_instantiate_base_runbook_strategy_directly() -> None:
    with pytest.raises(TypeError):
        BaseRunbookStrategy()  # type: ignore[abstract]


# 3. Comprobar que una subclase sin implementar build_plan() tampoco se puede instanciar
def test_cannot_instantiate_subclass_without_build_plan() -> None:
    with pytest.raises(TypeError):
        _IncompleteStrategy()  # type: ignore[abstract]


# 4 y 5. Crear una estrategia de prueba que implemente build_plan() y devuelva un InvestigationPlan válido
def test_concrete_test_strategy_returns_valid_investigation_plan() -> None:
    strategy = _DummyStrategy()
    sample_alert: RawAlert = {
        "alert_id": "ALT-001",
        "rule_id": "UC-EDR-002",
        "runbook": "RB-02",
    }

    plan = strategy.build_plan(sample_alert)

    assert isinstance(plan, InvestigationPlan)
    assert plan.runbook_id == "RB-02"
    assert plan.required_checks == [
        "check_process_tree",
        "check_file_signature",
        "check_hash_reputation",
    ]
    assert plan.suggested_sources == ["edr_events", "proxy", "dns"]


# 6. Comprobar que build_plan() recibe una alerta y devuelve el modelo esperado
def test_build_plan_receives_alert_and_uses_its_data() -> None:
    strategy = _DummyStrategy()
    custom_alert: RawAlert = {
        "alert_id": "ALT-099",
        "rule_id": "UC-EML-001",
        "runbook": "RB-01",
    }

    plan = strategy.build_plan(custom_alert)

    assert isinstance(plan, InvestigationPlan)
    assert plan.runbook_id == custom_alert["runbook"]
    assert len(plan.required_checks) > 0
    assert len(plan.suggested_sources) > 0


# 7. Comprobar que las diez estrategias existentes heredan de BaseRunbookStrategy
@pytest.mark.parametrize("strategy_cls", ALL_STRATEGIES)
def test_all_ten_existing_strategies_inherit_from_base(
    strategy_cls: type[BaseRunbookStrategy],
) -> None:
    assert issubclass(strategy_cls, BaseRunbookStrategy)
    instance = strategy_cls()
    assert isinstance(instance, BaseRunbookStrategy)
    assert callable(getattr(instance, "build_plan", None))
