"""Pruebas automatizadas para las 10 estrategias de investigación (RB-01 a RB-10)."""
from __future__ import annotations

import csv
from pathlib import Path
from typing import Any, get_args

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
from tarvia_soc.models import InvestigationPlan, LogSource, RawAlert

VALID_LOG_SOURCES: set[str] = set(get_args(LogSource))

STRATEGY_BY_RUNBOOK: dict[str, type[BaseRunbookStrategy]] = {
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

SAMPLE_RULE_BY_RUNBOOK: dict[str, str] = {
    "RB-01": "UC-EML-001",
    "RB-02": "UC-EDR-002",
    "RB-03": "UC-IDP-001",
    "RB-04": "UC-DLP-001",
    "RB-05": "UC-WEB-001",
    "RB-06": "UC-CLD-001",
    "RB-07": "UC-AI-001",
    "RB-08": "UC-OT-001",
    "RB-09": "UC-NET-001",
    "RB-10": "UC-DEV-001",
}

CATALOG_PATH = (
    Path(__file__).resolve().parents[3]
    / "RepositoriDeloitte"
    / "01_contexto"
    / "catalogo_casos_de_uso.csv"
)


def _load_catalog_rows() -> list[dict[str, str]]:
    with CATALOG_PATH.open(encoding="utf-8", newline="") as fh:
        return list(csv.DictReader(fh))


def _make_synthetic_alert(
    *,
    rule_id: str,
    runbook: str,
    source_product: str = "SIEM",
    severity: str = "medium",
) -> RawAlert:
    """Construye una alerta sintética con la misma estructura que las alertas reales."""
    return {
        "alert_id": f"SYNTH-{rule_id}",
        "created_at": "2026-10-15T10:00:00.000Z",
        "source_product": source_product,
        "rule_id": rule_id,
        "rule_name": f"Regla sintética {rule_id}",
        "severity": severity,
        "status": "new",
        "mitre": {
            "tactic": "Initial Access",
            "technique_id": "T1078",
            "technique": "Valid Accounts",
        },
        "description": f"Alerta sintética para {rule_id}",
        "entities": {
            "hosts": [{"hostname": "WS-TEST-01", "ip": "10.10.1.50"}],
            "users": [{"upn": "usuario.test@tarvia.example"}],
        },
        "evidence": {"sample": True},
        "related_events": ["EVT-000001"],
        "runbook": runbook,
    }


# 1 y 2. Las diez clases heredan de BaseRunbookStrategy e implementan build_plan()
@pytest.mark.parametrize(("runbook_id", "strategy_cls"), list(STRATEGY_BY_RUNBOOK.items()))
def test_strategy_inherits_and_implements_build_plan(
    runbook_id: str,
    strategy_cls: type[BaseRunbookStrategy],
) -> None:
    assert issubclass(strategy_cls, BaseRunbookStrategy)
    strategy = strategy_cls()
    assert isinstance(strategy, BaseRunbookStrategy)
    assert callable(strategy.build_plan)


# 3, 4, 5, 6 y 7. Plan válido, runbook_id correcto, fuentes en LogSource y sin duplicados
@pytest.mark.parametrize(("runbook_id", "strategy_cls"), list(STRATEGY_BY_RUNBOOK.items()))
def test_strategy_returns_valid_plan_without_duplicates(
    runbook_id: str,
    strategy_cls: type[BaseRunbookStrategy],
) -> None:
    strategy = strategy_cls()
    rule_id = SAMPLE_RULE_BY_RUNBOOK[runbook_id]
    alert = _make_synthetic_alert(rule_id=rule_id, runbook=runbook_id)

    plan_1 = strategy.build_plan(alert)
    plan_2 = strategy.build_plan(alert)

    assert isinstance(plan_1, InvestigationPlan)
    assert plan_1 == plan_2  # Determinista
    assert plan_1.runbook_id == runbook_id
    assert len(plan_1.required_checks) >= 4
    assert len(plan_1.suggested_sources) >= 1

    # Sin checks ni fuentes duplicadas
    assert len(plan_1.required_checks) == len(set(plan_1.required_checks))
    assert len(plan_1.suggested_sources) == len(set(plan_1.suggested_sources))

    # Todas las fuentes pertenecen a LogSource y los checks están en snake_case
    for source in plan_1.suggested_sources:
        assert source in VALID_LOG_SOURCES
    for check in plan_1.required_checks:
        assert check == check.lower()
        assert " " not in check


# 8. Se seleccionan correctamente las comprobaciones para reglas diferentes del mismo runbook
@pytest.mark.parametrize(
    ("runbook_id", "rule_a", "rule_b"),
    [
        ("RB-01", "UC-EML-001", "UC-EML-004"),
        ("RB-02", "UC-EDR-002", "UC-EDR-012"),
        ("RB-03", "UC-IDP-003", "UC-VPN-001"),
        ("RB-04", "UC-DLP-001", "UC-DLP-002"),
        ("RB-05", "UC-WEB-002", "UC-EDR-009"),
        ("RB-06", "UC-CLD-001", "UC-CLD-004"),
        ("RB-07", "UC-AI-001", "UC-AI-002"),
        ("RB-09", "UC-NET-003", "UC-NET-006"),
    ],
)
def test_different_rules_in_same_runbook_produce_tailored_checks(
    runbook_id: str,
    rule_a: str,
    rule_b: str,
) -> None:
    strategy = STRATEGY_BY_RUNBOOK[runbook_id]()
    plan_a = strategy.build_plan(_make_synthetic_alert(rule_id=rule_a, runbook=runbook_id))
    plan_b = strategy.build_plan(_make_synthetic_alert(rule_id=rule_b, runbook=runbook_id))

    assert plan_a.required_checks != plan_b.required_checks


# 9. Una alerta cuyo runbook no coincide provoca un error
@pytest.mark.parametrize(("runbook_id", "strategy_cls"), list(STRATEGY_BY_RUNBOOK.items()))
def test_mismatched_runbook_in_alert_raises_value_error(
    runbook_id: str,
    strategy_cls: type[BaseRunbookStrategy],
) -> None:
    strategy = strategy_cls()
    wrong_runbook = "RB-02" if runbook_id == "RB-01" else "RB-01"
    alert = _make_synthetic_alert(rule_id="UC-ANY-001", runbook=wrong_runbook)

    with pytest.raises(ValueError, match=runbook_id):
        strategy.build_plan(alert)


# 10. Una regla desconocida con runbook válido utiliza checks generales y revisión de regla desconocida
@pytest.mark.parametrize(("runbook_id", "strategy_cls"), list(STRATEGY_BY_RUNBOOK.items()))
def test_unknown_rule_with_valid_runbook_uses_general_checks(
    runbook_id: str,
    strategy_cls: type[BaseRunbookStrategy],
) -> None:
    strategy = strategy_cls()
    alert = _make_synthetic_alert(rule_id="UC-UNKNOWN-999", runbook=runbook_id)

    plan = strategy.build_plan(alert)

    assert isinstance(plan, InvestigationPlan)
    assert plan.runbook_id == runbook_id
    assert "check_unknown_rule_context" in plan.required_checks
    assert len(plan.required_checks) >= 4
    assert len(plan.required_checks) == len(set(plan.required_checks))
    assert len(plan.suggested_sources) == len(set(plan.suggested_sources))


# 11. Todas las 44 reglas del catálogo tienen cobertura específica en su estrategia asignada
def test_all_44_catalog_rules_are_covered_by_assigned_strategy() -> None:
    rows = _load_catalog_rows()
    assert len(rows) == 44

    for row in rows:
        rule_id = row["rule_id"]
        runbook_id = row["runbook"]
        assert runbook_id in STRATEGY_BY_RUNBOOK

        strategy_cls = STRATEGY_BY_RUNBOOK[runbook_id]
        strategy = strategy_cls()
        alert = _make_synthetic_alert(
            rule_id=rule_id,
            runbook=runbook_id,
            source_product=row["fuente"],
            severity=row["severidad_base"],
        )

        plan = strategy.build_plan(alert)

        assert isinstance(plan, InvestigationPlan)
        assert plan.runbook_id == runbook_id
        # Debe estar cubierta explícitamente (no caer en el fallback de regla desconocida)
        assert "check_unknown_rule_context" not in plan.required_checks, (
            f"La regla {rule_id} ({runbook_id}) no tiene cobertura explícita en {strategy_cls.__name__}"
        )
        assert len(plan.required_checks) == len(set(plan.required_checks))
        assert len(plan.suggested_sources) == len(set(plan.suggested_sources))
        assert set(plan.suggested_sources).issubset(VALID_LOG_SOURCES)


# 12. Los checks particulares mencionados en cada runbook están representados en los planes
def test_specific_runbook_particularities_are_represented() -> None:
    # RB-01: Fraude de cambio de IBAN en UC-EML-004
    p_iban = PhishingStrategy().build_plan(
        _make_synthetic_alert(rule_id="UC-EML-004", runbook="RB-01")
    )
    assert any("iban" in c for c in p_iban.required_checks)

    # RB-02: Manipulación de agente EDR (UC-EDR-011) y lectura de memoria TPV (UC-EDR-012)
    p_edr11 = MalwareStrategy().build_plan(
        _make_synthetic_alert(rule_id="UC-EDR-011", runbook="RB-02")
    )
    assert any("edr_agent" in c or "telemetry" in c for c in p_edr11.required_checks)

    p_edr12 = MalwareStrategy().build_plan(
        _make_synthetic_alert(rule_id="UC-EDR-012", runbook="RB-02")
    )
    assert any("tpv" in c or "pos" in c for c in p_edr12.required_checks)

    # RB-03: Consentimiento OAuth (UC-IDP-007), AD privilegiado (UC-IDP-008) y VPN proveedor (UC-VPN-001)
    p_oauth = IdentityStrategy().build_plan(
        _make_synthetic_alert(rule_id="UC-IDP-007", runbook="RB-03")
    )
    assert any("oauth" in c for c in p_oauth.required_checks)

    p_ad = IdentityStrategy().build_plan(
        _make_synthetic_alert(rule_id="UC-IDP-008", runbook="RB-03")
    )
    assert any("active_directory" in c or "privileged_group" in c for c in p_ad.required_checks)
    assert "ad_events" in p_ad.suggested_sources

    p_vpn = IdentityStrategy().build_plan(
        _make_synthetic_alert(rule_id="UC-VPN-001", runbook="RB-03")
    )
    assert any("vpn" in c for c in p_vpn.required_checks)
    assert "vpn" in p_vpn.suggested_sources

    # RB-05: Web shell en servidor web (UC-EDR-009 asignado a RB-05)
    p_webshell = EcommerceStrategy().build_plan(
        _make_synthetic_alert(rule_id="UC-EDR-009", runbook="RB-05")
    )
    assert any("webshell" in c or "web_server" in c for c in p_webshell.required_checks)
    assert "edr_events" in p_webshell.suggested_sources

    # RB-08: Puertos industriales (502/44818) y prohibición explícita de contención OT
    p_ot = OTStrategy().build_plan(
        _make_synthetic_alert(rule_id="UC-OT-001", runbook="RB-08")
    )
    assert any("modbus_502" in c and "44818" in c for c in p_ot.required_checks)
    assert any("prohibit_direct_soc_ot_containment" in c for c in p_ot.required_checks)

    # RB-09: Escáner autorizado NESSUS01 (UC-NET-003) y DNS tunneling (UC-NET-006)
    p_scan = NetworkStrategy().build_plan(
        _make_synthetic_alert(rule_id="UC-NET-003", runbook="RB-09")
    )
    assert any("nessus01" in c or "scanner" in c for c in p_scan.required_checks)

    p_dnstun = NetworkStrategy().build_plan(
        _make_synthetic_alert(rule_id="UC-NET-006", runbook="RB-09")
    )
    assert any("dns_tunneling" in c for c in p_dnstun.required_checks)
    assert "dns" in p_dnstun.suggested_sources

    # RB-10: Paquetes @tarvia/*, postinstall, secretos y CloudTrail (UC-DEV-001)
    p_sc = SupplyChainStrategy().build_plan(
        _make_synthetic_alert(rule_id="UC-DEV-001", runbook="RB-10")
    )
    assert any("tarvia" in c for c in p_sc.required_checks)
    assert any("postinstall" in c for c in p_sc.required_checks)
    assert "cicd_builds" in p_sc.suggested_sources
    assert "cloudtrail" in p_sc.suggested_sources
