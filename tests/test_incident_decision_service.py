"""Pruebas unitarias para `IncidentDecisionService` (Nivel 2 SOC Tarvia)."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from src.triage.decision.escalation_engine import EscalationEngine
from src.triage.decision.severity_calculator import SeverityCalculator
from src.triage.decision.verdict_engine import VerdictEngine
from src.triage.level2.incident_decision_service import (
    AlertInvestigationInput,
    IncidentDecisionResult,
    IncidentDecisionService,
    IncidentGroup,
)
from src.triage.models import (
    Analysis,
    ContextSnapshot,
    Evidence,
    Finding,
    PolicySignals,
)


def _signals(**overrides: bool) -> PolicySignals:
    """Construir `PolicySignals` con valores por defecto `False` y overrides explícitos."""
    base = {
        "execution_or_access_confirmed": False,
        "blocked_before_effect": False,
        "privileged_or_vip": False,
        "sensitive_or_payment_data": False,
        "malicious_execution": False,
        "credentials_compromised": False,
        "persistence": False,
        "personal_data_exposure": False,
        "financial_fraud": False,
        "attack_chain": False,
        "authorized_activity": False,
    }
    base.update(overrides)
    return PolicySignals(**base)


def _build_service_with_spies() -> tuple[
    IncidentDecisionService, MagicMock, MagicMock, MagicMock
]:
    """Crear `IncidentDecisionService` con mocks que envuelven los motores reales de N1."""
    verdict_spy = MagicMock(wraps=VerdictEngine())
    severity_spy = MagicMock(wraps=SeverityCalculator())
    escalation_spy = MagicMock(wraps=EscalationEngine())
    service = IncidentDecisionService(
        verdict_engine=verdict_spy,
        severity_calculator=severity_spy,
        escalation_engine=escalation_spy,
    )
    return service, verdict_spy, severity_spy, escalation_spy


# ---------------------------------------------------------------------------
# Escenario 1: Ataque confirmado sobre un servidor crítico
# ---------------------------------------------------------------------------


def test_scenario_1_confirmed_attack_on_critical_server() -> None:
    service, verdict_spy, severity_spy, escalation_spy = _build_service_with_spies()

    alert_1 = {
        "alert_id": "ALR-CRIT-001",
        "rule_id": "UC-WEB-002",
        "severity": "high",
        "created_at": "2026-10-15T10:15:00Z",
        "entities": {
            "hosts": [{"hostname": "PAY-GW01", "ip": "10.20.1.10"}],
            "ips": ["10.20.1.10", "185.220.101.5"],
            "users": ["svc_payments"],
        },
    }
    alert_2 = {
        "alert_id": "ALR-CRIT-002",
        "rule_id": "UC-EDR-002",
        "severity": "high",
        "created_at": "2026-10-15T10:18:00Z",
        "entities": {
            "hosts": [{"hostname": "PAY-GW01", "ip": "10.20.1.10"}],
            "ips": ["10.20.1.10"],
            "users": ["svc_payments"],
        },
    }

    context = ContextSnapshot(
        assets=[
            {
                "asset_id": "AST-PAY-01",
                "hostname": "PAY-GW01",
                "ip": "10.20.1.10",
                "type": "servidor",
                "zone": "DC-SERVERS",
                "criticality": "crítica",
                "business_service": "Pasarela de pagos (PCI DSS)",
            }
        ],
        services=[
            {
                "servicio": "Pasarela de pagos (PCI DSS)",
                "criticidad": "crítica",
                "responsable": "Carlos Mendez",
            }
        ],
    )

    ev_1 = [
        Evidence(
            source="waf",
            event_id="EVT-WAF-901",
            timestamp="2026-10-15T10:14:55Z",
            raw={"summary": "Explotación RCE confirmada hacia PAY-GW01 desde 185.220.101.5."},
        )
    ]
    ev_2 = [
        Evidence(
            source="edr_events",
            event_id="EVT-EDR-902",
            timestamp="2026-10-15T10:17:40Z",
            raw={"summary": "Ejecución de reverseshell y dump de memoria en PAY-GW01."},
        )
    ]

    analysis_1 = Analysis(
        title="Explotación remota en pasarela de pagos PAY-GW01",
        verdict="true_positive",
        confidence=0.95,
        summary="Se confirma ejecución de comandos tras explotación web en PAY-GW01.",
        findings=[
            Finding(
                statement="Petición de explotación seguida de comando remoto en PAY-GW01.",
                evidence_ids=["EVT-WAF-901"],
            )
        ],
        signals=_signals(
            execution_or_access_confirmed=True,
            sensitive_or_payment_data=True,
            malicious_execution=True,
            attack_chain=True,
        ),
        proposed_actions=[],
        open_questions=[],
    )
    analysis_2 = Analysis(
        title="Ejecución de payload malicioso y persistencia en PAY-GW01",
        verdict="true_positive",
        confidence=0.92,
        summary="El EDR confirma ejecución maliciosa bajo cuenta svc_payments.",
        findings=[
            Finding(
                statement="Binario malicioso ejecutado en memoria sobre PAY-GW01.",
                evidence_ids=["EVT-EDR-902"],
            )
        ],
        signals=_signals(
            execution_or_access_confirmed=True,
            sensitive_or_payment_data=True,
            malicious_execution=True,
            persistence=True,
            attack_chain=True,
        ),
        proposed_actions=[],
        open_questions=[],
    )

    group = IncidentGroup(
        incident_id="INC-001",
        alert_ids=["ALR-CRIT-001", "ALR-CRIT-002"],
        alerts=[alert_1, alert_2],
        correlation_reason="Mismo servidor crítico PAY-GW01 y cuenta svc_payments en 3 minutos.",
    )

    result = service.decide(
        incident_group=group,
        analyses=[analysis_1, analysis_2],
        contexts=[context, context],
        evidence=[ev_1, ev_2],
    )

    assert isinstance(result, IncidentDecisionResult)
    assert result.alert_ids == ["ALR-CRIT-001", "ALR-CRIT-002"]
    assert result.verdict == "true_positive"
    assert result.confidence >= 0.90
    assert "ALR-CRIT-001" in result.verdict_rationale
    assert "ALR-CRIT-002" in result.verdict_rationale
    assert result.severity == "critical"
    assert "PAY-GW01" in result.severity_rationale
    assert result.escalation.escalate is True
    assert result.escalation.to == "N2 de guardia"
    assert "15 minutos" in result.escalation.reason
    assert "ejecución maliciosa" in result.escalation.reason
    assert result.key_evidence_ids == ["EVT-WAF-901", "EVT-EDR-902"]

    assert verdict_spy.decide.call_count == 2
    assert severity_spy.calculate.call_count >= 1
    assert escalation_spy.decide.call_count >= 1


# ---------------------------------------------------------------------------
# Escenario 2: Actividad legítima explicada por un mantenimiento autorizado
# ---------------------------------------------------------------------------


def test_scenario_2_authorized_maintenance_activity() -> None:
    service, verdict_spy, severity_spy, escalation_spy = _build_service_with_spies()

    alert_1 = {
        "alert_id": "ALR-MAINT-001",
        "rule_id": "UC-NET-003",
        "severity": "medium",
        "created_at": "2026-10-14T02:10:00Z",
        "entities": {
            "hosts": [{"hostname": "NESSUS01", "ip": "10.10.5.50"}],
            "ips": ["10.10.5.50", "10.20.1.25"],
        },
    }
    alert_2 = {
        "alert_id": "ALR-MAINT-002",
        "rule_id": "UC-NET-006",
        "severity": "low",
        "created_at": "2026-10-14T02:25:00Z",
        "entities": {
            "hosts": [{"hostname": "NESSUS01", "ip": "10.10.5.50"}],
            "ips": ["10.10.5.50", "10.20.1.26"],
        },
    }

    change_record = {
        "id": "CHG-2026-044",
        "inicio": "2026-10-14T01:00:00Z",
        "fin": "2026-10-14T05:00:00Z",
        "detalle": "Ventana de escaneo semanal autorizado desde NESSUS01 (01:00-06:00).",
        "activos": ["NESSUS01"],
        "alcance": "NESSUS01",
    }
    context = ContextSnapshot(
        assets=[
            {
                "asset_id": "AST-SEC-01",
                "hostname": "NESSUS01",
                "ip": "10.10.5.50",
                "criticality": "media",
            }
        ],
        changes=[change_record],
    )

    ev_1 = [
        Evidence(
            source="firewall",
            event_id="EVT-FW-101",
            timestamp="2026-10-14T02:10:00Z",
            raw={"hostname": "NESSUS01", "summary": "Escaneo de puertos desde NESSUS01 dentro de ventana CHG-2026-044."},
        )
    ]
    ev_2 = [
        Evidence(
            source="firewall",
            event_id="EVT-FW-102",
            timestamp="2026-10-14T02:25:00Z",
            raw={"hostname": "NESSUS01", "summary": "Sondeo de servicios desde NESSUS01 dentro de ventana CHG-2026-044."},
        )
    ]

    analysis_1 = Analysis(
        title="Escaneo interno autorizado desde NESSUS01",
        verdict="benign_true_positive",
        confidence=0.90,
        summary="Actividad cubierta por el cambio aprobado CHG-2026-044.",
        findings=[
            Finding(
                statement="Tráfico originado en NESSUS01 durante ventana CHG-2026-044.",
                evidence_ids=["EVT-FW-101", "CHG-2026-044"],
            )
        ],
        signals=_signals(authorized_activity=True),
        proposed_actions=[],
        open_questions=[],
    )
    analysis_2 = Analysis(
        title="Sondeo de servicios autorizado desde NESSUS01",
        verdict="benign_true_positive",
        confidence=0.88,
        summary="Segundo tramo del escaneo cubierto por CHG-2026-044.",
        findings=[
            Finding(
                statement="Sondeo originado en NESSUS01 dentro del cambio CHG-2026-044.",
                evidence_ids=["EVT-FW-102", "CHG-2026-044"],
            )
        ],
        signals=_signals(authorized_activity=True),
        proposed_actions=[],
        open_questions=[],
    )

    group = IncidentGroup(
        incident_id="INC-002",
        alert_ids=["ALR-MAINT-001", "ALR-MAINT-002"],
        alerts=[alert_1, alert_2],
    )

    result = service.decide(
        group,
        analyses=[analysis_1, analysis_2],
        contexts=context,
        evidence={"ALR-MAINT-001": ev_1, "ALR-MAINT-002": ev_2},
    )

    assert result.verdict == "benign_true_positive"
    assert result.severity in ("informational", "low")
    assert "benign_true_positive" in result.verdict_rationale
    assert "benign_true_positive" in result.severity_rationale
    assert result.escalation.escalate is False
    assert result.escalation.to == ""
    assert "CHG-2026-044" in result.key_evidence_ids
    assert verdict_spy.decide.call_count == 2
    assert severity_spy.calculate.call_count >= 1
    assert escalation_spy.decide.call_count >= 1


# ---------------------------------------------------------------------------
# Escenario 3: Incidente con varias alertas y evidencias contradictorias
# ---------------------------------------------------------------------------


def test_scenario_3_multiple_alerts_with_contradictory_evidence() -> None:
    service, verdict_spy, _, _ = _build_service_with_spies()

    alert_1 = {
        "alert_id": "ALR-CONTRA-001",
        "rule_id": "UC-EDR-004",
        "severity": "medium",
        "created_at": "2026-10-16T11:00:00Z",
        "entities": {"hosts": [{"hostname": "CRM-APP01", "ip": "10.20.2.15"}]},
    }
    alert_2 = {
        "alert_id": "ALR-CONTRA-002",
        "rule_id": "UC-EDR-005",
        "severity": "medium",
        "created_at": "2026-10-16T11:01:00Z",
        "entities": {"hosts": [{"hostname": "CRM-APP01", "ip": "10.20.2.15"}]},
    }

    # El mismo event_id `EVT-SHARED-500` presenta contenidos distintos y veredictos
    # opuestos (true_positive vs false_positive) entre las dos investigaciones.
    ev_1 = [
        Evidence(
            source="edr_events",
            event_id="EVT-SHARED-500",
            timestamp="2026-10-16T11:00:00Z",
            raw={"summary": "Proceso powershell.exe ejecutado con éxito extrayendo credenciales."},
        )
    ]
    ev_2 = [
        Evidence(
            source="edr_events",
            event_id="EVT-SHARED-500",
            timestamp="2026-10-16T11:00:00Z",
            raw={"summary": "Falsa alarma del sensor: el proceso no llegó a iniciarse."},
        )
    ]

    analysis_1 = Analysis(
        title="Ejecución sospechosa en CRM-APP01",
        verdict="true_positive",
        confidence=0.80,
        summary="Se afirma ejecución maliciosa basada en EVT-SHARED-500.",
        findings=[
            Finding(
                statement="Ejecución maliciosa en CRM-APP01.",
                evidence_ids=["EVT-SHARED-500"],
            )
        ],
        signals=_signals(
            execution_or_access_confirmed=True,
            malicious_execution=True,
        ),
        proposed_actions=[],
        open_questions=[],
    )
    analysis_2 = Analysis(
        title="Descarte de ejecución en CRM-APP01",
        verdict="false_positive",
        confidence=0.85,
        summary="Se afirma que EVT-SHARED-500 es un falso positivo sin actividad real.",
        findings=[
            Finding(
                statement="El evento EVT-SHARED-500 corresponde a un error de telemetría.",
                evidence_ids=["EVT-SHARED-500"],
            )
        ],
        signals=_signals(blocked_before_effect=True),
        proposed_actions=[],
        open_questions=[],
    )

    context = ContextSnapshot(
        assets=[
            {
                "asset_id": "AST-CRM-01",
                "hostname": "CRM-APP01",
                "ip": "10.20.2.15",
                "criticality": "alta",
            }
        ]
    )

    group = IncidentGroup(
        incident_id="INC-003",
        alert_ids=["ALR-CONTRA-001", "ALR-CONTRA-002"],
        alerts=[alert_1, alert_2],
    )

    result = service.decide(
        group,
        analyses=[analysis_1, analysis_2],
        contexts=context,
        evidence=[ev_1, ev_2],
    )

    assert result.verdict == "needs_more_info"
    assert "contradic" in result.verdict_rationale.casefold()
    assert "EVT-SHARED-500" in result.verdict_rationale
    assert any("EVT-SHARED-500" in q for q in result.open_questions)
    assert verdict_spy.decide.call_count == 2


# ---------------------------------------------------------------------------
# Escenario 4: Información insuficiente para decidir
# ---------------------------------------------------------------------------


def test_scenario_4_insufficient_information_to_decide() -> None:
    service, verdict_spy, _, _ = _build_service_with_spies()

    alert_1 = {
        "alert_id": "ALR-INFO-001",
        "rule_id": "UC-IDP-003",
        "severity": "medium",
        "created_at": "2026-10-17T09:00:00Z",
        "entities": {"users": ["m.garcia"], "hosts": [{"hostname": "WKST-042"}]},
    }
    alert_2 = {
        "alert_id": "ALR-INFO-002",
        "rule_id": "UC-VPN-001",
        "severity": "medium",
        "created_at": "2026-10-17T09:05:00Z",
        "entities": {"users": ["m.garcia"], "hosts": [{"hostname": "WKST-042"}]},
    }

    # Análisis que propone true_positive pero sin evidencias disponibles que respalden
    # los hallazgos, más una segunda alerta explícitamente en needs_more_info.
    analysis_1 = Analysis(
        title="Inicio de sesión atípico de m.garcia",
        verdict="true_positive",
        confidence=0.75,
        summary="Sospecha de acceso no autorizado pero faltan logs de IdP.",
        findings=[
            Finding(
                statement="Acceso desde IP externa sin evento en logs.",
                evidence_ids=["EVT-MISSING-999"],
            )
        ],
        signals=_signals(execution_or_access_confirmed=True),
        proposed_actions=[],
        open_questions=["Confirmar con el usuario m.garcia si se encontraba de viaje."],
    )
    analysis_2 = Analysis(
        title="Conexión VPN pendiente de verificación",
        verdict="needs_more_info",
        confidence=0.45,
        summary="No hay telemetría suficiente para confirmar o descartar la sesión VPN.",
        findings=[],
        signals=_signals(),
        proposed_actions=[],
        open_questions=["Obtener registros completos del concentrador VPN."],
    )

    context = ContextSnapshot(
        assets=[{"hostname": "WKST-042", "criticality": "media"}],
        missing_lookups=["user:m.garcia"],
    )

    group = IncidentGroup(
        incident_id="INC-004",
        alert_ids=["ALR-INFO-001", "ALR-INFO-002"],
        alerts=[alert_1, alert_2],
    )

    result = service.decide(
        group,
        analyses=[analysis_1, analysis_2],
        contexts=context,
        evidence=[[], []],
    )

    assert result.verdict == "needs_more_info"
    assert "needs_more_info" in result.verdict_rationale
    assert len(result.open_questions) >= 2
    assert any("m.garcia" in q for q in result.open_questions)
    assert verdict_spy.decide.call_count == 2


# ---------------------------------------------------------------------------
# Escenario 5: Varias tiendas afectadas
# ---------------------------------------------------------------------------


def test_scenario_5_multiple_stores_affected() -> None:
    service, _, severity_spy, _ = _build_service_with_spies()

    alert_store_1 = {
        "alert_id": "ALR-STR-001",
        "rule_id": "UC-EDR-009",
        "severity": "medium",
        "created_at": "2026-10-18T14:00:00Z",
        "entities": {
            "hosts": [{"hostname": "POS-T01-01", "ip": "10.101.1.10"}],
            "ips": ["10.101.1.10"],
        },
    }
    alert_store_2 = {
        "alert_id": "ALR-STR-002",
        "rule_id": "UC-EDR-009",
        "severity": "medium",
        "created_at": "2026-10-18T14:03:00Z",
        "entities": {
            "hosts": [{"hostname": "POS-T02-01", "ip": "10.102.1.10"}],
            "ips": ["10.102.1.10"],
        },
    }
    alert_store_3 = {
        "alert_id": "ALR-STR-003",
        "rule_id": "UC-EDR-009",
        "severity": "medium",
        "created_at": "2026-10-18T14:06:00Z",
        "entities": {
            "hosts": [{"hostname": "POS-T03-01", "ip": "10.103.1.10"}],
            "ips": ["10.103.1.10"],
        },
    }

    # Cada TPV individual tiene criticidad "media", pero al afectar a 3 tiendas (T01, T02, T03)
    # simultáneamente, la severidad global debe reflejar el alcance multitienda y de pagos.
    context = ContextSnapshot(
        assets=[
            {
                "hostname": "POS-T01-01",
                "ip": "10.101.1.10",
                "type": "tpv",
                "zone": "STORES",
                "tienda_id": "T01",
                "criticality": "media",
            },
            {
                "hostname": "POS-T02-01",
                "ip": "10.102.1.10",
                "type": "tpv",
                "zone": "STORES",
                "tienda_id": "T02",
                "criticality": "media",
            },
            {
                "hostname": "POS-T03-01",
                "ip": "10.103.1.10",
                "type": "tpv",
                "zone": "STORES",
                "tienda_id": "T03",
                "criticality": "media",
            },
        ],
        network_zones=[
            {"zona": "STORES", "tienda_id": "T01", "cidr": "10.101.0.0/16"},
            {"zona": "STORES", "tienda_id": "T02", "cidr": "10.102.0.0/16"},
            {"zona": "STORES", "tienda_id": "T03", "cidr": "10.103.0.0/16"},
        ],
    )

    ev_list = [
        [Evidence(source="edr_events", event_id="EVT-POS-1", raw={"summary": "Proceso anómalo en POS-T01-01."})],
        [Evidence(source="edr_events", event_id="EVT-POS-2", raw={"summary": "Proceso anómalo en POS-T02-01."})],
        [Evidence(source="edr_events", event_id="EVT-POS-3", raw={"summary": "Proceso anómalo en POS-T03-01."})],
    ]

    analyses = [
        Analysis(
            title=f"Actividad maliciosa en TPV {i}",
            verdict="true_positive",
            confidence=0.90,
            summary="Acceso y ejecución confirmada en terminal TPV de tienda.",
            findings=[
                Finding(
                    statement=f"Ejecución confirmada en TPV {i}.",
                    evidence_ids=[f"EVT-POS-{i}"],
                )
            ],
            signals=_signals(
                execution_or_access_confirmed=True,
                sensitive_or_payment_data=True,
                malicious_execution=True,
            ),
            proposed_actions=[],
            open_questions=[],
        )
        for i in (1, 2, 3)
    ]

    group = IncidentGroup(
        incident_id="INC-005",
        alert_ids=["ALR-STR-001", "ALR-STR-002", "ALR-STR-003"],
        alerts=[alert_store_1, alert_store_2, alert_store_3],
    )

    result = service.decide(
        group,
        analyses=analyses,
        contexts=context,
        evidence=ev_list,
    )

    assert result.verdict == "true_positive"
    assert result.severity in ("high", "critical")
    assert "tiendas afectadas" in result.severity_rationale.casefold()
    assert "T01" in result.severity_rationale
    assert "T02" in result.severity_rationale
    assert "T03" in result.severity_rationale
    assert result.escalation.escalate is True
    assert "tiendas" in result.escalation.reason.casefold()
    assert severity_spy.calculate.call_count >= 1


# ---------------------------------------------------------------------------
# Escenario 6: Muchas alertas, pero impacto reducido
# ---------------------------------------------------------------------------


def test_scenario_6_many_alerts_but_reduced_impact() -> None:
    service, _, severity_spy, _ = _build_service_with_spies()

    alerts = []
    evidences = []
    analyses = []
    for idx in range(1, 9):
        aid = f"ALR-LOW-{idx:03d}"
        eid = f"EVT-PROXY-{idx:03d}"
        alerts.append(
            {
                "alert_id": aid,
                "rule_id": "UC-EML-001",
                "severity": "low",
                "created_at": f"2026-10-19T08:{idx:02d}:00Z",
                "entities": {
                    "hosts": [{"hostname": "WKST-105", "ip": "10.50.1.105"}],
                    "ips": ["10.50.1.105"],
                },
            }
        )
        evidences.append(
            [
                Evidence(
                    source="email",
                    event_id=eid,
                    timestamp=f"2026-10-19T08:{idx:02d}:00Z",
                    raw={"summary": "Correo de spam/phishing bloqueado en pasarela antes de entrega."},
                )
            ]
        )
        analyses.append(
            Analysis(
                title=f"Intento bloqueado {idx}",
                verdict="true_positive",
                confidence=0.88,
                summary="Intento bloqueado por pasarela sin interacción ni ejecución.",
                findings=[
                    Finding(
                        statement="Bloqueo confirmado en pasarela antes de efecto.",
                        evidence_ids=[eid],
                    )
                ],
                signals=_signals(
                    blocked_before_effect=True,
                    execution_or_access_confirmed=False,
                    malicious_execution=False,
                ),
                proposed_actions=[],
                open_questions=[],
            )
        )

    context = ContextSnapshot(
        assets=[
            {
                "asset_id": "AST-WKST-105",
                "hostname": "WKST-105",
                "ip": "10.50.1.105",
                "type": "puesto de trabajo",
                "criticality": "baja",
            }
        ]
    )

    group = IncidentGroup(
        incident_id="INC-006",
        alert_ids=[a["alert_id"] for a in alerts],
        alerts=alerts,
    )

    result = service.decide(
        group,
        analyses=analyses,
        contexts=context,
        evidence=evidences,
    )

    # 8 alertas de severidad low sobre un único activo de criticidad baja y bloqueadas
    # antes de producir efecto NO deben inflar la severidad.
    assert result.verdict == "true_positive"
    assert result.severity in ("informational", "low")
    assert "no se aplica media simple ni incremento automático por volumen" in result.severity_rationale
    assert severity_spy.calculate.call_count >= 1


# ---------------------------------------------------------------------------
# Escenario 7: Incidente crítico que requiere escalado inmediato
# ---------------------------------------------------------------------------


def test_scenario_7_critical_incident_requiring_immediate_escalation() -> None:
    service, _, _, escalation_spy = _build_service_with_spies()

    alert_1 = {
        "alert_id": "ALR-ESC-001",
        "rule_id": "UC-DLP-001",
        "severity": "critical",
        "created_at": "2026-10-20T22:10:00Z",
        "entities": {
            "hosts": [{"hostname": "SQL-CRM01", "ip": "10.20.2.10"}],
            "ips": ["10.20.2.10"],
            "users": ["adm.db"],
        },
    }
    alert_2 = {
        "alert_id": "ALR-ESC-002",
        "rule_id": "UC-IDP-005",
        "severity": "high",
        "created_at": "2026-10-20T22:14:00Z",
        "entities": {
            "hosts": [{"hostname": "SQL-CRM01", "ip": "10.20.2.10"}],
            "ips": ["10.20.2.10"],
            "users": ["adm.db"],
        },
    }

    context = ContextSnapshot(
        assets=[
            {
                "asset_id": "AST-CRM-DB",
                "hostname": "SQL-CRM01",
                "ip": "10.20.2.10",
                "type": "servidor",
                "zone": "DC-SERVERS",
                "criticality": "crítica",
                "business_service": "CRM y base de clientes (RGPD)",
            }
        ],
        services=[
            {
                "servicio": "CRM y base de clientes (RGPD)",
                "criticidad": "crítica",
                "responsable": "Laura Vidal",
            }
        ],
        users=[{"username": "adm.db", "privileged": True}],
    )

    ev_1 = [
        Evidence(
            source="sql_audit",
            event_id="EVT-SQL-701",
            timestamp="2026-10-20T22:09:30Z",
            raw={"summary": "Volcado masivo de tabla clientes (1,3M registros) desde SQL-CRM01."},
        )
    ]
    ev_2 = [
        Evidence(
            source="dlp",
            event_id="EVT-DLP-702",
            timestamp="2026-10-20T22:13:50Z",
            raw={"summary": "Exfiltración de archivo cifrado con PII de clientes hacia IP externa."},
        )
    ]

    analysis_1 = Analysis(
        title="Extracción masiva en base de datos SQL-CRM01",
        verdict="true_positive",
        confidence=0.96,
        summary="Compromiso de cuenta privilegiada adm.db y volcado masivo del CRM.",
        findings=[
            Finding(
                statement="Volcado masivo ejecutado por adm.db fuera de JUMP01.",
                evidence_ids=["EVT-SQL-701"],
            )
        ],
        signals=_signals(
            execution_or_access_confirmed=True,
            privileged_or_vip=True,
            sensitive_or_payment_data=True,
            credentials_compromised=True,
            personal_data_exposure=True,
            attack_chain=True,
        ),
        proposed_actions=[],
        open_questions=[],
    )
    analysis_2 = Analysis(
        title="Exfiltración de datos personales de clientes",
        verdict="true_positive",
        confidence=0.94,
        summary="Salida confirmada de datos personales de clientes (RGPD).",
        findings=[
            Finding(
                statement="Transferencia externa detectada por DLP.",
                evidence_ids=["EVT-DLP-702"],
            )
        ],
        signals=_signals(
            execution_or_access_confirmed=True,
            privileged_or_vip=True,
            sensitive_or_payment_data=True,
            personal_data_exposure=True,
            attack_chain=True,
        ),
        proposed_actions=[],
        open_questions=[],
    )

    group = IncidentGroup(
        incident_id="INC-007",
        alert_ids=["ALR-ESC-001", "ALR-ESC-002"],
        alerts=[alert_1, alert_2],
    )

    result = service.decide(
        group,
        analyses=[analysis_1, analysis_2],
        contexts=context,
        evidence=[ev_1, ev_2],
    )

    assert result.verdict == "true_positive"
    assert result.severity == "critical"
    assert result.escalation.escalate is True
    assert result.escalation.to == "N2 de guardia"
    assert "CISO" in result.escalation.reason
    assert "DPO" in result.escalation.reason
    assert "credenciales comprometidas" in result.escalation.reason
    # Comprobar que los motivos no estén duplicados aunque ambas alertas compartan señales.
    assert result.escalation.reason.count("DPO") == 1
    assert escalation_spy.decide.call_count >= 1


# ---------------------------------------------------------------------------
# Escenario 8: Una parte del incidente está autorizada y otra contiene actividad maliciosa
# ---------------------------------------------------------------------------


def test_scenario_8_partial_authorization_and_confirmed_malicious_activity() -> None:
    service, verdict_spy, severity_spy, escalation_spy = _build_service_with_spies()

    # Alerta 1: Mantenimiento autorizado sobre WEB-ECOM01 (benign_true_positive).
    alert_authorized = {
        "alert_id": "ALR-MIX-001",
        "rule_id": "UC-CLD-001",
        "severity": "medium",
        "created_at": "2026-10-09T10:30:00Z",
        "entities": {
            "hosts": [{"hostname": "WEB-ECOM01", "ip": "10.30.1.11"}],
            "ips": ["10.30.1.11"],
        },
    }
    # Alerta 2: En el mismo marco temporal, un atacante aprovecha credenciales robadas
    # para ejecutar malware y establecer persistencia (true_positive).
    alert_malicious = {
        "alert_id": "ALR-MIX-002",
        "rule_id": "UC-EDR-002",
        "severity": "high",
        "created_at": "2026-10-09T10:42:00Z",
        "entities": {
            "hosts": [{"hostname": "WEB-ECOM01", "ip": "10.30.1.11"}],
            "ips": ["10.30.1.11"],
        },
    }

    change_record = {
        "id": "CHG-2026-099",
        "inicio": "2026-10-09T08:00:00",
        "fin": "2026-10-09T14:00:00",
        "detalle": "Despliegue programado en frontal WEB-ECOM01 (08:00-14:00).",
        "activos": ["WEB-ECOM01"],
    }
    context = ContextSnapshot(
        assets=[
            {
                "asset_id": "AST-WEB-01",
                "hostname": "WEB-ECOM01",
                "ip": "10.30.1.11",
                "type": "frontal web",
                "zone": "DMZ",
                "criticality": "crítica",
                "business_service": "Tienda online y app",
            }
        ],
        changes=[change_record],
    )

    ev_auth = [
        Evidence(
            source="cloudtrail",
            event_id="EVT-CLD-301",
            timestamp="2026-10-09T10:30:00Z",
            raw={"summary": "Actualización de configuración dentro del cambio CHG-2026-099."},
        )
    ]
    ev_mal = [
        Evidence(
            source="edr_events",
            event_id="EVT-EDR-302",
            timestamp="2026-10-09T10:42:00Z",
            raw={"summary": "Descarga y ejecución de webshell no autorizada en WEB-ECOM01."},
        )
    ]

    analysis_auth = Analysis(
        title="Cambio de configuración autorizado en WEB-ECOM01",
        verdict="benign_true_positive",
        confidence=0.91,
        summary="La alerta ALR-MIX-001 está cubierta por el cambio aprobado CHG-2026-099.",
        findings=[
            Finding(
                statement="Despliegue programado conforme a CHG-2026-099.",
                evidence_ids=["EVT-CLD-301", "CHG-2026-099"],
            )
        ],
        signals=_signals(authorized_activity=True),
        proposed_actions=[],
        open_questions=[],
    )
    analysis_mal = Analysis(
        title="Instalación de webshell maliciosa en WEB-ECOM01",
        verdict="true_positive",
        confidence=0.95,
        summary="Ejecución de código malicioso y persistencia fuera del alcance del cambio.",
        findings=[
            Finding(
                statement="Webshell ejecutada en WEB-ECOM01 con conexión C2 externa.",
                evidence_ids=["EVT-EDR-302"],
            )
        ],
        signals=_signals(
            execution_or_access_confirmed=True,
            malicious_execution=True,
            persistence=True,
        ),
        proposed_actions=[],
        open_questions=[],
    )

    group = IncidentGroup(
        incident_id="INC-008",
        alert_ids=["ALR-MIX-001", "ALR-MIX-002"],
        alerts=[alert_authorized, alert_malicious],
        investigations=[
            AlertInvestigationInput(
                alert_id="ALR-MIX-001",
                alert=alert_authorized,
                analysis=analysis_auth,
                context=context,
                evidence=ev_auth,
            ),
            AlertInvestigationInput(
                alert_id="ALR-MIX-002",
                alert=alert_malicious,
                analysis=analysis_mal,
                context=context,
                evidence=ev_mal,
            ),
        ],
    )

    result = service.decide(group)

    # No debe clasificar el incidente como benigno: debe mantener true_positive
    # y señalar qué parte está autorizada y qué parte es maliciosa.
    assert result.verdict == "true_positive"
    assert "ALR-MIX-002" in result.verdict_rationale
    assert "ALR-MIX-001" in result.verdict_rationale
    assert "autorizada" in result.verdict_rationale.casefold()
    assert result.severity == "critical"
    assert result.escalation.escalate is True
    assert result.escalation.to == "N2 de guardia"
    # La evidencia maliciosa debe figurar primero en key_evidence_ids.
    assert result.key_evidence_ids[0] == "EVT-EDR-302"
    assert "EVT-CLD-301" in result.key_evidence_ids
    assert verdict_spy.decide.call_count == 2
    assert severity_spy.calculate.call_count >= 1
    assert escalation_spy.decide.call_count >= 1


# ---------------------------------------------------------------------------
# Pruebas adicionales de contrato (False Positive, alcance de cambio y OT)
# ---------------------------------------------------------------------------


def test_false_positive_incident_consolidation() -> None:
    service, verdict_spy, _, _ = _build_service_with_spies()

    alert_1 = {
        "alert_id": "ALR-FP-001",
        "rule_id": "UC-WEB-001",
        "severity": "low",
        "created_at": "2026-10-21T10:00:00Z",
        "entities": {"hosts": [{"hostname": "WEB-ECOM02"}]},
    }
    alert_2 = {
        "alert_id": "ALR-FP-002",
        "rule_id": "UC-WEB-001",
        "severity": "low",
        "created_at": "2026-10-21T10:02:00Z",
        "entities": {"hosts": [{"hostname": "WEB-ECOM02"}]},
    }

    ev_1 = [Evidence(source="waf", event_id="EVT-FP-1", raw={"status": 200})]
    ev_2 = [Evidence(source="waf", event_id="EVT-FP-2", raw={"status": 200})]

    analysis_1 = Analysis(
        title="Tráfico legítimo clasificado erróneamente",
        verdict="false_positive",
        confidence=0.92,
        summary="Petición GET estática sin payload malicioso.",
        findings=[Finding(statement="Petición benigna en WAF.", evidence_ids=["EVT-FP-1"])],
        signals=_signals(blocked_before_effect=True),
        proposed_actions=[],
        open_questions=[],
    )
    analysis_2 = Analysis(
        title="Segunda petición benigna de estáticos",
        verdict="false_positive",
        confidence=0.90,
        summary="Petición de recursos estáticos legítima.",
        findings=[Finding(statement="Recurso CSS legítimo.", evidence_ids=["EVT-FP-2"])],
        signals=_signals(blocked_before_effect=True),
        proposed_actions=[],
        open_questions=[],
    )

    context = ContextSnapshot(
        assets=[{"hostname": "WEB-ECOM02", "criticality": "media"}]
    )

    result = service.decide(
        {"alert_ids": ["ALR-FP-001", "ALR-FP-002"], "alerts": [alert_1, alert_2]},
        analyses=[analysis_1, analysis_2],
        contexts=context,
        evidence=[ev_1, ev_2],
    )

    assert result.verdict == "false_positive"
    assert result.confidence >= 0.85
    assert result.escalation.escalate is False
    assert result.escalation.to == ""
    assert result.key_evidence_ids == ["EVT-FP-1", "EVT-FP-2"]
    assert verdict_spy.decide.call_count == 2


def test_authorization_scope_mismatch_downgrades_to_needs_more_info() -> None:
    service, _, _, _ = _build_service_with_spies()

    alert = {
        "alert_id": "ALR-SCOPE-001",
        "rule_id": "UC-NET-003",
        "severity": "medium",
        "created_at": "2026-10-14T02:15:00Z",
        "entities": {"hosts": [{"hostname": "PLC-SORT01"}]},
    }
    change_record = {
        "id": "CHG-2026-044",
        "inicio": "2026-10-14T01:00:00",
        "fin": "2026-10-14T05:00:00",
        "detalle": "Escaneo autorizado exclusivamente sobre WEB-ECOM01 (01:00-05:00).",
        "activos": ["WEB-ECOM01"],
    }
    context = ContextSnapshot(
        assets=[
            {
                "hostname": "PLC-SORT01",
                "zone": "LOGISTICS-OT",
                "criticality": "crítica",
            }
        ],
        changes=[change_record],
    )
    ev = [
        Evidence(
            source="firewall",
            event_id="EVT-OT-1",
            timestamp="2026-10-14T02:15:00Z",
            raw={"dst": "PLC-SORT01"},
        )
    ]
    analysis = Analysis(
        title="Actividad en red OT atribuida erróneamente a cambio web",
        verdict="benign_true_positive",
        confidence=0.85,
        summary="Intento de justificar tráfico en PLC-SORT01 con CHG-2026-044.",
        findings=[
            Finding(
                statement="Tráfico hacia PLC-SORT01 durante CHG-2026-044.",
                evidence_ids=["EVT-OT-1", "CHG-2026-044"],
            )
        ],
        signals=_signals(authorized_activity=True),
        proposed_actions=[],
        open_questions=[],
    )

    result = service.decide(
        IncidentGroup(alert_ids=["ALR-SCOPE-001"], alerts=[alert]),
        analyses=[analysis],
        contexts=context,
        evidence=[ev],
    )

    # El activo PLC-SORT01 no coincide con el alcance del cambio (WEB-ECOM01),
    # por lo que debe rechazarse benign_true_positive y escalar por zona OT / crítica.
    assert result.verdict == "needs_more_info"
    assert "alcance del cambio" in result.verdict_rationale
    assert result.escalation.escalate is True
    assert "LOGISTICS-OT" in result.escalation.reason

