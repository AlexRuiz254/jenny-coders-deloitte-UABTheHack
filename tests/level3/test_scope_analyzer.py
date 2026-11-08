"""Tests unitarios para ScopeAnalyzer (Fase 3 - N3).

Cubre todos los requisitos obligatorios:
1. Identificación correcta de equipos afectados.
2. Identificación correcta de usuarios.
3. Identificación de servicios de negocio.
4. Identificación de zonas de red.
5. Detección de posible exposición de datos.
6. Diferenciación entre acceso y exfiltración.
7. Separación entre hallazgos confirmados y sospechas.
8. Evidencias insuficientes.
9. Bundle vacío.
10. Datos incompletos o campos opcionales.
"""
from __future__ import annotations

import pytest

from src.triage.level3.scope_analyzer import (
    InvestigationBundle,
    ScopeAnalysis,
    ScopeAnalyzer,
)


@pytest.fixture
def analyzer() -> ScopeAnalyzer:
    """Instancia base del analizador con catálogo predeterminado de Tarvia."""
    return ScopeAnalyzer()


# 1. Identificación correcta de equipos afectados
def test_identify_affected_assets(analyzer: ScopeAnalyzer) -> None:
    bundle = {
        "events": [
            {
                "hostname": "WEB-ECOM01",
                "event_type": "process_creation",
                "action": "executed",
                "command_line": "powershell.exe -enc aW52b2tlLW1pbWlrYXR6",
            },
            {
                "hostname": "WS-HQ-042",
                "event_type": "network_connection",
                "action": "blocked",
            },
        ],
        "alerts": [
            {
                "alert_id": "ALT-001",
                "hostname": "WEB-ECOM01",
                "rule_name": "Web Shell Execution",
                "status": "new",
                "verdict": "true_positive",
                "execution_confirmed": True,
            },
            {
                "alert_id": "ALT-002",
                "hostname": "WS-HQ-042",
                "rule_name": "Port Scan Blocked",
                "status": "new",
            },
        ],
    }

    result = analyzer.assess(bundle)

    assert "WEB-ECOM01" in result.affected_assets
    assert "WS-HQ-042" in result.affected_assets

    # WEB-ECOM01 tiene ejecución maliciosa confirmada
    confirmed = [a.asset_id for a in result.asset_details if a.status == "confirmed"]
    assert "WEB-ECOM01" in confirmed

    # WS-HQ-042 solo tuvo un intento bloqueado: no debe marcarse como comprometido
    suspected = [a.asset_id for a in result.asset_details if a.status == "suspected"]
    assert "WS-HQ-042" in suspected


# 2. Identificación correcta de usuarios
def test_identify_affected_users(analyzer: ScopeAnalyzer) -> None:
    bundle = {
        "events": [
            {
                "user": "adm.gonzalez",
                "event_type": "idp_signins",
                "status": "success",
                "anomalous": True,
            },
            {
                "user": "j.garcia",
                "event_type": "idp_signins",
                "status": "failure",
            },
        ],
        "alerts": [
            {
                "alert_id": "ALT-003",
                "username": "j.garcia",
                "rule_name": "Phishing email received",
            }
        ],
    }

    result = analyzer.assess(bundle)

    assert "adm.gonzalez" in result.affected_users
    assert "j.garcia" in result.affected_users

    # adm.gonzalez tiene inicio de sesión anómalo exitoso: confirmado
    confirmed_users = [u.username for u in result.user_details if u.status == "confirmed"]
    assert "adm.gonzalez" in confirmed_users

    # j.garcia solo recibió phishing y tuvo fallos: sospechoso / no comprometido
    suspected_users = [u.username for u in result.user_details if u.status == "suspected"]
    assert "j.garcia" in suspected_users


# 3. Identificación de servicios de negocio
def test_identify_business_services(analyzer: ScopeAnalyzer) -> None:
    bundle = {
        "events": [
            {
                "hostname": "SQL-CRM01",
                "event_type": "sql_audit",
                "action": "read",
            },
            {
                "hostname": "PAY-GW01",
                "event_type": "process_creation",
                "action": "executed",
            },
        ]
    }

    result = analyzer.assess(bundle)

    assert "Tienda online y app" in result.affected_services
    assert "Cobros online (PCI DSS)" in result.affected_services
    assert "CRM y datos de clientes (1,3 M registros, RGPD)" in result.affected_services


# 4. Identificación de zonas de red
def test_identify_network_zones(analyzer: ScopeAnalyzer) -> None:
    bundle = {
        "events": [
            {"src_ip": "10.50.10.15", "hostname": "WEB-ECOM01"},  # DMZ
            {"dest_ip": "10.20.1.5", "hostname": "SQL-CRM01"},    # DC-SERVERS
            {"src_ip": "10.10.5.20", "hostname": "WS-01"},        # HQ-USERS
        ]
    }

    result = analyzer.assess(bundle)

    assert "DMZ" in result.affected_network_zones
    assert "DC-SERVERS" in result.affected_network_zones
    assert "HQ-USERS" in result.affected_network_zones


# 5. Detección de posible exposición de datos
def test_data_exposure_detection(analyzer: ScopeAnalyzer) -> None:
    bundle = {
        "events": [
            {
                "event_type": "sql_audit",
                "query": "SELECT pan, cvv FROM tarjetas WHERE activo=1",
                "hostname": "PAY-GW01",
            }
        ]
    }

    result = analyzer.assess(bundle)

    assert "PCI DSS" in result.affected_data or "tarjetas" in result.affected_data.lower()


# 6. Diferenciación entre acceso y exfiltración
def test_differentiate_access_vs_exfiltration(analyzer: ScopeAnalyzer) -> None:
    # Caso A: Solo consulta / lectura a BD (acceso pero NO exfiltración)
    bundle_access_only = {
        "events": [
            {
                "event_type": "sql_audit",
                "query": "SELECT nombre, email, nif FROM clientes",
                "action": "read",
                "bytes_sent": 500,
            }
        ]
    }

    result_access = analyzer.assess(bundle_access_only)
    assert "Acceso detectado" in result_access.affected_data
    assert "Exfiltración confirmada" not in result_access.affected_data

    # Caso B: Transferencia masiva hacia destino externo (exfiltración confirmada)
    bundle_exfiltration = {
        "events": [
            {
                "event_type": "network_connection",
                "dest_host": "mega.nz",
                "dest_ip": "185.120.44.10",
                "bytes_sent": 45_000_000,
                "action": "transfer",
            }
        ]
    }

    result_exfil = analyzer.assess(bundle_exfiltration)
    assert "Exfiltración confirmada" in result_exfil.affected_data


# 7. Separación entre hallazgos confirmados y sospechas
def test_separation_of_confirmed_and_suspected_findings(analyzer: ScopeAnalyzer) -> None:
    bundle = {
        "events": [
            {
                "hostname": "WEB-ECOM01",
                "event_type": "malware_execution",
                "action": "executed",
            },
            {
                "hostname": "WS-099",
                "event_type": "network_connection",
                "action": "blocked",
            },
        ]
    }

    result = analyzer.assess(bundle)

    # WEB-ECOM01 en hallazgos confirmados
    assert any("WEB-ECOM01" in f for f in result.confirmed_findings)
    # WS-099 en hallazgos sospechosos
    assert any("WS-099" in f for f in result.suspected_findings)


# 8. Evidencias insuficientes
def test_insufficient_evidence(analyzer: ScopeAnalyzer) -> None:
    bundle = {
        "events": [
            {
                "hostname": "UNKNOWN-DEVICE",
                "event_type": "generic_ping",
                "action": "info",
            }
        ]
    }

    result = analyzer.assess(bundle)

    assert result.impact_level in ["low", "medium"]
    assert len(result.unknowns) > 0


# 9. Bundle vacío
def test_empty_bundle(analyzer: ScopeAnalyzer) -> None:
    # Probar con None
    res_none = analyzer.assess(None)
    assert isinstance(res_none, ScopeAnalysis)
    assert res_none.affected_assets == []
    assert res_none.affected_users == []
    assert res_none.impact_level == "low"
    assert len(res_none.unknowns) > 0

    # Probar con dict vacío
    res_empty_dict = analyzer.assess({})
    assert isinstance(res_empty_dict, ScopeAnalysis)
    assert res_empty_dict.affected_assets == []
    assert res_empty_dict.impact_level == "low"

    # Probar con modelo InvestigationBundle vacío
    res_bundle_obj = analyzer.assess(InvestigationBundle())
    assert isinstance(res_bundle_obj, ScopeAnalysis)
    assert res_bundle_obj.affected_assets == []
    assert res_bundle_obj.impact_level == "low"


# 10. Datos incompletos o campos opcionales
def test_incomplete_data_and_optional_fields(analyzer: ScopeAnalyzer) -> None:
    bundle = {
        "events": [
            {"random_key": "some_value"},
            {"hostname": None, "event_type": None},
            {"src_ip": "invalid-ip-string"},
        ],
        "alerts": [
            {"no_id": True}
        ],
        "entities": {
            "hosts": [None, 1234, {"host": "WS-TEST"}],
            "users": [None, "", {"username": "u_test"}],
        },
    }

    # No debe levantar ninguna excepción no controlada
    result = analyzer.assess(bundle)
    assert isinstance(result, ScopeAnalysis)
    assert "WS-TEST" in result.affected_assets
    assert "u_test" in result.affected_users


# Test adicional: Cálculo del impacto empresarial y severidad crítica
def test_critical_business_impact_calculation(analyzer: ScopeAnalyzer) -> None:
    bundle = {
        "events": [
            {
                "hostname": "WEB-ECOM01",
                "event_type": "process_creation",
                "action": "executed",
            },
            {
                "hostname": "SQL-CRM01",
                "event_type": "sql_audit",
                "query": "SELECT * FROM clientes",
                "action": "read",
            },
            {
                "dest_host": "mega.nz",
                "bytes_sent": 20_000_000,
            },
        ]
    }

    result = analyzer.assess(bundle)

    assert result.impact_level == "critical"
    # Debe mencionar la caída de e-commerce (120.000 €/h) o notificación AEPD en 72 h
    assert "120.000" in result.business_impact or "AEPD" in result.business_impact
