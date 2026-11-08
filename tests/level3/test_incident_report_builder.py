"""Tests unitarios para IncidentReportBuilder (Fase 3 - N3).

Cubre todos los requisitos obligatorios:
1. Construcción correcta del informe.
2. Inclusión de la cronología.
3. Inclusión del alcance e impacto.
4. Conservación de identificadores.
5. Inclusión de evidencias y trazabilidad.
6. Gestión de campos opcionales.
7. Validación del modelo de salida contra el esquema oficial de Deloitte.
8. Gestión de información incompleta.
"""
from __future__ import annotations

import json
from pathlib import Path
import pytest

from src.triage.level3.incident_report_builder import (
    IncidentReport,
    IncidentReportBuilder,
    TimelineEntry,
)
from src.triage.level3.scope_analyzer import ScopeAnalysis, ScopeAnalyzer


@pytest.fixture
def builder() -> IncidentReportBuilder:
    return IncidentReportBuilder()


@pytest.fixture
def sample_scope() -> ScopeAnalysis:
    return ScopeAnalysis(
        affected_assets=["WEB-ECOM01", "SQL-CRM01"],
        affected_users=["adm.gonzalez"],
        affected_services=["Tienda online y app", "CRM y datos de clientes (1,3 M registros, RGPD)"],
        affected_data="Exfiltración confirmada de: Datos personales de clientes (RGPD)",
        affected_network_zones=["DMZ", "DC-SERVERS"],
        business_impact="Afectación a la venta online. Brecha de datos notificable a la AEPD en 72 h.",
        impact_level="critical",
        confirmed_findings=["Ejecución de web shell en WEB-ECOM01", "Exfiltración de 15 MB de datos"],
        suspected_findings=["Posible persistencia en SQL-CRM01"],
        unknowns=["Se desconoce si se comprometieron otras credenciales"],
    )


@pytest.fixture
def sample_reconstruction() -> dict:
    return {
        "patient_zero": "WEB-ECOM01",
        "initial_access": "Explotación de vulnerabilidad en pasarela web",
        "root_cause": "Fallo de inyección en API expuesta sin autenticación previa",
        "timeline": [
            {
                "timestamp": "2026-10-15T08:30:00Z",
                "event_id": "EVT-1001",
                "description": "Petición HTTP anómala con payload de inyección",
                "mitre": "T1190",
            },
            {
                "timestamp": "2026-10-15T08:32:00Z",
                "event_id": "EVT-1002",
                "description": "Ejecución de PowerShell y descarga de binario",
                "mitre": "T1059.001",
            },
        ],
        "open_questions": ["¿Se utilizó proxy residencial para ocultar la IP de origen?"],
    }


# 1. Construcción correcta del informe
def test_build_full_report(
    builder: IncidentReportBuilder,
    sample_scope: ScopeAnalysis,
    sample_reconstruction: dict,
) -> None:
    incident = {
        "incident_id": "INC-2026-0042",
        "title": "Ataque coordinado contra plataforma e-commerce",
        "alert_ids": ["ALT-101", "ALT-102", "ALT-103"],
    }
    bundle = {
        "incident_id": "INC-2026-0042",
        "alerts": [{"alert_id": "ALT-101"}],
    }

    report = builder.build(
        incident=incident,
        bundle=bundle,
        reconstruction=sample_reconstruction,
        scope=sample_scope,
    )

    assert isinstance(report, IncidentReport)
    assert report.incident_id == "INC-2026-0042"
    assert report.patient_zero == "WEB-ECOM01"
    assert report.initial_access == "Explotación de vulnerabilidad en pasarela web"
    assert report.root_cause == "Fallo de inyección en API expuesta sin autenticación previa"
    assert report.impact_level == "critical"
    assert len(report.timeline) == 2
    assert len(report.containment_plan) > 0


# 2. Inclusión de la cronología
def test_include_timeline_from_reconstruction(
    builder: IncidentReportBuilder,
    sample_scope: ScopeAnalysis,
    sample_reconstruction: dict,
) -> None:
    incident = {"incident_id": "INC-TIMELINE", "alert_ids": ["ALT-01"]}
    report = builder.build(incident, {}, sample_reconstruction, sample_scope)

    assert len(report.timeline) == 2
    assert report.timeline[0].timestamp == "2026-10-15T08:30:00Z"
    assert report.timeline[0].event_id == "EVT-1001"
    assert report.timeline[0].mitre == "T1190"
    assert "inyección" in report.timeline[0].description.lower()


# 3. Inclusión del alcance e impacto
def test_include_scope_and_impact(
    builder: IncidentReportBuilder,
    sample_scope: ScopeAnalysis,
    sample_reconstruction: dict,
) -> None:
    incident = {"incident_id": "INC-SCOPE", "alert_ids": ["ALT-01"]}
    report = builder.build(incident, {}, sample_reconstruction, sample_scope)

    assert report.scope.hosts == ["WEB-ECOM01", "SQL-CRM01"]
    assert report.scope.users == ["adm.gonzalez"]
    assert "RGPD" in report.scope.data
    assert "AEPD" in report.scope.business_impact or "venta online" in report.scope.business_impact.lower()


# 4. Conservación de identificadores
def test_preserve_identifiers(
    builder: IncidentReportBuilder,
    sample_scope: ScopeAnalysis,
    sample_reconstruction: dict,
) -> None:
    incident = {
        "ticket_id": "TKT-N2-8888",
        "alert_ids": ["ALT-A", "ALT-B", "ALT-C"],
    }
    bundle = {
        "tickets": [{"alert_ids": ["ALT-C", "ALT-D"]}],
    }

    report = builder.build(incident, bundle, sample_reconstruction, sample_scope)

    assert report.incident_id == "TKT-N2-8888"
    # Debe preservar la unión sin duplicados de todos los identificadores de alertas
    assert set(report.alert_ids) == {"ALT-A", "ALT-B", "ALT-C", "ALT-D"}


# 5. Inclusión de evidencias y trazabilidad
def test_include_evidence_and_traceability(
    builder: IncidentReportBuilder,
    sample_scope: ScopeAnalysis,
    sample_reconstruction: dict,
) -> None:
    incident = {"incident_id": "INC-EV", "alert_ids": ["ALT-01"]}
    report = builder.build(incident, {}, sample_reconstruction, sample_scope)

    # Hallazgos confirmados y sospechas trazables
    assert len(report.confirmed_findings) > 0
    assert "WEB-ECOM01" in report.confirmed_findings[0]
    assert len(report.suspected_findings) > 0


# 6. Gestión de campos opcionales
def test_optional_fields_handling(
    builder: IncidentReportBuilder,
    sample_scope: ScopeAnalysis,
    sample_reconstruction: dict,
) -> None:
    incident = {
        "incident_id": "INC-OPT",
        "alert_ids": ["ALT-01"],
        "related_incidents": ["INC-2026-0001", "INC-2026-0005"],
    }

    report = builder.build(incident, {}, sample_reconstruction, sample_scope)

    assert report.related_incidents == ["INC-2026-0001", "INC-2026-0005"]
    assert report.eradication_and_recovery is not None
    assert len(report.eradication_and_recovery) > 0
    assert report.notifications is not None
    assert len(report.notifications) > 0
    assert report.detection_gaps is not None
    assert report.confidence is not None
    assert 0.0 <= report.confidence <= 1.0


# 7. Validación del modelo de salida contra el esquema oficial
def test_validate_output_schema(
    builder: IncidentReportBuilder,
    sample_scope: ScopeAnalysis,
    sample_reconstruction: dict,
) -> None:
    incident = {
        "incident_id": "INC-VALID-SCHEMA",
        "title": "Intrusión crítica en e-commerce",
        "alert_ids": ["ALT-01", "ALT-02"],
    }

    report = builder.build(incident, {}, sample_reconstruction, sample_scope)

    # El método validate utiliza jsonschema con informe_incidente.schema.json
    builder.validate(report)

    # Asegurar que la serialización a dict cumple con los tipos requeridos
    report_dict = report.to_dict()
    assert report_dict["incident_id"] == "INC-VALID-SCHEMA"
    assert isinstance(report_dict["scope"], dict)
    assert isinstance(report_dict["timeline"], list)
    assert isinstance(report_dict["containment_plan"], list)


# 8. Gestión de información incompleta
def test_incomplete_information_handling(builder: IncidentReportBuilder) -> None:
    # Todos los parámetros son None o vacíos
    report = builder.build(
        incident=None,
        bundle=None,
        reconstruction=None,
        scope=None,
    )

    assert isinstance(report, IncidentReport)
    assert report.incident_id == "INC-UNKNOWN"
    assert report.alert_ids == ["ALERT-UNKNOWN"]
    assert report.patient_zero == "Desconocido / En investigación"
    assert report.initial_access == "Desconocido / En investigación"
    assert report.root_cause == "En investigación"
    assert isinstance(report.timeline, list)
    assert len(report.timeline) > 0
    assert isinstance(report.containment_plan, list)

    # Debe seguir validando contra el esquema oficial incluso estando incompleto
    builder.validate(report)


# 9. Verificación del plan de contención acorde a la política SOC
def test_containment_plan_generation(
    builder: IncidentReportBuilder,
    sample_scope: ScopeAnalysis,
    sample_reconstruction: dict,
) -> None:
    incident = {"incident_id": "INC-CONT", "alert_ids": ["ALT-01"]}
    report = builder.build(incident, {}, sample_reconstruction, sample_scope)

    targets = [c.target for c in report.containment_plan]
    assert "WEB-ECOM01" in targets
    assert "adm.gonzalez" in targets

    # Aprobadores según política SOC de Tarvia
    approvers = [c.approver for c in report.containment_plan]
    assert any("N2" in app for app in approvers)


# 10. Verificación de notificaciones regulatorias (RGPD / AEPD en 72 h)
def test_notifications_generation(
    builder: IncidentReportBuilder,
    sample_scope: ScopeAnalysis,
    sample_reconstruction: dict,
) -> None:
    incident = {"incident_id": "INC-NOTIF", "alert_ids": ["ALT-01"]}
    report = builder.build(incident, {}, sample_reconstruction, sample_scope)

    # Dado que sample_scope incluye RGPD, debe exigir notificación AEPD en 72 h
    assert any("AEPD" in n and "72" in n for n in report.notifications)
    assert any("CISO" in n for n in report.notifications)
