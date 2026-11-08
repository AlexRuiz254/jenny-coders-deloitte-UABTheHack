"""Pruebas unitarias para `AttackReconstructor` (Nivel 3 SOC Tarvia)."""

from __future__ import annotations

import pytest

from src.triage.level3.attack_reconstructor import (
    AttackReconstruction,
    AttackReconstructor,
    InvestigationBundle,
)
from src.triage.models import Evidence


# ---------------------------------------------------------------------------
# 1. Orden cronológico correcto (incluyendo empates de timestamp en eventos distintos)
# ---------------------------------------------------------------------------


def test_1_chronological_order_and_same_timestamp_preserved() -> None:
    reconstructor = AttackReconstructor()

    bundle = InvestigationBundle(
        incident_id="INC-N3-001",
        alert_ids=["ALR-001"],
        evidence=[
            Evidence(
                source="edr_events",
                event_id="EDR-003",
                timestamp="2026-10-10T10:15:00Z",
                raw={
                    "hostname": "WS-BCN-101",
                    "user": "laura.vila",
                    "process_name": "powershell.exe",
                    "command_line": "powershell.exe -EncodedCommand ZQBjAGgAbwA=",
                },
            ),
            Evidence(
                source="email",
                event_id="EML-001",
                timestamp="2026-10-10T10:00:00Z",
                raw={
                    "sender": "soporte@externo-phish.example",
                    "recipient": "laura.vila@tarvia.example",
                    "subject": "Urgente: verifique su cuenta",
                    "message_id": "<msg-101@externo-phish.example>",
                    "verdict": "phishing",
                },
            ),
            Evidence(
                source="email_clicks",
                event_id="CLK-002A",
                timestamp="2026-10-10T10:05:00Z",
                raw={
                    "user": "laura.vila@tarvia.example",
                    "hostname": "WS-BCN-101",
                    "url": "https://login-tarvia-auth.example/auth",
                    "message_id": "<msg-101@externo-phish.example>",
                },
            ),
            # Segundo evento distinto con el MISMO timestamp exacto que CLK-002A
            Evidence(
                source="proxy",
                event_id="PRX-002B",
                timestamp="2026-10-10T10:05:00Z",
                raw={
                    "user": "laura.vila",
                    "hostname": "WS-BCN-101",
                    "url": "https://login-tarvia-auth.example/auth",
                    "category": "phishing",
                },
            ),
        ],
    )

    result = reconstructor.reconstruct(bundle)

    assert isinstance(result, AttackReconstruction)
    assert [ev.event_id for ev in result.timeline] == [
        "EML-001",
        "CLK-002A",
        "PRX-002B",
        "EDR-003",
    ]


# ---------------------------------------------------------------------------
# 2. Normalización de fechas UTC (con y sin zona horaria)
# ---------------------------------------------------------------------------


def test_2_utc_timestamp_normalization_with_and_without_timezone() -> None:
    reconstructor = AttackReconstructor()

    # 12:00+02:00 equivale a 10:00Z, por lo que debe ordenarse entre 09:30Z y 10:15 (naive->UTC)
    bundle = InvestigationBundle(
        incident_id="INC-N3-002",
        evidence=[
            Evidence(
                source="edr_events",
                event_id="EDR-103",
                timestamp="2026-10-10T10:15:00",  # Sin zona -> se asume UTC
                raw={
                    "hostname": "WS-BCN-202",
                    "user": "marc.soler",
                    "process_name": "cmd.exe",
                    "command_line": "vssadmin delete shadows /all /quiet",
                },
            ),
            Evidence(
                source="edr_events",
                event_id="EDR-102",
                timestamp="2026-10-10T12:00:00+02:00",  # Con zona +02:00 -> 10:00:00Z
                raw={
                    "hostname": "WS-BCN-202",
                    "user": "marc.soler",
                    "process_name": "powershell.exe",
                    "command_line": "powershell.exe -EncodedCommand AAA=",
                },
            ),
            Evidence(
                source="idp_signins",
                event_id="SIGN-101",
                timestamp="2026-10-10T09:30:00.500Z",  # Con Z explícita
                raw={
                    "user_upn": "marc.soler@tarvia.example",
                    "src_ip": "185.220.101.9",
                    "risk_level": "high",
                    "is_tor": True,
                },
            ),
        ],
    )

    result = reconstructor.reconstruct(bundle)

    assert [ev.event_id for ev in result.timeline] == [
        "SIGN-101",
        "EDR-102",
        "EDR-103",
    ]
    assert result.timeline[0].timestamp == "2026-10-10T09:30:00.500Z"
    assert result.timeline[1].timestamp == "2026-10-10T10:00:00Z"
    assert result.timeline[2].timestamp == "2026-10-10T10:15:00Z"
    assert all(ev.timestamp_valid for ev in result.timeline)


# ---------------------------------------------------------------------------
# 3. Eventos sin timestamp o con timestamp inválido
# ---------------------------------------------------------------------------


def test_3_events_with_missing_or_invalid_timestamp() -> None:
    reconstructor = AttackReconstructor()

    bundle = InvestigationBundle(
        incident_id="INC-N3-003",
        evidence=[
            Evidence(
                source="edr_events",
                event_id="EDR-NO-TS",
                timestamp=None,
                raw={
                    "hostname": "WS-BCN-300",
                    "user": "ana.perez",
                    "process_name": "powershell.exe",
                    "command_line": "powershell -EncodedCommand ZZZ=",
                },
            ),
            Evidence(
                source="edr_events",
                event_id="EDR-BAD-TS",
                timestamp="fecha-corrupta-2026",
                raw={
                    "hostname": "WS-BCN-300",
                    "user": "ana.perez",
                    "process_name": "mimikatz.exe",
                    "command_line": "sekurlsa::logonpasswords lsass",
                },
            ),
            Evidence(
                source="email_clicks",
                event_id="CLK-VALID-TS",
                timestamp="2026-10-11T08:00:00Z",
                raw={
                    "user": "ana.perez@tarvia.example",
                    "hostname": "WS-BCN-300",
                    "url": "https://malicious-phish.example/login",
                },
            ),
        ],
    )

    result = reconstructor.reconstruct(bundle)

    # El evento con fecha válida va primero; los eventos sin fecha o con fecha inválida
    # se conservan al final sin detener la reconstrucción.
    assert [ev.event_id for ev in result.timeline] == [
        "CLK-VALID-TS",
        "EDR-NO-TS",
        "EDR-BAD-TS",
    ]
    assert result.timeline[0].timestamp_valid is True
    assert result.timeline[1].timestamp is None
    assert result.timeline[1].timestamp_valid is False
    assert result.timeline[2].timestamp is None
    assert result.timeline[2].timestamp_valid is False
    assert result.timeline[2].raw_timestamp == "fecha-corrupta-2026"
    assert any("EDR-NO-TS" in u for u in result.uncertainties)
    assert any("EDR-BAD-TS" in u for u in result.uncertainties)


# ---------------------------------------------------------------------------
# 4. Deduplicación por (source, event_id)
# ---------------------------------------------------------------------------


def test_4_deduplication_by_source_and_event_id() -> None:
    reconstructor = AttackReconstructor()

    bundle = InvestigationBundle(
        incident_id="INC-N3-004",
        evidence=[
            Evidence(
                source="edr_events",
                event_id="EDR-DUP-001",
                timestamp="2026-10-12T11:00:00Z",
                raw={
                    "hostname": "SRV-WEB01",
                    "user": "www-data",
                    "parent_process": "nginx",
                    "process_name": "bash",
                    "command_line": "bash -c whoami",
                },
            ),
            # Mismo event_id y misma fuente -> debe deduplicarse
            Evidence(
                source="edr_events",
                event_id="EDR-DUP-001",
                timestamp="2026-10-12T11:00:00Z",
                raw={
                    "hostname": "SRV-WEB01",
                    "user": "www-data",
                    "parent_process": "nginx",
                    "process_name": "bash",
                    "command_line": "bash -c whoami",
                },
            ),
            # Mismo timestamp pero distinto event_id -> NO debe eliminarse
            Evidence(
                source="waf",
                event_id="WAF-DUP-002",
                timestamp="2026-10-12T11:00:00Z",
                raw={
                    "host": "SRV-WEB01",
                    "src_ip": "198.51.100.77",
                    "uri": "/upload.php?cmd=whoami",
                    "rule_msg": "RCE Webshell attempt",
                    "action": "alert",
                },
            ),
        ],
    )

    result = reconstructor.reconstruct(bundle)

    assert len(result.timeline) == 2
    assert [ev.event_id for ev in result.timeline] == ["EDR-DUP-001", "WAF-DUP-002"]


# ---------------------------------------------------------------------------
# 5. Eventos relacionados por entidades compuestas y sesiones
# ---------------------------------------------------------------------------


def test_5_events_correlated_by_shared_entities_and_phases() -> None:
    reconstructor = AttackReconstructor()

    bundle = InvestigationBundle(
        incident_id="INC-N3-005",
        alert_ids=["ALR-501", "ALR-502", "ALR-503"],
        alerts=[
            {
                "alert_id": "ALR-501",
                "rule_id": "UC-EML-003",
                "related_events": ["CLK-501"],
            },
            {
                "alert_id": "ALR-502",
                "rule_id": "UC-EDR-002",
                "related_events": ["EDR-502"],
            },
            {
                "alert_id": "ALR-503",
                "rule_id": "UC-DLP-001",
                "related_events": ["DLP-503"],
            },
        ],
        evidence=[
            Evidence(
                source="email_clicks",
                event_id="CLK-501",
                timestamp="2026-10-13T09:00:00Z",
                raw={
                    "user": "carla.mora@tarvia.example",
                    "hostname": "WS-BCN-500",
                    "url": "https://cdn-update-tarvia.example/payload.ps1",
                    "message_id": "<msg-500@phish.example>",
                },
            ),
            Evidence(
                source="edr_events",
                event_id="EDR-502",
                timestamp="2026-10-13T09:03:00Z",
                raw={
                    "user": "TARVIA\\carla.mora",
                    "hostname": "WS-BCN-500",
                    "process_name": "powershell.exe",
                    "command_line": "powershell.exe -EncodedCommand SQBFAFgA",
                    "sha256": "a" * 64,
                },
            ),
            Evidence(
                source="dlp",
                event_id="DLP-503",
                timestamp="2026-10-13T09:10:00Z",
                raw={
                    "user": "carla.mora",
                    "hostname": "WS-BCN-500",
                    "channel": "web_upload",
                    "destination": "mega.nz",
                    "file_name": "clientes_vip.xlsx",
                    "file_size_mb": 120,
                    "sha256": "a" * 64,
                },
            ),
        ],
    )

    result = reconstructor.reconstruct(bundle)

    assert "EDR-502" in result.timeline[0].correlated_event_ids
    assert "DLP-503" in result.timeline[1].correlated_event_ids
    assert result.related_entities.users == ["carla.mora"]
    assert result.related_entities.hosts == ["WS-BCN-500"]
    assert ("a" * 64) in result.related_entities.hashes
    assert len(result.related_entities.relationships) >= 2
    assert [p.phase for p in result.attack_phases] == [
        "initial_access",
        "execution",
        "exfiltration",
    ]


# ---------------------------------------------------------------------------
# 6. Eventos que NO deben relacionarse (solo comparten una IP o un único usuario)
# ---------------------------------------------------------------------------


def test_6_events_sharing_only_single_ip_or_single_user_are_not_linked() -> None:
    reconstructor = AttackReconstructor()

    bundle = InvestigationBundle(
        incident_id="INC-N3-006",
        evidence=[
            # Evento sospechoso 1: Usuario jordi.puig en equipo WS-BCN-010
            Evidence(
                source="edr_events",
                event_id="EDR-601",
                timestamp="2026-10-14T10:00:00Z",
                raw={
                    "user": "jordi.puig",
                    "hostname": "WS-BCN-010",
                    "src_ip": "10.10.1.50",
                    "process_name": "powershell.exe",
                    "command_line": "powershell.exe -EncodedCommand AAA=",
                },
            ),
            # Evento sospechoso 2: Comparte ÚNICAMENTE la IP 10.10.1.50 (p. ej. NAT/DHCP)
            # pero otro usuario y otro equipo sin ningún otro indicador común.
            Evidence(
                source="waf",
                event_id="WAF-602",
                timestamp="2026-10-14T10:20:00Z",
                raw={
                    "user": "otro.usuario",
                    "hostname": "WS-MAD-999",
                    "src_ip": "10.10.1.50",
                    "uri": "/login?test=<script>",
                    "action": "block",
                },
            ),
            # Evento sospechoso 3: Comparte ÚNICAMENTE el usuario jordi.puig pero en otro
            # equipo/contexto aislado sin IP, sesión ni hash común.
            Evidence(
                source="dlp",
                event_id="DLP-603",
                timestamp="2026-10-14T11:00:00Z",
                raw={
                    "user": "jordi.puig",
                    "hostname": "LAPTOP-EXT-777",
                    "destination": "dropbox.com",
                    "file_size_mb": 80,
                },
            ),
        ],
    )

    result = reconstructor.reconstruct(bundle)

    for ev in result.timeline:
        assert ev.correlated_event_ids == []
    assert result.related_entities.relationships == []
    assert any("comparten únicamente la IP" in u for u in result.uncertainties)
    assert any("comparten únicamente el usuario" in u for u in result.uncertainties)


# ---------------------------------------------------------------------------
# 7. Identificación del posible paciente cero (distinto del primer evento observado)
# ---------------------------------------------------------------------------


def test_7_patient_zero_distinguished_from_earliest_observed_event() -> None:
    reconstructor = AttackReconstructor()

    bundle = InvestigationBundle(
        incident_id="INC-N3-007",
        evidence=[
            # Primer evento observado (07:00Z): actividad normal y benigna en otro equipo
            Evidence(
                source="sql_audit",
                event_id="SQL-BENIGN-000",
                timestamp="2026-10-15T07:00:00Z",
                raw={
                    "user": "svc_sql",
                    "client_host": "CRM-APP01",
                    "database": "CRM_PROD",
                    "statement_type": "SELECT",
                    "object": "dbo.Products",
                    "rows_returned": 5,
                },
            ),
            # Inicio real de la cadena de ataque (08:30Z): phishing clicado por elena.ros en WS-BCN-707
            Evidence(
                source="email_clicks",
                event_id="CLK-PZ-001",
                timestamp="2026-10-15T08:30:00Z",
                raw={
                    "user": "elena.ros@tarvia.example",
                    "hostname": "WS-BCN-707",
                    "url": "https://phish-tarvia.example/login",
                    "message_id": "<pz-msg@phish.example>",
                    "verdict": "phishing",
                    "action": "allowed",
                },
            ),
            # Ejecución posterior en el mismo equipo y usuario (08:32Z)
            Evidence(
                source="edr_events",
                event_id="EDR-PZ-002",
                timestamp="2026-10-15T08:32:00Z",
                raw={
                    "user": "TARVIA\\elena.ros",
                    "hostname": "WS-BCN-707",
                    "process_name": "powershell.exe",
                    "command_line": "powershell.exe -EncodedCommand ZZZ=",
                },
            ),
        ],
    )

    result = reconstructor.reconstruct(bundle)

    # El primer evento observado es SQL-BENIGN-000, pero el paciente cero es WS-BCN-707 / elena.ros (CLK-PZ-001)
    assert result.first_observed_event is not None
    assert result.first_observed_event.event_id == "SQL-BENIGN-000"
    assert result.first_suspicious_event is not None
    assert result.first_suspicious_event.event_id == "CLK-PZ-001"
    assert result.patient_zero.event_id == "CLK-PZ-001"
    assert result.patient_zero.host == "WS-BCN-707"
    assert result.patient_zero.user == "elena.ros"
    assert "WS-BCN-707" in result.patient_zero
    assert "elena.ros" in result.patient_zero
    assert result.patient_zero.first_observed_event_id == "SQL-BENIGN-000"
    assert result.patient_zero.status == "hypothesis"  # Mismo equipo/usuario no prueba causalidad.


def test_ordinary_click_and_blocked_attempt_do_not_confirm_attack_origin():
    click = Evidence(source="email_clicks", event_id="CLK-ORDINARY", timestamp="2026-10-08T08:00:00Z",
        raw={"user": "alice", "hostname": "WS-1", "url": "https://shop.example/products", "action": "allowed"})
    execution = Evidence(source="edr_events", event_id="EDR-EXEC", timestamp="2026-10-09T08:00:00Z",
        raw={"user": "alice", "hostname": "WS-1", "event_type": "process_start", "process_name": "powershell.exe",
             "command_line": "powershell -EncodedCommand AAA="})
    result = AttackReconstructor().reconstruct({"incident_id": "INC-CAUSAL", "evidence": [click, execution]})
    assert not result.timeline[0].is_suspicious
    assert result.initial_access.status == "undetermined"
    assert result.patient_zero.status == "hypothesis"
    blocked = Evidence(source="waf", event_id="WAF-BLOCKED", timestamp="2026-10-09T07:59:00Z",
        raw={"hostname": "WS-1", "rule_id": "UC-WEB-001", "action": "blocked"})
    execution.raw["parent_event_id"] = blocked.event_id
    result = AttackReconstructor().reconstruct({"incident_id": "INC-CAUSAL", "evidence": [blocked, execution]})
    assert result.initial_access.status == "hypothesis"
    assert not result.root_cause.is_confirmed


# ---------------------------------------------------------------------------
# 8. Causa raíz no demostrable (se reporta como hipótesis, no como confirmada)
# ---------------------------------------------------------------------------


def test_8_unprovable_root_cause_reported_as_hypothesis() -> None:
    reconstructor = AttackReconstructor()

    # Solo se observa un volcado de memoria de LSASS y movimiento lateral en un servidor,
    # sin ninguna evidencia de cómo entró inicialmente el atacante.
    bundle = InvestigationBundle(
        incident_id="INC-N3-008",
        evidence=[
            Evidence(
                source="edr_events",
                event_id="EDR-801",
                timestamp="2026-10-16T03:10:00Z",
                raw={
                    "hostname": "SRV-APP02",
                    "user": "svc_app",
                    "process_name": "procdump.exe",
                    "command_line": "procdump.exe -ma lsass.exe lsass.dmp",
                },
            ),
            Evidence(
                source="firewall",
                event_id="FW-802",
                timestamp="2026-10-16T03:14:00Z",
                raw={
                    "src_host": "SRV-APP02",
                    "user": "svc_app",
                    "src_ip": "10.20.1.30",
                    "dst_ip": "10.20.1.40",
                    "dst_port": 445,
                    "zone_src": "DC-SERVERS",
                    "zone_dst": "LOGISTICS-OT",
                    "action": "allow",
                },
            ),
        ],
    )

    result = reconstructor.reconstruct(bundle)

    assert result.initial_access.status == "undetermined"
    assert result.root_cause.is_confirmed is False
    assert result.root_cause.status in ("hypothesis", "undetermined")
    assert "no demostr" in result.root_cause.conclusion.casefold() or "hipótesis" in result.root_cause.conclusion.casefold()
    assert any("acceso inicial" in u.casefold() for u in result.uncertainties)


# ---------------------------------------------------------------------------
# 9. Reconstrucción con evidencias incompletas y bundle vacío
# ---------------------------------------------------------------------------


def test_9_reconstruction_with_incomplete_or_empty_evidence() -> None:
    reconstructor = AttackReconstructor()

    # Caso 9A: Evidencias parciales con truncamiento de búsqueda de logs
    partial_bundle = InvestigationBundle(
        incident_id="INC-N3-009A",
        evidence=[
            Evidence(
                source="edr_events",
                event_id="EDR-901",
                timestamp="2026-10-17T15:00:00Z",
                raw={
                    "hostname": "WS-BCN-901",
                    "user": "pau.font",
                    "process_name": "anydesk.exe",
                    "command_line": "anydesk.exe --start-service",
                },
            ),
            # Resumen de consulta truncada devuelto por EvidenceCollector
            Evidence(
                source="proxy",
                event_id=None,
                raw={"q": "WS-BCN-901", "count": 2000, "truncated": True},
            ),
        ],
    )

    partial_res = reconstructor.reconstruct(partial_bundle)
    assert len(partial_res.timeline) == 1
    assert partial_res.timeline[0].event_id == "EDR-901"
    assert any("truncada" in u.casefold() for u in partial_res.uncertainties)
    assert partial_res.root_cause.is_confirmed is False

    # Caso 9B: Bundle completamente vacío -> resultado indeterminado sin excepciones
    empty_res = reconstructor.reconstruct(InvestigationBundle(incident_id="INC-N3-009B"))
    assert empty_res.is_indeterminate is True
    assert empty_res.confidence == 0.0
    assert empty_res.patient_zero.status == "undetermined"
    assert empty_res.initial_access.status == "undetermined"
    assert empty_res.root_cause.status == "undetermined"
    assert empty_res.timeline == []


# ---------------------------------------------------------------------------
# 10. Conservación intacta de las referencias originales y exportación de esquema
# ---------------------------------------------------------------------------


def test_10_preservation_of_original_references_and_schema_export() -> None:
    reconstructor = AttackReconstructor()

    original_raw_1 = {
        "event_id": "WAF-1001",
        "host": "WEB-ECOM01",
        "src_ip": "203.0.113.55",
        "uri": "/api/checkout?id=1%20UNION%20SELECT%20*",
        "rule_id": "UC-WEB-001",
        "action": "alert",
    }
    original_raw_2 = {
        "event_id": "EDR-1002",
        "hostname": "WEB-ECOM01",
        "src_ip": "203.0.113.55",
        "parent_process": "nginx",
        "process_name": "sh",
        "command_line": "sh -c 'id; cat /etc/passwd'",
        "rule_id": "UC-EDR-009",
        "parent_event_id": "WAF-1001",  # Nexo explícito, no solo la misma IP y host.
    }

    bundle = InvestigationBundle(
        incident_id="INC-N3-010",
        alert_ids=["ALR-1001", "ALR-1002"],
        evidence=[
            Evidence(
                source="waf",
                event_id="WAF-1001",
                timestamp="2026-10-18T20:00:00Z",
                raw=original_raw_1,
            ),
            Evidence(
                source="edr_events",
                event_id="EDR-1002",
                timestamp="2026-10-18T20:01:00Z",
                raw=original_raw_2,
            ),
        ],
    )

    result = reconstructor.reconstruct(bundle)

    # Verificar que se conservan source, event_id, raw y MITRE oficiales sin inventar IDs
    assert result.timeline[0].source == "waf"
    assert result.timeline[0].event_id == "WAF-1001"
    assert result.timeline[0].raw == original_raw_1
    assert result.timeline[0].mitre == "T1190"

    assert result.timeline[1].source == "edr_events"
    assert result.timeline[1].event_id == "EDR-1002"
    assert result.timeline[1].raw == original_raw_2
    assert result.timeline[1].mitre == "T1505.003"

    assert result.supporting_evidence == ["WAF-1001", "EDR-1002"]
    assert "WAF-1001" in result.initial_access.supporting_evidence
    assert "WAF-1001" in result.patient_zero.supporting_evidence
    assert result.root_cause.is_confirmed is True

    # Verificar compatibilidad con `informe_incidente.schema.json`
    report_fields = result.to_incident_report_fields()
    assert report_fields["incident_id"] == "INC-N3-010"
    assert report_fields["alert_ids"] == ["ALR-1001", "ALR-1002"]
    assert len(report_fields["timeline"]) == 2
    assert report_fields["timeline"][0]["event_id"] == "WAF-1001"
    assert report_fields["timeline"][0]["mitre"] == "T1190"
