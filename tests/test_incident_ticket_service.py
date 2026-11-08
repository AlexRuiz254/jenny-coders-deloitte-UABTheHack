"""Pruebas unitarias para IncidentTicketService (Fase 2 de triaje SOC).

Comprueba los 10 requisitos mínimos y casos límite con datos simulados y mocks,
sin depender de APIs activas ni claves LLM.
"""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional
import pytest

import src
from src.triage.level2.incident_ticket_service import (
    EmptyGroupError,
    IncidentDecision,
    IncidentGroup,
    IncidentTicketService,
    IncompleteDecisionError,
    MissingInvestigationError,
    N1Investigation,
    PersistenceError,
)
from src.triage.models import (
    Escalation,
    IntelEntry,
    Ticket,
    TicketAction,
    TicketEvidence,
)
from src.triage.output.validation import validate_ticket


# =====================================================================
# Repositorio simulado en memoria para tests
# =====================================================================

class InMemoryTicketRepository:
    """Implementación en memoria de TicketRepository para pruebas unitarias."""

    def __init__(self) -> None:
        self.tickets: Dict[str, Dict[str, Any]] = {}
        self.save_calls: List[Dict[str, Any]] = []

    def save(self, record: Dict[str, Any], trace: List[Dict[str, Any]], *, allow_reprocess: bool = False) -> None:
        ticket_id = record["id"]
        if not allow_reprocess and ticket_id in self.tickets:
            raise ValueError(f"Ticket {ticket_id} ya existe en el repositorio.")
        self.tickets[ticket_id] = record
        self.save_calls.append({"record": record, "trace": trace})

    def get(self, ticket_id: str) -> Optional[Dict[str, Any]]:
        return self.tickets.get(ticket_id)

    def find_by_alert(self, alert_id: str) -> Optional[Dict[str, Any]]:
        for record in self.tickets.values():
            details = record.get("details", {})
            ticket_data = details.get("ticket", {})
            if alert_id in ticket_data.get("alert_ids", []):
                return record
        return None

    def list_recent(self, limit: int = 25) -> List[Dict[str, Any]]:
        return list(self.tickets.values())[:limit]


# =====================================================================
# Fixtures y Generadores de Datos Simulados
# =====================================================================

def make_sample_ticket(alert_id: str, host: str, user: str, event_id: str) -> Ticket:
    """Generar un ticket individual N1 simulado válido."""
    return Ticket(
        ticket_id=f"TKT-{alert_id}",
        alert_ids=[alert_id],
        title=f"Alerta N1 para {alert_id}",
        verdict="true_positive",
        confidence=0.85,
        severity="medium",
        summary=f"Investigación N1 individual para la alerta {alert_id} en el host {host}.",
        evidence=[
            TicketEvidence(source="waf", event_id=event_id, finding="Intento de SQL Injection detectado"),
        ],
        recommended_actions=[
            TicketAction(action="block_ip", target="192.168.1.100", requires_approval=True, justification="IP maliciosa"),
        ],
        escalation=Escalation(escalate=False),
        affected={
            "hosts": [host],
            "users": [user],
            "business_services": ["Portal Empleado"],
        },
        enrichment=[
            IntelEntry(indicator="192.168.1.100", type="ip", source="ti_feed", result="malicious_scanner"),
        ],
        mitre=["T1190"],
        triage_seconds=12.5,
    )


# =====================================================================
# 1. Un grupo con tres alertas genera un único ticket
# =====================================================================

def test_grupo_tres_alertas_genera_unico_ticket() -> None:
    repo = InMemoryTicketRepository()
    service = IncidentTicketService(repository=repo)

    group = IncidentGroup(
        incident_id="INC-20261108-001",
        alert_ids=["ALR-001", "ALR-002", "ALR-003"],
        justification="Alertas correlacionadas sobre el mismo activo en ventana de 30m.",
    )

    decision = IncidentDecision(
        verdict="true_positive",
        severity="high",
        confidence=0.95,
        escalation=Escalation(escalate=True, to="SOC N3", reason="Ataque coordinado en progreso"),
        justification="Múltiples alertas confirman compromiso de credenciales y movimiento lateral.",
    )

    investigations = {
        "ALR-001": make_sample_ticket("ALR-001", "SRV-APP01", "admin@tarvia.com", "EVT-101"),
        "ALR-002": make_sample_ticket("ALR-002", "SRV-APP01", "admin@tarvia.com", "EVT-102"),
        "ALR-003": make_sample_ticket("ALR-003", "SRV-DB01", "svc_sql@tarvia.com", "EVT-103"),
    }

    ticket = service.build_and_save(group, decision, investigations)

    assert isinstance(ticket, Ticket)
    assert ticket.ticket_id == "INC-20261108-001"
    assert len(repo.tickets) == 1
    assert "INC-20261108-001" in repo.tickets


# =====================================================================
# 2. Las tres alertas aparecen en el ticket
# =====================================================================

def test_tres_alertas_aparecen_en_ticket() -> None:
    repo = InMemoryTicketRepository()
    service = IncidentTicketService(repository=repo)

    alert_ids = ["ALR-ALPHA", "ALR-BETA", "ALR-GAMMA"]
    group = IncidentGroup(incident_id="INC-TRIPLET", alert_ids=alert_ids)
    decision = IncidentDecision(verdict="true_positive", severity="high")

    investigations = {
        aid: make_sample_ticket(aid, f"HOST-{i}", f"user{i}@tarvia.com", f"EVT-{i}")
        for i, aid in enumerate(alert_ids, start=1)
    }

    ticket = service.build_and_save(group, decision, investigations)

    assert set(ticket.alert_ids) == set(alert_ids)
    assert len(ticket.alert_ids) == 3


# =====================================================================
# 3. Las evidencias repetidas no se duplican
# =====================================================================

def test_evidencias_repetidas_no_se_duplican() -> None:
    repo = InMemoryTicketRepository()
    service = IncidentTicketService(repository=repo)

    group = IncidentGroup(incident_id="INC-DEDUP-EV", alert_ids=["ALR-01", "ALR-02"])
    decision = IncidentDecision(verdict="true_positive", severity="medium")

    # Ambas alertas comparten exactamente la misma evidencia
    identical_evidence = TicketEvidence(source="firewall", event_id="FW-9999", finding="Conexión C2 bloqueada")
    unique_evidence = TicketEvidence(source="edr", event_id="EDR-001", finding="Proceso powershell sospechoso")

    inv1 = N1Investigation(
        alert_id="ALR-01",
        evidence=[identical_evidence, unique_evidence],
        affected={"hosts": ["H1"]},
    )
    inv2 = N1Investigation(
        alert_id="ALR-02",
        evidence=[identical_evidence],  # Repetida
        affected={"hosts": ["H2"]},
    )

    ticket = service.build_and_save(group, decision, [inv1, inv2])

    assert len(ticket.evidence) == 2
    event_ids = [e.event_id for e in ticket.evidence]
    assert event_ids.count("FW-9999") == 1
    assert event_ids.count("EDR-001") == 1


# =====================================================================
# 4. Los activos y usuarios se consolidan correctamente
# =====================================================================

def test_activos_y_usuarios_se_consolidan_correctamente() -> None:
    repo = InMemoryTicketRepository()
    service = IncidentTicketService(repository=repo)

    group = IncidentGroup(incident_id="INC-AFFECTED", alert_ids=["ALR-A", "ALR-B", "ALR-C"])
    decision = IncidentDecision(verdict="true_positive", severity="critical")

    inv_a = N1Investigation(
        alert_id="ALR-A",
        affected={"hosts": ["SRV-WEB01"], "users": ["alice@tarvia.com", "shared_admin"]},
    )
    inv_b = N1Investigation(
        alert_id="ALR-B",
        affected={"hosts": ["SRV-WEB01", "SRV-WEB02"], "users": ["bob@tarvia.com"]},
    )
    inv_c = N1Investigation(
        alert_id="ALR-C",
        affected={"hosts": ["SRV-DB01"], "users": ["alice@tarvia.com"]},  # alice repetida
    )

    ticket = service.build_and_save(group, decision, [inv_a, inv_b, inv_c])

    assert set(ticket.affected["hosts"]) == {"SRV-WEB01", "SRV-WEB02", "SRV-DB01"}
    assert set(ticket.affected["users"]) == {"alice@tarvia.com", "shared_admin", "bob@tarvia.com"}
    assert len(ticket.affected["hosts"]) == 3
    assert len(ticket.affected["users"]) == 3


# =====================================================================
# 5. Se conservan el veredicto y la severidad recibidos
# =====================================================================

def test_se_conservan_veredicto_y_severidad() -> None:
    repo = InMemoryTicketRepository()
    service = IncidentTicketService(repository=repo)

    group = IncidentGroup(incident_id="INC-VERDICT-TEST", alert_ids=["ALR-1"])
    decision = IncidentDecision(
        verdict="benign_true_positive",
        severity="low",
        confidence=0.99,
        escalation=Escalation(escalate=False),
        justification="Cambio autorizado según CHG-2026-1031.",
    )

    inv = make_sample_ticket("ALR-1", "H1", "U1", "E1")
    ticket = service.build_and_save(group, decision, {"ALR-1": inv})

    assert ticket.verdict == "benign_true_positive"
    assert ticket.severity == "low"
    assert ticket.confidence == 0.99
    assert ticket.escalation.escalate is False
    assert "CHG-2026-1031" in ticket.severity_rationale


# =====================================================================
# 6. Se guardan correctamente los tickets
# =====================================================================

def test_se_guardan_correctamente_los_tickets() -> None:
    repo = InMemoryTicketRepository()
    service = IncidentTicketService(repository=repo)

    group = IncidentGroup(
        incident_id="INC-STORAGE-001",
        alert_ids=["ALR-STORE-1"],
        justification="Prueba de almacenamiento",
    )
    decision = IncidentDecision(verdict="true_positive", severity="high")
    inv = make_sample_ticket("ALR-STORE-1", "HOST-ST", "user@tarvia.com", "EV-ST")

    ticket = service.build_and_save(group, decision, [inv])

    stored_record = repo.get("INC-STORAGE-001")
    assert stored_record is not None
    assert stored_record["id"] == "INC-STORAGE-001"
    assert stored_record["alert_id"] == "ALR-STORE-1"
    assert stored_record["details"]["incident_id"] == "INC-STORAGE-001"
    assert stored_record["details"]["is_incident"] is True
    assert validate_ticket(stored_record["details"]["ticket"]) == ticket


# =====================================================================
# 7. Un grupo vacío produce un error controlado
# =====================================================================

def test_grupo_vacio_produce_error_controlado() -> None:
    repo = InMemoryTicketRepository()
    service = IncidentTicketService(repository=repo)

    decision = IncidentDecision(verdict="true_positive", severity="medium")

    # Grupo con lista vacía de alertas
    empty_group = IncidentGroup(incident_id="INC-EMPTY-1", alert_ids=[], alerts=[])

    with pytest.raises(EmptyGroupError) as exc_info:
        service.build_and_save(empty_group, decision, [])
    assert "vacío" in str(exc_info.value).lower()

    # Grupo None
    with pytest.raises(EmptyGroupError):
        service.build_and_save(None, decision, [])


# =====================================================================
# 8. Una investigación inexistente se gestiona correctamente
# =====================================================================

def test_investigacion_inexistente_gestion_correcta() -> None:
    repo = InMemoryTicketRepository()
    service = IncidentTicketService(repository=repo)

    group = IncidentGroup(incident_id="INC-MISSING", alert_ids=["ALR-EXIST", "ALR-MISSING"])
    decision = IncidentDecision(verdict="true_positive", severity="medium")

    # Solo proporcionamos investigación para ALR-EXIST
    investigations = {"ALR-EXIST": make_sample_ticket("ALR-EXIST", "H1", "U1", "E1")}

    # Por defecto debe fallar de forma controlada sin inventar datos
    with pytest.raises(MissingInvestigationError) as exc_info:
        service.build_and_save(group, decision, investigations)
    assert "ALR-MISSING" in str(exc_info.value)
    assert "Fase de investigación" in str(exc_info.value)

    # Con allow_missing_investigations=True, gestiona la ausencia añadiendo a open_questions
    ticket = service.build_and_save(
        group, decision, investigations, allow_missing_investigations=True
    )
    assert ticket is not None
    assert any("ALR-MISSING" in q for q in ticket.open_questions)


# =====================================================================
# 9. Un error de persistencia no devuelve un ticket como si se hubiera guardado
# =====================================================================

class FailingTicketRepository:
    """Repositorio que falla al intentar guardar."""

    def save(self, record: Dict[str, Any], trace: List[Dict[str, Any]], **kwargs: Any) -> None:
        raise RuntimeError("Error de I/O en base de datos: disco bloqueado.")

    def get(self, ticket_id: str) -> Optional[Dict[str, Any]]:
        return None


def test_error_persistencia_no_devuelve_ticket_como_guardado() -> None:
    failing_repo = FailingTicketRepository()
    service = IncidentTicketService(repository=failing_repo)

    group = IncidentGroup(incident_id="INC-FAIL-PERSIST", alert_ids=["ALR-F1"])
    decision = IncidentDecision(verdict="true_positive", severity="high")
    inv = make_sample_ticket("ALR-F1", "H1", "U1", "E1")

    with pytest.raises(PersistenceError) as exc_info:
        service.build_and_save(group, decision, [inv])

    assert "disco bloqueado" in str(exc_info.value)
    assert "Fase de persistencia" in str(exc_info.value)


# =====================================================================
# 10. Procesar dos veces el mismo incidente no genera duplicados
# =====================================================================

def test_procesar_dos_veces_mismo_incidente_no_genera_duplicados() -> None:
    repo = InMemoryTicketRepository()
    service = IncidentTicketService(repository=repo)

    group = IncidentGroup(incident_id="INC-IDEMPOTENT", alert_ids=["ALR-ID-1", "ALR-ID-2"])
    decision = IncidentDecision(verdict="true_positive", severity="medium")
    investigations = {
        "ALR-ID-1": make_sample_ticket("ALR-ID-1", "H1", "U1", "E1"),
        "ALR-ID-2": make_sample_ticket("ALR-ID-2", "H2", "U2", "E2"),
    }

    # Primera ejecución: crea y guarda
    ticket1 = service.build_and_save(group, decision, investigations)
    assert len(repo.tickets) == 1
    assert len(repo.save_calls) == 1

    # Segunda ejecución: recupera el existente sin llamar a save de nuevo
    ticket2 = service.build_and_save(group, decision, investigations)
    assert ticket2.ticket_id == ticket1.ticket_id
    assert len(repo.tickets) == 1
    assert len(repo.save_calls) == 1


# =====================================================================
# Pruebas Adicionales: IOCs, Acciones, MITRE y Decisión Incompleta
# =====================================================================

def test_ioc_enrichment_y_mitre_deduplicacion() -> None:
    repo = InMemoryTicketRepository()
    service = IncidentTicketService(repository=repo)

    group = IncidentGroup(incident_id="INC-ENRICH-MITRE", alert_ids=["ALR-1", "ALR-2"])
    decision = IncidentDecision(verdict="true_positive", severity="high")

    ioc1 = IntelEntry(indicator="10.0.0.1", type="ip", source="ti", result="scanner")
    ioc2 = IntelEntry(indicator="10.0.0.2", type="ip", source="ti", result="c2")

    inv1 = N1Investigation(alert_id="ALR-1", enrichment=[ioc1, ioc2], mitre=["T1190", "T1078"])
    inv2 = N1Investigation(alert_id="ALR-2", enrichment=[ioc1], mitre=["T1078", "T1059"])

    ticket = service.build_and_save(group, decision, [inv1, inv2])

    assert len(ticket.enrichment) == 2
    assert set(e.indicator for e in ticket.enrichment) == {"10.0.0.1", "10.0.0.2"}
    assert set(ticket.mitre) == {"T1190", "T1078", "T1059"}
    assert len(ticket.mitre) == 3


def test_decision_incompleta_produce_error() -> None:
    repo = InMemoryTicketRepository()
    service = IncidentTicketService(repository=repo)

    group = IncidentGroup(incident_id="INC-DEC-ERR", alert_ids=["ALR-1"])
    inv = make_sample_ticket("ALR-1", "H1", "U1", "E1")

    # Decisión sin severidad
    invalid_decision = {"verdict": "true_positive"}

    with pytest.raises(IncompleteDecisionError) as exc_info:
        service.build_and_save(group, invalid_decision, [inv])
    assert "Fase de decisión" in str(exc_info.value)


# =====================================================================
# Prueba con Repositorio SQLite Real en Disco Temporal
# =====================================================================

# =====================================================================
# Prueba con Repositorio SQLite Real en Disco Temporal
# =====================================================================

class RealSQLiteTicketRepository:
    """Implementación de repositorio SQLite real en disco para tests de integración."""

    def __init__(self, db_path) -> None:
        import sqlite3
        self.db_path = str(db_path)
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS tickets (
                    id TEXT PRIMARY KEY,
                    alert_id TEXT,
                    status TEXT,
                    created_at TEXT,
                    details TEXT,
                    trace TEXT
                );
                """
            )
            conn.commit()

    def save(self, record: Dict[str, Any], trace: List[Dict[str, Any]], *, allow_reprocess: bool = False) -> None:
        import sqlite3
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO tickets (id, alert_id, status, created_at, details, trace)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    record["id"],
                    record["alert_id"],
                    record["status"],
                    record["created_at"],
                    json.dumps(record["details"]),
                    json.dumps(trace),
                ),
            )
            conn.commit()

    def get(self, ticket_id: str) -> Optional[Dict[str, Any]]:
        import sqlite3
        with sqlite3.connect(self.db_path) as conn:
            cur = conn.cursor()
            cur.execute("SELECT id, alert_id, status, created_at, details, trace FROM tickets WHERE id = ?", (ticket_id,))
            row = cur.fetchone()
            if not row:
                return None
            return {
                "id": row[0],
                "alert_id": row[1],
                "status": row[2],
                "created_at": row[3],
                "details": json.loads(row[4]),
                "trace": json.loads(row[5]),
            }

    def list_recent(self, limit: int = 25) -> List[Dict[str, Any]]:
        import sqlite3
        with sqlite3.connect(self.db_path) as conn:
            cur = conn.cursor()
            cur.execute("SELECT id, alert_id, status, created_at, details, trace FROM tickets LIMIT ?", (limit,))
            rows = cur.fetchall()
            return [
                {
                    "id": r[0],
                    "alert_id": r[1],
                    "status": r[2],
                    "created_at": r[3],
                    "details": json.loads(r[4]),
                    "trace": json.loads(r[5]),
                }
                for r in rows
            ]


def test_persistencia_con_sqlite_real(tmp_path) -> None:
    db_file = tmp_path / "test_tickets.sqlite3"
    sqlite_repo = RealSQLiteTicketRepository(db_path=db_file)

    service = IncidentTicketService(repository=sqlite_repo)

    group = IncidentGroup(
        incident_id="INC-SQLITE-REAL",
        alert_ids=["ALR-SQL-1", "ALR-SQL-2"],
        justification="Incidente persistido en SQLite real",
    )
    decision = IncidentDecision(
        verdict="true_positive",
        severity="critical",
        confidence=0.97,
        escalation=Escalation(escalate=True, to="CISO", reason="Ataque a infraestructura crítica"),
    )
    inv1 = make_sample_ticket("ALR-SQL-1", "SRV-OT-01", "operator", "EV-OT-1")
    inv2 = make_sample_ticket("ALR-SQL-2", "SRV-OT-02", "operator", "EV-OT-2")

    ticket = service.build_and_save(group, decision, [inv1, inv2])

    assert ticket.ticket_id == "INC-SQLITE-REAL"
    assert ticket.severity == "critical"

    # Verificar que el registro se guardó físicamente en la base de datos SQLite
    saved_record = sqlite_repo.get("INC-SQLITE-REAL")
    assert saved_record is not None
    assert saved_record["id"] == "INC-SQLITE-REAL"
    assert saved_record["alert_id"] == "ALR-SQL-1"
    assert saved_record["details"]["ticket"]["verdict"] == "true_positive"

    # Segunda ejecución: prueba de idempotencia en SQLite real
    ticket2 = service.build_and_save(group, decision, [inv1, inv2])
    assert ticket2.ticket_id == ticket.ticket_id
    recent = sqlite_repo.list_recent(limit=10)
    # Debe haber exactamente 1 ticket guardado
    assert len([t for t in recent if t["id"] == "INC-SQLITE-REAL"]) == 1
