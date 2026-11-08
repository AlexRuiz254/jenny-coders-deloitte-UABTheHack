"""Reconstrucción cronológica y razonada de ataques para SOC Nivel 3 (N3).

Este módulo implementa `AttackReconstructor`, responsable de transformar un
`InvestigationBundle` (o colección de evidencias, alertas, análisis y tickets de
N1/N2) en un objeto estructurado `AttackReconstruction` sin realizar llamadas a
APIs externas ni inventar eventos o técnicas no respaldadas por las pruebas.

Contratos de integración N3:
- Entrada (desde Persona 1 `InvestigationExpander` o Persona 4 `Level3Orchestrator`):
  `InvestigationBundle` (o diccionario/objeto equivalente con `evidence`, `alerts`,
  `tickets`, `analyses`, `context`, `intel`).
- Salida (para Persona 3 `ScopeAnalyzer` / generador de `informe_incidente.schema.json`
  y Persona 4 `Level3Orchestrator`):
  `AttackReconstruction` con cronología normalizada en UTC, correlaciones verificadas,
  fases del ataque, distinción entre primer evento observado, primer evento sospechoso,
  paciente cero, vector de acceso inicial, causa raíz (confirmada, hipótesis o
  indeterminada), impacto técnico observable, entidades relacionadas, confianza,
  evidencias de soporte e incertidumbres.
"""

from __future__ import annotations

from bisect import bisect_right

from collections.abc import Mapping, Sequence
from datetime import datetime, timedelta, timezone
from ipaddress import ip_address
import json
import re
from typing import Any, Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field

from src.triage.models import (
    Analysis,
    ContextSnapshot,
    Evidence,
    IntelEntry,
    RawAlert,
    Ticket,
)
from src.triage.time_windows import parse_utc


ConclusionStatus = Literal["confirmed", "hypothesis", "undetermined"]

AttackPhaseId = Literal[
    "initial_access",
    "execution",
    "persistence",
    "privilege_escalation",
    "lateral_movement",
    "data_access",
    "exfiltration",
    "post_activity",
]

PHASE_LABELS: dict[AttackPhaseId, str] = {
    "initial_access": "Acceso inicial",
    "execution": "Ejecución",
    "persistence": "Persistencia",
    "privilege_escalation": "Escalada de privilegios",
    "lateral_movement": "Movimiento lateral",
    "data_access": "Acceso a información",
    "exfiltration": "Exfiltración",
    "post_activity": "Actividad posterior",
}

PHASE_ORDER: tuple[AttackPhaseId, ...] = (
    "initial_access",
    "execution",
    "persistence",
    "privilege_escalation",
    "lateral_movement",
    "data_access",
    "exfiltration",
    "post_activity",
)

# Catálogo oficial de reglas de Tarvia (de `01_contexto/catalogo_casos_de_uso.csv`).
# No se inventan técnicas MITRE: solo se asignan cuando provienen de la alerta/evento
# o coinciden con el rule_id oficial del catálogo del proyecto.
RULE_CATALOG: dict[str, dict[str, str]] = {
    "UC-EML-001": {"phase": "initial_access", "mitre": "T1566", "name": "Correo reportado como phishing"},
    "UC-EML-002": {"phase": "initial_access", "mitre": "T1566.001", "name": "Adjunto potencialmente malicioso entregado"},
    "UC-EML-003": {"phase": "initial_access", "mitre": "T1566.002", "name": "Clic en URL de phishing"},
    "UC-EML-004": {"phase": "post_activity", "mitre": "T1657", "name": "Petición de cambio de datos bancarios por correo"},
    "UC-IDP-001": {"phase": "initial_access", "mitre": "T1078", "name": "Viaje imposible"},
    "UC-IDP-002": {"phase": "initial_access", "mitre": "T1110.003", "name": "Password spraying"},
    "UC-IDP-003": {"phase": "privilege_escalation", "mitre": "T1621", "name": "Fatiga MFA"},
    "UC-IDP-004": {"phase": "initial_access", "mitre": "T1078", "name": "Inicio de sesión desde infraestructura anónima"},
    "UC-IDP-005": {"phase": "persistence", "mitre": "T1114.003", "name": "Regla de buzón sospechosa"},
    "UC-IDP-006": {"phase": "privilege_escalation", "mitre": "T1539", "name": "Reutilización de token de sesión (AiTM)"},
    "UC-IDP-007": {"phase": "persistence", "mitre": "T1550.001", "name": "Consentimiento OAuth a aplicación no verificada"},
    "UC-IDP-008": {"phase": "privilege_escalation", "mitre": "T1098", "name": "Alta en grupo privilegiado de AD"},
    "UC-EDR-001": {"phase": "execution", "mitre": "T1204.002", "name": "Proceso hijo sospechoso de Office o intérprete"},
    "UC-EDR-002": {"phase": "execution", "mitre": "T1059.001", "name": "PowerShell con comando codificado"},
    "UC-EDR-003": {"phase": "execution", "mitre": "T1204", "name": "Malware detectado por el antivirus"},
    "UC-EDR-004": {"phase": "privilege_escalation", "mitre": "T1003.001", "name": "Acceso a la memoria de LSASS"},
    "UC-EDR-005": {"phase": "post_activity", "mitre": "T1219", "name": "Herramienta de acceso remoto no autorizada"},
    "UC-EDR-006": {"phase": "post_activity", "mitre": "T1496", "name": "Comportamiento de minería de criptomonedas"},
    "UC-EDR-007": {"phase": "post_activity", "mitre": "T1490", "name": "Borrado de instantáneas de volumen"},
    "UC-EDR-008": {"phase": "lateral_movement", "mitre": "T1087.002", "name": "Comandos de reconocimiento de dominio"},
    "UC-EDR-009": {"phase": "persistence", "mitre": "T1505.003", "name": "Proceso sospechoso lanzado por servidor web"},
    "UC-EDR-010": {"phase": "privilege_escalation", "mitre": "T1555.003", "name": "Robo de credenciales de navegador"},
    "UC-EDR-011": {"phase": "post_activity", "mitre": "T1562.001", "name": "Manipulación o detención del agente EDR"},
    "UC-EDR-012": {"phase": "data_access", "mitre": "T1005", "name": "Lectura de memoria de aplicación de cobro (TPV)"},
    "UC-NET-001": {"phase": "post_activity", "mitre": "T1071.001", "name": "Beaconing a dominio poco frecuente"},
    "UC-NET-002": {"phase": "post_activity", "mitre": "T1071", "name": "Conexión a IP en lista de bloqueo de TI"},
    "UC-NET-003": {"phase": "lateral_movement", "mitre": "T1046", "name": "Escaneo de puertos interno"},
    "UC-NET-004": {"phase": "lateral_movement", "mitre": "T1021.002", "name": "Movimiento lateral SMB/RDP/PsExec"},
    "UC-NET-005": {"phase": "post_activity", "mitre": "T1568.002", "name": "Consulta DNS a dominio con aspecto DGA"},
    "UC-NET-006": {"phase": "exfiltration", "mitre": "T1048.003", "name": "Posible túnel DNS"},
    "UC-WEB-001": {"phase": "initial_access", "mitre": "T1190", "name": "Ataque de inyección contra aplicación web"},
    "UC-WEB-002": {"phase": "initial_access", "mitre": "T1110.004", "name": "Credential stuffing contra login de clientes"},
    "UC-WEB-003": {"phase": "post_activity", "mitre": "T1657", "name": "Toma de control de cuenta de cliente (ATO)"},
    "UC-CLD-001": {"phase": "initial_access", "mitre": "T1078.004", "name": "Uso de credenciales cloud desde ASN inusual"},
    "UC-CLD-002": {"phase": "persistence", "mitre": "T1098.001", "name": "Creación de identidad privilegiada en la nube"},
    "UC-CLD-003": {"phase": "exfiltration", "mitre": "T1537", "name": "Bucket de almacenamiento con acceso público"},
    "UC-CLD-004": {"phase": "data_access", "mitre": "T1530", "name": "Descarga masiva desde bucket crítico"},
    "UC-DLP-001": {"phase": "exfiltration", "mitre": "T1567.002", "name": "Subida masiva a almacenamiento personal"},
    "UC-DLP-002": {"phase": "exfiltration", "mitre": "T1048", "name": "Envío de datos personales a correo externo"},
    "UC-AI-001": {"phase": "initial_access", "mitre": "AML.T0051", "name": "Posible prompt injection en asistente Vela"},
    "UC-AI-002": {"phase": "data_access", "mitre": "AML.T0057", "name": "Intento de acceso a datos de otro cliente vía asistente"},
    "UC-OT-001": {"phase": "lateral_movement", "mitre": "T0886", "name": "Conexión a red OT desde origen no autorizado"},
    "UC-DEV-001": {"phase": "initial_access", "mitre": "T1195.002", "name": "Dependencia con script postinstall malicioso en CI/CD"},
    "UC-VPN-001": {"phase": "initial_access", "mitre": "T1133", "name": "Acceso VPN de proveedor fuera de horario u origen nuevo"},
}

_EMPTY_TOKENS = {"", "-", "none", "null", "n/a", "unknown", "desconocido", "ninguno"}
_HASH_LENGTHS = {32, 40, 64}


# ---------------------------------------------------------------------------
# Modelos de contrato local (compatibles con N1, N2 y N3)
# ---------------------------------------------------------------------------


class InvestigationBundle(BaseModel):
    """Contrato local provisional para el paquete de investigación N3 de Persona 1.

    Admite campos adicionales (`extra="allow"`) para garantizar compatibilidad
    con `InvestigationExpander` (Persona 1) y `Level3Orchestrator` (Persona 4).
    """

    model_config = ConfigDict(extra="allow")

    incident_id: str = ""
    alert_ids: list[str] = Field(default_factory=list)
    alerts: list[RawAlert] = Field(default_factory=list)
    evidence: list[Evidence | dict[str, Any]] = Field(default_factory=list)
    expanded_evidence: list[Evidence | dict[str, Any]] = Field(default_factory=list)
    events: list[Evidence | dict[str, Any]] = Field(default_factory=list)
    tickets: list[Ticket | dict[str, Any]] = Field(default_factory=list)
    incident_ticket: Ticket | dict[str, Any] | None = None
    analyses: list[Analysis | dict[str, Any]] = Field(default_factory=list)
    context: ContextSnapshot | dict[str, Any] = Field(default_factory=ContextSnapshot)
    contexts: list[ContextSnapshot | dict[str, Any]] = Field(default_factory=list)
    intel: list[IntelEntry | dict[str, Any]] = Field(default_factory=list)
    decision: Any = None


class TimelineEvent(BaseModel):
    """Evento normalizado y ordenado dentro de la cronología del incidente."""

    model_config = ConfigDict(extra="allow")

    timestamp: str | None = None
    raw_timestamp: str | None = None
    timestamp_valid: bool = True
    event_id: str | None = None
    source: str
    description: str
    mitre: str | None = None
    phase: AttackPhaseId | None = None
    is_suspicious: bool = False
    entities: dict[str, list[str]] = Field(default_factory=dict)
    correlated_event_ids: list[str] = Field(default_factory=list)
    correlation_reasons: list[str] = Field(default_factory=list)
    evidence_refs: list[str] = Field(default_factory=list)
    raw: dict[str, Any] = Field(default_factory=dict)

    def to_schema_item(self) -> dict[str, str]:
        """Serializar al formato de `timeline` exigido por `informe_incidente.schema.json`."""
        item: dict[str, str] = {
            "timestamp": self.timestamp or "unknown",
            "event_id": self.event_id or "",
            "description": self.description,
        }
        if self.mitre:
            item["mitre"] = self.mitre
        return item


class ReconstructionConclusion(BaseModel):
    """Conclusión razonada (acceso inicial, paciente cero o causa raíz) con soporte e incertidumbre."""

    model_config = ConfigDict(extra="allow")

    status: ConclusionStatus = "undetermined"
    conclusion: str = "indeterminado"
    explanation: str = ""
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    supporting_evidence: list[str] = Field(default_factory=list)
    uncertainties: list[str] = Field(default_factory=list)

    # Metadatos opcionales específicos según el tipo de conclusión
    event_id: str | None = None
    timestamp: str | None = None
    host: str | None = None
    user: str | None = None
    vector: str | None = None
    mitre: str | None = None
    category: str | None = None
    is_confirmed: bool = False
    first_observed_event_id: str | None = None
    first_suspicious_event_id: str | None = None

    def __str__(self) -> str:
        return self.conclusion

    def __contains__(self, item: str) -> bool:
        haystack = f"{self.conclusion} {self.explanation} {self.event_id or ''} {self.host or ''} {self.user or ''}"
        return item in haystack


class AttackPhase(BaseModel):
    """Fase del ataque identificada y respaldada por evidencias."""

    model_config = ConfigDict(extra="allow")

    phase: AttackPhaseId
    name: str
    description: str
    event_ids: list[str] = Field(default_factory=list)
    supporting_evidence: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    uncertainties: list[str] = Field(default_factory=list)


class EntityRelationship(BaseModel):
    """Relación verificada entre dos entidades o eventos dentro del incidente."""

    source_entity: str
    target_entity: str
    relation_type: str
    shared_identifiers: list[str] = Field(default_factory=list)
    supporting_evidence: list[str] = Field(default_factory=list)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)


class RelatedEntities(BaseModel):
    """Entidades e indicadores relacionados durante la reconstrucción del ataque."""

    model_config = ConfigDict(extra="allow")

    users: list[str] = Field(default_factory=list)
    hosts: list[str] = Field(default_factory=list)
    ips: list[str] = Field(default_factory=list)
    domains: list[str] = Field(default_factory=list)
    urls: list[str] = Field(default_factory=list)
    hashes: list[str] = Field(default_factory=list)
    sessions: list[str] = Field(default_factory=list)
    customers: list[str] = Field(default_factory=list)
    relationships: list[EntityRelationship] = Field(default_factory=list)

    def __getitem__(self, key: str) -> Any:
        return getattr(self, key)

    def get(self, key: str, default: Any = None) -> Any:
        return getattr(self, key, default)

    def keys(self) -> list[str]:
        return [
            "users",
            "hosts",
            "ips",
            "domains",
            "urls",
            "hashes",
            "sessions",
            "customers",
            "relationships",
        ]


class AttackReconstruction(BaseModel):
    """Resultado completo de la reconstrucción cronológica y causal del ataque (N3)."""

    model_config = ConfigDict(extra="allow")

    incident_id: str = ""
    alert_ids: list[str] = Field(default_factory=list)
    timeline: list[TimelineEvent] = Field(default_factory=list)
    first_observed_event: TimelineEvent | None = None
    first_suspicious_event: TimelineEvent | None = None
    initial_access: ReconstructionConclusion = Field(
        default_factory=ReconstructionConclusion
    )
    patient_zero: ReconstructionConclusion = Field(
        default_factory=ReconstructionConclusion
    )
    attack_phases: list[AttackPhase] = Field(default_factory=list)
    root_cause: ReconstructionConclusion = Field(
        default_factory=ReconstructionConclusion
    )
    technical_impact: str = ""
    related_entities: RelatedEntities = Field(default_factory=RelatedEntities)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    supporting_evidence: list[str] = Field(default_factory=list)
    uncertainties: list[str] = Field(default_factory=list)
    is_indeterminate: bool = False
    summary: str = ""

    def to_incident_report_fields(self) -> dict[str, Any]:
        """Exportar los campos compatibles con `informe_incidente.schema.json` para Persona 3."""
        return {
            "incident_id": self.incident_id,
            "alert_ids": list(self.alert_ids),
            "patient_zero": self.patient_zero.conclusion,
            "initial_access": self.initial_access.conclusion,
            "timeline": [ev.to_schema_item() for ev in self.timeline],
            "root_cause": self.root_cause.conclusion,
            "confidence": self.confidence,
            "open_questions": list(self.uncertainties),
        }


# ---------------------------------------------------------------------------
# Clase principal AttackReconstructor
# ---------------------------------------------------------------------------


class AttackReconstructor:
    """Reconstruye cronológicamente la cadena de ataque a partir de un `InvestigationBundle`."""

    def __init__(
        self,
        *,
        llm_client: Any = None,
        correlation_window_hours: float = 48.0,
    ) -> None:
        """Inicializar el reconstructor.

        Args:
            llm_client: Cliente LLM opcional (no requerido para ordenar ni correlacionar).
            correlation_window_hours: Ventana temporal máxima en horas para correlacionar
                eventos por entidades compuestas.
        """
        if correlation_window_hours <= 0:
            raise ValueError("correlation_window_hours debe ser mayor que cero")
        self.llm_client = llm_client
        self.correlation_window = timedelta(hours=correlation_window_hours)

    def reconstruct(
        self,
        bundle: InvestigationBundle | dict[str, Any] | Sequence[Any] | Any,
    ) -> AttackReconstruction:
        """Transformar las evidencias recopiladas en una reconstrucción cronológica y razonada."""
        norm_bundle = self._coerce_bundle(bundle)
        uncertainties: list[str] = []

        # Paso A y B: Normalización de fechas UTC, preservación de referencias,
        # deduplicación segura y ordenación cronológica.
        timeline, parsed_times, norm_notes = self._build_normalized_timeline(
            norm_bundle
        )
        for note in norm_notes:
            if note not in uncertainties:
                uncertainties.append(note)

        if not timeline:
            msg = (
                "No se dispone de eventos ni evidencias verificables para reconstruir "
                "el ataque; resultado indeterminado."
            )
            if msg not in uncertainties:
                uncertainties.append(msg)
            undetermined = ReconstructionConclusion(
                status="undetermined",
                conclusion="indeterminado",
                explanation=msg,
                confidence=0.0,
                supporting_evidence=[],
                uncertainties=[msg],
            )
            return AttackReconstruction(
                incident_id=norm_bundle.incident_id,
                alert_ids=list(norm_bundle.alert_ids),
                timeline=[],
                first_observed_event=None,
                first_suspicious_event=None,
                initial_access=undetermined,
                patient_zero=undetermined.model_copy(),
                attack_phases=[],
                root_cause=undetermined.model_copy(),
                technical_impact="Indeterminado: sin evidencias técnicas disponibles.",
                related_entities=RelatedEntities(),
                confidence=0.0,
                supporting_evidence=[],
                uncertainties=uncertainties,
                is_indeterminate=True,
                summary=msg,
            )

        # Paso C: Correlación de eventos mediante identificadores fuertes o compuestos.
        relationships, chain_indices, corr_notes = self._correlate_events(
            timeline=timeline,
            parsed_times=parsed_times,
            bundle=norm_bundle,
        )
        for note in corr_notes:
            if note not in uncertainties:
                uncertainties.append(note)

        # Seleccionar los eventos que forman parte de la cadena de ataque principal
        # (o eventos sospechosos verificados).
        chain_events = [timeline[i] for i in sorted(chain_indices)]
        suspicious_events = [ev for ev in timeline if ev.is_suspicious]

        first_observed = timeline[0] if timeline else None
        first_suspicious = suspicious_events[0] if suspicious_events else None

        # Paso D: Reconstrucción de las fases del ataque respaldadas por evidencias.
        attack_phases = self._reconstruct_phases(
            chain_events=chain_events,
            all_suspicious=suspicious_events,
            uncertainties=uncertainties,
        )

        # Paso E: Identificación de paciente cero, vector de acceso inicial y causa raíz.
        patient_zero = self._identify_patient_zero(
            timeline=timeline,
            chain_events=chain_events,
            first_observed=first_observed,
            first_suspicious=first_suspicious,
            uncertainties=uncertainties,
        )
        initial_access = self._identify_initial_access(
            chain_events=chain_events,
            attack_phases=attack_phases,
            patient_zero=patient_zero,
            uncertainties=uncertainties,
        )
        root_cause = self._identify_root_cause(
            chain_events=chain_events,
            attack_phases=attack_phases,
            initial_access=initial_access,
            patient_zero=patient_zero,
            bundle=norm_bundle,
            uncertainties=uncertainties,
        )

        # Impacto técnico observable y entidades relacionadas
        related_entities = self._collect_related_entities(
            events=chain_events if chain_events else timeline,
            relationships=relationships,
        )
        technical_impact = self._assess_technical_impact(
            chain_events=chain_events,
            attack_phases=attack_phases,
            related_entities=related_entities,
            bundle=norm_bundle,
        )

        # Paso F: Confianza global, referencias de soporte y resumen analítico
        supporting_evidence = self._collect_supporting_evidence(
            chain_events=chain_events,
            timeline=timeline,
        )
        is_indeterminate = (
            not chain_events
            or (
                patient_zero.status == "undetermined"
                and initial_access.status == "undetermined"
                and not attack_phases
            )
        )
        confidence = self._calculate_overall_confidence(
            chain_events=chain_events,
            timeline=timeline,
            attack_phases=attack_phases,
            patient_zero=patient_zero,
            root_cause=root_cause,
            uncertainties=uncertainties,
            is_indeterminate=is_indeterminate,
        )

        # Incorporar preguntas abiertas previas de análisis o tickets sin duplicarlas
        for analysis in norm_bundle.analyses:
            qs = (
                analysis.open_questions
                if isinstance(analysis, Analysis)
                else (analysis.get("open_questions") or [])
                if isinstance(analysis, dict)
                else []
            )
            for q in qs:
                if isinstance(q, str) and q.strip() and q.strip() not in uncertainties:
                    uncertainties.append(q.strip())

        summary = self._build_summary(
            incident_id=norm_bundle.incident_id,
            timeline=timeline,
            chain_events=chain_events,
            first_observed=first_observed,
            first_suspicious=first_suspicious,
            patient_zero=patient_zero,
            initial_access=initial_access,
            attack_phases=attack_phases,
            root_cause=root_cause,
            technical_impact=technical_impact,
            confidence=confidence,
            uncertainties=uncertainties,
            is_indeterminate=is_indeterminate,
        )

        return AttackReconstruction(
            incident_id=norm_bundle.incident_id,
            alert_ids=list(norm_bundle.alert_ids),
            timeline=timeline,
            first_observed_event=first_observed,
            first_suspicious_event=first_suspicious,
            initial_access=initial_access,
            patient_zero=patient_zero,
            attack_phases=attack_phases,
            root_cause=root_cause,
            technical_impact=technical_impact,
            related_entities=related_entities,
            confidence=confidence,
            supporting_evidence=supporting_evidence,
            uncertainties=uncertainties,
            is_indeterminate=is_indeterminate,
            summary=summary,
        )

    # ------------------------------------------------------------------
    # Paso A y B: Normalización de timestamps UTC, deduplicación y orden
    # ------------------------------------------------------------------

    def _build_normalized_timeline(
        self, bundle: InvestigationBundle
    ) -> tuple[list[TimelineEvent], list[datetime | None], list[str]]:
        """Normalizar eventos, convertir timestamps a UTC, deduplicar y ordenar."""
        notes: list[str] = []
        raw_items = self._gather_raw_evidence_items(bundle, notes)

        # Mapear técnicas MITRE y fases conocidas desde las alertas del bundle
        alert_context_by_event = self._index_alert_metadata_by_event(bundle.alerts)
        corroborated_iocs = self._extract_malicious_iocs(bundle.intel, bundle.tickets)

        dedup_by_source_id: dict[tuple[str, str], TimelineEvent] = {}
        dedup_dt_by_source_id: dict[tuple[str, str], tuple[datetime | None, int]] = {}
        anonymous_seen: set[tuple[str, str]] = set()
        staged: list[tuple[TimelineEvent, datetime | None, int]] = []

        for idx, ev in enumerate(raw_items):
            source = str(ev.source or "unknown").strip() or "unknown"
            raw_dict = dict(ev.raw) if isinstance(ev.raw, dict) else {}

            # Ignorar resúmenes de búsqueda truncada sin event_id que genera EvidenceCollector,
            # registrando el truncamiento como incertidumbre.
            if (
                ev.event_id is None
                and (raw_dict.get("kind") == "query_summary"
                     or "q" in raw_dict and "truncated" in raw_dict)
            ):
                if raw_dict.get("truncated"):
                    notes.append(
                        f"Búsqueda truncada en fuente '{source}' para consulta "
                        f"'{raw_dict.get('q')}': podrían faltar eventos en la cronología."
                    )
                continue

            event_id = (
                str(ev.event_id).strip()
                if ev.event_id is not None and str(ev.event_id).strip()
                else str(raw_dict.get("event_id") or "").strip() or None
            )

            raw_ts = ev.timestamp
            if raw_ts is None:
                for ts_field in ("timestamp", "eventTime", "created_at", "time", "date"):
                    if raw_dict.get(ts_field) is not None:
                        raw_ts = str(raw_dict[ts_field])
                        break

            parsed_dt, norm_ts, ts_valid = self._normalize_timestamp(raw_ts)
            if not ts_valid:
                ref_label = f"{source}:{event_id}" if event_id else f"{source}#idx-{idx + 1}"
                if raw_ts is None or str(raw_ts).strip() == "":
                    notes.append(
                        f"Evento {ref_label} sin timestamp: se conserva al final de la "
                        "cronología sin asumir su posición temporal exacta."
                    )
                else:
                    notes.append(
                        f"Evento {ref_label} con timestamp inválido ({raw_ts!r}): se "
                        "conserva al final de la cronología."
                    )

            entities = self._extract_event_entities(source, raw_dict)
            alert_meta = alert_context_by_event.get(event_id or "", {})
            phase, mitre, is_suspicious = self._classify_event(
                source=source,
                event_id=event_id,
                raw=raw_dict,
                entities=entities,
                alert_meta=alert_meta,
                corroborated_iocs=corroborated_iocs,
            )
            description = self._describe_event(
                source=source,
                event_id=event_id,
                raw=raw_dict,
                alert_meta=alert_meta,
            )
            ev_ref = event_id if event_id else f"{source}:anon-{idx + 1}"

            timeline_ev = TimelineEvent(
                timestamp=norm_ts,
                raw_timestamp=str(raw_ts) if raw_ts is not None else None,
                timestamp_valid=ts_valid,
                event_id=event_id,
                source=source,
                description=description,
                mitre=mitre,
                phase=phase,
                is_suspicious=is_suspicious,
                entities=entities,
                correlated_event_ids=[],
                correlation_reasons=[],
                evidence_refs=[ev_ref],
                raw=raw_dict,
            )

            # Deduplicación por (source, event_id)
            if event_id is not None:
                key = (source.casefold(), event_id)
                if key in dedup_by_source_id:
                    existing = dedup_by_source_id[key]
                    # Si el evento duplicado aporta timestamp válido que faltaba o metadatos
                    # adicionales, enriquecer sin duplicar la entrada en la cronología.
                    if not existing.timestamp_valid and ts_valid:
                        existing.timestamp = norm_ts
                        existing.timestamp_valid = True
                        prev_idx = dedup_dt_by_source_id[key][1]
                        dedup_dt_by_source_id[key] = (parsed_dt, prev_idx)
                    if not existing.mitre and mitre:
                        existing.mitre = mitre
                    if not existing.phase and phase:
                        existing.phase = phase
                    existing.is_suspicious = existing.is_suspicious or is_suspicious
                    for e_group, e_vals in entities.items():
                        bucket = existing.entities.setdefault(e_group, [])
                        for val in e_vals:
                            if val not in bucket:
                                bucket.append(val)
                    continue
                dedup_by_source_id[key] = timeline_ev
                dedup_dt_by_source_id[key] = (parsed_dt, idx)
            else:
                canon = json.dumps(raw_dict, sort_keys=True, ensure_ascii=False, default=str)
                anon_key = (source.casefold(), f"{norm_ts or ''}:{canon}")
                if anon_key in anonymous_seen:
                    continue
                anonymous_seen.add(anon_key)
                staged.append((timeline_ev, parsed_dt, idx))

        for key, ev_obj in dedup_by_source_id.items():
            dt_val, orig_idx = dedup_dt_by_source_id[key]
            staged.append((ev_obj, dt_val, orig_idx))

        # Ordenar: primero los que tienen timestamp válido por fecha UTC ascendente
        # (conservando orden relativo en empates de timestamp sin eliminar eventos distintos),
        # y al final los que carecen de timestamp válido.
        staged.sort(
            key=lambda item: (
                0 if item[1] is not None else 1,
                item[1] if item[1] is not None else datetime.max.replace(tzinfo=timezone.utc),
                item[2],
            )
        )

        ordered_events = [item[0] for item in staged]
        ordered_dts = [item[1] for item in staged]
        return ordered_events, ordered_dts, notes

    @staticmethod
    def _normalize_timestamp(
        value: Any,
    ) -> tuple[datetime | None, str | None, bool]:
        """Normalizar fecha ISO 8601 (con o sin zona) a UTC y formato canónico `...Z`."""
        if value is None:
            return None, None, False
        if isinstance(value, datetime):
            dt = (
                value.replace(tzinfo=timezone.utc)
                if value.tzinfo is None
                else value.astimezone(timezone.utc)
            )
            return dt, AttackReconstructor._format_utc(dt), True
        if not isinstance(value, str):
            return None, None, False

        text = value.strip()
        if not text:
            return None, None, False

        # Soportar sufijo Z y espacio entre fecha y hora
        candidate = text
        if candidate.endswith(("Z", "z")):
            candidate = candidate[:-1] + "+00:00"
        try:
            parsed = datetime.fromisoformat(candidate)
        except ValueError:
            # Intentar formatos comunes alternativos ISO sin microsegundos
            for fmt in ("%Y-%m-%d %H:%M:%S", "%Y/%m/%d %H:%M:%S", "%Y-%m-%d"):
                try:
                    parsed = datetime.strptime(text, fmt)
                    break
                except ValueError:
                    continue
            else:
                return None, None, False

        if parsed.tzinfo is None:
            utc_dt = parsed.replace(tzinfo=timezone.utc)
        else:
            utc_dt = parsed.astimezone(timezone.utc)

        return utc_dt, AttackReconstructor._format_utc(utc_dt), True

    @staticmethod
    def _format_utc(dt: datetime) -> str:
        utc_dt = dt.astimezone(timezone.utc)
        if utc_dt.microsecond:
            return (
                utc_dt.isoformat(timespec="milliseconds").replace("+00:00", "Z")
            )
        return utc_dt.isoformat(timespec="seconds").replace("+00:00", "Z")

    # ------------------------------------------------------------------
    # Paso C: Correlación entre eventos y entidades
    # ------------------------------------------------------------------

    def _correlate_events(
        self,
        *,
        timeline: list[TimelineEvent],
        parsed_times: list[datetime | None],
        bundle: InvestigationBundle,
    ) -> tuple[list[EntityRelationship], set[int], list[str]]:
        """Relacionar eventos mediante identificadores compartidos sin unir por un único IP/usuario."""
        relationships: list[EntityRelationship] = []
        notes: list[str] = []
        n = len(timeline)
        adj: dict[int, set[int]] = {i: set() for i in range(n)}
        weak_pairs_noted: set[tuple[str, str]] = set()

        # Evaluar solo pares que puedan compartir un identificador. Consultar
        # varios días añade mucho tráfico de fondo sin interés para la cadena.
        by_entity: dict[tuple[str, str], dict[tuple, list[int]]] = {}
        by_reference: dict[str, set[int]] = {}
        dimensions = ("sessions", "hashes", "urls", "users", "hosts", "ips", "domains", "customers")
        for index, event in enumerate(timeline):
            if event.is_suspicious:
                for group in dimensions:
                    for token in event.entities.get(group, []):
                        by_entity.setdefault((group, token), {}).setdefault((event.source, event.phase), []).append(index)
            for reference in [*event.entities.get("related_events", []), event.event_id]:
                if reference:
                    by_reference.setdefault(reference, set()).add(index)

        for i in range(n):
            event = timeline[i]
            candidates: set[int] = set()
            if event.is_suspicious:
                for group in dimensions:
                    for token in event.entities.get(group, []):
                        for indices in by_entity.get((group, token), {}).values():
                            position = bisect_right(indices, i)
                            # Conservar relaciones entre fuentes/fases y conectar
                            # las repeticiones consecutivas, sin un grafo completo
                            # de miles de beacons idénticos. No se pierden eventos.
                            candidates.update(indices[position:position + 2])
            for reference in [*event.entities.get("related_events", []), event.event_id]:
                if reference:
                    candidates.update(by_reference.get(reference, set()))
            for j in sorted(value for value in candidates if value > i):
                ev_a, ev_b = timeline[i], timeline[j]
                dt_a, dt_b = parsed_times[i], parsed_times[j]

                if (
                    dt_a is not None
                    and dt_b is not None
                    and abs(dt_b - dt_a) > self.correlation_window
                ):
                    continue

                strong, reason, shared_tokens, score, weak_note = self._evaluate_event_pair(
                    ev_a, ev_b
                )
                if weak_note:
                    pair_key = (
                        ev_a.event_id or ev_a.source,
                        ev_b.event_id or ev_b.source,
                    )
                    if pair_key not in weak_pairs_noted:
                        weak_pairs_noted.add(pair_key)
                        notes.append(weak_note)

                if not strong:
                    continue

                adj[i].add(j)
                adj[j].add(i)

                id_a = ev_a.event_id or f"{ev_a.source}#{i + 1}"
                id_b = ev_b.event_id or f"{ev_b.source}#{j + 1}"
                if id_b not in ev_a.correlated_event_ids:
                    ev_a.correlated_event_ids.append(id_b)
                if id_a not in ev_b.correlated_event_ids:
                    ev_b.correlated_event_ids.append(id_a)
                if reason not in ev_a.correlation_reasons:
                    ev_a.correlation_reasons.append(reason)
                if reason not in ev_b.correlation_reasons:
                    ev_b.correlation_reasons.append(reason)

                relationships.append(
                    EntityRelationship(
                        source_entity=id_a,
                        target_entity=id_b,
                        relation_type=reason,
                        shared_identifiers=shared_tokens,
                        supporting_evidence=[id_a, id_b],
                        confidence=score,
                    )
                )

        # Determinar la componente conexa principal de eventos sospechosos
        chain_indices = self._select_primary_attack_chain(timeline, adj)
        if n > 500:
            notes.append("Las relaciones muestran vínculos representativos entre fuentes y fases; no enumeran todos los pares de eventos repetidos. La cronología conserva todos los eventos recuperados.")
        return relationships, chain_indices, notes

    def _evaluate_event_pair(
        self,
        ev_a: TimelineEvent,
        ev_b: TimelineEvent,
    ) -> tuple[bool, str, list[str], float, str | None]:
        """Evaluar si dos eventos tienen relación demostrable o solo coincidencia débil."""
        # No unir eventos puramente benignos/administrativos de fondo que no participan
        # en actividad sospechosa a menos que estén referenciados explícitamente por ID.
        ent_a = ev_a.entities
        ent_b = ev_b.entities

        # 1. Referencia explícita de event_id entre ambos eventos
        refs_a = set(ent_a.get("related_events", []))
        refs_b = set(ent_b.get("related_events", []))
        if (ev_a.event_id and ev_a.event_id in refs_b) or (
            ev_b.event_id and ev_b.event_id in refs_a
        ) or (refs_a & refs_b):
            shared_ev = sorted(
                ({ev_a.event_id} & refs_b)
                | ({ev_b.event_id} & refs_a)
                | (refs_a & refs_b)
            )
            return (
                True,
                "Referencia explícita de evento relacionado",
                [f"event_id:{x}" for x in shared_ev if x],
                0.98,
                None,
            )

        # Si uno de los eventos NO es sospechoso y no tiene referencia explícita,
        # no incorporarlo a la cadena de ataque.
        if not (ev_a.is_suspicious and ev_b.is_suspicious):
            return False, "", [], 0.0, None

        shared: dict[str, list[str]] = {}
        for group in (
            "sessions",
            "hashes",
            "urls",
            "users",
            "hosts",
            "ips",
            "domains",
            "customers",
        ):
            common = sorted(set(ent_a.get(group, [])) & set(ent_b.get(group, [])))
            if common:
                shared[group] = common

        # 2. Identificadores específicos fuertes: sesión/mensaje/build, hash de fichero o URL exacta
        if shared.get("sessions"):
            tokens = [f"session:{s}" for s in shared["sessions"]]
            return (
                True,
                "Misma sesión, message_id o clave de acceso",
                tokens,
                0.95,
                None,
            )
        if shared.get("hashes"):
            tokens = [f"hash:{h}" for h in shared["hashes"]]
            return (
                True,
                "Mismo hash criptográfico de fichero o artefacto",
                tokens,
                0.94,
                None,
            )
        if shared.get("urls"):
            tokens = [f"url:{u}" for u in shared["urls"]]
            return (
                True,
                "Misma URL específica en la secuencia",
                tokens,
                0.90,
                None,
            )

        # 3. Correlación compuesta: al menos dos dimensiones compartidas (p. ej. usuario + equipo,
        # equipo + dominio/IP, usuario + IP/dominio, equipo + cliente, etc.)
        active_dimensions = [
            dim
            for dim in ("users", "hosts", "ips", "domains", "customers")
            if shared.get(dim)
        ]
        if len(active_dimensions) >= 2:
            tokens = [
                f"{dim}:{val}"
                for dim in active_dimensions
                for val in shared[dim]
            ]
            return (
                True,
                f"Correlación multifacética ({', '.join(active_dimensions)})",
                tokens,
                0.88,
                None,
            )

        # 4. Movimiento lateral / pivote entre equipos o IPs internas cuando un evento
        # de red/ejecución en el origen conecta con el equipo destino del siguiente evento.
        if shared.get("hosts") and ev_a.phase != ev_b.phase:
            tokens = [f"host:{h}" for h in shared["hosts"]]
            return (
                True,
                "Secuencia de distintas fases sobre el mismo equipo comprometido",
                tokens,
                0.84,
                None,
            )

        # 5. Regla explícita de no-correlación por un único IP o un único usuario aislado:
        # Compartir únicamente una IP o únicamente un usuario NO demuestra que dos eventos
        # pertenezcan al mismo ataque.
        if active_dimensions == ["ips"]:
            id_a = ev_a.event_id or ev_a.source
            id_b = ev_b.event_id or ev_b.source
            return (
                False,
                "",
                [],
                0.0,
                f"Los eventos {id_a} y {id_b} comparten únicamente la IP "
                f"{shared['ips'][0]}; no se correlacionan automáticamente al no "
                "ser prueba suficiente de pertenecer al mismo ataque.",
            )
        if active_dimensions == ["users"]:
            id_a = ev_a.event_id or ev_a.source
            id_b = ev_b.event_id or ev_b.source
            return (
                False,
                "",
                [],
                0.0,
                f"Los eventos {id_a} y {id_b} comparten únicamente el usuario "
                f"{shared['users'][0]} en contextos/equipos distintos; no se "
                "asume que pertenezcan al mismo ataque sin evidencia adicional.",
            )

        return False, "", [], 0.0, None

    @staticmethod
    def _select_primary_attack_chain(
        timeline: list[TimelineEvent],
        adj: dict[int, set[int]],
    ) -> set[int]:
        """Seleccionar la componente conexa principal de eventos sospechosos."""
        suspicious_indices = [
            idx for idx, ev in enumerate(timeline) if ev.is_suspicious
        ]
        if not suspicious_indices:
            return set()

        visited: set[int] = set()
        components: list[set[int]] = []
        for idx in suspicious_indices:
            if idx in visited:
                continue
            comp: set[int] = set()
            queue = [idx]
            visited.add(idx)
            while queue:
                curr = queue.pop(0)
                comp.add(curr)
                for nxt in adj.get(curr, set()):
                    if nxt not in visited and timeline[nxt].is_suspicious:
                        visited.add(nxt)
                        queue.append(nxt)
            components.append(comp)

        # Priorizar la componente con más eventos correlacionados y mayor diversidad de fases;
        # en caso de empate, la más temprana con timestamp válido.
        def component_rank(comp: set[int]) -> tuple[int, int, int]:
            phases = {
                timeline[i].phase
                for i in comp
                if timeline[i].phase is not None
            }
            earliest_idx = min(comp)
            return (len(comp), len(phases), -earliest_idx)

        components.sort(key=component_rank, reverse=True)
        return components[0]

    # ------------------------------------------------------------------
    # Paso D: Reconstrucción de fases del ataque
    # ------------------------------------------------------------------

    def _reconstruct_phases(
        self,
        *,
        chain_events: list[TimelineEvent],
        all_suspicious: list[TimelineEvent],
        uncertainties: list[str],
    ) -> list[AttackPhase]:
        """Agrupar los eventos de la cadena en las fases del ataque respaldadas por pruebas."""
        target_events = chain_events if chain_events else all_suspicious
        if not target_events:
            return []

        by_phase: dict[AttackPhaseId, list[TimelineEvent]] = {}
        for ev in target_events:
            if ev.phase is None:
                continue
            by_phase.setdefault(ev.phase, []).append(ev)

        phases: list[AttackPhase] = []
        # Conservar el orden cronológico de primera aparición de cada fase (y PHASE_ORDER en empate)
        first_positions = {}
        for index, event in enumerate(target_events):
            first_positions.setdefault(event.phase, index)
        sorted_phase_keys = sorted(by_phase, key=lambda phase: first_positions[phase])

        for phase_id in sorted_phase_keys:
            evs = by_phase[phase_id]
            ev_ids: list[str] = []
            refs: list[str] = []
            mitre_list: list[str] = []
            phase_uncertainties: list[str] = []

            for ev in evs:
                if ev.event_id and ev.event_id not in ev_ids:
                    ev_ids.append(ev.event_id)
                for r in ev.evidence_refs:
                    if r not in refs:
                        refs.append(r)
                if ev.mitre and ev.mitre not in mitre_list:
                    mitre_list.append(ev.mitre)
                if not ev.timestamp_valid:
                    msg = (
                        f"El evento {ev.event_id or ev.source} en la fase "
                        f"'{PHASE_LABELS[phase_id]}' carece de timestamp válido."
                    )
                    if msg not in phase_uncertainties:
                        phase_uncertainties.append(msg)

            base_conf = min(0.95, 0.70 + 0.08 * len(evs))
            if phase_uncertainties:
                base_conf = max(0.35, round(base_conf - 0.15, 2))
            else:
                base_conf = round(base_conf, 2)

            desc = "; ".join(ev.description for ev in evs[:4])
            if len(evs) > 4:
                desc += f" (+{len(evs) - 4} eventos adicionales)"

            phases.append(
                AttackPhase(
                    phase=phase_id,
                    name=PHASE_LABELS[phase_id],
                    description=desc,
                    event_ids=ev_ids,
                    supporting_evidence=refs,
                    mitre_techniques=mitre_list,
                    confidence=base_conf,
                    uncertainties=phase_uncertainties,
                )
            )

        if phases and phases[0].phase != "initial_access":
            msg = (
                f"La primera fase observada con evidencias es '{phases[0].name}' "
                f"({phases[0].phase}); no existen evidencias directas de la fase de "
                "Acceso inicial en los registros recibidos."
            )
            if msg not in uncertainties:
                uncertainties.append(msg)

        return phases

    # ------------------------------------------------------------------
    # Paso E: Paciente cero, acceso inicial y causa raíz
    # ------------------------------------------------------------------

    def _identify_patient_zero(
        self,
        *,
        timeline: list[TimelineEvent],
        chain_events: list[TimelineEvent],
        first_observed: TimelineEvent | None,
        first_suspicious: TimelineEvent | None,
        uncertainties: list[str],
    ) -> ReconstructionConclusion:
        """Identificar el posible paciente cero distinguiéndolo del primer evento observado."""
        first_obs_id = (
            first_observed.event_id or first_observed.source
            if first_observed is not None
            else None
        )
        first_susp_id = (
            first_suspicious.event_id or first_suspicious.source
            if first_suspicious is not None
            else None
        )

        if not chain_events:
            msg = "No hay eventos sospechosos correlacionados que permitan identificar un paciente cero."
            return ReconstructionConclusion(
                status="undetermined",
                conclusion="indeterminado",
                explanation=msg,
                confidence=0.0,
                supporting_evidence=[],
                uncertainties=[msg],
                first_observed_event_id=first_obs_id,
                first_suspicious_event_id=first_susp_id,
            )

        # Preferir el primer evento con timestamp válido dentro de la cadena investigada
        dated_chain = [ev for ev in chain_events if ev.timestamp_valid]
        origin_ev = dated_chain[0] if dated_chain else chain_events[0]

        hosts = origin_ev.entities.get("hosts", [])
        users = origin_ev.entities.get("users", [])
        # Si el primer evento (p. ej. email entrante) aún no tiene hostname pero sí usuario
        # y el siguiente evento correlacionado del mismo usuario revela el host:
        if not hosts:
            for ev in chain_events:
                if ev.entities.get("hosts"):
                    hosts = ev.entities["hosts"]
                    break
        if not users:
            for ev in chain_events:
                if ev.entities.get("users"):
                    users = ev.entities["users"]
                    break

        host = hosts[0] if hosts else None
        user = users[0] if users else None
        ev_id = origin_ev.event_id or origin_ev.source

        pz_uncertainties: list[str] = []
        if first_observed is not None and first_observed is not origin_ev:
            obs_label = first_observed.event_id or first_observed.source
            pz_uncertainties.append(
                f"El primer evento observado en la cronología ({obs_label}) es anterior "
                f"al inicio demostrable de la cadena ({ev_id}), pero no constituye el "
                "origen del ataque por tratarse de actividad benigna o no relacionada."
            )
        if first_suspicious is not None and first_suspicious is not origin_ev:
            susp_label = first_suspicious.event_id or first_suspicious.source
            note = (
                f"Existe un evento sospechoso previo ({susp_label}) sin vínculo "
                f"demostrable con la cadena principal iniciada en {ev_id}."
            )
            pz_uncertainties.append(note)
            if note not in uncertainties:
                uncertainties.append(note)

        has_initial_access = origin_ev.phase == "initial_access"
        if not has_initial_access:
            gap_note = (
                f"El evento más antiguo de la cadena ({ev_id}) corresponde a la fase "
                f"'{PHASE_LABELS.get(origin_ev.phase or 'execution', 'intermedia')}' y "
                "no a un vector de acceso inicial; el paciente cero real podría ser "
                "anterior a las evidencias disponibles."
            )
            pz_uncertainties.append(gap_note)
            if gap_note not in uncertainties:
                uncertainties.append(gap_note)

        if not host and not user:
            msg = (
                f"El evento inicial de la cadena ({ev_id}) no contiene identificadores "
                "de equipo ni de usuario para fijar el paciente cero."
            )
            pz_uncertainties.append(msg)
            return ReconstructionConclusion(
                status="undetermined",
                conclusion="indeterminado",
                explanation=msg,
                confidence=0.25,
                supporting_evidence=list(origin_ev.evidence_refs),
                uncertainties=pz_uncertainties,
                event_id=origin_ev.event_id,
                timestamp=origin_ev.timestamp,
                first_observed_event_id=first_obs_id,
                first_suspicious_event_id=first_susp_id,
            )

        status: ConclusionStatus = "confirmed" if has_initial_access and self._initial_link(origin_ev, chain_events) else "hypothesis"
        if status == "hypothesis":
            pz_uncertainties.append("El primer evento de la cadena no demuestra por sí solo el paciente cero; falta un vínculo directo con el compromiso posterior.")
        conf = 0.88 if status == "confirmed" else 0.62
        if not origin_ev.timestamp_valid:
            conf = max(0.35, round(conf - 0.20, 2))

        target_parts = []
        if host:
            target_parts.append(f"equipo {host}")
        if user:
            target_parts.append(f"usuario {user}")
        target_desc = " / ".join(target_parts)

        conclusion_text = (
            f"Posible paciente cero en {target_desc} (evento {ev_id}"
            + (f" a las {origin_ev.timestamp}" if origin_ev.timestamp else "")
            + ")."
        )
        explanation = (
            f"Identificado a partir del evento más antiguo con relación demostrable "
            f"con la cadena investigada ({ev_id}: {origin_ev.description}). "
            f"Primer evento observado global: {first_obs_id}. "
            f"Primer evento sospechoso: {first_susp_id}."
        )

        supp_refs = list(origin_ev.evidence_refs)
        for ev in chain_events[:2]:
            for r in ev.evidence_refs:
                if r not in supp_refs:
                    supp_refs.append(r)

        return ReconstructionConclusion(
            status=status,
            conclusion=conclusion_text,
            explanation=explanation,
            confidence=conf,
            supporting_evidence=supp_refs,
            uncertainties=pz_uncertainties,
            event_id=origin_ev.event_id,
            timestamp=origin_ev.timestamp,
            host=host,
            user=user,
            is_confirmed=(status == "confirmed"),
            first_observed_event_id=first_obs_id,
            first_suspicious_event_id=first_susp_id,
        )

    def _identify_initial_access(
        self,
        *,
        chain_events: list[TimelineEvent],
        attack_phases: list[AttackPhase],
        patient_zero: ReconstructionConclusion,
        uncertainties: list[str],
    ) -> ReconstructionConclusion:
        """Determinar el posible vector de acceso inicial a partir de las evidencias."""
        initial_events = [
            ev for ev in chain_events if ev.phase == "initial_access"
        ]
        if not initial_events:
            msg = (
                "No se han encontrado evidencias de la fase de acceso inicial; "
                "el vector de entrada permanece indeterminado."
            )
            if msg not in uncertainties:
                uncertainties.append(msg)
            return ReconstructionConclusion(
                status="undetermined",
                conclusion="indeterminado",
                explanation=msg,
                confidence=0.0,
                supporting_evidence=[],
                uncertainties=[msg],
            )

        first_ia = initial_events[0]
        refs: list[str] = []
        mitres: list[str] = []
        for ev in initial_events:
            for r in ev.evidence_refs:
                if r not in refs:
                    refs.append(r)
            if ev.mitre and ev.mitre not in mitres:
                mitres.append(ev.mitre)

        vector = self._infer_access_vector_label(initial_events)
        has_follow_up = any(ev.phase != "initial_access" for ev in chain_events)
        status: ConclusionStatus = "confirmed" if any(self._initial_link(event, chain_events) for event in initial_events) else "hypothesis"
        conf = 0.88 if status == "confirmed" else 0.65
        ia_uncertainties: list[str] = []
        if not has_follow_up:
            note = (
                "Se observa un evento de acceso inicial pero faltan eventos posteriores "
                "que confirmen la progresión completa de la intrusión."
            )
            ia_uncertainties.append(note)
        if status != "confirmed":
            ia_uncertainties.append("La proximidad temporal, compartir usuario/equipo o una fase posterior no prueba que este intento causara la intrusión.")

        mitre_str = f" ({', '.join(mitres)})" if mitres else ""
        conclusion_text = f"{vector}{mitre_str} evidenciado en {', '.join(refs)}."
        explanation = (
            f"Vector de acceso inicial determinado por {len(initial_events)} evento(s) "
            f"en la fase de entrada ({first_ia.description})."
        )

        return ReconstructionConclusion(
            status=status,
            conclusion=conclusion_text,
            explanation=explanation,
            confidence=conf,
            supporting_evidence=refs,
            uncertainties=ia_uncertainties,
            event_id=first_ia.event_id,
            timestamp=first_ia.timestamp,
            vector=vector,
            mitre=mitres[0] if mitres else None,
            is_confirmed=(status == "confirmed"),
        )

    def _identify_root_cause(
        self,
        *,
        chain_events: list[TimelineEvent],
        attack_phases: list[AttackPhase],
        initial_access: ReconstructionConclusion,
        patient_zero: ReconstructionConclusion,
        bundle: InvestigationBundle,
        uncertainties: list[str],
    ) -> ReconstructionConclusion:
        """Determinar la causa raíz distinguendo entre causa demostrada, hipótesis o indeterminada."""
        if not chain_events:
            msg = "Sin evidencias suficientes en la cadena para proponer una causa raíz."
            return ReconstructionConclusion(
                status="undetermined",
                conclusion="indeterminado",
                explanation=msg,
                confidence=0.0,
                supporting_evidence=[],
                uncertainties=[msg],
                is_confirmed=False,
            )

        # Para que una causa raíz esté CONFIRMADA ("confirmed"), debe existir:
        # 1) Evidencia verificable del vector de acceso inicial (initial_access != undetermined)
        # 2) Al menos una fase posterior correlacionada que demuestre que esa causa produjo
        #    la intrusión (p. ej. clic en phishing -> ejecución/robo de sesión; o exploit WAF -> shell).
        has_initial = initial_access.status != "undetermined"
        has_progression = len({ev.phase for ev in chain_events if ev.phase}) >= 2
        all_dated = all(ev.timestamp_valid for ev in chain_events[:2])

        refs: list[str] = []
        for ev in chain_events:
            for r in ev.evidence_refs:
                if r not in refs:
                    refs.append(r)

        if initial_access.status == "confirmed" and patient_zero.status == "confirmed" and has_progression and all_dated:
            category = initial_access.vector or "Compromiso en acceso inicial"
            conclusion_text = (
                f"Causa raíz confirmada: {category} sobre "
                f"{patient_zero.host or patient_zero.user or 'entidad inicial'} "
                f"respaldada por {', '.join(initial_access.supporting_evidence)}."
            )
            explanation = (
                f"Las evidencias demuestran la secuencia causal completa desde el vector "
                f"de entrada ({initial_access.conclusion}) hasta las fases posteriores "
                f"({', '.join(p.name for p in attack_phases)})."
            )
            return ReconstructionConclusion(
                status="confirmed",
                conclusion=conclusion_text,
                explanation=explanation,
                confidence=min(0.92, round((initial_access.confidence + patient_zero.confidence) / 2, 2)),
                supporting_evidence=refs,
                uncertainties=[],
                category=category,
                is_confirmed=True,
            )

        # Si hay eventos sospechosos pero falta el acceso inicial o no hay encadenamiento
        # completo que demuestre cómo se originó el fallo/compromiso -> HIPÓTESIS o INDETERMINADO.
        rc_uncertainties: list[str] = []
        if not has_initial:
            gap = (
                "Causa raíz no demostrable con las evidencias actuales: no existen "
                "registros del vector de entrada inicial previo a la actividad observada."
            )
            rc_uncertainties.append(gap)
            if gap not in uncertainties:
                uncertainties.append(gap)
        if not has_progression:
            gap = (
                "Solo se dispone de eventos de una única fase; no se puede demostrar "
                "de forma concluyente la cadena causal completa."
            )
            rc_uncertainties.append(gap)
            if gap not in uncertainties:
                uncertainties.append(gap)

        # Si tenemos al menos indicios técnicos claros (p. ej. uso de credenciales o
        # ejecución maliciosa o acceso inicial aislado), formulamos una hipótesis explícita
        # sin afirmar que está demostrada.
        first_ev = chain_events[0]
        if first_ev.phase is not None:
            hypothesis_desc = (
                initial_access.vector
                if has_initial and initial_access.vector
                else f"Posible compromiso previo asociado a {PHASE_LABELS[first_ev.phase].lower()}"
            )
            conclusion_text = (
                f"Hipótesis no demostrada: {hypothesis_desc} (pendiente de confirmar "
                "el mecanismo exacto de origen con telemetría adicional)."
            )
            explanation = (
                f"Las evidencias disponibles ({', '.join(refs)}) muestran actividad "
                f"sospechosa ({first_ev.description}), pero son insuficientes para "
                "demostrar de forma concluyente la causa raíz original."
            )
            return ReconstructionConclusion(
                status="hypothesis",
                conclusion=conclusion_text,
                explanation=explanation,
                confidence=0.45 if has_initial else 0.35,
                supporting_evidence=refs,
                uncertainties=rc_uncertainties,
                category=hypothesis_desc,
                is_confirmed=False,
            )

        return ReconstructionConclusion(
            status="undetermined",
            conclusion="indeterminado",
            explanation=(
                "Las evidencias recopiladas no permiten demostrar ni formular una "
                "causa raíz específica."
            ),
            confidence=0.20,
            supporting_evidence=refs,
            uncertainties=rc_uncertainties,
            is_confirmed=False,
        )

    # ------------------------------------------------------------------
    # Clasificación de eventos y extracción de entidades
    # ------------------------------------------------------------------

    def _classify_event(
        self,
        *,
        source: str,
        event_id: str | None,
        raw: dict[str, Any],
        entities: dict[str, list[str]],
        alert_meta: dict[str, Any],
        corroborated_iocs: set[str],
    ) -> tuple[AttackPhaseId | None, str | None, bool]:
        """Determinar fase del ataque, técnica MITRE (si existe) y si el evento es sospechoso."""
        src = source.casefold()

        # 1. Comprobar si el evento o su alerta asociada tiene un rule_id del catálogo
        rule_id = str(
            raw.get("rule_id") or alert_meta.get("rule_id") or ""
        ).strip().upper()
        mitre: str | None = None
        phase: AttackPhaseId | None = None

        raw_mitre = raw.get("mitre") or alert_meta.get("mitre")
        if isinstance(raw_mitre, dict):
            mitre = str(raw_mitre.get("technique_id") or "").strip() or None
        elif isinstance(raw_mitre, str) and raw_mitre.strip():
            mitre = raw_mitre.strip()

        if rule_id in RULE_CATALOG:
            cat = RULE_CATALOG[rule_id]
            phase = cat["phase"]  # type: ignore[assignment]
            if not mitre:
                mitre = cat["mitre"]
            return phase, mitre, True

        # Permitir campo explícito `phase` o `tactic` si viene en pruebas/bundle
        explicit_phase = str(raw.get("phase") or raw.get("attack_phase") or "").strip().casefold()
        if explicit_phase in PHASE_LABELS:
            phase = explicit_phase  # type: ignore[assignment]

        # Evaluar heurísticas deterministas según los campos reales de las 18 fuentes
        is_suspicious = bool(raw.get("malicious") is True or raw.get("suspicious") is True)
        text_blob = json.dumps(raw, ensure_ascii=False, default=str).casefold()

        # Si el evento contiene algún indicador corroborado como malicioso en TI/sandbox
        for group in ("ips", "domains", "urls", "hashes"):
            for indicator in entities.get(group, []):
                if indicator.casefold() in corroborated_iocs:
                    is_suspicious = True

        if src in ("email", "email_clicks"):
            verdict = str(raw.get("verdict") or raw.get("phishing_verdict") or raw.get("gateway_verdict") or "").casefold()
            subject = str(raw.get("subject") or "").casefold()
            if (
                "phish" in verdict
                or "malicious" in verdict
                or "suspicious" in verdict
                or raw.get("is_phishing") is True
                or is_suspicious
            ):
                if "iban" in text_blob:
                    return phase or "post_activity", mitre, True
                return phase or "initial_access", mitre, True

        elif src == "edr_events":
            proc = str(raw.get("process_name") or "").casefold()
            parent = str(raw.get("parent_process") or raw.get("parent_name") or "").casefold()
            cmd = str(raw.get("command_line") or raw.get("cmdline") or "").casefold()
            ev_type = str(raw.get("event_type") or "").casefold()
            action = str(raw.get("action") or "").casefold()

            if "lsass" in cmd or "lsass" in str(raw.get("target_process") or "").casefold():
                return phase or "privilege_escalation", mitre, True
            if "vssadmin" in cmd and "delete" in cmd or "shadowcopy" in cmd:
                return phase or "post_activity", mitre, True
            if any(rmm in proc or rmm in cmd for rmm in ("anydesk", "ngrok", "chisel")):
                return phase or "post_activity", mitre, True
            if any(
                 disc in cmd
                for disc in ("nltest", "adfind", "net group", "net localgroup", "psexec", "wmic /node")
            ):
                return phase or "lateral_movement", mitre, True
            if any(srv in parent for srv in ("nginx", "php-fpm", "w3wp", "httpd", "tomcat", "java")) and any(
                sh in proc for sh in ("sh", "bash", "cmd.exe", "powershell.exe", "whoami")
            ):
                return phase or "persistence", mitre, True
            if "schtasks" in proc or "schtasks" in cmd or "\\currentversion\\run" in cmd:
                return phase or "persistence", mitre, True
            if (
                "-enc" in cmd
                or "encodedcommand" in cmd
                or "invoke-webrequest" in cmd
                or "downloadstring" in cmd
                or "mimikatz" in cmd
                or (
                    parent in ("winword.exe", "excel.exe", "outlook.exe", "powerpnt.exe")
                    and proc in ("powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe")
                )
                or ev_type in ("malware_detected", "tamper_attempt", "memory_read")
                or action in ("quarantined", "blocked_malware")
                or is_suspicious
            ):
                return phase or "execution", mitre, True

        elif src == "idp_signins":
            result = str(raw.get("result") or "").casefold()
            reason = str(raw.get("failure_reason") or "").casefold()
            mfa = str(raw.get("mfa_result") or "").casefold()
            risk = str(raw.get("risk_level") or raw.get("risk") or "").casefold()
            if (
                "mfa_fatigue" in reason
                or "push_bomb" in reason
                or "token_reuse" in reason
                or "aitm" in text_blob
            ):
                return phase or "privilege_escalation", mitre, True
            if (
                "impossible_travel" in reason
                or risk in ("high", "critical")
                or raw.get("is_tor") is True
                or raw.get("anomalous") is True
                or (result == "failure" and "spray" in reason)
                or is_suspicious
            ):
                return phase or "initial_access", mitre, True

        elif src == "idp_audit":
            op = str(raw.get("operation") or "").casefold()
            if any(k in op for k in ("inbox rule", "forwarding", "oauth", "consent", "add app role")):
                return phase or "persistence", mitre, True
            if any(k in op for k in ("add member to role", "domain admins", "reset password", "elevate")):
                return phase or "privilege_escalation", mitre, True

        elif src == "ad_events":
            code = raw.get("event_code")
            event_desc = str(raw.get("event") or "").casefold()
            target_grp = str(raw.get("group") or raw.get("target_group") or "").casefold()
            if code in (4728, 4732, 4756) or any(
                g in target_grp or g in event_desc
                for g in ("domain admins", "enterprise admins", "backup operators")
            ):
                return phase or "privilege_escalation", mitre, True
            if code == 4724 and is_suspicious:
                return phase or "privilege_escalation", mitre, True

        elif src == "firewall":
            dst_port = raw.get("dst_port")
            zone_dst = str(raw.get("zone_dst") or "").upper()
            src_host = str(raw.get("src_host") or raw.get("hostname") or "").upper()
            if zone_dst == "LOGISTICS-OT" and src_host not in ("ENG-WS01", "WMS01"):
                return phase or "lateral_movement", mitre, True
            if str(dst_port) in ("445", "3389", "5985", "5986", "135") and (
                is_suspicious or str(raw.get("zone_src") or "").upper() != str(raw.get("zone_dst") or "").upper()
            ):
                return phase or "lateral_movement", mitre, True
            if is_suspicious:
                return phase or "post_activity", mitre, True

        elif src == "waf":
            action = str(raw.get("action") or "").casefold()
            rule_msg = str(raw.get("rule_msg") or "").casefold()
            uri = str(raw.get("uri") or "").casefold()
            if (
                rule_msg
                or action in ("block", "alert", "flagged")
                or any(tok in uri for tok in ("union select", "../", "cmd=", "exec", "<script"))
                or is_suspicious
            ):
                return phase or "initial_access", mitre, True

        elif src == "sql_audit":
            rows = int(raw.get("rows_returned") or 0)
            stmt = str(raw.get("statement_type") or "").upper()
            if rows >= 1000 or stmt in ("DUMP", "COPY", "BULK INSERT") or is_suspicious:
                return phase or "data_access", mitre, True

        elif src == "dlp":
            action = str(raw.get("action") or "").casefold()
            dest = str(raw.get("destination") or "").casefold()
            size_mb = float(raw.get("file_size_mb") or (int(raw.get("file_size") or 0) / (1024 * 1024)))
            if (
                any(d in dest for d in ("mega.nz", "dropbox", "wetransfer", "anonfiles", "pastebin"))
                or size_mb >= 50
                or action in ("alert", "blocked", "flagged")
                or raw.get("pii_detected") is True
                or is_suspicious
            ):
                return phase or "exfiltration", mitre, True

        elif src == "cloudtrail":
            ev_name = str(raw.get("eventName") or "")
            if ev_name in ("CreateUser", "CreateAccessKey", "AttachUserPolicy", "PutUserPolicy"):
                return phase or "persistence", mitre, True
            if ev_name in ("PutBucketAcl", "PutBucketPolicy") and (
                "public" in text_blob or is_suspicious
            ):
                return phase or "exfiltration", mitre, True
            if ev_name == "GetObject" and (int(raw.get("count") or 1) >= 100 or is_suspicious):
                return phase or "data_access", mitre, True
            if is_suspicious:
                return phase or "initial_access", mitre, True

        elif src == "dns":
            query = str(raw.get("query") or "").strip(".")
            labels = query.split(".")
            if any(len(lbl) > 40 for lbl in labels):
                return phase or "exfiltration", mitre, True
            if is_suspicious:
                return phase or "post_activity", mitre, True

        elif src == "proxy":
            cat = str(raw.get("category") or "").casefold()
            bytes_out = int(raw.get("bytes_out") or 0)
            if bytes_out >= 50_000_000:
                return phase or "exfiltration", mitre, True
            if any(c in cat for c in ("malware", "c2", "command", "phishing", "anonymizer")) or is_suspicious:
                return phase or "post_activity", mitre, True

        elif src == "ai_gateway":
            guard = str(raw.get("guardrail_action") or raw.get("status") or "").casefold()
            prompt = str(raw.get("prompt") or "").casefold()
            if "ignore" in prompt or "ignora" in prompt or "system prompt" in prompt or "injection" in guard:
                return phase or "initial_access", mitre, True
            if "unauthorized" in guard or "other_customer" in text_blob or is_suspicious:
                return phase or "data_access", mitre, True

        elif src == "cicd_builds":
            status = str(raw.get("status") or "").casefold()
            if status in ("warning", "suspicious", "failed_security") or "postinstall" in text_blob or is_suspicious:
                return phase or "initial_access", mitre, True

        elif src == "vpn":
            if raw.get("anomalous") is True or str(raw.get("country") or "ES") not in ("ES", "PT") or is_suspicious:
                return phase or "initial_access", mitre, True

        elif src in ("ecom_auth", "ecom_account"):
            ev_name = str(raw.get("event") or "").casefold()
            if "gift_card" in text_blob or "email_changed" in ev_name or is_suspicious:
                return phase or "post_activity", mitre, True

        if phase is not None:
            return phase, mitre, True
        if is_suspicious:
            return "execution", mitre, True
        return None, mitre, False

    @staticmethod
    def _initial_link(origin: TimelineEvent, chain_events: list[TimelineEvent]) -> bool:
        """Confirmar progresión solo con referencia directa o artefacto exacto y víctima.

        Un intento bloqueado, un clic corriente o dos fases en el mismo equipo
        no demuestran causalidad. Se conserva la hipótesis cuando falta el nexo.
        """
        if not origin.timestamp_valid:
            return False
        blocked = {"blocked", "block", "denied", "deny", "quarantined", "prevented"}
        origin_details = origin.raw.get("details") if isinstance(origin.raw.get("details"), dict) else {}
        action = origin.raw.get("action") or origin_details.get("action")
        if action in blocked:
            return False
        for following in chain_events:
            if (following is origin or not following.timestamp_valid or parse_utc(following.timestamp) < parse_utc(origin.timestamp)
                    or following.source != "edr_events"):
                continue
            raw = following.raw
            details = raw.get("details") if isinstance(raw.get("details"), dict) else {}
            if (raw.get("action") or details.get("action")) in blocked:
                continue
            executed = raw.get("event_type") in {"process_start", "process_access", "service_install", "registry_set"} or bool(raw.get("process_name") and (raw.get("parent_process") or raw.get("parent_name")))
            explicit = origin.event_id in following.entities.get("related_events", []) or following.event_id in origin.entities.get("related_events", [])
            artifact = any(set(origin.entities.get(key, [])) & set(following.entities.get(key, [])) for key in ("hashes", "urls"))
            victim = any(set(origin.entities.get(key, [])) & set(following.entities.get(key, [])) for key in ("hosts", "users"))
            if executed and (explicit or artifact and victim):
                return True
        return False

    @staticmethod
    def _extract_event_entities(
        source: str, raw: dict[str, Any]
    ) -> dict[str, list[str]]:
        """Extraer y normalizar identificadores de entidades de un evento de log o alerta."""
        result: dict[str, list[str]] = {
            "users": [],
            "hosts": [],
            "ips": [],
            "domains": [],
            "urls": [],
            "hashes": [],
            "sessions": [],
            "customers": [],
            "related_events": [],
        }

        def add_token(group: str, val: Any) -> None:
            if not isinstance(val, str):
                return
            clean = val.strip()
            if not clean or clean.casefold() in _EMPTY_TOKENS or clean.startswith("("):
                return
            if group == "users":
                clean = clean.rsplit("\\", 1)[-1]
                if clean.casefold().endswith("@tarvia.example"):
                    clean = clean.split("@", 1)[0]
                clean = clean.casefold()
            elif group == "hosts":
                # Si es una IP, redirigir a ips
                try:
                    ip_address(clean)
                    add_token("ips", clean)
                    return
                except ValueError:
                    clean = clean.upper()
            elif group == "ips":
                try:
                    clean = str(ip_address(clean))
                except ValueError:
                    return
            elif group == "domains":
                clean = clean.rstrip(".").casefold()
                if "." not in clean or " " in clean:
                    return
            elif group == "hashes":
                if len(clean) not in _HASH_LENGTHS or not re.fullmatch(r"[0-9a-fA-F]+", clean):
                    return
                clean = clean.casefold()
            elif group == "sessions":
                clean = clean.strip()

            bucket = result[group]
            if clean not in bucket:
                bucket.append(clean)

        # Campos de usuario
        for u_field in (
            "user",
            "username",
            "user_upn",
            "upn",
            "actor_upn",
            "subject",
            "sender",
            "email",
            "identity",
            "new_user",
        ):
            val = raw.get(u_field)
            if isinstance(val, str):
                add_token("users", val)
        for r_field in ("recipient", "recipients"):
            val = raw.get(r_field)
            if isinstance(val, str):
                add_token("users", val)
            elif isinstance(val, list):
                for item in val:
                    add_token("users", item)

        # Campos de equipo / host
        for h_field in (
            "hostname",
            "host",
            "src_host",
            "dst_host",
            "client_host",
            "dc",
            "runner",
            "asset_id",
            "workstation",
        ):
            val = raw.get(h_field)
            if isinstance(val, str):
                if h_field == "host" and "." in val and val.casefold().endswith(".example"):
                    add_token("domains", val)
                else:
                    add_token("hosts", val)

        # Campos de IP
        for ip_field in (
            "ip",
            "src_ip",
            "dst_ip",
            "sender_ip",
            "sourceIPAddress",
            "assigned_ip",
            "client_ip",
        ):
            val = raw.get(ip_field)
            if isinstance(val, str):
                add_token("ips", val)
            elif isinstance(val, list):
                for item in val:
                    add_token("ips", item)

        # Campos de sesión / message_id / correlación explícita
        for s_field in (
            "session_id",
            "ai_session",
            "access_key",
            "access_key_id",
            "message_id",
            "build_id",
        ):
            val = raw.get(s_field)
            if isinstance(val, str):
                add_token("sessions", val)

        # Campos de hashes
        for hash_field in ("sha256", "sha1", "md5", "file_hash", "hash"):
            val = raw.get(hash_field)
            if isinstance(val, str):
                add_token("hashes", val)

        # Campos de dominio y URL
        for d_field in ("domain", "query", "destination"):
            val = raw.get(d_field)
            if isinstance(val, str):
                add_token("domains", val)
        for url_field in ("url", "downloaded_from"):
            val = raw.get(url_field)
            if isinstance(val, str):
                add_token("urls", val)
                try:
                    parsed_u = urlsplit(val)
                    if parsed_u.hostname:
                        add_token("domains", parsed_u.hostname)
                except ValueError:
                    pass

        # Cliente
        if isinstance(raw.get("customer_id"), str):
            add_token("customers", raw["customer_id"])

        # Eventos relacionados explícitos
        for rel_field in ("related_events", "parent_event_id", "source_event_id", "triggered_by"):
            val = raw.get(rel_field)
            if isinstance(val, str):
                add_token("related_events", val)
            elif isinstance(val, list):
                for item in val:
                    add_token("related_events", item)

        # Si el propio evento contiene una sub-estructura `entities` (p. ej. una alerta)
        nested = raw.get("entities")
        if isinstance(nested, dict):
            for h in nested.get("hosts") or []:
                if isinstance(h, str):
                    add_token("hosts", h)
                elif isinstance(h, dict):
                    add_token("hosts", h.get("hostname") or h.get("asset_id"))
                    add_token("ips", h.get("ip"))
            for u in nested.get("users") or []:
                if isinstance(u, str):
                    add_token("users", u)
                elif isinstance(u, dict):
                    add_token("users", u.get("username") or u.get("upn"))
            for ip in nested.get("ips") or []:
                add_token("ips", ip if isinstance(ip, str) else ip.get("ip") if isinstance(ip, dict) else None)
            for dom in nested.get("domains") or []:
                add_token("domains", dom if isinstance(dom, str) else dom.get("domain") if isinstance(dom, dict) else None)
            for u_item in nested.get("urls") or []:
                add_token("urls", u_item if isinstance(u_item, str) else u_item.get("url") if isinstance(u_item, dict) else None)
            for h_item in nested.get("hashes") or []:
                if isinstance(h_item, str):
                    add_token("hashes", h_item)
                elif isinstance(h_item, dict):
                    for alg in ("sha256", "sha1", "md5"):
                        add_token("hashes", h_item.get(alg))
            for s_item in nested.get("sessions") or []:
                add_token("sessions", s_item if isinstance(s_item, str) else s_item.get("session_id") if isinstance(s_item, dict) else None)

        return {k: v for k, v in result.items() if v}

    # ------------------------------------------------------------------
    # Impacto, entidades relacionadas, confianza y resumen
    # ------------------------------------------------------------------

    @staticmethod
    def _collect_related_entities(
        *,
        events: list[TimelineEvent],
        relationships: list[EntityRelationship],
    ) -> RelatedEntities:
        """Agrupar todas las entidades e indicadores observados en los eventos."""
        rel = RelatedEntities(relationships=list(relationships))
        for ev in events:
            for group in (
                "users",
                "hosts",
                "ips",
                "domains",
                "urls",
                "hashes",
                "sessions",
                "customers",
            ):
                bucket = getattr(rel, group)
                for val in ev.entities.get(group, []):
                    if val not in bucket:
                        bucket.append(val)
        return rel

    @staticmethod
    def _assess_technical_impact(
        *,
        chain_events: list[TimelineEvent],
        attack_phases: list[AttackPhase],
        related_entities: RelatedEntities,
        bundle: InvestigationBundle,
    ) -> str:
        """Describir el impacto técnico observable a partir de las fases y entidades."""
        if not chain_events:
            return "Sin impacto técnico malicioso confirmado en las evidencias analizadas."

        impacts: list[str] = []
        phase_ids = {p.phase for p in attack_phases}

        if "exfiltration" in phase_ids:
            impacts.append("exfiltración o exposición externa de información")
        if "data_access" in phase_ids:
            impacts.append("acceso no autorizado a datos o registros sensibles")
        if "privilege_escalation" in phase_ids:
            impacts.append("compromiso de credenciales o escalada de privilegios")
        if "lateral_movement" in phase_ids:
            impacts.append("movimiento lateral entre sistemas de la red")
        if "persistence" in phase_ids:
            impacts.append("establecimiento de mecanismos de persistencia")
        if "execution" in phase_ids:
            impacts.append("ejecución de código o comandos sospechosos")
        if "post_activity" in phase_ids:
            impacts.append("actividad post-explotación / comando y control / impacto operativo")
        if not impacts and "initial_access" in phase_ids:
            impacts.append("intento o vector de acceso inicial sobre activos expuestos")

        scope_parts: list[str] = []
        if related_entities.hosts:
            scope_parts.append(f"{len(related_entities.hosts)} equipo(s) ({', '.join(related_entities.hosts[:5])})")
        if related_entities.users:
            scope_parts.append(f"{len(related_entities.users)} usuario(s) ({', '.join(related_entities.users[:5])})")
        if related_entities.customers:
            scope_parts.append(f"{len(related_entities.customers)} cliente(s)")

        scope_str = f" sobre {', '.join(scope_parts)}" if scope_parts else ""
        return f"Se observa {', '.join(impacts)}{scope_str}."

    @staticmethod
    def _collect_supporting_evidence(
        *,
        chain_events: list[TimelineEvent],
        timeline: list[TimelineEvent],
    ) -> list[str]:
        """Obtener lista ordenada y sin duplicados de referencias a evidencias de soporte."""
        target = chain_events if chain_events else timeline
        refs: list[str] = []
        for ev in target:
            if ev.event_id and ev.event_id not in refs:
                refs.append(ev.event_id)
            else:
                for r in ev.evidence_refs:
                    if r not in refs:
                        refs.append(r)
        return refs

    @staticmethod
    def _calculate_overall_confidence(
        *,
        chain_events: list[TimelineEvent],
        timeline: list[TimelineEvent],
        attack_phases: list[AttackPhase],
        patient_zero: ReconstructionConclusion,
        root_cause: ReconstructionConclusion,
        uncertainties: list[str],
        is_indeterminate: bool,
    ) -> float:
        """Calcular confianza heurística global entre 0.0 y 1.0."""
        if is_indeterminate or not chain_events:
            return 0.0

        phase_avg = (
            sum(p.confidence for p in attack_phases) / len(attack_phases)
            if attack_phases
            else 0.45
        )
        base = (
            0.40 * phase_avg
            + 0.30 * patient_zero.confidence
            + 0.30 * root_cause.confidence
        )
        invalid_ts_count = sum(1 for ev in chain_events if not ev.timestamp_valid)
        penalty = 0.05 * invalid_ts_count + 0.03 * min(len(uncertainties), 5)
        return max(0.10, min(0.98, round(base - penalty, 2)))

    @staticmethod
    def _build_summary(
        *,
        incident_id: str,
        timeline: list[TimelineEvent],
        chain_events: list[TimelineEvent],
        first_observed: TimelineEvent | None,
        first_suspicious: TimelineEvent | None,
        patient_zero: ReconstructionConclusion,
        initial_access: ReconstructionConclusion,
        attack_phases: list[AttackPhase],
        root_cause: ReconstructionConclusion,
        technical_impact: str,
        confidence: float,
        uncertainties: list[str],
        is_indeterminate: bool,
    ) -> str:
        """Construir un resumen claro y estructurado para el analista N3."""
        header = f"Reconstrucción N3 {incident_id}".strip()
        if is_indeterminate:
            return (
                f"{header}: Resultado indeterminado ({len(timeline)} evento(s) revisados). "
                f"Las evidencias disponibles no permiten confirmar una cadena de ataque. "
                f"Incertidumbres: {len(uncertainties)}."
            )

        phases_str = (
            " -> ".join(p.name for p in attack_phases)
            if attack_phases
            else "Sin fases confirmadas"
        )
        obs_id = (
            first_observed.event_id or first_observed.source
            if first_observed
            else "N/A"
        )
        susp_id = (
            first_suspicious.event_id or first_suspicious.source
            if first_suspicious
            else "N/A"
        )
        return (
            f"{header}: Se reconstruyeron {len(chain_events)} evento(s) correlacionados "
            f"(de {len(timeline)} totales). Primer evento observado: {obs_id}. "
            f"Primer evento sospechoso: {susp_id}. "
            f"Paciente cero ({patient_zero.status}): {patient_zero.conclusion} "
            f"Acceso inicial ({initial_access.status}): {initial_access.conclusion} "
            f"Fases: {phases_str}. "
            f"Causa raíz ({root_cause.status}): {root_cause.conclusion} "
            f"Impacto: {technical_impact} Confianza: {confidence}."
        )

    # ------------------------------------------------------------------
    # Utilidades auxiliares de coerción y descripción
    # ------------------------------------------------------------------

    @staticmethod
    def _infer_access_vector_label(initial_events: list[TimelineEvent]) -> str:
        sources = {ev.source.casefold() for ev in initial_events}
        if "email" in sources or "email_clicks" in sources:
            return "Phishing por correo electrónico"
        if "waf" in sources:
            return "Explotación o inyección contra aplicación web expuesta"
        if "vpn" in sources:
            return "Acceso remoto VPN anómalo o con credenciales comprometidas"
        if "idp_signins" in sources:
            return "Inicio de sesión en IdP con cuenta válida desde origen anómalo"
        if "cloudtrail" in sources:
            return "Uso de credenciales o claves Cloud (IAM) desde origen inusual"
        if "ai_gateway" in sources:
            return "Prompt injection en el asistente de IA Vela"
        if "cicd_builds" in sources:
            return "Compromiso de cadena de suministro en pipeline CI/CD"
        return "Vector de acceso inicial detectado en telemetría de entrada"

    @staticmethod
    def _describe_event(
        *,
        source: str,
        event_id: str | None,
        raw: dict[str, Any],
        alert_meta: dict[str, Any],
    ) -> str:
        """Generar una descripción legible del evento sin inventar datos."""
        for field in ("summary", "description", "finding", "title"):
            val = raw.get(field)
            if isinstance(val, str) and val.strip():
                return val.strip()

        src = source.casefold()
        if src == "email":
            sender = raw.get("sender") or "desconocido"
            rcpt = raw.get("recipients") or raw.get("recipient") or ""
            subj = raw.get("subject") or ""
            return f"Correo de {sender} hacia {rcpt} (asunto: {subj!r})".strip()
        if src == "email_clicks":
            return f"Clic de {raw.get('user', 'usuario')} en URL {raw.get('url', '')}".strip()
        if src == "edr_events":
            proc = raw.get("process_name") or raw.get("event_type") or "proceso"
            host = raw.get("hostname") or "equipo"
            cmd = raw.get("command_line") or ""
            return f"EDR en {host}: {proc} {cmd}".strip()
        if src == "idp_signins":
            return (
                f"Inicio de sesión IdP de {raw.get('user_upn') or raw.get('user', 'usuario')} "
                f"({raw.get('result', 'evento')}) desde {raw.get('src_ip', 'IP')}"
            )
        if src == "idp_audit":
            return (
                f"Auditoría IdP: {raw.get('operation', 'operación')} por "
                f"{raw.get('actor_upn', 'actor')} sobre {raw.get('target', 'objetivo')}"
            )
        if src == "ad_events":
            return (
                f"Evento AD {raw.get('event_code', '')}: {raw.get('event', 'actividad')} "
                f"(sujeto: {raw.get('subject', '')}, objetivo: {raw.get('target', '')})"
            ).strip()
        if src == "firewall":
            return (
                f"Tráfico firewall {raw.get('action', '')}: {raw.get('src_ip', '')} -> "
                f"{raw.get('dst_ip', '')}:{raw.get('dst_port', '')} ({raw.get('zone_dst', '')})"
            ).strip()
        if src == "waf":
            return (
                f"Evento WAF en {raw.get('host', 'web')}{raw.get('uri', '')} "
                f"desde {raw.get('src_ip', '')} ({raw.get('rule_msg') or raw.get('action', '')})"
            ).strip()
        if src == "sql_audit":
            return (
                f"Consulta SQL {raw.get('statement_type', '')} sobre {raw.get('object', '')} "
                f"por {raw.get('user', '')} ({raw.get('rows_returned', 0)} filas)"
            ).strip()
        if src == "dlp":
            return (
                f"Alerta DLP ({raw.get('channel', '')}): {raw.get('user', '')} en "
                f"{raw.get('hostname', '')} hacia {raw.get('destination', '')} "
                f"({raw.get('file_name', '')})"
            ).strip()
        if src == "cloudtrail":
            return (
                f"Evento CloudTrail {raw.get('eventName', '')} desde "
                f"{raw.get('sourceIPAddress', '')}"
            ).strip()
        if src == "dns":
            return f"Consulta DNS de {raw.get('hostname') or raw.get('src_ip', '')} a {raw.get('query', '')}".strip()
        if src == "proxy":
            return f"Petición proxy de {raw.get('user') or raw.get('hostname', '')} a {raw.get('url') or raw.get('domain', '')}".strip()
        if src == "vpn":
            return f"Conexión VPN ({raw.get('action', '')}) de {raw.get('user', '')} desde {raw.get('src_ip', '')}".strip()
        if src == "ai_gateway":
            return f"Sesión asistente IA {raw.get('session_id', '')} de cliente {raw.get('customer_id', '')}".strip()
        if src == "cicd_builds":
            return f"Build CI/CD {raw.get('build_id', '')} en {raw.get('runner', '')} (estado: {raw.get('status', '')})".strip()

        if alert_meta.get("title"):
            return str(alert_meta["title"])
        return f"Evento en fuente {source}" + (f" ({event_id})" if event_id else "")

    @classmethod
    def _coerce_bundle(cls, bundle: Any) -> InvestigationBundle:
        """Convertir cualquier entrada compatible en un `InvestigationBundle`."""
        if bundle is None:
            return InvestigationBundle()
        if isinstance(bundle, InvestigationBundle):
            return bundle
        if isinstance(bundle, BaseModel):
            data = bundle.model_dump()
            for field in (
                "alerts",
                "evidence",
                "expanded_evidence",
                "events",
                "tickets",
                "incident_ticket",
                "analyses",
                "context",
                "contexts",
                "intel",
            ):
                if hasattr(bundle, field):
                    data[field] = getattr(bundle, field)
            return InvestigationBundle.model_validate(data)
        if isinstance(bundle, Mapping):
            return InvestigationBundle.model_validate(dict(bundle))
        if isinstance(bundle, Sequence) and not isinstance(bundle, (str, bytes)):
            return InvestigationBundle(evidence=list(bundle))

        payload: dict[str, Any] = {}
        for attr in (
            "incident_id",
            "alert_ids",
            "alerts",
            "evidence",
            "expanded_evidence",
            "events",
            "tickets",
            "incident_ticket",
            "analyses",
            "context",
            "contexts",
            "intel",
            "decision",
        ):
            if hasattr(bundle, attr):
                payload[attr] = getattr(bundle, attr)
        return InvestigationBundle.model_validate(payload)

    def _gather_raw_evidence_items(
        self, bundle: InvestigationBundle, notes: list[str]
    ) -> list[Evidence]:
        """Reunir objetos `Evidence` desde todas las colecciones disponibles del bundle."""
        collected: list[Evidence] = []

        def append_item(item: Any, default_source: str = "unknown") -> None:
            if isinstance(item, Evidence):
                collected.append(item)
                return
            if isinstance(item, Mapping):
                d = dict(item)
                # Si es una alerta RawAlert pasada como evento
                if "alert_id" in d and "source" not in d:
                    collected.append(
                        Evidence(
                            source=str(d.get("sensor") or d.get("rule_source") or "alert"),
                            event_id=str(d["alert_id"]),
                            timestamp=d.get("created_at") or d.get("timestamp"),
                            raw=d,
                        )
                    )
                    return
                source = str(d.get("source") or default_source)
                event_id = d.get("event_id")
                timestamp = (
                    d.get("timestamp")
                    or d.get("eventTime")
                    or d.get("created_at")
                    or (d.get("raw", {}).get("timestamp") if isinstance(d.get("raw"), dict) else None)
                )
                raw_payload = d.get("raw") if isinstance(d.get("raw"), dict) else d
                collected.append(
                    Evidence(
                        source=source,
                        event_id=str(event_id) if event_id is not None else None,
                        timestamp=str(timestamp) if timestamp is not None else None,
                        raw=dict(raw_payload),
                    )
                )

        for seq in (bundle.evidence, bundle.expanded_evidence, bundle.events):
            for it in seq or []:
                append_item(it)

        # Extraer también desde colecciones adicionales como `logs` si existen en extra fields
        extra_logs = getattr(bundle, "logs", None)
        if isinstance(extra_logs, Mapping):
            for src_name, rows in extra_logs.items():
                if isinstance(rows, Sequence) and not isinstance(rows, (str, bytes)):
                    for r in rows:
                        append_item(r, default_source=str(src_name))
        elif isinstance(extra_logs, Sequence) and not isinstance(extra_logs, (str, bytes)):
            for r in extra_logs:
                append_item(r)

        # Si no se proporcionaron evidencias directas pero sí alertas con `evidence` o tickets,
        # incorporar las evidencias referenciadas en ellos sin inventar eventos.
        if not collected:
            for alert in bundle.alerts:
                if not isinstance(alert, Mapping):
                    continue
                if isinstance(alert.get("evidence"), Sequence) and not isinstance(
                    alert.get("evidence"), (str, bytes)
                ):
                    for ev in alert["evidence"]:
                        append_item(ev, default_source=str(alert.get("source") or "alert"))
                else:
                    append_item(alert, default_source="alert")

            all_tickets = list(bundle.tickets)
            if bundle.incident_ticket is not None:
                all_tickets.append(bundle.incident_ticket)
            for t in all_tickets:
                t_ev = (
                    t.evidence
                    if isinstance(t, Ticket)
                    else (t.get("evidence") or [])
                    if isinstance(t, Mapping)
                    else []
                )
                for tev in t_ev:
                    if isinstance(tev, Mapping):
                        append_item(
                            {
                                "source": tev.get("source", "ticket"),
                                "event_id": tev.get("event_id"),
                                "timestamp": tev.get("timestamp"),
                                "raw": {"finding": tev.get("finding", "")},
                            }
                        )
                    elif hasattr(tev, "source"):
                        append_item(
                            {
                                "source": getattr(tev, "source", "ticket"),
                                "event_id": getattr(tev, "event_id", None),
                                "raw": {"finding": getattr(tev, "finding", "")},
                            }
                        )

        return collected

    @staticmethod
    def _index_alert_metadata_by_event(
        alerts: Sequence[RawAlert],
    ) -> dict[str, dict[str, Any]]:
        """Vincular metadatos reales de alertas (`rule_id`, `mitre`, `title`) a sus `related_events`."""
        mapping: dict[str, dict[str, Any]] = {}
        for alert in alerts or []:
            if not isinstance(alert, Mapping):
                continue
            meta = {
                "alert_id": alert.get("alert_id"),
                "rule_id": alert.get("rule_id"),
                "mitre": alert.get("mitre"),
                "title": alert.get("title"),
            }
            if alert.get("alert_id"):
                mapping[str(alert["alert_id"])] = meta
            for eid in alert.get("related_events") or []:
                if isinstance(eid, str) and eid.strip():
                    mapping.setdefault(eid.strip(), meta)
        return mapping

    @staticmethod
    def _extract_malicious_iocs(
        intel: Sequence[Any],
        tickets: Sequence[Any],
    ) -> set[str]:
        """Extraer indicadores corroborados como maliciosos en entradas de inteligencia."""
        malicious: set[str] = set()
        entries = list(intel or [])
        for t in tickets or []:
            if isinstance(t, Ticket):
                entries.extend(t.enrichment)
            elif isinstance(t, Mapping):
                entries.extend(t.get("enrichment") or [])

        for entry in entries:
            ind = (
                entry.indicator
                if isinstance(entry, IntelEntry)
                else entry.get("indicator", "")
                if isinstance(entry, Mapping)
                else ""
            )
            res = (
                entry.result
                if isinstance(entry, IntelEntry)
                else entry.get("result", "")
                if isinstance(entry, Mapping)
                else ""
            )
            if not ind:
                continue
            res_low = str(res).casefold()
            if "malicious" in res_low or "malware" in res_low or "phishing" in res_low or "c2" in res_low:
                malicious.add(str(ind).strip().casefold())
        return malicious
