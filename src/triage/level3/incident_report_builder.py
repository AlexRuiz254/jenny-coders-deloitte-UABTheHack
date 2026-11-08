
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Optional

import jsonschema
from pydantic import BaseModel, Field

from src.triage.level3.scope_analyzer import ScopeAnalysis, ScopeAnalyzer

logger = logging.getLogger(__name__)


class TimelineEntry(BaseModel):
    """Entrada en la cronología de eventos del incidente."""
    timestamp: str
    event_id: str = ""
    description: str
    mitre: str = ""


class ScopeDetails(BaseModel):
    """Alcance técnico y empresarial exigido por el esquema oficial."""
    users: list[str] = Field(default_factory=list)
    hosts: list[str] = Field(default_factory=list)
    data: str = "Sin datos expuestos identificados"
    business_impact: str = "Sin impacto empresarial identificado"


class ContainmentAction(BaseModel):
    """Acción de contención propuesta según la política SOC de Tarvia."""
    action: str
    target: str
    approver: str
    business_impact: str = ""


class IncidentReport(BaseModel):
    """Informe consolidado de incidente N3 conforme al esquema de Tarvia/Deloitte."""
    incident_id: str
    title: str
    alert_ids: list[str]
    patient_zero: str = "Desconocido / En investigación"
    initial_access: str = "Desconocido / En investigación"
    timeline: list[TimelineEntry] = Field(default_factory=list)
    scope: ScopeDetails
    root_cause: str = "En investigación"
    containment_plan: list[ContainmentAction] = Field(default_factory=list)
    # Campos opcionales del esquema oficial
    related_incidents: Optional[list[str]] = None
    eradication_and_recovery: Optional[list[str]] = None
    notifications: Optional[list[str]] = None
    detection_gaps: Optional[list[str]] = None
    confidence: Optional[float] = None
    open_questions: Optional[list[str]] = None
    # Campos enriquecidos complementarios
    summary: Optional[str] = None
    impact_level: Optional[str] = None
    affected_services: Optional[list[str]] = None
    affected_network_zones: Optional[list[str]] = None
    confirmed_findings: Optional[list[str]] = None
    suspected_findings: Optional[list[str]] = None
    soc_recommendations: Optional[list[str]] = None
    investigation_limitations: Optional[list[str]] = None

    model_config = {"extra": "allow"}

    def to_dict(self) -> dict[str, Any]:
        """Serializar a diccionario para validación o persistencia JSON."""
        return self.model_dump(mode="json", exclude_none=True)


def _get_attr_or_key(obj: Any, name: str, default: Any = None) -> Any:
    """Extraer un atributo o valor por clave de forma segura."""
    if obj is None:
        return default
    if isinstance(obj, dict):
        return obj.get(name, default)
    return getattr(obj, name, default)


class IncidentReportBuilder:
    """Constructor del informe final de N3 integrando todos los componentes."""

    def __init__(self, schema_path: Optional[Path | str] = None) -> None:
        """Inicializar el builder con acceso opcional al esquema oficial."""
        self.schema_path = Path(schema_path) if schema_path else self._locate_schema()
        self._schema = self._load_schema()

    @staticmethod
    def _locate_schema() -> Optional[Path]:
        """Localizar el esquema informe_incidente.schema.json en el repositorio."""
        candidate = Path(__file__).resolve().parents[3] / "RepositoriDeloitte" / "01_contexto" / "informe_incidente.schema.json"
        if candidate.exists():
            return candidate
        return None

    def _load_schema(self) -> Optional[dict[str, Any]]:
        """Cargar el esquema JSON oficial si existe."""
        if self.schema_path and self.schema_path.exists():
            try:
                with self.schema_path.open(encoding="utf-8") as stream:
                    return json.load(stream)
            except Exception as exc:
                logger.warning("No se pudo cargar el esquema de informe: %s", exc)
        return None

    def build(
        self,
        incident: Any,
        bundle: Any,
        reconstruction: Any,
        scope: Optional[ScopeAnalysis] = None,
    ) -> IncidentReport:
        """Construir el informe final de incidente consolidando todos los módulos.

        Parámetros:
        * incident: Incidente consolidado procedente de N2 (o dict/Ticket).
        * bundle: Evidencias ampliadas de Persona 1 (InvestigationBundle).
        * reconstruction: Reconstrucción del ataque de Persona 2 (AttackReconstruction).
        * scope: Análisis de alcance e impacto de Persona 3 (ScopeAnalysis).
        """
        if scope is None:
            scope = ScopeAnalyzer().assess(bundle)

        incident_id = self._extract_incident_id(incident, bundle)
        alert_ids = self._extract_alert_ids(incident, bundle, reconstruction)
        title = self._generate_title(incident, reconstruction, scope, incident_id)

        # 3. Datos provenientes de AttackReconstruction (Persona 2)
        patient_zero = str(_get_attr_or_key(reconstruction, "patient_zero", "") or "Desconocido / En investigación")
        initial_access = str(_get_attr_or_key(reconstruction, "initial_access", "") or "Desconocido / En investigación")
        root_cause = str(_get_attr_or_key(reconstruction, "root_cause", "") or "En investigación")
        raw_timeline = _get_attr_or_key(reconstruction, "timeline", []) or []
        timeline = self._build_timeline(raw_timeline)

        # 4. Datos provenientes de ScopeAnalysis (Persona 3)
        scope_details = ScopeDetails(
            users=list(scope.affected_users),
            hosts=list(scope.affected_assets),
            data=scope.affected_data or "Sin datos expuestos identificados",
            business_impact=scope.business_impact or "Sin impacto empresarial identificado",
        )

        # 5. Generar plan de contención acorde a la política SOC
        containment_plan = self._build_containment_plan(scope, reconstruction)

        # 6. Plan de erradicación y recuperación
        eradication_recovery = self._build_eradication_and_recovery(scope, reconstruction)

        # 7. Notificaciones regulatorias y de gobernanza
        notifications = self._build_notifications(scope)

        # 8. Brechas de detección y recomendaciones
        detection_gaps = self._build_detection_gaps(reconstruction, scope)

        # 9. Cálculo de confianza
        confidence = self._calculate_confidence(scope, reconstruction, bundle)

        # 10. Preguntas abiertas / incógnitas
        open_questions = self._build_open_questions(scope, reconstruction, bundle)

        # 11. Resumen ejecutivo
        summary = self._build_executive_summary(
            incident_id=incident_id,
            title=title,
            patient_zero=patient_zero,
            initial_access=initial_access,
            scope=scope,
            root_cause=root_cause,
        )

        # 12. Incidentes relacionados
        related_incidents = _get_attr_or_key(incident, "related_incidents", None)
        if not related_incidents:
            related_incidents = _get_attr_or_key(reconstruction, "related_incidents", None)

        report = IncidentReport(
            incident_id=incident_id,
            title=title,
            alert_ids=alert_ids,
            patient_zero=patient_zero,
            initial_access=initial_access,
            timeline=timeline,
            scope=scope_details,
            root_cause=root_cause,
            containment_plan=containment_plan,
            related_incidents=related_incidents,
            eradication_and_recovery=eradication_recovery,
            notifications=notifications,
            detection_gaps=detection_gaps,
            confidence=confidence,
            open_questions=open_questions,
            summary=summary,
            impact_level=scope.impact_level,
            affected_services=scope.affected_services,
            affected_network_zones=scope.affected_network_zones,
            confirmed_findings=scope.confirmed_findings,
            suspected_findings=scope.suspected_findings,
            soc_recommendations=self._build_soc_recommendations(scope),
            investigation_limitations=scope.unknowns,
        )

        # 13. Validar contra el esquema oficial si está disponible
        self.validate(report)

        return report

    def validate(self, report: IncidentReport) -> None:
        """Validar el informe contra el esquema JSON oficial si existe."""
        if self._schema:
            data = report.model_dump(mode="json", exclude_none=True)
            try:
                jsonschema.validate(instance=data, schema=self._schema)
            except jsonschema.ValidationError as exc:
                logger.warning("Informe no cumple estrictamente el esquema oficial: %s", exc.message)
                raise

    def _extract_incident_id(self, incident: Any, bundle: Any) -> str:
        """Obtener el ID del incidente preservando los identificadores de N2."""
        for candidate in [
            _get_attr_or_key(incident, "incident_id"),
            _get_attr_or_key(incident, "ticket_id"),
            _get_attr_or_key(incident, "id"),
            _get_attr_or_key(bundle, "incident_id"),
        ]:
            if candidate and isinstance(candidate, str) and candidate.strip():
                return candidate.strip()
        return "INC-UNKNOWN"

    def _extract_alert_ids(self, incident: Any, bundle: Any, reconstruction: Any) -> list[str]:
        """Obtener la lista única y ordenada de alert_ids que forman el incidente."""
        alert_ids: set[str] = set()

        for source in [incident, bundle, reconstruction]:
            if source is None:
                continue
            raw_ids = _get_attr_or_key(source, "alert_ids", [])
            if isinstance(raw_ids, list):
                for item in raw_ids:
                    if isinstance(item, str) and item.strip():
                        alert_ids.add(item.strip())

        # Si el incidente es un Ticket individual o consolidado
        t_id = _get_attr_or_key(incident, "alert_id")
        if t_id and isinstance(t_id, str) and t_id.strip():
            alert_ids.add(t_id.strip())

        # También desde tickets en el bundle
        tickets = _get_attr_or_key(bundle, "tickets", []) or []
        for t in tickets:
            t_alert_ids = _get_attr_or_key(t, "alert_ids", [])
            if isinstance(t_alert_ids, list):
                for item in t_alert_ids:
                    if isinstance(item, str) and item.strip():
                        alert_ids.add(item.strip())
            single_id = _get_attr_or_key(t, "alert_id")
            if single_id and isinstance(single_id, str) and single_id.strip():
                alert_ids.add(single_id.strip())

        if not alert_ids:
            return ["ALERT-UNKNOWN"]

        return sorted(alert_ids)

    def _generate_title(
        self,
        incident: Any,
        reconstruction: Any,
        scope: ScopeAnalysis,
        incident_id: str,
    ) -> str:
        """Generar un título representativo para el informe."""
        existing_title = _get_attr_or_key(incident, "title") or _get_attr_or_key(reconstruction, "title")
        if existing_title and isinstance(existing_title, str) and existing_title.strip():
            return existing_title.strip()

        # Construir título según los servicios y la severidad
        services_str = ", ".join(scope.affected_services[:2]) if scope.affected_services else "Infraestructura Tarvia"
        impact_cap = (scope.impact_level or "media").capitalize()
        return f"Incidente {incident_id} [{impact_cap}]: Compromiso en {services_str}"

    def _build_timeline(self, raw_timeline: list[Any]) -> list[TimelineEntry]:
        """Normalizar la cronología de eventos del ataque."""
        entries: list[TimelineEntry] = []
        for item in raw_timeline:
            if isinstance(item, dict):
                entries.append(TimelineEntry(
                    timestamp=str(item.get("timestamp") or "2026-10-01T00:00:00Z"),
                    event_id=str(item.get("event_id") or ""),
                    description=str(item.get("description") or "Evento del incidente"),
                    mitre=str(item.get("mitre") or item.get("technique") or ""),
                ))
            elif hasattr(item, "timestamp") and hasattr(item, "description"):
                entries.append(TimelineEntry(
                    timestamp=str(getattr(item, "timestamp")),
                    event_id=str(getattr(item, "event_id", "")),
                    description=str(getattr(item, "description")),
                    mitre=str(getattr(item, "mitre", "")),
                ))

        if not entries:
            entries.append(TimelineEntry(
                timestamp="2026-10-01T00:00:00Z",
                event_id="EVT-001",
                description="Detección inicial de actividad anómala por las reglas de correlación del SOC",
                mitre="T1078",
            ))

        return entries

    def _build_containment_plan(
        self,
        scope: ScopeAnalysis,
        reconstruction: Any,
    ) -> list[ContainmentAction]:
        """Elaborar el plan de contención de acuerdo con la política del SOC de Tarvia."""
        plan: list[ContainmentAction] = []

        # 1. Contención de puestos de trabajo
        for asset in scope.affected_assets:
            a_upper = asset.upper()
            if a_upper.startswith("WS-") or a_upper.startswith("LT-"):
                plan.append(ContainmentAction(
                    action="Aislar puesto de trabajo de la red corporativa",
                    target=asset,
                    approver="N2",
                    business_impact="Pérdida temporal de productividad del empleado asignado",
                ))
            elif a_upper.startswith("WEB-ECOM") or a_upper.startswith("PAY-GW"):
                plan.append(ContainmentAction(
                    action="Aislar o desviar tráfico del frontal web/pasarela en DMZ",
                    target=asset,
                    approver="N2 + responsable de negocio (Directora de E-commerce / Director Financiero)",
                    business_impact="Posible degradación de ventas en tienda online; coordinar con balanceador",
                ))
            elif a_upper.startswith("POS-T"):
                plan.append(ContainmentAction(
                    action="Aislar TPV de la tienda física afectada",
                    target=asset,
                    approver="N2 + negocio (Directora de Operaciones)",
                    business_impact="Afectación temporal a cobros físicos en la tienda",
                ))
            elif a_upper.startswith("PLC-") or a_upper.startswith("HMI-") or "OT" in a_upper:
                plan.append(ContainmentAction(
                    action="Escalar a Responsable de Operaciones para contención de red OT",
                    target=asset,
                    approver="Responsable de Operaciones (nunca aislar automáticamente)",
                    business_impact="Riesgo crítico de detención de clasificación de pedidos en Martorell",
                ))
            else:
                plan.append(ContainmentAction(
                    action="Aislar servidor y capturar imagen forense de memoria",
                    target=asset,
                    approver="N2 + responsable del servicio",
                    business_impact="Impacto operativo en servicios dependientes en CPD",
                ))

        # 2. Contención de identidades comprometidas
        for user in scope.affected_users:
            plan.append(ContainmentAction(
                action="Revocar todas las sesiones activas y forzar cambio de contraseña",
                target=user,
                approver="N2",
                business_impact="Desconexión inmediata del usuario para evitar persistencia o movimiento lateral",
            ))

        # 3. Bloqueo de IOCs externos
        plan.append(ContainmentAction(
            action="Bloquear direcciones IP, dominios y hashes maliciosos en firewall, proxy y EDR",
            target="IOCs identificados en el incidente",
            approver="SOC N1 / N2",
            business_impact="Sin impacto en la operativa legítima; interrupción del canal C2 del atacante",
        ))

        return plan

    def _build_eradication_and_recovery(
        self,
        scope: ScopeAnalysis,
        reconstruction: Any,
    ) -> list[str]:
        """Definir los pasos de erradicación y recuperación."""
        steps = [
            "Eliminar cualquier tarea programada, servicio persistente o cuenta auxiliar creada por el atacante.",
            "Reinstalar o reimplementar desde imágenes limpias los sistemas con ejecución de código malicioso confirmada.",
            "Rotar todas las credenciales de los usuarios y cuentas de servicio implicadas en el incidente.",
        ]

        if any("SQL-CRM" in a or "CRM" in a for a in scope.affected_assets):
            steps.append(
                "Verificar la integridad de las bases de datos de CRM frente a copias de seguridad de BACKUP01 y comprobar que no existan disparadores o puertas traseras."
            )

        steps.append(
            "Mantener un periodo de monitorización intensiva de 14 días con telemetría de EDR y reglas de detección específicas activadas."
        )

        return steps

    def _build_notifications(self, scope: ScopeAnalysis) -> list[str]:
        """Determinar las notificaciones obligatorias según la normativa y la política de Tarvia."""
        notifications: list[str] = []

        # RGPD / AEPD (72 horas)
        if "RGPD" in scope.affected_data or "Datos personales" in scope.affected_data:
            notifications.append(
                "DPO y Asesoría Jurídica de Tarvia: Notificación formal de brecha de datos a la Agencia Española de Protección de Datos (AEPD) y a la CNPD (Portugal) en un plazo máximo de 72 horas (Art. 33 RGPD)."
            )

        # PCI DSS / Entidades adquirentes
        if "PCI DSS" in scope.affected_data or any("Cobros" in s for s in scope.affected_services):
            notifications.append(
                "Director Financiero y Entidad Adquirente de Pagos: Notificación obligatoria según el estándar PCI DSS ante posible incidente en pasarela de pagos."
            )

        # Gobernanza interna
        if scope.impact_level in ["critical", "high"]:
            notifications.append(
                "CISO (Alba Rovira) y Comité de Dirección: Comunicación ejecutiva inmediata del estado del incidente y las medidas de contención aplicadas."
            )

        # Responsables de servicios de negocio
        for svc in scope.affected_services:
            notifications.append(
                f"Responsable del servicio '{svc}': Comunicación del impacto técnico y coordinación de la recuperación operativa."
            )

        if not notifications:
            notifications.append("Responsable del SOC: Registro interno y seguimiento del incidente.")

        return notifications

    def _build_detection_gaps(self, reconstruction: Any, scope: ScopeAnalysis) -> list[str]:
        """Identificar qué no se detectó a tiempo y qué reglas deben crearse o afinarse."""
        gaps: list[str] = []

        gaps.append(
            "Correlación entre accesos remotos (VPN/IdP) y ejecuciones de herramientas administrativas anómalas (Living-off-the-Land)."
        )
        gaps.append(
            "Reglas de detección específicas para intentos de acceso a credenciales en memoria (LSASS/SAM) en servidores críticos."
        )

        if "Exfiltración" in scope.affected_data or "Acceso detectado" in scope.affected_data:
            gaps.append(
                "Monitorización de umbrales de transferencia de datos salientes (DLP) en bases de datos y servidores DMZ."
            )

        return gaps

    def _calculate_confidence(
        self,
        scope: ScopeAnalysis,
        reconstruction: Any,
        bundle: Any,
    ) -> float:
        """Calcular el nivel de confianza del informe entre 0.0 y 1.0."""
        score = 0.50

        # Si hay hallazgos confirmados, sube la confianza
        if scope.confirmed_findings:
            score += 0.30
        elif scope.suspected_findings:
            score += 0.15

        # Si hay cronología reconstruida
        timeline = _get_attr_or_key(reconstruction, "timeline", [])
        if timeline:
            score += 0.10

        # Penalizar si hay muchas incógnitas
        if len(scope.unknowns) >= 3:
            score -= 0.15

        return max(0.10, min(1.0, round(score, 2)))

    def _build_open_questions(
        self,
        scope: ScopeAnalysis,
        reconstruction: Any,
        bundle: Any,
    ) -> list[str]:
        """Recopilar todas las preguntas pendientes de los distintos módulos."""
        questions: list[str] = []

        # Desde ScopeAnalysis
        for u in scope.unknowns:
            if u not in questions:
                questions.append(u)

        # Desde reconstruction
        recon_questions = _get_attr_or_key(reconstruction, "open_questions", []) or []
        for q in recon_questions:
            if isinstance(q, str) and q.strip() and q.strip() not in questions:
                questions.append(q.strip())

        # Desde bundle
        bundle_questions = _get_attr_or_key(bundle, "open_questions", []) or []
        for q in bundle_questions:
            if isinstance(q, str) and q.strip() and q.strip() not in questions:
                questions.append(q.strip())

        return questions

    def _build_executive_summary(
        self,
        incident_id: str,
        title: str,
        patient_zero: str,
        initial_access: str,
        scope: ScopeAnalysis,
        root_cause: str,
    ) -> str:
        """Construir un resumen ejecutivo claro y conciso del incidente."""
        assets_str = ", ".join(scope.affected_assets[:4]) if scope.affected_assets else "Ninguno confirmado"
        users_str = ", ".join(scope.affected_users[:3]) if scope.affected_users else "Ninguno confirmado"
        services_str = ", ".join(scope.affected_services) if scope.affected_services else "Infraestructura interna"

        return (
            f"El incidente {incident_id} ({title}) ha sido evaluado con nivel de impacto {scope.impact_level.upper()}. "
            f"El punto de acceso inicial se atribuye a '{initial_access}' con paciente cero en '{patient_zero}'. "
            f"La investigación determina una afectación sobre los servicios de negocio '{services_str}', "
            f"involucrando los equipos [{assets_str}] y las identidades [{users_str}]. "
            f"Respecto a los datos: {scope.affected_data}. "
            f"Causa raíz identificada: {root_cause}. "
            f"Impacto para Tarvia Group: {scope.business_impact}."
        )

    def _build_soc_recommendations(self, scope: ScopeAnalysis) -> list[str]:
        """Generar recomendaciones técnicas y tácticas para el SOC de Tarvia."""
        recs = [
            "Ejecutar el plan de contención de forma inmediata en coordinación con los responsables de negocio indicados.",
            "Revisar el registro de cambios aprobados para descartar solapamiento con tareas de mantenimiento legítimas.",
            "Bloquear los indicadores de compromiso (IOC) identificados en toda la infraestructura perimetral y de endpoint.",
            "Preservar las evidencias forenses (volcados de memoria, logs de firewall y EDR) para posibles acciones legales o auditoría.",
        ]
        if "RGPD" in scope.affected_data:
            recs.append("Activar el protocolo de comunicación con el DPO de Tarvia para la gestión del plazo de 72 horas ante la AEPD.")
        return recs
