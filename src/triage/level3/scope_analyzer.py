
from __future__ import annotations

import csv
from ipaddress import ip_address, ip_network
import logging
from pathlib import Path
from typing import Any, Optional

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

# Catálogo predeterminado de zonas de red de Tarvia (zonas_red.csv)
DEFAULT_NETWORK_ZONES = [
    ("HQ-USERS", "10.10.0.0/16", "Barcelona HQ", "Puestos de usuario de oficinas centrales"),
    ("MAD-USERS", "10.11.0.0/16", "Madrid Oficina", "Puestos de Atención al Cliente"),
    ("DC-SERVERS", "10.20.0.0/16", "CPD Barcelona", "Servidores corporativos"),
    ("STORES", "10.30.0.0/16", "Tiendas", "Red de tiendas: TPV y portátiles (10.30.<tienda>.0/24)"),
    ("LOGISTICS-IT", "10.40.0.0/20", "Martorell CL", "IT del centro logístico"),
    ("LOGISTICS-OT", "10.40.16.0/20", "Martorell CL", "OT: PLC de clasificación y HMI"),
    ("DMZ", "10.50.0.0/16", "CPD Barcelona", "Frontales web e-commerce, pasarela de pagos, asistente IA"),
    ("DEV", "10.60.0.0/16", "CPD Barcelona", "Entorno de desarrollo (Jenkins, Git)"),
    ("VPN-POOL", "10.99.0.0/16", "Remoto", "Usuarios en VPN"),
    ("AWS-PROD", "172.16.0.0/16", "AWS eu-west-1", "Cuenta tarvia-prod"),
]

# Catálogo predeterminado de servicios de negocio (servicios_negocio.csv)
DEFAULT_SERVICES = [
    {
        "servicio": "Tienda online y app",
        "criticidad": "Crítica",
        "impacto": "38% de la facturación; 1,3 M clientes registrados (120.000 €/h de caída)",
        "activos": ["WEB-ECOM", "PAY-GW01", "SQL-CRM01"],
        "responsable": "Directora de E-commerce",
    },
    {
        "servicio": "Cobros online (PCI DSS)",
        "criticidad": "Crítica",
        "impacto": "Toda la venta online; cumplimiento PCI DSS",
        "activos": ["PAY-GW01"],
        "responsable": "Director Financiero",
    },
    {
        "servicio": "Cobro en tienda (PCI DSS)",
        "criticidad": "Alta",
        "impacto": "Venta física de 64 tiendas",
        "activos": ["POS-T"],
        "responsable": "Directora de Operaciones",
    },
    {
        "servicio": "CRM y datos de clientes (1,3 M registros, RGPD)",
        "criticidad": "Crítica",
        "impacto": "Datos personales: brecha notificable a la AEPD en 72 h",
        "activos": ["SQL-CRM01", "CRM-APP01"],
        "responsable": "DPO",
    },
    {
        "servicio": "Identidad y directorio activo",
        "criticidad": "Crítica",
        "impacto": "Acceso de todos los empleados",
        "activos": ["DC01", "DC02", "IdP"],
        "responsable": "Director de Tecnología",
    },
    {
        "servicio": "ERP: finanzas, compras, stock",
        "criticidad": "Alta",
        "impacto": "Pagos a proveedores, stock",
        "activos": ["ERP-APP01", "ERP-DB01"],
        "responsable": "Director Financiero",
    },
    {
        "servicio": "Gestión de almacén (WMS)",
        "criticidad": "Alta",
        "impacto": "Salida de pedidos online desde Martorell",
        "activos": ["WMS01"],
        "responsable": "Directora de Operaciones",
    },
    {
        "servicio": "Clasificación automática de pedidos",
        "criticidad": "Alta",
        "impacto": "Parada = retraso de todos los pedidos online",
        "activos": ["PLC-SORT", "HMI-SORT01"],
        "responsable": "Directora de Operaciones",
    },
    {
        "servicio": "Asistente de compra con IA «Vela»",
        "criticidad": "Alta",
        "impacto": "Atención 24/7; acceso a pedidos del cliente autenticado",
        "activos": ["AI-ASSIST01"],
        "responsable": "Responsable de IA",
    },
    {
        "servicio": "Copias de seguridad",
        "criticidad": "Alta",
        "impacto": "Recuperación ante ransomware",
        "activos": ["BACKUP01", "tarvia-backups-prod"],
        "responsable": "Director de Tecnología",
    },
    {
        "servicio": "Nóminas y portal del empleado",
        "criticidad": "Alta",
        "impacto": "Datos personales de empleados",
        "activos": ["HR-APP01"],
        "responsable": "Directora de Personas",
    },
    {
        "servicio": "Integración continua",
        "criticidad": "Media",
        "impacto": "Despliegues de e-commerce",
        "activos": ["JENKINS-DEV01", "GIT-DEV01"],
        "responsable": "Director de Tecnología",
    },
    {
        "servicio": "Puesto de trabajo",
        "criticidad": "Media",
        "impacto": "Productividad",
        "activos": ["WS-", "LT-"],
        "responsable": "Director de Tecnología",
    },
]


class AffectedAsset(BaseModel):
    """Detalle de un activo evaluado en el alcance."""
    asset_id: str
    status: str = "confirmed"  # "confirmed" | "suspected"
    criticality: Optional[str] = None
    role: Optional[str] = None
    reason: Optional[str] = None


class AffectedUser(BaseModel):
    """Detalle de un usuario evaluado en el alcance."""
    username: str
    status: str = "confirmed"  # "confirmed" | "suspected"
    role: Optional[str] = None
    reason: Optional[str] = None


class ScopeAnalysis(BaseModel):
    """Resultado estructurado del análisis de alcance e impacto N3."""
    affected_assets: list[str] = Field(default_factory=list)
    affected_users: list[str] = Field(default_factory=list)
    affected_services: list[str] = Field(default_factory=list)
    affected_data: str = "Sin datos expuestos identificados"
    affected_network_zones: list[str] = Field(default_factory=list)
    business_impact: str = "Sin impacto empresarial identificado"
    impact_level: str = "low"  # "low" | "medium" | "high" | "critical"
    confirmed_findings: list[str] = Field(default_factory=list)
    suspected_findings: list[str] = Field(default_factory=list)
    unknowns: list[str] = Field(default_factory=list)
    # Metadatos granulares opcionales para mayor fidelidad
    asset_details: list[AffectedAsset] = Field(default_factory=list)
    user_details: list[AffectedUser] = Field(default_factory=list)


class InvestigationBundle(BaseModel):
    """Modelo flexible para recibir el bundle de evidencias de Persona 1."""
    incident_id: Optional[str] = None
    incident: Any = None
    tickets: list[Any] = Field(default_factory=list)
    evidence: list[Any] = Field(default_factory=list)
    expanded_evidence: list[Any] = Field(default_factory=list)
    events: list[dict[str, Any]] = Field(default_factory=list)
    alerts: list[dict[str, Any]] = Field(default_factory=list)
    network_flows: list[dict[str, Any]] = Field(default_factory=list)
    entities: dict[str, Any] = Field(default_factory=dict)
    open_questions: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)

    model_config = {"extra": "allow"}


def _get_field(obj: Any, name: str, default: Any = None) -> Any:
    """Extraer un atributo o clave con soporte para dicts y objetos."""
    if obj is None:
        return default
    if isinstance(obj, dict):
        return obj.get(name, default)
    return getattr(obj, name, default)


class ScopeAnalyzer:
    """Analizador de alcance e impacto de incidentes N3."""

    def __init__(
        self,
        references: Any = None,
        dataset_root: Optional[Path | str] = None,
    ) -> None:
        """Inicializar el analizador con referencias o repositorios auxiliares."""
        self.references = references
        self.dataset_root = Path(dataset_root) if dataset_root else None
        self._zones = self._load_network_zones()
        self._services = self._load_business_services()

    def _load_network_zones(self) -> list[tuple[str, str, str, str]]:
        """Cargar zonas de red desde archivo o utilizar valores predeterminados."""
        if self.dataset_root:
            path = self.dataset_root / "02_inventario" / "zonas_red.csv"
            if path.exists():
                try:
                    with path.open(encoding="utf-8-sig", newline="") as stream:
                        reader = csv.DictReader(stream)
                        loaded = [
                            (r.get("zona", ""), r.get("cidr", ""), r.get("ubicacion", ""), r.get("descripcion", ""))
                            for r in reader if r.get("cidr")
                        ]
                        if loaded:
                            return loaded
                except Exception as exc:
                    logger.debug("No se pudo cargar zonas_red.csv: %s", exc)
        return DEFAULT_NETWORK_ZONES

    def _load_business_services(self) -> list[dict[str, Any]]:
        """Cargar servicios de negocio desde inventario o valores predeterminados."""
        if self.dataset_root:
            path = self.dataset_root / "02_inventario" / "servicios_negocio.csv"
            if path.exists():
                try:
                    with path.open(encoding="utf-8-sig", newline="") as stream:
                        reader = csv.DictReader(stream)
                        loaded = []
                        for r in reader:
                            activos_raw = r.get("activos", "")
                            # Normalizar lista de activos separada por coma o patrones
                            activos = [a.strip() for a in activos_raw.replace("..", ",").split(",") if a.strip()]
                            loaded.append({
                                "servicio": r.get("servicio", ""),
                                "criticidad": r.get("criticidad", "Media"),
                                "impacto": r.get("impacto", ""),
                                "activos": activos,
                                "responsable": r.get("responsable", ""),
                            })
                        if loaded:
                            return loaded
                except Exception as exc:
                    logger.debug("No se pudo cargar servicios_negocio.csv: %s", exc)
        return DEFAULT_SERVICES

    def assess(self, bundle: Any) -> ScopeAnalysis:
        """Determinar el alcance real o potencial del incidente a partir del bundle."""
        if bundle is None:
            return self._empty_scope("Bundle es None")

        # Extraer elementos clave del bundle
        all_evidence = self._collect_evidence(bundle)
        all_events = self._collect_events(bundle)
        all_alerts = self._collect_alerts(bundle)
        entities = _get_field(bundle, "entities", {}) or {}

        # Si no hay absolutamente ninguna información
        if not all_evidence and not all_events and not all_alerts and not entities:
            return self._empty_scope("Bundle sin evidencias, alertas ni eventos")

        # 1. Identificar activos
        affected_assets_details = self._identify_assets(
            evidence=all_evidence,
            events=all_events,
            alerts=all_alerts,
            entities=entities,
        )
        confirmed_assets = [a.asset_id for a in affected_assets_details if a.status == "confirmed"]
        suspected_assets = [a.asset_id for a in affected_assets_details if a.status == "suspected"]
        # Lista agregada de activos afectados
        affected_assets = [a.asset_id for a in affected_assets_details]

        # 2. Identificar usuarios
        affected_users_details = self._identify_users(
            evidence=all_evidence,
            events=all_events,
            alerts=all_alerts,
            entities=entities,
        )
        confirmed_users = [u.username for u in affected_users_details if u.status == "confirmed"]
        suspected_users = [u.username for u in affected_users_details if u.status == "suspected"]
        affected_users = [u.username for u in affected_users_details]

        # 3. Identificar zonas de red
        affected_network_zones = self._identify_network_zones(
            assets=affected_assets,
            events=all_events,
            evidence=all_evidence,
            entities=entities,
        )

        # 4. Identificar exposición de datos
        data_summary, data_findings = self._identify_data_exposure(
            evidence=all_evidence,
            events=all_events,
            alerts=all_alerts,
        )

        # 5. Identificar servicios de negocio afectados
        affected_services, service_impacts = self._identify_services(
            assets=affected_assets,
            confirmed_assets=confirmed_assets,
        )

        # 6. Calcular impacto empresarial y nivel de impacto
        business_impact, impact_level = self._calculate_business_impact(
            services=affected_services,
            service_impacts=service_impacts,
            data_exposure=data_summary,
            confirmed_assets=confirmed_assets,
            confirmed_users=confirmed_users,
            zones=affected_network_zones,
        )

        # 7. Separar hallazgos confirmados y sospechas
        confirmed_findings = []
        suspected_findings = []

        for asset in affected_assets_details:
            if asset.status == "confirmed":
                confirmed_findings.append(f"Activo comprometido: {asset.asset_id} ({asset.reason or 'evidencia de ejecución/acceso'})")
            else:
                suspected_findings.append(f"Activo sospechoso/observado: {asset.asset_id} ({asset.reason or 'actividad registrada'})")

        for user in affected_users_details:
            if user.status == "confirmed":
                confirmed_findings.append(f"Usuario comprometido: {user.username} ({user.reason or 'sesión/actividad maliciosa confirmada'})")
            else:
                suspected_findings.append(f"Usuario observado/sospechoso: {user.username} ({user.reason or 'intento bloqueado o usuario relacionado'})")

        for finding in data_findings.get("confirmed", []):
            confirmed_findings.append(finding)
        for finding in data_findings.get("suspected", []):
            suspected_findings.append(finding)

        # 8. Identificar incertidumbres o información desconocida
        unknowns = self._identify_unknowns(bundle, affected_assets_details, affected_users_details, data_summary)

        return ScopeAnalysis(
            affected_assets=affected_assets,
            affected_users=affected_users,
            affected_services=affected_services,
            affected_data=data_summary,
            affected_network_zones=affected_network_zones,
            business_impact=business_impact,
            impact_level=impact_level,
            confirmed_findings=confirmed_findings,
            suspected_findings=suspected_findings,
            unknowns=unknowns,
            asset_details=affected_assets_details,
            user_details=affected_users_details,
        )

    def _empty_scope(self, reason: str) -> ScopeAnalysis:
        """Devolver un ScopeAnalysis seguro para bundles vacíos o sin evidencias."""
        return ScopeAnalysis(
            affected_assets=[],
            affected_users=[],
            affected_services=[],
            affected_data="Sin datos expuestos identificados",
            affected_network_zones=[],
            business_impact="Sin impacto empresarial identificado debido a ausencia de evidencias.",
            impact_level="low",
            confirmed_findings=[],
            suspected_findings=[],
            unknowns=[f"Investigación sin evidencias o datos insuficientes: {reason}"],
            asset_details=[],
            user_details=[],
        )

    def _collect_evidence(self, bundle: Any) -> list[Any]:
        """Recopilar todas las evidencias disponibles en el bundle."""
        items: list[Any] = []
        raw_evidence = _get_field(bundle, "evidence", []) or []
        items.extend(raw_evidence)
        expanded = _get_field(bundle, "expanded_evidence", []) or []
        items.extend(expanded)

        # También extraer de tickets si existen
        tickets = _get_field(bundle, "tickets", []) or []
        for ticket in tickets:
            t_evidence = _get_field(ticket, "evidence", []) or []
            items.extend(t_evidence)

        return items

    def _collect_events(self, bundle: Any) -> list[dict[str, Any]]:
        """Recopilar eventos y logs disponibles en el bundle."""
        events: list[dict[str, Any]] = []
        raw_events = _get_field(bundle, "events", []) or []
        if isinstance(raw_events, list):
            for ev in raw_events:
                if isinstance(ev, dict):
                    events.append(ev)

        # Si hay flujos de red o logs
        flows = _get_field(bundle, "network_flows", []) or []
        if isinstance(flows, list):
            for fl in flows:
                if isinstance(fl, dict):
                    events.append(fl)

        return events

    def _collect_alerts(self, bundle: Any) -> list[dict[str, Any]]:
        """Recopilar alertas presentes en el bundle o en el incidente."""
        alerts: list[dict[str, Any]] = []
        raw_alerts = _get_field(bundle, "alerts", []) or []
        if isinstance(raw_alerts, list):
            for al in raw_alerts:
                if isinstance(al, dict):
                    alerts.append(al)

        # También desde el incidente si es IncidentGroup
        incident = _get_field(bundle, "incident", None)
        if incident:
            inc_alerts = _get_field(incident, "alerts", []) or []
            for al in inc_alerts:
                if isinstance(al, dict):
                    alerts.append(al)

        return alerts

    def _identify_assets(
        self,
        evidence: list[Any],
        events: list[dict[str, Any]],
        alerts: list[dict[str, Any]],
        entities: dict[str, Any],
    ) -> list[AffectedAsset]:
        """Identificar activos involucrados y diferenciar comprometidos de sospechosos.

        Regla importante: No considerar comprometido un equipo simplemente porque
        aparece en una alerta. Verificar si hubo ejecución confirmada o brecha.
        """
        asset_map: dict[str, dict[str, Any]] = {}

        def record(asset_id: str, is_confirmed: bool, reason: str, role: Optional[str] = None):
            if not asset_id or not isinstance(asset_id, str):
                return
            clean_id = asset_id.strip()
            if not clean_id:
                return

            # No confundir IPs con nombres de host si ya tenemos mapeo
            existing = asset_map.get(clean_id)
            if existing:
                if is_confirmed:
                    existing["confirmed"] = True
                    existing["reasons"].append(reason)
                else:
                    existing["reasons"].append(reason)
            else:
                asset_map[clean_id] = {
                    "confirmed": is_confirmed,
                    "reasons": [reason],
                    "role": role,
                }

        # 1. Entidades explícitas en el bundle
        host_entities = entities.get("hosts") or entities.get("assets") or []
        if isinstance(host_entities, list):
            for h in host_entities:
                if isinstance(h, str):
                    record(h, False, "Entidad identificada en investigación")
                elif isinstance(h, dict):
                    h_id = h.get("host") or h.get("hostname") or h.get("asset_id")
                    h_conf = h.get("compromised", False) or h.get("status") == "confirmed"
                    record(str(h_id), h_conf, h.get("reason", "Entidad en investigación"))

        # 2. Análisis de eventos/logs
        for ev in events:
            host = ev.get("hostname") or ev.get("computer_name") or ev.get("host") or ev.get("device_name")
            if not host:
                continue

            event_type = str(ev.get("event_type", "")).lower()
            action = str(ev.get("action", "")).lower()
            status = str(ev.get("status", "")).lower()

            # Evidencias de compromiso confirmado
            is_malicious_exec = any(k in event_type for k in ["process_creation", "malware", "c2", "ransomware", "powershell"]) and action in ["executed", "success", "detected"]
            is_dump = "lsass" in str(ev.get("command_line", "")).lower() or "mimikatz" in str(ev.get("command_line", "")).lower()
            is_auth_success = "logon" in event_type and status == "success" and ev.get("anomalous") is True

            if is_malicious_exec or is_dump or is_auth_success:
                record(str(host), True, f"Ejecución o acceso malicioso confirmado en evento: {event_type or 'proceso'}")
            elif action in ["blocked", "denied", "prevented", "drop"]:
                record(str(host), False, f"Intento bloqueado por control de seguridad en host: {event_type or 'red'}")
            else:
                record(str(host), False, f"Actividad registrada en host: {event_type or 'evento'}")

        # 3. Análisis de evidencias
        for ev in evidence:
            target = _get_field(ev, "target") or _get_field(ev, "asset_id") or _get_field(ev, "host")
            if target and isinstance(target, str):
                summary = str(_get_field(ev, "summary", "")).lower()
                is_conf = any(w in summary for w in ["confirmad", "malicios", "ejecutad", "compromiso"]) and "bloquead" not in summary
                record(target, is_conf, f"Evidencia: {_get_field(ev, 'summary', 'Registro de evidencia')}")

        # 4. Análisis de alertas
        for al in alerts:
            al_host = al.get("hostname") or al.get("asset_id") or al.get("host")
            if al_host and isinstance(al_host, str):
                status = str(al.get("status", "")).lower()
                verdict = str(al.get("verdict", "")).lower()
                # Una alerta por sí sola no confirma compromiso a menos que el veredicto sea true_positive con impacto
                is_conf = verdict == "true_positive" and al.get("execution_confirmed") is True
                reason = f"Alerta {al.get('alert_id', '')}: {al.get('rule_name', 'Detección')}"
                record(al_host, is_conf, reason)

        results: list[AffectedAsset] = []
        for asset_id, data in asset_map.items():
            status = "confirmed" if data["confirmed"] else "suspected"
            reasons_str = "; ".join(data["reasons"][:3])
            results.append(AffectedAsset(
                asset_id=asset_id,
                status=status,
                role=data.get("role"),
                reason=reasons_str,
            ))

        return results

    def _identify_users(
        self,
        evidence: list[Any],
        events: list[dict[str, Any]],
        alerts: list[dict[str, Any]],
        entities: dict[str, Any],
    ) -> list[AffectedUser]:
        """Identificar usuarios involucrados y evaluar si están comprometidos o son sospechosos.

        Regla importante: No considerar comprometida una cuenta solo porque aparece
        como usuario relacionado o destinatario de un intento.
        """
        user_map: dict[str, dict[str, Any]] = {}

        def record(username: str, is_confirmed: bool, reason: str):
            if not username or not isinstance(username, str):
                return
            clean_u = username.strip()
            # Ignorar cuentas de sistema no humanas genéricas
            if not clean_u or clean_u.lower() in ["system", "local system", "n/a", "none"]:
                return

            existing = user_map.get(clean_u)
            if existing:
                if is_confirmed:
                    existing["confirmed"] = True
                existing["reasons"].append(reason)
            else:
                user_map[clean_u] = {
                    "confirmed": is_confirmed,
                    "reasons": [reason],
                }

        # 1. Entidades explícitas
        user_entities = entities.get("users") or []
        if isinstance(user_entities, list):
            for u in user_entities:
                if isinstance(u, str):
                    record(u, False, "Usuario identificado en investigación")
                elif isinstance(u, dict):
                    uname = u.get("username") or u.get("user")
                    uconf = u.get("compromised", False) or u.get("status") == "confirmed"
                    record(str(uname), uconf, u.get("reason", "Usuario en investigación"))

        # 2. Eventos (e.g. idp_signins, ad_events)
        for ev in events:
            user = ev.get("user") or ev.get("username") or ev.get("user_id") or ev.get("account")
            if not user:
                continue

            event_type = str(ev.get("event_type", "")).lower()
            status = str(ev.get("status", "")).lower()
            action = str(ev.get("action", "")).lower()

            # Inicio de sesión exitoso desde IP maliciosa o con flag anómalo
            is_malicious_login = "signin" in event_type and status == "success" and (
                ev.get("anomalous") is True or ev.get("impossible_travel") is True or ev.get("mfa_bypassed") is True
            )
            # Uso de credenciales para persistencia o movimiento lateral
            is_abuse = any(k in event_type for k in ["privilege_escalation", "credential_abuse", "unauthorized_access"])

            if is_malicious_login or is_abuse:
                record(str(user), True, f"Acceso exitoso o abuso confirmado ({event_type})")
            elif status == "failure" or action in ["blocked", "denied"]:
                record(str(user), False, f"Intento fallido o bloqueado contra la cuenta ({event_type})")
            else:
                record(str(user), False, f"Actividad asociada a la cuenta ({event_type or 'registro'})")

        # 3. Alertas y evidencias
        for al in alerts:
            user = al.get("username") or al.get("user")
            if user:
                # Si la regla es phishing recibido, la cuenta es sospechosa/objetivo, no comprometida
                rule = str(al.get("rule_name", "")).lower()
                if "phishing" in rule and "clicked" not in rule:
                    record(str(user), False, f"Destinatario de correo de phishing ({al.get('alert_id', '')})")
                elif al.get("credential_theft_confirmed") is True:
                    record(str(user), True, f"Robo de credenciales confirmado ({al.get('alert_id', '')})")
                else:
                    record(str(user), False, f"Usuario relacionado en alerta ({al.get('alert_id', '')})")

        results: list[AffectedUser] = []
        for uname, data in user_map.items():
            status = "confirmed" if data["confirmed"] else "suspected"
            reasons_str = "; ".join(data["reasons"][:3])
            results.append(AffectedUser(
                username=uname,
                status=status,
                reason=reasons_str,
            ))

        return results

    def _identify_network_zones(
        self,
        assets: list[str],
        events: list[dict[str, Any]],
        evidence: list[Any],
        entities: dict[str, Any],
    ) -> list[str]:
        """Identificar zonas de red involucradas basándose en IPs y nombres de host."""
        zones: set[str] = set()

        # Extraer IPs candidatas
        candidate_ips: set[str] = set()
        for ev in events:
            for key in ["src_ip", "dest_ip", "ip", "client_ip", "source_ip", "destination_ip"]:
                ip = ev.get(key)
                if ip and isinstance(ip, str) and not ip.startswith("127."):
                    candidate_ips.add(ip.strip())

        for ent_ip in entities.get("ips", []):
            if isinstance(ent_ip, str) and not ent_ip.startswith("127."):
                candidate_ips.add(ent_ip.strip())

        # Mapear IPs a zonas de red usando CIDR
        for ip_str in candidate_ips:
            try:
                addr = ip_address(ip_str)
                for zone_name, cidr, _, _ in self._zones:
                    try:
                        net = ip_network(cidr, strict=False)
                        if addr in net:
                            zones.add(zone_name)
                    except ValueError:
                        continue
            except ValueError:
                continue

        # Deducir también por convención de nombres de activos de Tarvia
        for asset in assets:
            a_upper = asset.upper()
            if a_upper.startswith("WEB-ECOM") or a_upper.startswith("PAY-GW") or "AI-ASSIST" in a_upper:
                zones.add("DMZ")
            elif a_upper.startswith("SQL-CRM") or a_upper.startswith("DC0") or a_upper.startswith("ERP-"):
                zones.add("DC-SERVERS")
            elif a_upper.startswith("POS-T"):
                zones.add("STORES")
            elif a_upper.startswith("PLC-") or a_upper.startswith("HMI-"):
                zones.add("LOGISTICS-OT")
            elif a_upper.startswith("WMS"):
                zones.add("LOGISTICS-IT")
            elif a_upper.startswith("WS-"):
                zones.add("HQ-USERS")
            elif a_upper.startswith("LT-MAD"):
                zones.add("MAD-USERS")
            elif "DEV" in a_upper or "JENKINS" in a_upper:
                zones.add("DEV")
            elif "AWS" in a_upper or "CI-RUNNER" in a_upper:
                zones.add("AWS-PROD")

        return sorted(zones)

    def _identify_data_exposure(
        self,
        evidence: list[Any],
        events: list[dict[str, Any]],
        alerts: list[dict[str, Any]],
    ) -> tuple[str, dict[str, list[str]]]:
        """Identificar si hubo acceso, modificación o exfiltración de datos sensibles.

        Regla importante:
        No afirmar que se han extraído datos porque exista acceso a una base de datos.
        Diferenciar acceso, modificación y exfiltración.
        """
        access_detected = False
        modification_detected = False
        exfiltration_detected = False

        data_types: set[str] = set()
        findings: dict[str, list[str]] = {"confirmed": [], "suspected": []}

        # Analizar eventos (e.g. sql_audit, dlp, firewall, cloudtrail)
        for ev in events:
            ev_str = str(ev).lower()

            # Tipos de datos
            if any(k in ev_str for k in ["clientes", "crm", "sql-crm", "rgpd", "gdpr", "personal_data"]):
                data_types.add("Datos personales de clientes (RGPD)")
            if any(k in ev_str for k in ["tarjeta", "pan", "cvv", "pay-gw", "pci", "credit_card"]):
                data_types.add("Datos de tarjetas de pago (PCI DSS)")
            if any(k in ev_str for k in ["nomina", "payroll", "hr-app", "empleado"]):
                data_types.add("Datos de nóminas y empleados")
            if any(k in ev_str for k in ["ntds.dit", "lsass", "kerberos", "password", "credencial"]):
                data_types.add("Credenciales corporativas de acceso")

            # Exfiltración (tráfico saliente significativo, servicios externos de almacenamiento, DLP)
            bytes_out = ev.get("bytes_sent") or ev.get("bytes_out") or 0
            dest_host = str(ev.get("dest_host") or ev.get("url") or "").lower()
            if (
                any(srv in dest_host for srv in ["mega.nz", "dropbox", "drive.google", "anonfiles"])
                or (isinstance(bytes_out, (int, float)) and bytes_out > 5_000_000)
                or ev.get("dlp_action") in ["blocked_exfiltration", "exfiltration_alert"]
            ):
                exfiltration_detected = True
                findings["confirmed"].append(f"Exfiltración confirmada de datos hacia destino externo: {dest_host or 'IP externa'}")

            # Modificación (UPDATE, DELETE, ransomware encryption)
            query = str(ev.get("query") or "").upper()
            action = str(ev.get("action") or "").lower()
            if any(q in query for q in ["UPDATE", "DELETE", "DROP", "ALTER"]) or "ransomware" in ev_str or "encrypt" in action:
                modification_detected = True
                findings["confirmed"].append("Modificación o alteración no autorizada de datos detectada")

            # Acceso (SELECT, lectura)
            if "SELECT" in query or action in ["read", "query", "accessed"] or "sql_audit" in ev_str:
                access_detected = True

        # Analizar alertas y evidencias
        for al in alerts:
            al_str = str(al).lower()
            if "exfiltration" in al_str or "exfiltración" in al_str:
                exfiltration_detected = True
                findings["confirmed"].append(f"Alerta de exfiltración de datos ({al.get('alert_id', '')})")
            elif "data access" in al_str or "sql injection" in al_str:
                access_detected = True
                findings["suspected"].append(f"Indicios de acceso no autorizado a datos ({al.get('alert_id', '')})")

        # Construir descripción diferenciada
        parts = []
        if exfiltration_detected:
            types_str = ", ".join(sorted(data_types)) or "información confidencial"
            parts.append(f"Exfiltración confirmada de: {types_str}")
        elif modification_detected:
            types_str = ", ".join(sorted(data_types)) or "bases de datos corporativas"
            parts.append(f"Modificación no autorizada de: {types_str} (sin evidencia de exfiltración externa)")
        elif access_detected:
            types_str = ", ".join(sorted(data_types)) or "bases de datos / repositorios"
            parts.append(f"Acceso detectado a {types_str}, pero sin evidencia concluyente de exfiltración externa")
        elif data_types:
            types_str = ", ".join(sorted(data_types))
            parts.append(f"Riesgo potencial sobre {types_str} por proximidad de activos, sin acceso demostrado")
        else:
            parts.append("Sin datos expuestos ni accesos a repositorios sensibles identificados")

        summary = ". ".join(parts)
        return summary, findings

    def _identify_services(
        self,
        assets: list[str],
        confirmed_assets: list[str],
    ) -> tuple[list[str], list[dict[str, Any]]]:
        """Identificar qué servicios de negocio de Tarvia están afectados."""
        affected_services: set[str] = set()
        service_impacts: list[dict[str, Any]] = []

        for svc in self._services:
            svc_name = svc["servicio"]
            svc_assets = svc.get("activos", [])
            matched = False

            for asset in assets:
                a_upper = asset.upper()
                for pattern in svc_assets:
                    pat_upper = pattern.upper().replace("*", "")
                    if pat_upper and pat_upper in a_upper:
                        matched = True
                        break
                if matched:
                    break

            if matched:
                affected_services.add(svc_name)
                service_impacts.append({
                    "servicio": svc_name,
                    "criticidad": svc.get("criticidad", "Media"),
                    "impacto": svc.get("impacto", ""),
                    "responsable": svc.get("responsable", ""),
                })

        return sorted(affected_services), service_impacts

    def _calculate_business_impact(
        self,
        services: list[str],
        service_impacts: list[dict[str, Any]],
        data_exposure: str,
        confirmed_assets: list[str],
        confirmed_users: list[str],
        zones: list[str],
    ) -> tuple[str, str]:
        """Evaluar el impacto empresarial y asignar el nivel de severidad."""
        critical_count = sum(1 for s in service_impacts if s.get("criticidad") == "Crítica")
        high_count = sum(1 for s in service_impacts if s.get("criticidad") == "Alta")

        impact_statements = []

        # Impacto financiero / e-commerce
        if any("Tienda online" in s for s in services):
            impact_statements.append("Afectación a la venta online (38% facturación de Tarvia; coste de caída estimado en ~120.000 €/h)")
        if any("Cobros online" in s or "Cobro en tienda" in s for s in services):
            impact_statements.append("Riesgo sobre cumplimiento PCI DSS en pasarela de cobros")

        # Impacto regulatorio / RGPD
        if "RGPD" in data_exposure or "Datos personales" in data_exposure:
            if "Exfiltración confirmada" in data_exposure or "Acceso detectado" in data_exposure:
                impact_statements.append("Posible brecha de datos personales: notificación obligatoria a la AEPD y CNPD en plazo máximo de 72 horas")

        # Impacto operativo / logística
        if any("almacén" in s or "Clasificación" in s for s in services):
            impact_statements.append("Riesgo de paralización de salida de pedidos desde el centro logístico de Martorell")

        # Determinar nivel de impacto
        if critical_count > 0 and (confirmed_assets or "Exfiltración confirmada" in data_exposure or "LOGISTICS-OT" in zones):
            impact_level = "critical"
        elif critical_count > 0 or high_count > 0 or len(confirmed_assets) >= 2:
            impact_level = "high"
        elif len(services) > 0 or len(confirmed_assets) == 1 or len(confirmed_users) > 0:
            impact_level = "medium"
        else:
            impact_level = "low"

        if not impact_statements:
            if services:
                impact_statements.append(f"Impacto operativo moderado sobre: {', '.join(services)}")
            else:
                impact_statements.append("Sin impacto significativo sobre procesos críticos de negocio registrado.")

        full_impact = ". ".join(impact_statements)
        return full_impact, impact_level

    def _identify_unknowns(
        self,
        bundle: Any,
        assets: list[AffectedAsset],
        users: list[AffectedUser],
        data_summary: str,
    ) -> list[str]:
        """Identificar preguntas pendientes o lagunas en las evidencias."""
        unknowns: list[str] = []

        # Añadir preguntas pendientes existentes en el bundle si las hay
        bundle_questions = _get_field(bundle, "open_questions", []) or []
        for q in bundle_questions:
            if isinstance(q, str) and q.strip():
                unknowns.append(q.strip())

        # Incertidumbre sobre activos sospechosos
        suspected_assets = [a.asset_id for a in assets if a.status == "suspected"]
        if suspected_assets:
            unknowns.append(
                f"Falta confirmación de compromiso en activos observados: {', '.join(suspected_assets[:4])} (se requiere análisis de memoria/disco)"
            )

        # Incertidumbre sobre usuarios con intentos bloqueados
        suspected_users = [u.username for u in users if u.status == "suspected"]
        if suspected_users:
            unknowns.append(
                f"Verificar si las credenciales de los usuarios investigados ({', '.join(suspected_users[:3])}) fueron expuestas en otros servicios"
            )

        # Incertidumbre sobre volumen total de datos si hubo acceso
        if "Acceso detectado" in data_summary and "Exfiltración confirmada" not in data_summary:
            unknowns.append(
                "Se detectó consulta a repositorios pero se desconoce el volumen exacto de registros leídos antes de la contención"
            )

        return unknowns
