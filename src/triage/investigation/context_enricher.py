"""Contexto empresarial fiable y cambios candidatos, sin decidir el triaje."""
import csv
from datetime import datetime, timezone
from fnmatch import fnmatchcase
from ipaddress import ip_address
import re
from urllib.parse import urlsplit
from zoneinfo import ZoneInfo

from src.triage.models import RawAlert, EntityKeys, ContextSnapshot
from src.triage.ingestion.entities import extract_entities
from src.data.soc_api_client import SOCAPIClient
from src.data.reference_repository import ReferenceRepository


class ContextEnricher:
    def __init__(self, api: SOCAPIClient, references: ReferenceRepository) -> None:
        self.api = api
        self.references = references

    def enrich(self, alert: RawAlert, entities: EntityKeys) -> ContextSnapshot:
        """Recuperar hechos a la fecha de la alerta, sin inferir equipos afectados."""
        snapshot = ContextSnapshot()
        instant = self._parse_time(alert.get("created_at"))
        if instant is None:
            snapshot.missing_lookups.append("changes:created_at")
        roles = self._entity_roles(alert, entities)
        self._resolve_assets(roles, instant, snapshot)
        self._resolve_users(roles["users"], instant, snapshot)
        self._resolve_services(alert, roles, snapshot)
        self._resolve_network(roles["ips"], snapshot)
        if instant is not None:
            self._select_changes(alert, roles, instant, snapshot)
        for field, keys in (
            ("assets", ("asset_id", "hostname", "ip")),
            ("users", ("user_id", "upn", "username")),
            ("services", ("servicio",)), ("changes", ("id",)),
        ):
            seen = set()
            unique = []
            for record in getattr(snapshot, field):
                key = next(((k, str(record[k]).casefold()) for k in keys if record.get(k)), None)
                if key is None:
                    if record not in unique:
                        unique.append(record)
                elif key not in seen:
                    seen.add(key)
                    unique.append(record)
            setattr(snapshot, field, unique)
        snapshot.missing_lookups = list(dict.fromkeys(snapshot.missing_lookups))
        return snapshot

    @staticmethod
    def _parse_time(value, local_zone=timezone.utc):
        if not isinstance(value, str) or not value.strip():
            return None
        try:
            parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
        except ValueError:
            return None
        return parsed.replace(tzinfo=local_zone) if parsed.tzinfo is None else parsed

    @staticmethod
    def _entity_roles(alert, entities):
        """Leer campos explícitos; no buscar identificadores dentro de comandos o frases."""
        roles = {key: [] for key in (
            "hosts", "users", "ips", "src_ips", "dst_ips", "domains", "urls",
            "resources", "applications", "recipients",
        )}

        def add(group, value):
            if isinstance(value, list):
                for item in value:
                    add(group, item)
            elif isinstance(value, str):
                value = value.strip()
                if value and value.casefold() not in {"unknown", "none", "null", "n/a", "-"}:
                    if value.casefold() not in {x.casefold() for x in roles[group]}:
                        roles[group].append(value)

        for source in (extract_entities(alert), entities):
            for group in ("hosts", "users", "ips", "domains", "urls"):
                add(group, getattr(source, group))
        fields = {
            "src_ip": "src_ips", "source_ip": "src_ips", "sourceIPAddress": "src_ips",
            "sender_ip": "src_ips", "dst_ip": "dst_ips", "destination_ip": "dst_ips",
            "ip": "ips", "hostname": "hosts", "from_host": "hosts", "src_host": "hosts",
            "dst_host": "hosts", "host": "hosts", "affected_host": "hosts",
            "username": "users", "upn": "users", "user": "users", "identity": "users",
            "affected_user": "users", "reported_by": "users", "recipient": "recipients",
            "recipients": "recipients", "url": "urls", "domain": "domains",
            "bucket": "resources", "resource": "resources", "resource_id": "resources",
            "arn": "resources", "application": "applications", "app": "applications",
            "appDisplayName": "applications", "service": "applications",
            "business_service": "applications",
        }

        def visit(record):
            if isinstance(record, list):
                for item in record:
                    visit(item)
            elif isinstance(record, dict):
                for field, value in record.items():
                    # No convertir un UPN externo en su username corporativo homónimo.
                    if field == "username" and record.get("upn"):
                        continue
                    if field in fields:
                        add(fields[field], value)
                    if isinstance(value, (dict, list)):
                        visit(value)

        visit(alert.get("entities"))
        visit(alert.get("evidence"))
        visit({k: v for k, v in alert.items() if k in fields})
        add("users", roles["recipients"])
        for group in ("src_ips", "dst_ips"):
            add("ips", roles[group])
        # En estas fuentes, ips sin papel explícito contiene clientes/orígenes.
        if alert.get("source_product") in {"WAF", "IDP", "VPN", "ECOM", "AI_GATEWAY"}:
            raw = alert.get("entities") or {}
            host_records = raw.get("hosts", []) if isinstance(raw, dict) else []
            if not isinstance(host_records, list):
                host_records = [host_records]
            host_ips = {h.get("ip") for h in host_records if isinstance(h, dict)}
            add("src_ips", [ip for ip in roles["ips"]
                            if ip not in roles["dst_ips"] and ip not in host_ips])
        return roles

    def _resolve_assets(self, roles, instant, snapshot):
        known = set()
        for key in roles["hosts"] + roles["ips"]:
            key = key.strip().rstrip(".").casefold()
            if not re.fullmatch(r"[\w.:-]+", key):
                continue
            if key in known:
                continue
            known.add(key)
            try:
                ip_address(key)
                is_ip = True
            except ValueError:
                is_ip = False
            zone = self.references.get_network_zone(key) if is_ip else None
            # Una IP privada ajena tampoco implica un equipo corporativo ausente.
            if is_ip and zone is None and key not in {h.casefold() for h in roles["hosts"]}:
                continue
            corporate = zone is not None or not is_ip and (
                "." not in key or key.endswith(".tarvia.example"))
            lookup = key.removesuffix(".tarvia.example") if not is_ip else key
            if lookup in known and lookup != key:
                continue
            known.add(lookup)
            # El nombre público identifica un servicio, no un frontal determinado.
            if key == "www.tarvia.example":
                continue
            asset = self.api.get_asset(lookup)
            if asset is None:
                # El pool VPN representa sesiones, no necesariamente activos CMDB.
                if corporate and (not zone or zone.get("zona") != "VPN-POOL"):
                    snapshot.missing_lookups.append(f"asset:{key}")
                continue
            asset = dict(asset)
            for field in ("hostname", "ip"):
                if asset.get(field):
                    known.add(str(asset[field]).casefold())
            asset["vulnerabilities"] = self._dated_records(
                asset.get("vulnerabilities", []), "detectada", instant,
                f"vulnerabilities:{lookup}", snapshot,
            )
            snapshot.assets.append(asset)

    def _resolve_users(self, identifiers, instant, snapshot):
        known = set()
        for identifier in identifiers:
            key = identifier.strip().casefold()
            if not re.fullmatch(r"[\w.@$+\\=-]+", key):
                continue
            if "\\" in key:
                realm, name = key.rsplit("\\", 1)
                if realm in {"tarvia", "tarvia.example"}:
                    key = name
            if key.endswith("@tarvia.example"):
                key = key.removesuffix("@tarvia.example")
            if key in known or key in {"system", "nt authority\\system"}:
                continue
            known.add(key)
            corporate = "@" not in key and "\\" not in key
            user = self.api.get_user(key)
            if user is None:
                if corporate:
                    snapshot.missing_lookups.append(f"user:{key}")
                continue
            created = self._parse_time(user.get("created"))
            if instant is not None and created is not None and created > instant:
                snapshot.missing_lookups.append(f"user:{key}:created_after_alert")
                continue
            user = dict(user)
            user["hr_events"] = self._dated_records(
                user.get("hr_events", []), "fecha", instant, f"hr_events:{key}", snapshot,
            )
            # Comunicación y vigencia son fechas diferentes. No inferir la fecha de fin.
            for event in user["hr_events"]:
                effective = self._parse_time(event.get("fecha_efectiva"))
                event["temporal_status"] = (
                    "unknown" if instant is None or effective is None else
                    "scheduled" if effective > instant else "effective_date_reached; end_unknown"
                )
            snapshot.users.append(user)

    def _dated_records(self, records, date_field, instant, label, snapshot):
        result = []
        for record in records:
            date = self._parse_time(record.get(date_field))
            if instant is None or date is None:
                snapshot.missing_lookups.append(f"{label}:temporal_validity_unknown")
            elif date <= instant:
                result.append(dict(record))
        return result

    def _service_catalog(self, snapshot):
        # dataset_root es público; ReferenceRepository no expone listar servicios.
        path = self.references.dataset_root / "02_inventario" / "servicios_negocio.csv"
        try:
            with path.open(encoding="utf-8-sig", newline="") as stream:
                return list(csv.DictReader(stream))
        except FileNotFoundError:
            snapshot.missing_lookups.append("services:servicios_negocio.csv")
            return []

    @staticmethod
    def _scope_matches(scope, identifiers):
        """Comparar listas CMDB, comodines y rangos como WEB-ECOM01..04."""
        for part in scope.split(","):
            pattern = part.strip().casefold()
            interval = re.fullmatch(r"(.*?)(\d+)\.\.(\d+)", pattern)
            for identifier in identifiers:
                key = identifier.casefold()
                if pattern and pattern == key:
                    return True
                if interval:
                    prefix, start, end = interval.groups()
                    tail = key[len(prefix):] if key.startswith(prefix) else ""
                    if tail.isdigit() and len(tail) == len(start) and int(start) <= int(tail) <= int(end):
                        return True
                elif pattern and fnmatchcase(key, pattern):
                    return True
        return False

    def _resolve_services(self, alert, roles, snapshot):
        catalog = self._service_catalog(snapshot)
        identifiers = [a.get("hostname", "") for a in snapshot.assets] + roles["hosts"]
        resources = []
        for resource in roles["resources"]:
            if resource.startswith("arn:") and ":s3:::" in resource:
                resource = "s3://" + resource.split(":s3:::", 1)[1]
            if ":" not in resource:
                resource = "s3://" + resource
            if resource.startswith("s3://"):
                resource = "s3://" + resource[5:].split("/", 1)[0]
            resources.append(resource.rstrip("/"))
        identifiers += resources
        names = list(roles["applications"])
        for asset in snapshot.assets:
            service = asset.get("business_service")
            if service:
                record = self.references.get_business_service(service)
                if record is not None:
                    snapshot.services.append(record)
                elif not any(self._scope_matches(s.get("activos", ""), [asset.get("hostname", "")])
                             for s in catalog):
                    snapshot.missing_lookups.append(f"service:{service}")
        # Relaciones explícitas documentadas en empresa_tarvia y calendario_cambios.
        domains = list(roles["domains"]) + [h for h in roles["hosts"] if "." in h]
        for url in roles["urls"]:
            try:
                domains.append(urlsplit(url).hostname or "")
            except ValueError:
                continue
        if any(d.rstrip(".").casefold() == "www.tarvia.example" for d in domains):
            names.append("Tienda online y app")
        product_services = {
            "ECOM": "Tienda online y app", "IDP": "Identidad y directorio activo",
            "AD": "Identidad y directorio activo", "EMAIL_GW": "Correo y colaboración (SaaS)",
            "AI_GATEWAY": "Asistente de compra con IA «Vela»", "CICD": "Integración continua",
        }
        if alert.get("source_product") in product_services:
            names.append(product_services[alert["source_product"]])
        matched = set()
        for service in catalog:
            aliases = [service["servicio"], *service.get("activos", "").split(",")]
            for name in names:
                if name.casefold() in {alias.strip().casefold() for alias in aliases}:
                    snapshot.services.append(service)
                    matched.add(name.casefold())
            if self._scope_matches(service.get("activos", ""), identifiers):
                snapshot.services.append(service)
        for name in names:
            if name.casefold() not in matched:
                snapshot.missing_lookups.append(f"service:{name}")
        for domain in domains:
            key = domain.rstrip(".").casefold()
            resolved_host = any(a.get("hostname", "").casefold() == key.removesuffix(".tarvia.example")
                                for a in snapshot.assets)
            if key.endswith(".tarvia.example") and key != "www.tarvia.example" and not resolved_host:
                snapshot.missing_lookups.append(f"service:{key}")
        for resource in resources:
            if not any(self._scope_matches(s.get("activos", ""), [resource]) for s in catalog):
                snapshot.missing_lookups.append(f"service:{resource}")

    def _resolve_network(self, ips, snapshot):
        addresses = list(ips) + [a["ip"] for a in snapshot.assets if a.get("ip")]
        for address in dict.fromkeys(addresses):
            zone = self.references.get_network_zone(address)
            store = self.references.get_store(address)
            record = {**(zone or {}), **(store or {})}
            if record and record not in snapshot.network_zones:
                snapshot.network_zones.append(record)
            if zone and zone.get("zona") == "STORES" and store is None:
                snapshot.missing_lookups.append(f"store:{address}")

    def _select_changes(self, alert, roles, instant, snapshot):
        local_zone = ZoneInfo("Europe/Madrid")
        hosts = roles["hosts"] + [a.get("hostname", "") for a in snapshot.assets]
        service_names = [s["servicio"] for s in snapshot.services]
        # Comparar actividad en los datos de la alerta no implica investigar ni ejecutar su contenido.
        activity = " ".join(str(alert.get(k, "")) for k in ("rule_name", "description"))
        activity += " " + str(alert.get("evidence", {})) + " " + str(alert.get("entities", {}))
        activity = activity.casefold()
        for change in self.api.get_changes():
            start = self._parse_time(change.get("inicio"), local_zone)
            end = self._parse_time(change.get("fin"), local_zone)
            if start is None or end is None or start > end:
                snapshot.missing_lookups.append(f"change:{change.get('id', '')}:invalid_window")
                continue
            if not start <= instant <= end:
                continue
            detail = change.get("detalle", "")
            hours = re.search(r"(\d{1,2}:\d{2})\s*[-–]\s*(\d{1,2}:\d{2})", detail)
            if hours:
                try:
                    hour_start, hour_end = [datetime.strptime(h, "%H:%M").time() for h in hours.groups()]
                except ValueError:
                    snapshot.missing_lookups.append(f"change:{change.get('id', '')}:invalid_hours")
                    continue
                now = instant.astimezone(local_zone).time()
                if not (hour_start <= now <= hour_end if hour_start <= hour_end else
                        now >= hour_start or now <= hour_end):
                    continue
            scope = change.get("alcance", "")
            scope_lower = scope.casefold()
            in_scope = self._scope_matches(scope, hosts + service_names)
            if scope_lower == "todos los puestos":
                in_scope = any(a.get("business_service") == "Puesto de trabajo" for a in snapshot.assets)
            elif scope_lower == "servidores windows":
                in_scope = any("windows server" in a.get("os", "").casefold() for a in snapshot.assets)
            elif scope_lower == "todas las redes salvo ot":
                in_scope = bool(snapshot.network_zones) and not any(
                    "OT" in z.get("zona", "") for z in snapshot.network_zones)
            elif scope_lower in {"correo", "directorio activo"}:
                in_scope = any(scope_lower in s.casefold() for s in service_names)
            # Con URL y sin equipo, comparar el alcance con la relación del servicio.
            if not hosts:
                in_scope = in_scope or any(
                    s.get("activos", "").casefold() == scope_lower or
                    self._scope_matches(scope, [name.strip()])
                    for s in snapshot.services for name in s.get("activos", "").split(",")
                    if "*" not in name
                )
            if not in_scope:
                continue
            title = change.get("titulo", "").casefold()
            # Afinidad sencilla de actividad: la fecha y el alcance por sí solos no bastan.
            if "pentest" in title or "escaneo" in title:
                compatible = alert.get("source_product") == "WAF" or any(
                    word in activity for word in ("escaneo", "scan", "inyección", "sqli", "xss", "lfi"))
            else:
                words = set(re.findall(r"[\w.-]+", title + " " + detail.casefold()))
                ignored = {"desde", "cuenta", "agente", "servidores", "actualización", "acceso",
                           "remoto", "fuera", "horario", "equipo", "sistemas", "origen", "destino",
                           "diariamente", "temporal", "nuevo", "miembro", "tecnología", "fabricante"}
                compatible = any(len(w) >= 4 and w not in ignored and
                                 re.search(r"(?<![\w.-])" + re.escape(w) + r"(?![\w.-])", activity)
                                 for w in words)
            if compatible and self._change_origin_matches(change, roles, hosts, activity):
                snapshot.changes.append(dict(change))

    @staticmethod
    def _change_origin_matches(change, roles, hosts, activity):
        """Descartar contradicciones de origen; no certificar autorización."""
        detail = change.get("detalle", "")
        ranges = re.findall(r"\b(\d{1,3}(?:\.\d{1,3}){3})(?:-(\d{1,3}))?\b", detail)
        if ranges:
            allowed = set()
            for first, last in ranges:
                try:
                    address = ip_address(first)
                    end = int(last) if last else int(first.rsplit(".", 1)[1])
                    begin = int(first.rsplit(".", 1)[1])
                    if begin <= end <= 255:
                        allowed.update(str(address + offset) for offset in range(end - begin + 1))
                except ValueError:
                    continue
            if not allowed.intersection(roles["src_ips"]):
                return False
        origin = re.search(r"(?:Origen|desde|vía)\s+([A-Z][A-Z0-9_-]*\d+)\b", detail)
        if origin and origin.group(1).casefold() not in {h.casefold() for h in hosts}:
            return False
        accounts = re.findall(r"\b(?:svc_[\w.-]+|ext\.[\w.-]+)\b", detail, re.IGNORECASE)
        if accounts:
            users = {u.casefold().rsplit("\\", 1)[-1].removesuffix("@tarvia.example") for u in roles["users"]}
            if users - {"system"} and not users.intersection(a.casefold() for a in accounts):
                return False
            if not users.intersection(a.casefold() for a in accounts) and origin is None:
                # Si solo consta SYSTEM o falta usuario, exigir al menos la herramienta
                # de gestión indicada por el cambio (p. ej. SCCM), no solo PowerShell.
                tools = re.findall(r"\b[A-Z]{3,}[0-9]*\b", change.get("titulo", ""))
                if not any(re.search(r"\b" + re.escape(tool.casefold()) + r"\b", activity)
                           for tool in tools):
                    return False
        return True
