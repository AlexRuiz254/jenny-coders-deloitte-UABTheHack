"""Contexto de activo/usuario/cambios y criticidad de negocio."""
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

from src.triage.models import RawAlert, EntityKeys, ContextSnapshot
from src.data.soc_api_client import SOCAPIClient
from src.data.reference_repository import ReferenceRepository

class ContextEnricher:
    def __init__(self, api: SOCAPIClient, references: ReferenceRepository) -> None:
        self.api = api
        self.references = references

    def enrich(self, alert: RawAlert, entities: EntityKeys) -> ContextSnapshot:
        """Resolver activos/usuarios/vulnerabilidades/servicios/zonas/cambios/RRHH."""
        snapshot = ContextSnapshot()
        ips = list(entities.ips)
        for key in dict.fromkeys(entities.hosts + entities.ips):
            asset = self.api.get_asset(key)
            if asset is None:
                snapshot.missing_lookups.append(f"asset:{key}")
                continue
            if asset not in snapshot.assets:
                snapshot.assets.append(asset)
            if asset.get("ip"):
                ips.append(asset["ip"])
            service = asset.get("business_service")
            if service:
                record = self.references.get_business_service(service)
                if record is None:
                    snapshot.missing_lookups.append(f"service:{service}")
                elif record not in snapshot.services:
                    snapshot.services.append(record)

        for key in dict.fromkeys(entities.users):
            # El directorio acepta username/UPN; el EDR también usa DOMINIO\\usuario.
            user = self.api.get_user(key.rsplit("\\", 1)[-1])
            if user is None:
                snapshot.missing_lookups.append(f"user:{key}")
            elif user not in snapshot.users:
                snapshot.users.append(user)

        for ip in dict.fromkeys(ips):
            zone = self.references.get_network_zone(ip)
            store = self.references.get_store(ip)
            if zone is None:
                snapshot.missing_lookups.append(f"network_zone:{ip}")
            # El modelo no tiene campo stores: conservar las columnas CSV junto
            # a la zona correspondiente, sin añadir campos al ContextSnapshot.
            record = {**(zone or {}), **(store or {})}
            if record and record not in snapshot.network_zones:
                snapshot.network_zones.append(record)
            if zone and zone.get("zona") == "STORES" and store is None:
                snapshot.missing_lookups.append(f"store:{ip}")

        # Son candidatos del calendario, no una afirmación de que la alerta
        # esté autorizada. Los logs están en UTC; el calendario, en hora de Madrid.
        def parse_time(value: str, local_zone=timezone.utc) -> datetime:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            return parsed.replace(tzinfo=local_zone) if parsed.tzinfo is None else parsed

        try:
            instant = parse_time(alert.get("created_at", ""))
        except ValueError:
            snapshot.missing_lookups.append("changes:created_at")
        else:
            for change in self.api.get_changes():
                try:
                    active = (parse_time(change["inicio"], ZoneInfo("Europe/Madrid")) <= instant
                              <= parse_time(change["fin"], ZoneInfo("Europe/Madrid")))
                except (KeyError, ValueError):
                    snapshot.missing_lookups.append(f"change:{change.get('id', '')}")
                    continue
                if active and change not in snapshot.changes:
                    snapshot.changes.append(change)

        snapshot.missing_lookups = list(dict.fromkeys(snapshot.missing_lookups))
        return snapshot
