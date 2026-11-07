
"""Buscar alertas potencialmente relacionadas por tiempo y entidades."""

from datetime import datetime, timedelta, timezone

from src.triage.models import RawAlert, EntityKeys
from src.data.soc_api_client import SOCAPIClient


class AlertCorrelator:

    def __init__(self, api: SOCAPIClient) -> None:
        """Guardar el cliente de acceso a la API."""
        self.api = api

    @staticmethod
    def _time(value: str) -> datetime:
        """Convertir una fecha ISO a UTC para compararla correctamente."""
        parsed = datetime.fromisoformat(
            value.replace("Z", "+00:00")
        )

        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=timezone.utc)

        return parsed.astimezone(timezone.utc)

    @staticmethod
    def _entities(alert: RawAlert) -> dict[str, set[str]]:
        """Extraer y normalizar identificadores de una alerta."""
        raw = alert.get("entities") or {}

        values = {
            name: set()
            for name in EntityKeys.model_fields
        }

        columns = {
            "hosts": ("hostname",),
            "users": ("upn", "username"),
            "ips": ("ip",),
            "domains": ("domain",),
            "urls": ("url",),
            "hashes": ("sha256", "sha1", "md5"),
            "sessions": ("session_id",),
            "customers": ("customer_id",),
        }

        def add(group: str, value: str) -> None:
            """Añadir un identificador normalizado."""
            if group not in values or not isinstance(value, str):
                return

            value = value.strip()

            if not value or value.startswith("("):
                return

            if group == "users":
                value = value.rsplit("\\", 1)[-1]

                # Unificar UPN y username únicamente para Tarvia.
                if value.casefold().endswith("@tarvia.example"):
                    value = value.split("@", 1)[0]

            if group != "urls":
                value = value.casefold()

            values[group].add(value)

        for group, fields in columns.items():
            for item in raw.get(group, []) or []:

                if isinstance(item, str):
                    add(group, item)

                elif isinstance(item, dict):
                    for field in fields:
                        add(group, item.get(field, ""))

                    if group == "hosts":
                        add("ips", item.get("ip", ""))

        for file in raw.get("files", []) or []:
            if isinstance(file, dict):
                for field in columns["hashes"]:
                    add("hashes", file.get(field, ""))

        cloud = raw.get("cloud") or {}

        if isinstance(cloud, dict):
            add("users", cloud.get("identity", ""))
            add("sessions", cloud.get("access_key", ""))

        add("sessions", raw.get("ai_session", ""))

        return values

    def find_related(
        self,
        alert: RawAlert,
        entities: EntityKeys,
        window_hours: int = 24
    ) -> list[RawAlert]:
        """
        Buscar alertas relacionadas en ±window_hours.

        Criterios:
        - Compartir usuario, equipo, hash, sesión, cliente o URL.
        - Compartir un evento de log.
        - No correlacionar únicamente por IP o dominio.
        """

        if window_hours < 0:
            raise ValueError(
                "window_hours no puede ser negativo"
            )

        # 1. Obtener la fecha de la alerta original.
        try:
            instant = self._time(
                alert.get("created_at", "")
            )
        except (ValueError, TypeError, AttributeError):
            return []

        start = instant - timedelta(hours=window_hours)
        end = instant + timedelta(hours=window_hours)

        desde = start.isoformat(
            timespec="milliseconds"
        ).replace("+00:00", "Z")

        hasta = end.isoformat(
            timespec="milliseconds"
        ).replace("+00:00", "Z")

        # 2. Combinar entidades originales y extraídas.
        target = self._entities(alert)

        extracted = self._entities({
            "entities": entities.model_dump()
        })

        for group in target:
            target[group].update(
                extracted.get(group, set())
            )

        # 3. Obtener los eventos vinculados a la alerta.
        event_ids = set(
            alert.get("related_events") or []
        )

        related = []
        seen = {alert.get("alert_id")}

        # Estos identificadores ofrecen relaciones
        # más específicas que compartir una IP o dominio.
        relevant_groups = {
            "hosts",
            "users",
            "hashes",
            "sessions",
            "customers",
            "urls",
        }

        # El dataset original es inmutable: todas sus alertas tienen estado new.
        # La API exige coincidencia exacta y status="" NO elimina el filtro.
        offset = 0
        page_size = 500

        while True:

            page = self.api.list_alerts(
                status="new",
                limit=page_size,
                offset=offset,
                desde=desde,
                hasta=hasta
            )

            items = page.get("items", [])

            if not items:
                break

            # 5. Revisar las alertas de la página.
            for candidate in items:

                alert_id = candidate.get("alert_id")

                if not alert_id or alert_id in seen:
                    continue

                seen.add(alert_id)

                # Comprobar el intervalo temporal.
                try:
                    candidate_time = self._time(
                        candidate.get("created_at", "")
                    )
                except (
                    ValueError,
                    TypeError,
                    AttributeError
                ):
                    continue

                if not start <= candidate_time <= end:
                    continue

                # Comparar identificadores.
                other = self._entities(candidate)

                shared_entities = any(
                    target[group] & other.get(group, set())
                    for group in relevant_groups
                    if group in target
                )

                # Comparar eventos originales de logs.
                shared_events = bool(
                    event_ids.intersection(
                        candidate.get("related_events") or []
                    )
                )

                if shared_entities or shared_events:
                    related.append(candidate)

            # 6. Avanzar a la siguiente página.
            offset += len(items)

            total = page.get("total")

            if isinstance(total, int) and offset >= total:
                break

            if len(items) < page_size:
                break

        return related
