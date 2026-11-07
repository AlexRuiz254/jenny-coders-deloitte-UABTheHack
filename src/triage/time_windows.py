"""Fechas UTC de la API y ventana operativa de correlación N1."""
from datetime import datetime, timedelta, timezone


def parse_utc(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed.astimezone(timezone.utc)


def api_time(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def alert_window(alert: dict) -> tuple[datetime, datetime]:
    instant = parse_utc(alert["created_at"])
    return instant - timedelta(hours=24), instant + timedelta(hours=24)
