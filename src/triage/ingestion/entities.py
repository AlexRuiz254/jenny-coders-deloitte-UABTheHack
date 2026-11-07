"""Dos helpers de extracción; no se necesita AlertNormalizer para el dataset."""
from ipaddress import ip_address
import re
from urllib.parse import urlsplit, urlunsplit

from src.triage.models import RawAlert, EntityKeys


_HASH_LENGTHS = {"md5": 32, "sha1": 40, "sha256": 64}
_EMPTY_VALUES = {"none", "null", "n/a", "unknown", "desconocido", "ninguno", "-"}


def _items(value: object) -> list:
    if isinstance(value, list):
        return value
    return [value] if isinstance(value, (str, dict)) else []


def _text(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    value = value.strip()
    if (not value or value.casefold() in _EMPTY_VALUES or value.startswith("(")
            or any(char.isspace() or ord(char) < 32 or ord(char) == 127 for char in value)):
        return None
    return value


def _ip(value: object) -> str | None:
    value = _text(value)
    if value is not None:
        try:
            return str(ip_address(value))
        except ValueError:
            pass
    return None


def _public_ip(value: str) -> bool:
    address = ip_address(value)
    return (address.is_global and not address.is_private and not address.is_reserved
            and not address.is_loopback and not address.is_link_local
            and not address.is_multicast and not address.is_unspecified)


def _domain(value: object) -> str | None:
    value = _text(value)
    if value is None:
        return None
    try:
        value = value.removesuffix(".").encode("idna").decode("ascii").lower()
    except UnicodeError:
        return None
    labels = value.split(".")
    if (len(value) > 253 or len(labels) < 2 or labels[-1].isdigit()
            or not all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
                       for label in labels)):
        return None
    return value


def _hash(value: object, algorithm: str | None = None) -> str | None:
    value = _text(value)
    if value is None or not re.fullmatch(r"[a-fA-F0-9]+", value):
        return None
    lengths = {_HASH_LENGTHS[algorithm]} if algorithm else set(_HASH_LENGTHS.values())
    return value.lower() if len(value) in lengths else None


def _url(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    value = value.strip()
    # El WAF registra payloads SQLi con espacios sin codificar en la consulta.
    # Conservarlos; rechazar controles y espacios en la autoridad, no en el payload.
    if (not value or "\\" in value
            or any(ord(char) < 32 or ord(char) == 127
                   or (char.isspace() and char != " ") for char in value)):
        return None
    try:
        parts = urlsplit(value)
        host = _ip(parts.hostname) or _domain(parts.hostname)
        port = parts.port  # También valida el formato y el máximo 65535.
        if (parts.scheme.lower() not in {"http", "https"} or not host or port == 0
                or _text(parts.netloc) is None):
            return None
        authority = f"[{host}]" if ":" in host else host
        if port is not None:
            authority += f":{port}"
        if "@" in parts.netloc:
            authority = parts.netloc.rsplit("@", 1)[0] + "@" + authority
        # Normalizar esquema/host, conservando mayúsculas de ruta y parámetros.
        return urlunsplit((parts.scheme.lower(), authority, parts.path, parts.query, parts.fragment))
    except ValueError:
        return None


def _identifier(group: str, value: object) -> str | None:
    if group == "ips":
        return _ip(value)
    if group == "domains":
        return _domain(value)
    if group == "urls":
        return _url(value)
    if group == "hashes":
        return _hash(value)
    value = _text(value)
    if value is None:
        return None
    if group == "hosts":
        if (len(value) > 253 or not all(
                re.fullmatch(r"[a-zA-Z0-9_](?:[a-zA-Z0-9_-]{0,61}[a-zA-Z0-9_])?", label)
                for label in value.split("."))):
            return None
    elif (not re.fullmatch(r"[\w.@$:/+\\=-]+", value)
          or not any(char.isalnum() for char in value)):
        return None
    if group == "users":
        if "\\" in value:
            realm, username = value.rsplit("\\", 1)
            if not realm or not username:
                return None
            if realm.rstrip("\\").casefold() not in {"tarvia", "tarvia.example"}:
                return value.casefold()  # Conservar organizaciones externas.
            value = username
        if "@" in value:
            if value.count("@") != 1:
                return None
            username, domain = value.split("@")
            domain = _domain(domain)
            if not username or domain is None:
                return None
            value = username if domain == "tarvia.example" else f"{username}@{domain}"
    return value.casefold()


def extract_entities(alert: RawAlert) -> EntityKeys:
    """Leer las distintas formas de entities: listas, cloud y ai_session."""
    result = EntityKeys()
    raw = alert.get("entities") if isinstance(alert, dict) else None
    if not isinstance(raw, dict):
        return result

    def add(group: str, value: object) -> None:
        value = _identifier(group, value)
        values = getattr(result, group)
        if value is not None and value not in values:
            values.append(value)

    columns = {
        "hosts": ("hostname",), "users": ("upn", "username"),
        "ips": ("ip",), "domains": ("domain",), "urls": ("url",),
        "hashes": tuple(_HASH_LENGTHS), "sessions": ("session_id",),
        "customers": ("customer_id",),
    }
    for group, fields in columns.items():
        for item in _items(raw.get(group)):
            if isinstance(item, str):
                add(group, item)
                if group == "hosts":
                    add("ips", item)
            elif isinstance(item, dict):
                if group == "users":
                    # Si hay UPN externo, su username sin dominio es ambiguo.
                    upn = _identifier("users", item.get("upn"))
                    add(group, upn if upn is not None else item.get("username"))
                else:
                    for field in fields:
                        value = item.get(field)
                        if group != "hashes" or _hash(value, field) is not None:
                            add(group, value)
                if group == "hosts":
                    add("ips", item.get("ip"))

    for file in _items(raw.get("files")):
        if isinstance(file, dict):
            for algorithm in _HASH_LENGTHS:
                add("hashes", _hash(file.get(algorithm), algorithm))
    for cloud in _items(raw.get("cloud")):
        if isinstance(cloud, dict):
            add("users", cloud.get("identity"))
            add("users", cloud.get("new_user"))
            # EntityKeys no tiene campos cloud: usar los grupos del correlador.
            add("sessions", cloud.get("access_key"))
    for session in _items(raw.get("ai_session")):
        add("sessions", session.get("session_id") if isinstance(session, dict) else session)
    return result


def extract_indicators(alert: RawAlert) -> list[str]:
    """Leer IOC explícitos; no recuperar logs ni interpretar texto libre."""
    result: list[str] = []

    def add(group: str, value: object) -> None:
        value = _identifier(group, value)
        if value is None:
            return
        if group == "ips" and not _public_ip(value):
            return
        if group == "urls":
            host = urlsplit(value).hostname
            address = _ip(host)
            if address and not _public_ip(address):
                return
            add("ips" if address else "domains", host)
        if value not in result:
            result.append(value)

    entities = extract_entities(alert)
    for group in ("ips", "domains", "urls", "hashes"):
        for value in getattr(entities, group):
            add(group, value)

    ip_fields = {"ip", "ips", "src_ip", "dst_ip", "sender_ip", "sourceIPAddress",
                 "created_from_ip", "submitted_from_ip"}
    domain_fields = {"domain", "domains", "parent_domain", "legit_supplier_domain",
                     "new_email_domain", "query"}

    def visit(record: object) -> None:
        if isinstance(record, list):
            for item in record:
                visit(item)
        elif isinstance(record, dict):
            for field, value in record.items():
                for item in _items(value):
                    if field in ip_fields:
                        add("ips", item)
                    elif field in domain_fields:
                        add("domains", item)
                    elif field in {"url", "urls"}:
                        add("urls", item)
                    elif field in _HASH_LENGTHS:
                        add("hashes", _hash(item, field))
                    elif field == "hashes":
                        add("hashes", item)
                    elif field in {"destination", "network", "downloaded_from"}:
                        # Solo valores completos: no extraer de frases o comandos.
                        for group in ("ips", "domains", "urls"):
                            add(group, item)
                    elif field in {"sender", "recipient", "recipients"}:
                        email = _text(item)
                        if email and email.count("@") == 1 and email.split("@")[0]:
                            add("domains", email.split("@")[1])
                if isinstance(value, (dict, list)):
                    visit(value)

    if isinstance(alert, dict):
        visit(alert.get("evidence"))
    return result
