"""Revisar las propuestas del investigador según la política SOC, sin ejecutarlas."""

from ipaddress import ip_address, ip_network
import re
from urllib.parse import urlsplit

from src.triage.models import (
    Analysis,
    ContextSnapshot,
    ProposedAction,
    SeverityDecision,
    TicketAction,
    VerdictDecision,
)


CONTAINMENT_ACTIONS = {
    "isolate_host", "disable_user", "revoke_sessions", "reset_password",
    "block_ioc", "purge_email", "disable_access_key",
}
AMBIGUOUS_TARGETS = {
    "", "*", "all", "todos", "unknown", "desconocido", "n/a", "none",
    "null", "pendiente", "tbd", "hostname", "usuario", "user", "message_id",
    "access_key_id", "ioc",
}
SERVICE_NAME_ALIASES = {
    "Tienda online y app (≈38% de la facturación)": "Tienda online y app",
}


class ActionRecommender:
    def recommend(
        self,
        analysis: Analysis,
        context: ContextSnapshot,
        *,
        verdict: VerdictDecision,
        severity: SeverityDecision,
    ) -> list[TicketAction]:
        """Filtrar por veredicto validado, aplicar permisos y eliminar duplicados.

        Las acciones ajenas a la API se conservan para revisión manual. El orden
        del investigador se mantiene: TicketAction no tiene campo de prioridad.
        """
        recommendations: list[TicketAction] = []
        seen: set[tuple[str, ...]] = set()
        for proposed in analysis.proposed_actions:
            action = proposed.model_copy(update={
                "action": proposed.action.strip().casefold(),
                "target": proposed.target.strip(),
                "justification": proposed.justification.strip(),
            })
            if not action.action:
                continue
            containment = action.action in CONTAINMENT_ACTIONS
            if not containment and (action.action.startswith(("close", "cerrar")) or action.action == "mark_as_benign"):
                if verdict.verdict == "needs_more_info" or severity.severity in {"high", "critical"}:
                    continue
                reason = action.justification.casefold()
                if ("autorizad" in reason or "benign" in reason) and verdict.verdict != "benign_true_positive":
                    continue
            if containment:
                if verdict.verdict in {"false_positive", "benign_true_positive"}:
                    continue
                # La justificación es la aportada por el investigador; no se
                # vuelve a investigar ni se da por confirmado el compromiso.
                if verdict.verdict == "needs_more_info" and (
                    severity.severity not in {"high", "critical"}
                    or not action.justification
                ):
                    continue
            if containment and (
                action.target.casefold() in AMBIGUOUS_TARGETS
                or (action.target.startswith("<") and action.target.endswith(">")
                    and not (action.action == "purge_email"
                             and re.fullmatch(r"<[^<>\s@]+@[^<>\s@]+>", action.target)))
            ):
                continue

            key = (action.action, action.target.casefold())
            # Dos investigaciones sobre la misma entidad pueden tener distinto fin.
            if not containment:
                key += (action.justification,)
            if key in seen:
                continue
            seen.add(key)

            recommendation = self._check_action_policy(
                action, context,
                provisional=containment and verdict.verdict == "needs_more_info",
            )
            if severity.severity in {"high", "critical"}:
                recommendation.justification = (
                    f"{recommendation.justification} "
                    f"Revisar con prioridad por severidad {severity.severity}."
                )
            recommendations.append(recommendation)
        return recommendations

    def _check_action_policy(
        self, action: ProposedAction, context: ContextSnapshot,
        *, provisional: bool = False,
    ) -> TicketAction:
        """Expresar permisos y restricciones del apartado 4 de politica_soc.md."""
        output_action = action.action
        containment = action.action in CONTAINMENT_ACTIONS
        requires_approval = containment and (
            provisional or action.action not in {"purge_email", "block_ioc"}
        )
        requires_review = provisional
        target = action.target.casefold()
        asset = next((
            item for item in context.assets
            if any(str(item.get(field, "")).strip().casefold() == target
                   for field in ("asset_id", "hostname", "ip")) and target
        ), None)

        # Resolver solo la zona del objetivo; otra entidad OT no condiciona todo
        # el ticket. Se usan exclusivamente los CIDR ya recibidos en el contexto.
        is_ot = bool(asset and asset.get("zone") == "LOGISTICS-OT")
        try:
            address = ip_address((asset.get("ip") if asset else None) or action.target)
        except ValueError:
            address = None
        if address is not None:
            for zone in context.network_zones:
                if zone.get("zona") != "LOGISTICS-OT":
                    continue
                try:
                    is_ot |= address in ip_network(zone.get("cidr", ""), strict=False)
                except ValueError:
                    continue

        if is_ot and containment:
            output_action = "coordinate_with_operations"
            requires_approval = False
            restriction = (
                f"La propuesta original {action.action} sobre {action.target} se "
                "sustituye por coordinación manual con el responsable de Operaciones, "
                "que debe evaluar y coordinar la respuesta. El SOC no ejecuta "
                "contención en OT, ni siquiera con aprobación N2. Esta recomendación "
                "manual no es un endpoint de contención."
            )
        elif not containment:
            restriction = (
                "Recomendación manual sin aprobación formal de contención; "
                "no ejecutar como endpoint de la API."
            )
        elif action.action == "isolate_host":
            restriction = "Requiere aprobación N2."
            if asset is None:
                restriction += (
                    " Antes de aislar, confirmar el tipo de activo: si es servidor, "
                    "también requiere al responsable del servicio; si es TPV o "
                    "frontal web, también a negocio."
                )
            else:
                asset_type = asset.get("type", "").casefold()
                server = (
                    "servidor" in asset_type
                    or asset.get("zone") in {"DC-SERVERS", "DMZ", "DEV", "AWS-PROD"}
                )
                if server or asset_type == "frontal web":
                    restriction += " También requiere aprobación del responsable del servicio."
                    service_name = asset.get("business_service", "")
                    service = next((item for item in context.services
                                    if item.get("servicio") == service_name), None)
                    if service is None and service_name in SERVICE_NAME_ALIASES:
                        catalog_name = SERVICE_NAME_ALIASES[service_name]
                        service = next((item for item in context.services
                                        if item.get("servicio") == catalog_name), None)
                    if service and service.get("responsable"):
                        restriction += f" Responsable: {service['responsable']}."
                if asset_type in {"tpv", "frontal web"}:
                    restriction += " También requiere aprobación de negocio por impacto en ventas."
        elif action.action == "block_ioc":
            valid_ioc, domain = self._parse_ioc(action.target)
            dual_use = any(
                domain == name or domain.endswith("." + name)
                for name in ("mega.nz", "mega", "anydesk.com", "anydesk", "teamviewer.com", "teamviewer")
            )
            
            wildcard = "*" in action.target
            requires_approval = provisional or dual_use or not valid_ioc or wildcard
            requires_review = requires_approval
            if dual_use:
                restriction = (
                    "Servicio legítimo de uso dual: requiere revisar el alcance "
                    "y aprobación N2 antes de bloquear por el posible impacto global. "
                    "El modelo no especifica el alcance."
                )
            elif not valid_ioc:
                restriction = (
                    "Formato de indicador inválido o no reconocido: validar el formato y el "
                    "alcance y obtener aprobación N2 "
                    "antes de cualquier bloqueo."
                )
            elif wildcard:
                restriction = (
                    "Indicador con comodín: requiere revisión del alcance "
                    "y aprobación N2 antes de bloquear."
                )
            elif provisional:
                restriction = "Requiere aprobación N2 antes de bloquear el IOC."
            else:
                restriction = "Permitida a N1 para un IOC concreto en proxy, correo o EDR."
        elif action.action == "purge_email":
            restriction = (
                "Requiere aprobación N2 antes de purgar."
                if provisional else "Permitida a N1 sin aprobación adicional."
            )
        else:
            restriction = "Requiere aprobación N2."
            if action.action == "disable_user":
                restriction += " Si es una cuenta de servicio, revisar el impacto en el proceso de negocio."

        if provisional:
            restriction += " Compromiso sin confirmar: propuesta preventiva."
        if requires_review and output_action in CONTAINMENT_ACTIONS:
            restriction += " Revisión humana antes de cualquier ejecución."

        return TicketAction(
            action=output_action,
            target=action.target,
            requires_approval=requires_approval,
            justification=" ".join(filter(None, (action.justification, restriction))),
        )

    def _parse_ioc(self, indicator: str) -> tuple[bool, str]:
        """Reconocer formatos básicos; devolver el dominio para revisar el uso dual."""
        if any(char.isspace() or ord(char) < 32 for char in indicator) or "\\" in indicator:
            return False, ""
        try:
            ip_address(indicator)
            return True, ""
        except ValueError:
            pass

        hash_lengths = {"md5": 32, "sha1": 40, "sha256": 64, "sha512": 128}
        algorithm, separator, digest = indicator.casefold().partition(":")
        if separator and algorithm in hash_lengths:
            return (
                len(digest) == hash_lengths[algorithm]
                and re.fullmatch(r"[0-9a-f]+", digest) is not None,
                "",
            )
        if len(indicator) in hash_lengths.values() and re.fullmatch(r"[0-9a-fA-F]+", indicator):
            return True, ""

        domain = indicator.casefold()
        if "://" in indicator:
            try:
                parsed = urlsplit(indicator)
                if parsed.scheme not in {"http", "https", "ftp"} or parsed.port == 0:
                    return False, ""
                domain = parsed.hostname or ""
            except ValueError:
                return False, ""
            try:
                ip_address(domain)
                return True, ""
            except ValueError:
                pass
        domain = domain.removeprefix("*.").rstrip(".")
        labels = domain.split(".")
        valid_domain = (
            len(domain) <= 253 and len(labels) > 1 and not labels[-1].isdigit()
            and all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
                    for label in labels)
        )
        return valid_domain, domain
