"""Propuestas N4 sobre el informe N3 validado; solo lecturas de CMDB/directorio.

Se reutilizan las acciones y el filtro de politica_soc.md del ActionRecommender
N1. Su único filtro reutilizable es _check_action_policy (privado): se utiliza
directamente para no fabricar Analysis/Verdict N1 ni duplicar ese filtro.
N4 añade aprobadores estructurados y exige revisión humana incluso para las
acciones que la política permite a N1. No se deduce compromiso de texto libre.
"""
from __future__ import annotations

from hashlib import sha256
from ipaddress import ip_address
import json
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from src.data.reference_repository import ReferenceRepository
from src.data.soc_api_client import SOCAPIClient
from src.triage.decision.action_recommender import ActionRecommender, AMBIGUOUS_TARGETS, CONTAINMENT_ACTIONS
from src.triage.ingestion.entities import extract_entities
from src.triage.level3.incident_report_builder import EvidenceReference, IncidentReport, validate_report
from src.triage.models import ContextSnapshot, ProposedAction

Action = Literal["isolate_host", "disable_user", "revoke_sessions", "reset_password",
                 "block_ioc", "purge_email", "disable_access_key"]
ApprovalRole = Literal["N1", "N2", "service_owner", "business_owner", "operations"]


def report_fingerprint(report: IncidentReport) -> str:
    return sha256(json.dumps(report.to_dict(), sort_keys=True, ensure_ascii=False).encode()).hexdigest()


class ContainmentProposal(BaseModel):
    """Snapshot inmutable por contrato; las copias evitan compartir listas/dicts.

    action=None identifica revisión manual, nunca un endpoint ficticio.
    required_approvals son roles que ApprovalService debe autenticar en el
    contexto concreto de target_snapshot; no basta con recibir esos nombres.
    """
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    proposal_id: str
    incident_id: str
    report_digest: str
    policy_digest: str
    action: Action | None
    target: str
    justification: str
    evidence: list[EvidenceReference]
    executable: bool
    requires_approval: Literal[True] = True
    required_approvals: list[ApprovalRole]
    target_snapshot: dict[str, Any]
    operational_impact: str
    risks: list[str]

    @property
    def ticket_id(self) -> str:
        """Nombre utilizado por el ejecutor/API existentes para el incidente."""
        return self.incident_id

    @property
    def content_hash(self) -> str:
        # Fórmula real de ApprovalService.request_approval(). proposal_id ya
        # vincula el informe, política, evidencias y snapshot completos de N4.
        raw = f"{self.proposal_id}:{(self.action or '').strip().lower()}:{self.target.strip().lower()}:{self.justification.strip()}"
        return sha256(raw.encode()).hexdigest()[:16]

    @staticmethod
    def identity(payload: dict) -> str:
        data = {key: value for key, value in payload.items() if key != "proposal_id"}
        return "RSP-" + sha256(json.dumps(data, sort_keys=True, ensure_ascii=False).encode()).hexdigest()[:32]

    def verify_identity(self) -> None:
        if self.proposal_id != self.identity(self.model_dump(mode="json")):
            raise ValueError("La propuesta no coincide con su identificador/contenido original")
        if (any(not value.strip() for value in (self.incident_id, self.target, self.justification,
                                                self.report_digest, self.policy_digest))
                or not self.evidence or not self.required_approvals
                or self.executable and self.action is None):
            raise ValueError("Propuesta incompleta o sin evidencias/aprobadores")


def _values(record: Any, fields: set[str]) -> set[str]:
    """Valores estructurados exactos, sin buscar objetivos dentro de narraciones."""
    result: set[str] = set()
    if isinstance(record, dict):
        for key, value in record.items():
            if key in fields:
                if isinstance(value, str):
                    result.add(value.strip())
                elif isinstance(value, list):
                    result.update(item.strip() for item in value if isinstance(item, str))
            if isinstance(value, (dict, list)):
                result.update(_values(value, fields))
    elif isinstance(record, list):
        for item in record:
            result.update(_values(item, fields))
    return result


class ResponsePlanner:
    def __init__(self, *, api: SOCAPIClient, references: ReferenceRepository,
                 recommender: ActionRecommender | None = None) -> None:
        self.api, self.references = api, references
        self.recommender = recommender if recommender is not None else ActionRecommender()

    def plan(self, report: IncidentReport | dict) -> list[ContainmentProposal]:
        report = validate_report(report)
        policy = self.references.get_policy()
        if not policy.strip():
            raise LookupError("No se dispone de politica_soc.md para planificar N4")
        known = {(item.source, item.event_id): item for item in report.evidence if item.event_id}
        conclusions = [*report.scope_analysis.hosts, *report.scope_analysis.users, *report.scope_analysis.services,
                       report.scope_analysis.data, report.scope_analysis.business_impact,
                       report.reconstruction.patient_zero, report.reconstruction.initial_access,
                       report.reconstruction.root_cause]
        confirmed_refs = set()
        for conclusion in conclusions:
            if conclusion.status != "unknown" and (not conclusion.statement or not conclusion.evidence):
                raise ValueError("Una conclusión conocida necesita texto y evidencias")
            for ref in conclusion.evidence:
                if (ref.source, ref.event_id) not in known:
                    raise ValueError(f"Evidencia inexistente: {ref.source}/{ref.event_id}")
                if conclusion.status == "confirmed":
                    confirmed_refs.add((ref.source, ref.event_id))
        candidates = []
        for conclusion in report.scope_analysis.hosts:
            if conclusion.status == "confirmed":
                candidates.append(("isolate_host", conclusion.statement, conclusion.evidence,
                                   f"Alcance N3 confirmado: {conclusion.statement}"))
        for conclusion in report.scope_analysis.users:
            if conclusion.status == "confirmed":
                for action in ("revoke_sessions", "reset_password"):
                    candidates.append((action, conclusion.statement, conclusion.evidence,
                                       f"Identidad comprometida según N3: {conclusion.statement}"))
        for measure in report.containment_plan:
            if measure.action not in CONTAINMENT_ACTIONS:
                continue  # N3 también contiene propuestas descriptivas/manuales.
            refs = {(ref.source, ref.event_id) for ref in measure.evidence}
            if refs - known.keys():
                raise ValueError("Una recomendación cita evidencias inexistentes")
            if refs and refs & confirmed_refs:
                candidates.append((measure.action, measure.target, measure.evidence, measure.justification))

        assets, users = {}, {}
        report_digest = report_fingerprint(report)
        policy_digest = sha256(policy.encode()).hexdigest()
        proposals: dict[tuple, dict] = {}
        for action, target, refs, justification in sorted(candidates, key=lambda item: (item[0], item[1], item[3])):
            if (target.casefold() in AMBIGUOUS_TARGETS or "*" in target
                    or any(ord(char) < 32 for char in target)):
                continue
            cited = [known[(ref.source, ref.event_id)] for ref in refs]
            context = ContextSnapshot()
            roles: list[ApprovalRole] = ["N2"]
            snapshot: dict[str, Any] = {}
            impact = "Revisar la interrupción operativa y el alcance antes de autorizar."
            executable = True
            risks = []
            if action == "isolate_host":
                key = target.casefold()
                if key not in assets:
                    assets[key] = self.api.get_asset(target)
                asset = assets[key]
                if not asset:
                    continue
                aliases = {str(asset.get(key, "")).casefold() for key in ("hostname", "asset_id", "ip")}
                assets.update({alias: asset for alias in aliases if alias})
                observed = {value.casefold() for item in cited for value in _values(
                    item.raw, {"hostname", "host", "src_host", "client_host", "asset_id"})}
                if target.casefold() not in aliases or not aliases.intersection(observed):
                    continue
                target = asset["hostname"]  # El endpoint exige el hostname exacto.
                context.assets = [asset]
                snapshot = {"asset": asset}
                zone = self.references.get_network_zone(asset.get("ip", ""))
                if zone:
                    context.network_zones = [zone]
                service = self.references.get_business_service(asset.get("business_service", ""))
                if service:
                    context.services = [service]
                    snapshot["service"] = service
                kind, area = asset.get("type", "").casefold(), asset.get("zone", "").upper()
                if "servidor" in kind or area in {"DC-SERVERS", "DMZ", "DEV", "AWS-PROD"}:
                    roles.append("service_owner")
                if "crític" in asset.get("criticality", "").casefold() or asset.get("criticality", "").casefold() == "critical":
                    if "service_owner" not in roles:
                        roles.append("service_owner")
                if kind in {"tpv", "frontal web"} or target.upper().startswith(("POS-", "TPV-", "WEB-")):
                    roles.append("business_owner")
                if not kind or not area:
                    executable = False
                    risks.append("Faltan tipo/zona del activo; revisión manual de permisos.")
                impact = f"Puede interrumpir {asset.get('business_service') or 'el servicio del activo'} y sus dependencias."
            elif action in {"disable_user", "revoke_sessions", "reset_password"}:
                key = target.casefold()
                if key not in users:
                    users[key] = self.api.get_user(target)
                user = users[key]
                if not user:
                    continue
                users.update({str(user[field]).casefold(): user for field in ("username", "upn") if user.get(field)})
                aliases = extract_entities({"entities": {"users": [user]}}).users
                observed = extract_entities({"entities": {"users": [value for item in cited for value in _values(
                    item.raw, {"user", "username", "upn", "user_upn", "actor_upn", "userName"})]}}).users
                requested = extract_entities({"entities": {"users": [target]}}).users
                if not set(requested) & set(aliases) or not set(aliases) & set(observed):
                    continue
                target = user.get("upn") or user["username"]
                snapshot = {"user": user}
                impact = "Interrupción de sesiones/acceso de la identidad; revisar procesos y aplicaciones dependientes."
                if user.get("account_type", "").casefold() in {"service", "service_account", "servicio"}:
                    roles.append("service_owner")
                    risks.append("Cuenta de servicio: puede detener procesos de negocio.")
            else:
                fields = {"block_ioc": {"ip", "src_ip", "dst_ip", "domain", "url", "sha256", "sha1", "md5"},
                          "purge_email": {"message_id"},
                          "disable_access_key": {"accessKeyId", "access_key", "access_key_id"}}[action]
                observed = {value for item in cited for value in _values(item.raw, fields)}
                if target not in observed:
                    continue
                snapshot = {"observed_target": target}
                if action == "block_ioc":
                    valid, _ = self.recommender._parse_ioc(target)
                    if not valid:
                        continue
                    roles = ["N1"]
                    try:
                        if not ip_address(target).is_global:
                            executable = False
                            roles = ["N2"]
                            risks.append("IP interna o reservada: revisar el alcance del bloqueo manualmente.")
                        zone = self.references.get_network_zone(target)
                        if zone:
                            context.network_zones = [zone]
                    except ValueError:
                        pass  # Dominio/hash válido según el filtro existente.
                elif action == "purge_email":
                    roles = ["N1"]
                    impact = "Retirada del mensaje identificado de los buzones afectados."
                else:
                    impact = "Interrupción de aplicaciones y trabajos que utilicen esta clave cloud."

            filtered = self.recommender._check_action_policy(
                ProposedAction(action=action, target=target, justification=justification), context
            )
            if filtered.action != action:
                executable = False
                roles = ["operations"]
                risks.append("El SOC no actúa sobre OT: escalar al Responsable de Operaciones.")
            elif action == "block_ioc" and filtered.requires_approval:
                roles = ["N2"]
                risks.append("Revisión N2 del alcance y del uso legítimo/dual antes del bloqueo global.")
            output_action = action if executable else None
            key = (output_action, target)
            if key not in proposals:
                proposals[key] = dict(
                    incident_id=report.incident_id, report_digest=report_digest,
                    policy_digest=policy_digest, action=output_action, target=target,
                    justification=filtered.justification or justification, evidence=[], executable=executable,
                    requires_approval=True,
                    required_approvals=sorted(set(roles)), target_snapshot=snapshot,
                    operational_impact=impact, risks=risks,
                )
            previous = proposals[key]
            evidence = {(ref.source, ref.event_id): ref.model_dump() for ref in refs}
            evidence.update({(ref["source"], ref["event_id"]): ref for ref in previous["evidence"]})
            previous["evidence"] = [evidence[key] for key in sorted(evidence)]
        result = []
        for key in sorted(proposals, key=str):
            data = proposals[key]
            proposal = ContainmentProposal(proposal_id=ContainmentProposal.identity(data), **data)
            proposal.verify_identity()
            result.append(proposal)
        return result
