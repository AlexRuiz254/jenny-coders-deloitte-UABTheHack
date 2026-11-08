"""Alcance con citas de eventos: una entidad observada no equivale a compromiso."""
from __future__ import annotations

from src.triage.investigation.investigation_agent import InvestigationAgent
from src.triage.investigation.authorization import check_authorization
from src.triage.ingestion.entities import extract_entities
from src.triage.models import ContextSnapshot, Evidence, Finding, IntelEntry


def supported_scope(bundle: dict, references=None) -> dict:
    from src.triage.level3.incident_report_builder import ScopeResult, SupportedConclusion

    incident_id = bundle["incident_id"]
    observed = {}
    for value in [*bundle.get("evidence", []), *bundle.get("expanded_evidence", []), *bundle.get("events", [])]:
        item = Evidence.model_validate(value)
        if item.event_id and item.source != "changes" and item.raw.get("kind") != "query_summary":
            observed[(item.source, item.event_id)] = item
    intel = [IntelEntry.model_validate(item) for item in bundle.get("intel", [])]
    contexts = [ContextSnapshot.model_validate(value) for value in bundle.get("contexts", [])]
    context = ContextSnapshot(
        assets=[item for value in contexts for item in value.assets],
        users=[item for value in contexts for item in value.users],
        changes=[item for value in contexts for item in value.changes],
    )
    seed_entities = [extract_entities(alert) for alert in bundle.get("alerts", [])]
    entities = bundle.get("entities", {})
    target_hosts = {name.casefold() for seed in seed_entities for name in seed.hosts}
    target_users = {name for seed in seed_entities for name in seed.users}
    if not seed_entities:
        target_hosts = {name.casefold() for name in entities.get("hosts", [])}
        target_users = set(extract_entities({"entities": {"users": entities.get("users", [])}}).users)
    hosts, users, services = {}, {}, {}
    data_refs, credential_refs = [], []

    def add(mapping, name, status, ref):
        if not isinstance(name, str) or not name.strip() or name.startswith("("):
            return
        if name.casefold() in {"system", "nt authority\\system", "local service", "network service"}:
            return
        name = name.strip()
        previous = mapping.setdefault(name, {"statement": name, "status": status, "evidence": []})
        if status == "confirmed":
            previous["status"] = status
        if ref not in previous["evidence"]:
            previous["evidence"].append(ref)

    for item in observed.values():
        ref = {"source": item.source, "event_id": item.event_id}
        raw = item.raw
        host = raw.get("hostname") or raw.get("host")
        user = raw.get("user_upn") or raw.get("user") or raw.get("username")
        support = InvestigationAgent._claim_support(
            alert={}, events=[item], evidence=[item], context=ContextSnapshot(), findings=[], intel=intel)
        outcome = InvestigationAgent._get_event_outcome(item)
        malicious_host = item.source == "edr_events" and outcome == "execution" and "malicious_execution" in support
        malicious_user = item.source in {"idp_signins", "vpn"} and outcome == "success" and "credentials_compromised" in support
        # Una ventana de mantenimiento puede explicar herramientas administrativas,
        # pero nunca convierte un hash malicioso en software autorizado.
        if malicious_host and context.changes:
            findings = [Finding(statement="Comprobar actividad del cambio", evidence_ids=[item.event_id, change["id"]])
                        for change in context.changes if change.get("id")]
            known_bad_hash = any(entry.indicator.casefold() == str(raw.get("sha256", "")).casefold()
                                 and '"malicious"' in entry.result for entry in intel)
            if not known_bad_hash and check_authorization(findings, [item], context)[0]:
                malicious_host = False
        if malicious_host or isinstance(host, str) and host.casefold() in target_hosts:
            add(hosts, host, "confirmed" if malicious_host else "hypothesis", ref)
        normalized_users = extract_entities({"entities": {"users": [user]}}).users
        if malicious_user or set(normalized_users) & target_users:
            add(users, user, "confirmed" if malicious_user else "hypothesis", ref)
        if "personal_data_exposure" in support and item.source == "dlp":
            data_refs.append(ref)
        if "credentials_compromised" in support and item.source in {"edr_events", "cicd_builds"}:
            credential_refs.append(ref)

    for name, conclusion in hosts.items():
        if conclusion["status"] != "confirmed":
            continue
        asset = next((a for a in context.assets if a.get("hostname", "").casefold() == name.casefold()), None)
        if asset and asset.get("business_service"):
            for ref in conclusion["evidence"]:
                # El compromiso del host implica riesgo para su servicio; no acredita una caída.
                add(services, asset["business_service"], "hypothesis", ref)

    data = SupportedConclusion()
    if data_refs:
        data = SupportedConclusion(statement="DLP registra transmisión de datos personales a un destino externo no aprobado; validar alcance y recepción.",
                                   status="confirmed", evidence=data_refs)
    elif credential_refs:
        data = SupportedConclusion(statement="Posible exposición de credenciales del equipo o entorno; determinar qué cuentas o claves se leyeron.",
                                   status="hypothesis", evidence=credential_refs)
    impact_refs = [ref for value in hosts.values() if value["status"] == "confirmed" for ref in value["evidence"]]
    impact_refs += [ref for value in users.values() if value["status"] == "confirmed" for ref in value["evidence"]]
    impact = SupportedConclusion()
    if impact_refs:
        impact = SupportedConclusion(
            statement="El compromiso observado puede afectar a los servicios y accesos asociados. No se ha confirmado indisponibilidad ni cuantificado una pérdida económica.",
            status="hypothesis", evidence=list({(r["source"], r["event_id"]): r for r in impact_refs}.values()))
    return ScopeResult(
        incident_id=incident_id, hosts=list(hosts.values()), users=list(users.values()),
        services=list(services.values()), data=data, business_impact=impact,
        open_questions=["Revisar con los responsables el alcance y el impacto operativo; la presencia en logs no confirma compromiso."],
        limitations=["El alcance confirmado exige eventos de ejecución maliciosa o acceso con indicador malicioso. Las demás entidades citadas se mantienen como hipótesis.",
                     "Una conexión, un volumen de tráfico o un acceso cloud no prueban por sí solos exfiltración."],
    ).model_dump(mode="json", exclude_none=True)
