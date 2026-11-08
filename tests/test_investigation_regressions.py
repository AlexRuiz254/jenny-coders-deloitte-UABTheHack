"""Regresiones de decisiones SOC; proveedor simulado y datos oficiales de solo lectura."""
from unittest.mock import MagicMock

import pytest

from test_level1_integration import official_api, transport, setup_service  # noqa: F401
from src.triage.models import (
    Analysis, ContextSnapshot, Evidence, Finding, IntelEntry, InvestigationPlan, LogQuery,
    PolicySignals, ProposedAction, SearchPlan, SeverityDecision, VerdictDecision,
)
from src.triage.investigation.investigation_agent import InvestigationAgent, MAX_SEARCH_QUERIES
from src.triage.investigation.authorization import check_authorization
from src.triage.decision.action_recommender import ActionRecommender
from src.triage.decision.severity_calculator import SeverityCalculator
from src.triage.decision.verdict_engine import VerdictEngine


def signals(**values):
    return PolicySignals(**{name: values.get(name, False) for name in PolicySignals.model_fields})


def analysis(findings, **values):
    return Analysis(**dict({
        "title": "Investigación SOC", "summary": "Hechos observados en las evidencias.",
        "verdict": "true_positive", "confidence": .9, "findings": findings,
        "signals": signals(), "proposed_actions": [], "open_questions": [],
    }, **values))


def event(source, event_id, **raw):
    return Evidence(source=source, event_id=event_id, timestamp=raw.pop("timestamp", "2026-10-05T06:02:00Z"), raw=raw)


def query(source, text, *, truncated=False, count=0):
    return Evidence(source=source, raw={
        "kind": "query_summary", "query_id": "QRY-test-" + source, "q": text,
        "desde": "2026-10-04T00:00:00Z", "hasta": "2026-10-06T23:59:59Z",
        "count": count, "truncated": truncated,
    })


@pytest.mark.parametrize("clicked_message,expected", [(None, False), ("<other@bad.example>", False), ("<original@bad.example>", True)])
def test_phishing_click_and_dependent_fields(clicked_message, expected):
    alert = {"created_at": "2026-10-05T07:00:00Z", "runbook": "RB-01", "rule_name": "Clic confirmado del usuario",
             "entities": {"users": ["beatriz@tarvia.example"]}, "evidence": {"message_id": "<original@bad.example>"},
             "related_events": ["EML-1"]}
    mail = event("email", "EML-1", message_id="<original@bad.example>", recipients=["beatriz@tarvia.example"], action="delivered")
    evidence = [mail]
    if clicked_message:
        evidence.append(event("email_clicks", "CLK-1", timestamp="2026-10-05T06:05:00Z",
                              message_id=clicked_message, user="beatriz@tarvia.example", action="allowed"))
    proposed = analysis([
        Finding(statement="Correo phishing entregado.", evidence_ids=["EML-1"]),
        Finding(statement="Beatriz hizo clic en el mensaje.", evidence_ids=["CLK-1" if clicked_message else "EML-1"]),
    ], title="Clic confirmado de Beatriz", summary="Beatriz hizo clic en el mensaje.",
        signals=signals(credentials_compromised=True), proposed_actions=[
            ProposedAction(action="reset_password", target="beatriz@tarvia.example", justification="Clic confirmado de Beatriz."),
            ProposedAction(action="purge_email", target="<original@bad.example>", justification="Phishing entregado."),
        ])
    result = InvestigationAgent._sanitize_analysis(analysis=proposed, alert=alert, context=ContextSnapshot(), evidence=evidence)
    assert any("hizo clic" in f.statement for f in result.findings) is expected
    assert not result.signals.credentials_compromised
    assert result.verdict == "true_positive"  # Una laguna de impacto no invalida phishing real.
    assert all(a.action != "reset_password" for a in result.proposed_actions)  # El clic tampoco prueba robo.
    if not expected:
        assert "clic" not in result.title.casefold() + result.summary.casefold()
        assert [a.action for a in result.proposed_actions] == ["purge_email"]
        assert any("interacción" in q for q in result.open_questions)


@pytest.mark.parametrize("reason,continuation,expected", [("invalid_password", False, False), ("blocked_by_smart_lockout", False, True), ("blocked_by_smart_lockout", True, False)])
def test_smart_lockout_and_successful_continuation(reason, continuation, expected):
    alert = {"created_at": "2026-10-05T06:04:00Z", "entities": {"ips": ["198.18.12.13"]}}
    ev = event("idp_signins", "SIGN-1", result="failure", failure_reason=reason, src_ip="198.18.12.13", user_upn="a@tarvia.example")
    evidence = [ev, query("idp_signins", "198.18.12.13")]
    if continuation:
        evidence.append(event("idp_signins", "SIGN-2", timestamp="2026-10-05T06:05:00Z", result="success", src_ip="198.18.12.13", user_upn="a@tarvia.example"))
    result = InvestigationAgent._sanitize_analysis(
        analysis=analysis([Finding(statement="Intentos de autenticación registrados.", evidence_ids=["SIGN-1"])], signals=signals(blocked_before_effect=True)),
        alert=alert, context=ContextSnapshot(), evidence=evidence)
    assert result.signals.blocked_before_effect is expected
    assert not result.signals.credentials_compromised


@pytest.mark.parametrize("user,host,expected", [("svc_sccm", "WS-1", True), ("SYSTEM", "WS-1", False), ("svc_sccm", "SERVER1", False)])
def test_authorization_checks_original_activity_only(user, host, expected):
    original = event("edr_events", "EDR-1", hostname=host, user=user, event_type="process_start", process_name="powershell.exe", parent_name="CcmExec.exe",
                     details={"decoded": "Get-CimInstance Win32_Product | Out-File C:\\Windows\\CCM\\Inventory\\sw.json"})
    later = event("edr_events", "EDR-2", timestamp="2026-10-05T16:00:00Z", hostname=host, event_type="process_start", process_name="excel.exe")
    context = ContextSnapshot(assets=[{"hostname": host, "business_service": "Puesto de trabajo" if host == "WS-1" else "Servidor"}], changes=[{
        "id": "CHG-1", "titulo": "Inventario SCCM", "inicio": "2026-09-28 00:00", "fin": "2026-12-31 23:59",
        "detalle": "svc_sccm diariamente 08:00-10:00", "alcance": "Todos los puestos",
    }])
    findings = [Finding(statement="Ejecución vinculada al cambio.", evidence_ids=["EDR-1", "CHG-1", "EDR-2"])]
    valid, reason = check_authorization(findings, [original, later], context)
    assert valid is expected
    if user == "SYSTEM":
        assert "ventana y alcance compatibles" in reason and "fuera de la ventana" not in reason
    proposed = analysis(findings, verdict="benign_true_positive", signals=signals(authorized_activity=True))
    normalized = InvestigationAgent._sanitize_analysis(analysis=proposed, alert={}, context=context, evidence=[original, later])
    assert normalized.signals.authorized_activity is expected
    assert (VerdictEngine().decide(normalized, [original, later], context).verdict == "benign_true_positive") is expected


def test_aggregates_sampling_and_absolute_claims():
    evidence = [event("proxy", f"PRX-{i}", hostname="WS-1", domain=f"dest{i % 3}.example", action="allowed", status=200) for i in range(9)]
    evidence += [event("cloudtrail", f"CT-{i}", eventName=["GetObject", "PutObject", "ListObjects", "PutBucketPolicy"][i % 4], errorCode="") for i in range(72)]
    aggregate = InvestigationAgent._summarize_evidence(evidence)
    assert aggregate["proxy"]["events_received"] == 9 and aggregate["proxy"]["distinct_destinations"] == 3
    assert aggregate["cloudtrail"]["operations"] == {key: 18 for key in ("GetObject", "PutObject", "ListObjects", "PutBucketPolicy")}
    sample, _, coverage = InvestigationAgent._prepare_evidence(evidence, {"related_events": ["CT-71"]}, 1800)
    assert "CT-71" in {r["event_id"] for r in sample} and coverage["omitted"]
    assert InvestigationAgent._claim_issues("Solo hubo una conexión.", support=set(), cited=[], evidence=evidence)
    assert InvestigationAgent._claim_issues("Solo hubo una conexión.", support=set(), cited=[], evidence=evidence[:1])
    assert InvestigationAgent._claim_issues("Se observaron 72 descargas.", support=set(), cited=[], evidence=evidence)


def test_manual_cloud_tasks_and_real_message_id():
    evidence = [event("cloudtrail", "CT-1", requestParameters={"bucketName": "tarvia-media-public"}, eventName="PutBucketPolicy", errorCode="")]
    result = InvestigationAgent._sanitize_analysis(
        analysis=analysis([Finding(statement="Modificación de política observada.", evidence_ids=["CT-1"])], proposed_actions=[
            ProposedAction(action="verify_authorization", target="bucket tarvia-media-public", justification="Verificar autorización de la política pública."),
            ProposedAction(action="review_classification", target="s3://tarvia-media-public", justification="Revisar la clasificación del contenido."),
        ]), alert={}, context=ContextSnapshot(), evidence=evidence)
    assert len(result.proposed_actions) == 2
    assert {a.target for a in result.proposed_actions} == {"tarvia-media-public"}
    result.proposed_actions = [ProposedAction(action="purge_email", target="<original@bad.example>", justification="Phishing entregado."),
                               ProposedAction(action="purge_email", target="<message_id>", justification="Placeholder."),
                               ProposedAction(action="close_as_authorized", target="ticket", justification="Cerrar low por actividad autorizada.")]
    actions = ActionRecommender().recommend(result, ContextSnapshot(), verdict=VerdictDecision(verdict="needs_more_info", confidence=.4, rationale="Pendiente"), severity=SeverityDecision(severity="high", rationale="Riesgo"))
    assert len(actions) == 1 and actions[0].target == "<original@bad.example>" and actions[0].requires_approval


def test_waf_service_criticality_and_safe_coverage():
    alert = {"created_at": "2026-10-05T06:04:00Z", "source_product": "WAF", "severity": "low", "entities": {"ips": ["198.18.12.7"], "urls": ["https://www.tarvia.example/api"]}}
    context = ContextSnapshot(services=[{"servicio": "Tienda online y app", "criticidad": "Crítica"}, {"servicio": "Otro servicio", "criticidad": "Crítica"}])
    proposed = analysis([Finding(statement="SQLi bloqueada.", evidence_ids=["WAF-1"])], signals=signals(blocked_before_effect=True))
    ev = event("waf", "WAF-1", src_ip="198.18.12.7", host="www.tarvia.example", action="blocked", status=403)
    result = InvestigationAgent._sanitize_analysis(analysis=proposed, alert=alert, context=context, evidence=[ev])
    assert result.verdict == "true_positive" and not result.signals.blocked_before_effect
    decision = VerdictDecision(verdict=result.verdict, confidence=.8, rationale="Intento")
    assert SeverityCalculator().calculate(alert, context, result, decision).severity == "medium"
    unrelated = {**alert, "entities": {"ips": ["198.18.12.7"]}}
    assert SeverityCalculator._get_criticality(unrelated, context) is None
    llm = MagicMock()
    llm.generate_json.return_value = SearchPlan(searches=[LogQuery(source="edr_events", query="WEB-INVENTED01", reason="Buscar backend")])
    agent = InvestigationAgent(llm)
    plan = InvestigationPlan(runbook_id="RB-05", required_checks=["check_waf_action_blocked_or_passed_to_backend", "check_backend_exploitation_and_database_queries"], suggested_sources=["waf", "edr_events", "sql_audit"])
    searches = agent.plan_searches(alert=alert, runbook_text="RB-05", plan=plan, context=context, evidence=[ev])
    assert len(searches.searches) == 1 and searches.searches[0].source == "waf"
    assert any(row["status"] == "pending" and row["source"] == "sql_audit" for row in agent.search_diagnostics["checks"])


@pytest.mark.parametrize("truncated,missing_window,covered", [(False, False, True), (True, False, False), (False, True, False)])
def test_coverage_requires_complete_compatible_query(truncated, missing_window, covered):
    alert = {"created_at": "2026-10-05T06:00:00Z", "entities": {"users": ["a@tarvia.example"]}, "evidence": {"message_id": "<m@bad.example>"}}
    ev = query("email_clicks", "<m@bad.example>", truncated=truncated)
    if missing_window:
        ev.raw.pop("desde")
    plan = InvestigationPlan(runbook_id="RB-01", required_checks=["check_url_clicks_and_user_interaction"], suggested_sources=["email_clicks"])
    coverage = InvestigationAgent._assess_runbook_coverage(alert, plan, ContextSnapshot(), [ev])
    assert (coverage[0]["status"] == "searched") is covered
    llm = MagicMock()
    llm.generate_json.return_value = SearchPlan(searches=[LogQuery(source="email_clicks", query="<fake@bad.example>", reason="Inventado")] * 8)
    result = InvestigationAgent(llm).plan_searches(alert=alert, runbook_text="RB-01", plan=plan, context=ContextSnapshot(), evidence=[ev])
    assert len(result.searches) <= MAX_SEARCH_QUERIES
    assert all(s.query == "<m@bad.example>" for s in result.searches)


def test_negative_query_does_not_prove_global_absence():
    negative = query("edr_events", "WS-1")
    proposed = analysis([Finding(statement="No hubo persistencia ni compromiso.", evidence_ids=[negative.raw["query_id"]])], summary="No hubo compromiso.")
    result = InvestigationAgent._sanitize_analysis(analysis=proposed, alert={}, context=ContextSnapshot(), evidence=[negative])
    assert not result.findings and result.verdict == "needs_more_info"
    assert "No hubo compromiso" not in result.summary


def test_discovered_entities_are_enriched_once(setup_service, monkeypatch):
    api, store, service = setup_service
    context = ContextSnapshot()
    looked_up = service.investigator._known_identifiers({}, context, [])
    evidence = [event("idp_signins", "SIGN-1", user_upn="beatriz.diaz@tarvia.example", src_ip="172.16.10.21"),
                event("idp_signins", "SIGN-2", user="TARVIA\\beatriz.diaz", src_ip="172.16.10.21")]
    users, assets = [], []
    original_user, original_asset = api.get_user, api.get_asset
    def get_user(key):
        users.append(key)
        return original_user(key)
    def get_asset(key):
        assets.append(key)
        return original_asset(key)
    monkeypatch.setattr(api, "get_user", get_user)
    monkeypatch.setattr(api, "get_asset", get_asset)
    alert = {"created_at": "2026-10-05T09:07:03Z", "source_product": "CLOUD"}
    assert service._enrich_discovered(alert, context, evidence, looked_up)
    assert not service._enrich_discovered(alert, context, evidence, looked_up)
    assert users == ["beatriz.diaz"] and assets == ["172.16.10.21"]
    assert context.assets[0]["hostname"] == "CI-RUNNER01" and len(context.users) == 1


@pytest.mark.parametrize("malicious", [False, True])
def test_confirmed_execution_requires_malicious_basis(malicious):
    ev = event("edr_events", "EDR-1", hostname="WS-1", event_type="process_start", process_name="tool.exe", sha256="a" * 64)
    intel = [IntelEntry(indicator="a" * 64, type="sha256", source="TIP", result='{"reputation":"malicious"}')] if malicious else []
    proposed = analysis([Finding(statement="Inicio de proceso observado.", evidence_ids=["EDR-1"])],
                        signals=signals(execution_or_access_confirmed=True, malicious_execution=True))
    result = InvestigationAgent._sanitize_analysis(analysis=proposed, alert={}, context=ContextSnapshot(), evidence=[ev], intel=intel)
    assert result.signals.execution_or_access_confirmed
    assert result.signals.malicious_execution is malicious


@pytest.mark.parametrize("suffix", ["000444", "000451", "000395", "000105", "000184"])
def test_five_real_alerts_through_orchestrator(setup_service, official_api, suffix):
    api, store, service = setup_service
    alert_id = "ALR-20261005-" + suffix
    alert = api.get_alert(alert_id)

    class ReplayLLM:
        def __init__(self):
            self.planning_calls = 0

        def generate_json(self, *, schema, prompt, **kwargs):
            if schema is SearchPlan:
                self.planning_calls += 1
                return SearchPlan(searches=[])
            refs = alert["related_events"][:1]
            findings = [Finding(statement={
                "000444": "SQLi bloqueada por WAF.", "000451": "Password spraying bloqueado por Smart Lockout.",
                "000395": "PowerShell iniciado por el agente SCCM.", "000105": "Correo phishing entregado.",
                "000184": "Política pública de bucket modificada mediante Terraform.",
            }[suffix], evidence_ids=refs)]
            actions = []
            if suffix == "000395":
                findings[0].evidence_ids.append("CHG-2026-1031")
                actions.append(ProposedAction(action="close_as_authorized", target="ticket", justification="Cerrar low por actividad autorizada."))
            if suffix == "000105":
                findings.append(Finding(statement="Beatriz hizo clic en el mensaje.", evidence_ids=refs))
                actions.append(ProposedAction(action="purge_email", target=alert["evidence"]["message_id"], justification="Phishing entregado."))
            if suffix == "000184":
                actions.extend(ProposedAction(action=name, target="bucket tarvia-media-public", justification=reason) for name, reason in [
                    ("verify_authorization", "Verificar autorización de política pública."), ("review_classification", "Revisar clasificación del contenido del bucket.")])
            return analysis(findings, verdict="benign_true_positive" if suffix == "000395" else "needs_more_info" if suffix == "000184" else "true_positive",
                            signals=signals(blocked_before_effect=suffix in {"000444", "000451"}, authorized_activity=suffix == "000395", execution_or_access_confirmed=suffix == "000395"), proposed_actions=actions)

    llm = ReplayLLM()
    service.investigator.llm = llm
    stages = []
    ticket = service.run(alert_id, on_event=stages.append)
    details = store.get(ticket.ticket_id)["details"]
    assert ticket.executed_actions == [] and llm.planning_calls <= 2
    searches = details["search_plan"]["searches"]
    assert len(searches) <= 10
    keys = [(s["source"], s["query"], s["start"], s["end"]) for s in searches]
    assert len(keys) == len(set(keys))
    if suffix == "000444":
        assert ticket.verdict == "true_positive" and ticket.severity == "medium"
        assert not details["analysis"]["signals"]["blocked_before_effect"]
    elif suffix == "000451":
        assert llm.planning_calls == 2
        assert ticket.verdict == "true_positive" and details["context"]["users"]
        assert all("cuentas)" not in str(u) for u in details["context"]["users"])
        assert details["analysis"]["signals"]["blocked_before_effect"]
    elif suffix == "000395":
        assert ticket.verdict == "needs_more_info" and ticket.severity == "high"
        assert any("ventana y alcance compatibles" in q for q in ticket.open_questions)
        assert all(a.action != "close_as_authorized" for a in ticket.recommended_actions)
        proxy = [Evidence.model_validate(e) for e in details["evidence"] if e["source"] == "proxy"]
        assert InvestigationAgent._summarize_evidence(proxy)["proxy"]["events_received"] == 9
    elif suffix == "000105":
        assert ticket.verdict == "true_positive" and "hizo clic" not in ticket.summary
        assert any(a.action == "purge_email" for a in ticket.recommended_actions)
    else:
        assert ticket.verdict == "needs_more_info" and not details["analysis"]["signals"]["personal_data_exposure"]
        assert any(a["hostname"] == "CI-RUNNER01" for a in details["context"]["assets"])
        assert {a.action for a in ticket.recommended_actions} >= {"verify_authorization", "review_classification"}


@pytest.mark.parametrize("expected_runbook", [f"RB-{i:02d}" for i in range(1, 11)])
def test_all_ten_runbooks_coherence_end_to_end(setup_service, official_api, expected_runbook):
    api, store, service = setup_service
    alert = next(a for a in official_api.ALERTS.values() if a["runbook"] == expected_runbook)
    alert_id = alert["alert_id"]

    class CoherentReplayLLM:
        def generate_json(self, *, schema, prompt, **kwargs):
            if schema is SearchPlan:
                return SearchPlan(searches=[])
            refs = alert["related_events"][:1]
            return analysis(
                [Finding(statement="Evidencia original verificada.", evidence_ids=refs)],
                verdict="true_positive",
                signals=signals(execution_or_access_confirmed=True),
            )

    service.investigator.llm = CoherentReplayLLM()
    ticket = service.run(alert_id)
    saved = store.get(ticket.ticket_id)
    assert saved is not None
    assert alert_id in ticket.alert_ids
    plan = service.runbooks.get_strategy(expected_runbook).build_plan(alert)
    assert plan.runbook_id == expected_runbook
    # Comprobar que la cobertura de runbook traduce comprobaciones a fuentes reales de cada estrategia
    checks = service.investigator.search_diagnostics["checks"]
    assert any(c.get("source") in plan.suggested_sources for c in checks)


def test_extended_signal_anchors_for_ad_pos_cicd_and_s3_crm():
    ad_ev = event("ad_events", "ADE-0000571", dc="DC01", event_code=4728, subject="adm_jgarcia", target="svc_backup_temp", details={"group": "Domain Admins"})
    ad_res = InvestigationAgent._sanitize_analysis(
        analysis=analysis([Finding(statement="Cambio en grupo privilegiado AD.", evidence_ids=["ADE-0000571"])],
                          signals=signals(execution_or_access_confirmed=True, persistence=True)),
        alert={}, context=ContextSnapshot(), evidence=[ad_ev],
    )
    assert ad_res.signals.execution_or_access_confirmed and ad_res.signals.persistence

    pos_ev = event("edr_events", "EDR-0123439", hostname="TPV-MAD04-02", event_type="process_access",
                   process_name="diag_helper.exe", details={"target_process": "TarviaPOS.exe", "access": "PROCESS_VM_READ"})
    pos_res = InvestigationAgent._sanitize_analysis(
        analysis=analysis([Finding(statement="Lectura de memoria sobre proceso TPV.", evidence_ids=["EDR-0123439"])],
                          signals=signals(malicious_execution=True, sensitive_or_payment_data=True)),
        alert={}, context=ContextSnapshot(), evidence=[pos_ev],
    )
    assert pos_res.signals.malicious_execution and pos_res.signals.sensitive_or_payment_data

    ci_ev = event("cicd_builds", "CI-0000602", runner="CI-RUNNER01", status="ok",
                  details={"command": "node scripts/postinstall.js", "env_accessed": ["AWS_SECRET_ACCESS_KEY", "NPM_TOKEN"]})
    ci_res = InvestigationAgent._sanitize_analysis(
        analysis=analysis([Finding(statement="Script postinstall accedió a secretos del runner.", evidence_ids=["CI-0000602"])],
                          signals=signals(malicious_execution=True, credentials_compromised=True)),
        alert={}, context=ContextSnapshot(), evidence=[ci_ev],
    )
    assert ci_res.signals.malicious_execution and ci_res.signals.credentials_compromised

    s3_ev = event("cloudtrail", "CT-0083606", eventName="GetObject", errorCode="",
                  requestParameters={"bucketName": "tarvia-db-backups", "key": "prod/CRM_PROD_20261005.bak.gz"})
    s3_res = InvestigationAgent._sanitize_analysis(
        analysis=analysis([Finding(statement="Descarga de backup CRM en S3.", evidence_ids=["CT-0083606"])],
                          signals=signals(sensitive_or_payment_data=True, personal_data_exposure=True)),
        alert={}, context=ContextSnapshot(), evidence=[s3_ev],
    )
    assert s3_res.signals.sensitive_or_payment_data and s3_res.signals.personal_data_exposure


def test_soc_api_client_rejects_html_or_invalid_catalog_json(monkeypatch):
    from unittest.mock import MagicMock
    from src.data.soc_api_client import SOCAPIClient

    client = SOCAPIClient("http://127.0.0.1:8501")
    html_resp = MagicMock()
    html_resp.status_code = 200
    html_resp.raise_for_status.return_value = None
    html_resp.json.side_effect = ValueError("Expecting value: line 1 column 1 (char 0)")

    monkeypatch.setattr(client.session, "get", lambda *a, **kw: html_resp)
    with pytest.raises(ConnectionError, match="Respuesta no JSON"):
        client.list_alerts()

    wrong_shape_resp = MagicMock()
    wrong_shape_resp.status_code = 200
    wrong_shape_resp.raise_for_status.return_value = None
    wrong_shape_resp.json.return_value = {"status": "ok"}

    monkeypatch.setattr(client.session, "get", lambda *a, **kw: wrong_shape_resp)
    with pytest.raises(ConnectionError, match="Respuesta de catálogo inválida"):
        client.list_alerts()
    client.close()


def test_ensure_local_soc_api_corrects_streamlit_port_collision_and_discovers_fallback(monkeypatch):
    import src.data.soc_api_client as soc_mod
    import src.interficie.dashboard as dash_mod

    soc_mod._LOCAL_API_STATE.clear()
    monkeypatch.setattr(soc_mod, "is_soc_api_healthy", lambda url, timeout=1.5: url == "http://127.0.0.1:8001")
    monkeypatch.setattr(dash_mod, "_is_soc_api_healthy", lambda url, timeout=1.5: url == "http://127.0.0.1:8001")

    assert soc_mod.ensure_local_soc_api("http://test-soc", auto_start=False) == "http://test-soc"
    assert dash_mod.ensure_local_soc_api("http://test-soc", auto_start=False) == "http://test-soc"

    # Si SOC_API_URL apunta por error al puerto 8501 de Streamlit, redirige a la API SOC sana (8000/8001)
    assert soc_mod.ensure_local_soc_api("http://127.0.0.1:8501", avoid_port=8501, auto_start=False) == "http://127.0.0.1:8001"
    assert dash_mod.ensure_local_soc_api("http://127.0.0.1:8501", avoid_port=8501, auto_start=False) == "http://127.0.0.1:8001"

    monkeypatch.setattr(soc_mod, "is_soc_api_healthy", lambda url, timeout=1.5: False)
    monkeypatch.setattr(dash_mod, "_is_soc_api_healthy", lambda url, timeout=1.5: False)
    assert soc_mod.ensure_local_soc_api("http://127.0.0.1:8501", avoid_port=8501, auto_start=False) == "http://127.0.0.1:8000"
    assert dash_mod.ensure_local_soc_api("http://127.0.0.1:8501", avoid_port=8501, auto_start=False) == "http://127.0.0.1:8000"

