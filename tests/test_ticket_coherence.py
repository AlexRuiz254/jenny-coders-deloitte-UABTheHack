"""Regresiones acotadas de coherencia; no sustituyen la evaluación con IA real."""
from test_investigation_regressions import analysis, event, query, signals
from test_level1_integration import official_api, transport, setup_service  # noqa: F401
from src.triage.decision.action_recommender import ActionRecommender
from src.triage.decision.verdict_engine import VerdictEngine
from src.triage.decision.severity_calculator import SeverityCalculator
from src.triage.investigation.investigation_agent import InvestigationAgent
from src.triage.models import ContextSnapshot, Finding, ProposedAction, SeverityDecision, VerdictDecision


def waf_case():
    alert = {"alert_id": "ALR-test", "created_at": "2026-10-05T06:04:00Z", "source_product": "WAF",
             "rule_id": "UC-WEB-001", "runbook": "RB-05", "severity": "low",
             "entities": {"ips": ["198.18.12.7"]}, "evidence": {"rule_id": "913100"},
             "related_events": ["WAF-test"]}
    ev = event("waf", "WAF-test", src_ip="198.18.12.7", uri="/wp-login.php", rule_id="913100",
               rule_msg="Scanner Detection", user_agent="Nuclei", action="blocked", status=403)
    return alert, ev


def test_waf_verdict_checks_activity_instead_of_control_outcome():
    alert, ev = waf_case()
    proposed = analysis([Finding(statement="Escaneo real de WordPress bloqueado.", evidence_ids=[ev.event_id])], verdict="false_positive")
    engine = VerdictEngine()
    assert engine.decide(proposed, [ev], ContextSnapshot(), alert=alert).verdict == "needs_more_info"
    proposed.verdict = "true_positive"
    assert engine.decide(proposed, [ev], ContextSnapshot(), alert=alert).verdict == "true_positive"
    alert["evidence"]["rule_id"] = "942100"
    assert engine.decide(proposed, [ev], ContextSnapshot(), alert=alert).verdict == "needs_more_info"


def test_genuine_waf_false_positive_remains_possible():
    alert, ev = waf_case()
    ev.raw.update(uri="/buscar?q=vestidos", rule_msg="SQL Injection", rule_id="942100", user_agent="Mozilla")
    alert["evidence"]["rule_id"] = "942100"
    proposed = analysis([Finding(statement="Búsqueda legítima de vestidos; firma incorrecta.", evidence_ids=[ev.event_id])], verdict="false_positive")
    assert VerdictEngine().decide(proposed, [ev], ContextSnapshot(), alert=alert).verdict == "false_positive"


def test_title_is_complete_and_observed_block_survives_rejected_absence():
    alert, ev = waf_case()
    proposed = analysis([Finding(statement="WAF bloqueado sin actividad posterior ni compromiso.", evidence_ids=[ev.event_id])],
                        title="Escaneo " * 30, summary="Sin compromiso ni acceso al backend.")
    normalized = InvestigationAgent._sanitize_analysis(analysis=proposed, alert=alert, evidence=[ev], context=ContextSnapshot())
    assert normalized.title == "Escaneo de WordPress bloqueado por WAF"
    assert len(normalized.title) <= 140
    assert normalized.findings and "bloqueó" in normalized.findings[0].statement
    assert "Sin compromiso" not in normalized.summary
    assert InvestigationAgent._claim_issues("Sin servir respuesta al backend.", support=set(), cited=[ev], evidence=[ev])
    assert InvestigationAgent._claim_issues("Las alertas relacionadas son el mismo ataque.", support=set(), cited=[query("waf", ev.raw["src_ip"])], evidence=[ev])
    assert InvestigationAgent._claim_issues("Escaneo SQLi bloqueado.", support=set(), cited=[ev], evidence=[ev])


def test_questions_match_query_results_and_do_not_penalize_by_count():
    complete = query("waf", "198.18.12.7", count=0)
    questions = InvestigationAgent._reconcile_questions(
        ["Las consultas están truncadas.", "¿Revisar el alcance?", "¿Revisar el alcance?"], [complete])
    assert questions == ["¿Revisar el alcance?"]
    alert, ev = waf_case()
    proposed = analysis([Finding(statement="Escaneo bloqueado.", evidence_ids=[ev.event_id])], open_questions=questions)
    decision = VerdictEngine().decide(proposed, [ev], ContextSnapshot(), alert=alert)
    assert decision.confidence == proposed.confidence
    scoped = [query("waf", "198.18.12.7"), query("dns", "other.example", truncated=True)]
    assert "El WAF está truncado" not in InvestigationAgent._reconcile_questions(["El WAF está truncado"], scoped)


def test_unrelated_truncation_does_not_cancel_verified_block(setup_service, monkeypatch):
    api, store, service = setup_service
    alert_id = "ALR-20261005-000451"
    alert = api.get_alert(alert_id)
    blocked = event("idp_signins", alert["related_events"][0], src_ip=alert["entities"]["ips"][0],
                    result="failure", failure_reason="blocked_by_smart_lockout")
    evidence = [blocked, query("idp_signins", blocked.raw["src_ip"]), query("dns", "other.example", truncated=True, count=2000)]
    proposed = analysis([Finding(statement="Password spraying bloqueado por Smart Lockout.", evidence_ids=[blocked.event_id])],
                        signals=signals(blocked_before_effect=True))
    normalized = InvestigationAgent._sanitize_analysis(analysis=proposed, alert=alert, evidence=evidence, context=ContextSnapshot())
    assert normalized.signals.blocked_before_effect
    monkeypatch.setattr(service.investigator, "analyze", lambda **kwargs: normalized)
    monkeypatch.setattr(service.evidence, "collect_related_events", lambda alert: evidence)
    ticket = service.run(alert_id)
    assert store.get(ticket.ticket_id)["details"]["analysis"]["signals"]["blocked_before_effect"]


def test_closure_depends_on_verdict_and_relevant_coverage():
    alert, ev = waf_case()
    proposed = analysis([Finding(statement="Escaneo bloqueado.", evidence_ids=[ev.event_id])], proposed_actions=[
        ProposedAction(action="close_ticket", target="ticket", justification="Sin explotación exitosa ni acceso al backend."),
        ProposedAction(action="review_route", target="ticket", justification="Revisar la ruta."),
    ])
    recommender = ActionRecommender()
    severity = SeverityDecision(severity="medium", rationale="Matriz low/crítica")
    def recommend(verdict, evidence):
        return recommender.recommend(proposed, ContextSnapshot(), verdict=VerdictDecision(verdict=verdict, confidence=.8, rationale="Prueba"),
                                     severity=severity, alert=alert, evidence=evidence)
    assert [a.action for a in recommend("true_positive", [ev])] == ["review_route"]
    actions = recommend("true_positive", [ev, query("waf", ev.raw["src_ip"])])
    assert actions[0].action == "close_ticket" and "ausencia global" in actions[0].justification
    assert "Sin explotación exitosa" not in actions[0].justification
    assert [a.action for a in recommend("needs_more_info", [ev])] == ["review_route"]


def test_identity_persistence_requires_suspicious_configuration():
    ev = event("idp_audit", "AUD-test", actor_upn="a@tarvia.example", operation="New-InboxRule",
               src_ip="198.18.200.10", details={"conditions": {"from_contains": "jira@"}, "actions": {"move_to_folder": "Jira"}})
    proposed = analysis([Finding(statement="Persistencia mediante regla de buzón no autorizada.", evidence_ids=[ev.event_id])],
                        title="Persistencia de buzón", summary="Persistencia confirmada.", signals=signals(persistence=True),
                        proposed_actions=[ProposedAction(action="block_ioc", target="198.18.200.10", justification="Regla de buzón no autorizada.")])
    normalized = InvestigationAgent._sanitize_analysis(analysis=proposed, alert={}, evidence=[ev], context=ContextSnapshot())
    assert not normalized.signals.persistence and not normalized.proposed_actions
    ev.raw["details"] = {"conditions": {"body_or_subject_contains": ["factura", "IBAN"]},
                         "actions": {"move_to_folder": "RSS Feeds", "mark_as_read": True}}
    support = InvestigationAgent._claim_support(alert={}, events=[ev], evidence=[ev], context=ContextSnapshot(), findings=[])
    assert "persistence" in support
    assert SeverityCalculator._get_criticality({"source_product": "IDP"}, ContextSnapshot(
        services=[{"servicio": "Identidad y directorio activo", "criticidad": "Crítica"}])) == "critical"


def test_manual_review_preserves_multiple_known_resources():
    result = InvestigationAgent._sanitize_proposed_actions([
        ProposedAction(action="verify_change", target="CI-RUNNER01 / bucket tarvia-media-public", justification="Verificar aprobación.")],
        manual_targets={"ci-runner01", "tarvia-media-public"})
    assert len(result) == 1 and result[0].target == "ci-runner01, tarvia-media-public"
    cloud_alert = {"rule_id": "UC-CLD-003", "entities": {"cloud": {"bucket": "media.example"}}}
    cloud_analysis = analysis([Finding(statement="Política pública observada.", evidence_ids=["CT-test"])])
    decision = VerdictEngine().decide(cloud_analysis, [event("cloudtrail", "CT-test", eventName="PutBucketPolicy", errorCode="")],
                                     ContextSnapshot(), alert=cloud_alert)
    assert decision.verdict == "needs_more_info"
    actions = ActionRecommender().recommend(cloud_analysis, ContextSnapshot(), verdict=decision,
        severity=SeverityDecision(severity="high", rationale="Provisional"), alert=cloud_alert)
    assert len(actions) == 1 and actions[0].action == "verify_cloud_change"
    assert "personal_data_exposure" not in InvestigationAgent._asserted_claims("La exposición de datos personales queda sin demostrar.")


def test_saved_identity_regression_does_not_disable_account_and_resolves_aggregate_users():
    import json
    from pathlib import Path
    from src.triage.models import Analysis, ContextSnapshot, Evidence, Escalation
    from src.triage.output.ticket_builder import TicketBuilder
    root = Path(__file__).resolve().parents[1]
    record = json.loads((root / "reports/soc_validation_20261108/iteration_3/ALR-20261005-000272.record.json").read_text(encoding="utf-8"))
    data = record["details"]
    proposed = Analysis.model_validate(data["analysis"])
    context = ContextSnapshot.model_validate(data["context"])
    evidence = [Evidence.model_validate(item) for item in data["evidence"]]
    verdict = VerdictDecision.model_validate(data["verdict"])
    severity = SeverityDecision(severity=data["ticket"]["severity"], rationale="Matriz del resultado guardado")
    actions = ActionRecommender().recommend(proposed, context, verdict=verdict, severity=severity,
                                           alert=data["alert"], evidence=evidence)
    assert not any(item.action == "disable_user" for item in actions)
    ticket = TicketBuilder().build(alert=data["alert"], related_alerts=[], context=context, analysis=proposed,
        verdict=verdict, severity=severity, escalation=Escalation(escalate=True), actions=actions,
        evidence=evidence, intel=[], triage_seconds=0)
    assert len(ticket.affected["users"]) == 12
    assert all("@tarvia.example" in name for name in ticket.affected["users"])


def test_waf_cloud_presentation_claims_require_source_specific_support():
    alert, ev = waf_case()
    for text in ("Sin salida exitosa al backend.", "Escaneo coordinado desde 22 orígenes."):
        assert InvestigationAgent._claim_issues(text, support=set(), cited=[ev], evidence=[ev])
    cloud = event("cloudtrail", "CT-test", eventName="GetObject", errorCode="")
    cloud.timestamp = "2026-10-06T08:54:31Z"
    ci = event("cicd_builds", "CI-test", status="ok")
    ci.timestamp = "2026-10-06T09:01:00Z"
    assert InvestigationAgent._claim_issues("CloudTrail registra actividad hasta las 09:01 UTC.",
                                           support=set(), cited=[cloud], evidence=[cloud, ci])
    assert "authorized_activity" in InvestigationAgent._asserted_claims("Bucket público desde runner CI autorizado.")
