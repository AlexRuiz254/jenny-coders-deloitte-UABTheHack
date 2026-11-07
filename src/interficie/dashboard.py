"""Panel SOC N1: presentación del orquestador y de los resultados persistidos."""
import json
import logging
import os
from pathlib import Path
import sys

# Streamlit ejecuta este fichero como script, también desde otro directorio.
PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from dotenv import load_dotenv
import streamlit as st

from src.data.reference_repository import ReferenceRepository
from src.data.soc_api_client import SOCAPIClient
from src.data.ticket_repository import TicketRepository
from src.triage.ingestion.imports import import_records
from src.triage.models import Ticket
from src.triage.output.validation import validate_ticket
from src.triage.triage_orchestrator import create_orchestrator

logger = logging.getLogger(__name__)
SEVERITIES = ["informational", "low", "medium", "high", "critical"]
VERDICTS = ["true_positive", "benign_true_positive", "false_positive", "needs_more_info"]
REVIEWS = {"close": "Confirmar cierre", "reject_close": "Rechazar cierre",
           "escalate": "Escalar a N2", "continue_investigation": "Continuar investigación"}
STAGES = {
    "get_alert": "Recuperar alerta", "extract_entities": "Identificar entidades",
    "extract_indicators": "Identificar indicadores", "load_runbook": "Consultar runbook",
    "get_strategy": "Seleccionar procedimiento", "build_plan": "Preparar comprobaciones",
    "enrich_context": "Consultar activos, usuarios y cambios",
    "enrich_intel": "Consultar TIP, GeoIP y sandbox",
    "collect_related_events": "Recuperar eventos de la alerta",
    "find_related_alerts": "Correlacionar alertas en ±24 h",
    "plan_searches": "Planificar búsquedas con IA", "search_evidence": "Consultar logs",
    "analyze": "Analizar evidencias con IA", "decide_verdict": "Validar veredicto",
    "calculate_severity": "Aplicar matriz de severidad", "decide_escalation": "Determinar escalado",
    "recommend_actions": "Revisar recomendaciones y permisos", "build_ticket": "Construir ticket",
    "validate_ticket": "Validar esquema oficial", "save_ticket": "Guardar ticket",
    "completed": "Ticket guardado", "already_processed": "Ticket existente recuperado",
}


@st.cache_data(ttl=300, show_spinner="Consultando catálogo de alertas…")
def load_alert_index(api_url: str) -> list[dict]:
    """Índice compacto compartido; la API original solo permite filtrar regla/fecha/estado.

    Consultar una vez por cinco minutos permite filtros globales y cifras exactas,
    sin descargar 11.061 alertas en cada interacción ni cachear todos sus logs.
    """
    api = SOCAPIClient(api_url)
    rows, offset = [], 0
    try:
        while True:
            page = api.list_alerts(limit=500, offset=offset)
            for alert in page["items"]:
                rows.append({key: alert.get(key, "") for key in (
                    "alert_id", "created_at", "rule_id", "rule_name", "severity", "status", "source_product")})
            offset += len(page["items"])
            if offset >= page["total"]:
                return rows
            if not page["items"]:
                raise RuntimeError("La API devolvió un catálogo incompleto. Actualiza para reintentar.")
    finally:
        api.close()


def render_progress(events: list[dict]) -> None:
    lines = []
    for event in events[-60:]:
        if event.get("status") == "started":
            continue
        label = STAGES.get(event["stage"], event["stage"])
        marker = "✕" if event.get("status") == "failed" else "✓"
        extra = f" · {event['count']} resultados" if "count" in event else ""
        if event.get("truncated"):
            extra += " · Consulta incompleta: límite de la API"
        lines.append(f"{marker} {event['alert_id']} · {label}{extra}")
    st.text("\n".join(lines) if lines else "Preparando investigación…")


def process_selection(alert_ids, api, store, service=None, *, reprocess=False) -> None:
    results, events = [], []
    progress = st.progress(0, text=f"0 de {len(alert_ids)} alertas completadas")
    with st.status("Investigando alertas…", expanded=True) as status:
        current = st.empty()
        history = st.empty()

        def on_event(event):
            events.append(event)
            current.write(STAGES.get(event["stage"], event["stage"]))
            with history.container():
                render_progress(events)

        try:
            service = service or create_orchestrator(api, store)
        except Exception as exc:
            message = str(exc).split("\n", 1)[0][:300]
            logger.error("No se pudo iniciar el investigador (%s)", type(exc).__name__)
            for alert_id in alert_ids:
                store.record_attempt(alert_id, "failed", "configuration", [], message)
                results.append({"Alerta": alert_id, "Resultado": "Fallida", "Ticket": "", "Detalle": message})
            status.update(label="No se pudo iniciar la investigación", state="error")
        else:
            for index, alert_id in enumerate(alert_ids):
                try:
                    ticket = service.run(alert_id, on_event=on_event, reprocess=reprocess)
                    results.append({"Alerta": alert_id, "Resultado": "Completada", "Ticket": ticket.ticket_id, "Detalle": "Guardado"})
                    st.session_state["ticket_id"] = ticket.ticket_id
                except Exception as exc:
                    logger.error("No se pudo investigar %s (%s)", alert_id, type(exc).__name__)
                    results.append({"Alerta": alert_id, "Resultado": "Fallida", "Ticket": "",
                                    "Detalle": str(exc).split("\n", 1)[0][:300]})
                progress.progress((index + 1) / len(alert_ids), text=f"{index + 1} de {len(alert_ids)} alertas finalizadas")
            failures = sum(row["Resultado"] == "Fallida" for row in results)
            status.update(label=f"{len(results) - failures} completadas · {failures} fallidas",
                          state="error" if failures else "complete")
    st.session_state["batch_results"] = results
    st.session_state["progress_events"] = events
    st.rerun()


def render_queue(api, store, index, service=None) -> None:
    st.subheader("Alertas pendientes")
    processed = store.processed_alert_ids()
    failures = {row["alert_id"]: row for row in store.list_attempts()}
    pending = [a for a in index if a["alert_id"] not in processed]
    c1, c2, c3, c4 = st.columns(4)
    search = c1.text_input("Buscar ID de alerta", key="queue_search")
    severity = c2.selectbox("Severidad original", ["Todas", *SEVERITIES])
    category = c3.selectbox("Producto", ["Todos", *sorted({a["source_product"] for a in pending})])
    state = c4.selectbox("Estado del triaje", ["Todos", "Pendiente", "Fallida"])
    c1, c2, c3 = st.columns(3)
    rule = c1.text_input("Regla (ID o nombre)")
    source = c2.selectbox("Fuente", ["Todas", "API Deloitte", "Importada"])
    order = c3.selectbox("Orden", ["Más antiguas", "Más recientes", "Severidad"])
    filtered = [a for a in pending if (not search or search.casefold() in a["alert_id"].casefold())
                and (severity == "Todas" or a["severity"] == severity)
                and (category == "Todos" or a["source_product"] == category)
                and (not rule or rule.casefold() in (a["rule_id"] + a["rule_name"]).casefold())
                and (source == "Todas" or a["source"] == source)
                and (state == "Todos" or (a["alert_id"] in failures) == (state == "Fallida"))]
    filtered.sort(key=lambda a: SEVERITIES.index(a["severity"]) if order == "Severidad" else a["created_at"],
                  reverse=order != "Más antiguas")
    c1, c2 = st.columns(2)
    size = c1.selectbox("Alertas por página", [25, 50, 100], index=1)
    pages = max(1, (len(filtered) + size - 1) // size)
    page = c2.number_input("Página de alertas", min_value=1, max_value=pages, value=1, step=1)
    visible = filtered[(page - 1) * size:page * size]
    st.caption(f"{len(filtered)} pendientes coinciden con los filtros · Página {page} de {pages}")
    st.dataframe([{"ID alerta": a["alert_id"], "Fecha UTC": a["created_at"], "Regla": a["rule_name"],
                   "ID regla": a["rule_id"], "Severidad": a["severity"],
                   "Estado": "Fallida" if a["alert_id"] in failures else "Pendiente",
                   "Fuente": a["source"]} for a in visible], hide_index=True, use_container_width=True)
    options = [a["alert_id"] for a in visible]
    if st.button("Seleccionar las primeras diez", disabled=not options):
        st.session_state["queue_selection"] = options[:10]
    st.session_state["queue_selection"] = [a for a in st.session_state.get("queue_selection", []) if a in options]
    selected = st.multiselect("Seleccionar alertas para investigar", options, key="queue_selection")
    st.caption(f"{len(selected)} alertas seleccionadas. El procesamiento es secuencial y cada ticket se guarda por separado.")
    if st.button("Investigar selección", type="primary", disabled=not selected):
        process_selection(selected, api, store, service)
    if failures:
        with st.expander("Procesamientos fallidos y reintentos"):
            st.dataframe([{k: row[k] for k in ("alert_id", "stage", "error", "updated_at")} for row in failures.values()],
                         hide_index=True, use_container_width=True)
            st.caption("Selecciona de nuevo la alerta fallida para reintentar. Los tickets anteriores se conservan.")


def render_ticket(ticket: Ticket, details=None, trace=None) -> None:
    details = details or {}
    st.subheader(ticket.title)
    st.caption(f"{ticket.ticket_id} · Alertas: {', '.join(ticket.alert_ids)}")
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Veredicto validado", ticket.verdict)
    c2.metric("Confianza", f"{ticket.confidence:.0%}")
    c3.metric("Severidad final", ticket.severity)
    c4.metric("Escalado recomendado", "Sí" if ticket.escalation.escalate else "No")
    st.write(ticket.summary)
    st.markdown("**Decisiones y motivos**")
    st.write(ticket.severity_rationale or "Sin justificación de severidad registrada.")
    if details.get("verdict"):
        st.write(details["verdict"]["rationale"])
    st.write(f"Destinatario: {ticket.escalation.to or 'N1'}")
    st.write(ticket.escalation.reason or "Sin motivo de escalado registrado.")
    with st.expander("Investigación y evidencias", expanded=True):
        st.caption("Las referencias permiten contrastar los hallazgos. Las señales son afirmaciones de la IA pendientes de revisión humana.")
        st.dataframe([e.model_dump(exclude_none=True) for e in ticket.evidence], hide_index=True, use_container_width=True)
        if details.get("analysis"):
            st.markdown("**Hallazgos de la investigación**")
            for finding in details["analysis"]["findings"]:
                st.write(f"{finding['statement']} · Referencias: {', '.join(finding['evidence_ids']) or 'Sin soporte verificable'}")
            with st.expander("Señales propuestas por la IA"):
                st.json(details["analysis"]["signals"])
        st.write(f"Runbook: {details.get('runbook_id', 'No disponible en el ticket importado')}")
        if details.get("runbook_text"):
            with st.expander("Procedimiento aplicado"):
                st.markdown(details["runbook_text"])
        related = details.get("related_alerts", [])
        st.write(f"Alertas potencialmente relacionadas: {len(related)}")
        if related:
            st.dataframe([{k: a.get(k) for k in ("alert_id", "created_at", "rule_id")} for a in related], hide_index=True)
            st.caption("Compartir una entidad no demuestra que pertenezcan a la misma intrusión.")
        if ticket.enrichment:
            st.markdown("**Inteligencia consultada**")
            st.dataframe([e.model_dump() for e in ticket.enrichment], hide_index=True, use_container_width=True)
        if details.get("context"):
            with st.expander("Contexto recuperado de activos, usuarios y cambios"):
                st.json(details["context"])
        if details.get("evidence"):
            with st.expander("Registros originales y límites de consulta"):
                st.json(details["evidence"])
    st.markdown("**Preguntas pendientes e incertidumbres**")
    for question in ticket.open_questions:
        st.warning(question)
    if not ticket.open_questions:
        st.caption("No se registraron preguntas pendientes.")
    st.markdown("**Respuesta recomendada**")
    st.dataframe([a.model_dump(exclude_none=True) for a in ticket.recommended_actions], hide_index=True, use_container_width=True)
    st.caption("El nivel 1 registra recomendaciones y decisiones humanas. Ninguna acción de contención se ejecuta desde este panel.")
    with st.expander("Trazabilidad: etapas y consultas"):
        if trace:
            st.dataframe(trace, hide_index=True, use_container_width=True)
        else:
            st.info("El ticket importado no incluye historial de investigación.")
        if details.get("search_plan"):
            st.json(details["search_plan"])
    payload = ticket.model_dump(mode="json", exclude_none=True)
    validate_ticket(payload)
    st.download_button("Descargar ticket JSON oficial", json.dumps(payload, ensure_ascii=False, indent=2),
                       file_name=f"{ticket.ticket_id}.json", mime="application/json")
    with st.expander("JSON del ticket final"):
        st.json(payload)


def render_human_review(ticket, store, record=None) -> None:
    record = record or store.get(ticket.ticket_id)
    review = record["review"]
    st.subheader("Revisión humana")
    st.write(f"Recomendación: {'escalar a ' + (ticket.escalation.to or 'N2') if ticket.escalation.escalate else 'mantener en N1; valorar cierre según las evidencias' }.")
    if review["decision"]:
        st.success(f"Decisión guardada: {REVIEWS.get(review['decision'], review['decision'])} · {review['timestamp'] or 'fecha no disponible'}")
        st.write(review["note"] or "Sin observaciones.")
    with st.form(f"review_{ticket.ticket_id}"):
        decisions = list(REVIEWS)
        decision = st.selectbox("Decisión del analista", decisions, format_func=REVIEWS.get,
                                index=decisions.index(review["decision"]) if review["decision"] in decisions else 3)
        note = st.text_area("Observaciones del analista", value=review["note"] or "")
        if st.form_submit_button("Guardar revisión humana"):
            store.save_review(ticket.ticket_id, decision, note)
            st.rerun()


def render_processed(store, api, service=None) -> None:
    st.subheader("Alertas procesadas / Tickets")
    c1, c2, c3, c4 = st.columns(4)
    search = c1.text_input("Buscar alerta o ticket")
    verdict = c2.selectbox("Veredicto", ["Todos", *VERDICTS])
    severity = c3.selectbox("Severidad final", ["Todas", *SEVERITIES])
    escalation = c4.selectbox("Escalado", ["Todos", "Sí", "No"])
    review = st.selectbox("Revisión humana", ["Todas", "Pendiente", *REVIEWS.values()])
    review_value = "pending" if review == "Pendiente" else next((k for k, v in REVIEWS.items() if v == review), "")
    page = st.number_input("Página de tickets", min_value=1, value=1, step=1)
    records = store.list_recent(limit=50, offset=(page - 1) * 50, search=search,
                                verdict="" if verdict == "Todos" else verdict,
                                severity="" if severity == "Todas" else severity,
                                escalation=None if escalation == "Todos" else escalation == "Sí", review=review_value)
    st.dataframe([{"Alerta": ', '.join(r["details"]["ticket"]["alert_ids"]), "Ticket": r["id"], "Procesado UTC": r["created_at"],
                   "Veredicto": r["details"]["ticket"]["verdict"], "Confianza": r["details"]["ticket"]["confidence"],
                   "Severidad": r["details"]["ticket"]["severity"], "Escalar": r["details"]["ticket"]["escalation"]["escalate"],
                   "Revisión": REVIEWS.get(r["review"]["decision"], "Pendiente"),
                   "Origen": r["details"].get("source", "Anterior")} for r in records], hide_index=True, use_container_width=True)
    ids = [r["id"] for r in records]
    selected = st.multiselect("Tickets para exportar", ids)
    if selected:
        tickets = [validate_ticket(r["details"]["ticket"]).model_dump(mode="json", exclude_none=True)
                   for r in records if r["id"] in selected]
        st.download_button("Descargar selección JSON", json.dumps(tickets, ensure_ascii=False, indent=2),
                           file_name="tickets_soc.json", mime="application/json")
    current_id = st.session_state.get("ticket_id")
    choices = ids
    if not choices:
        st.info("No hay tickets que coincidan. Puedes investigar alertas o importar tickets válidos.")
        return
    ticket_id = st.selectbox("Abrir detalle y revisión", choices,
                             index=choices.index(current_id) if current_id in choices else 0)
    record = store.get(ticket_id)
    ticket = validate_ticket(record["details"]["ticket"])
    render_ticket(ticket, record["details"], record["trace"])
    render_human_review(ticket, store, record)
    with st.expander("Reprocesar explícitamente"):
        st.caption("Crea un ticket nuevo y conserva el resultado y la revisión anteriores.")
        confirmed = st.checkbox("Crear una nueva investigación conservando la anterior")
        if st.button("Reprocesar alerta", disabled=not confirmed):
            process_selection([record["alert_id"]], api, store, service, reprocess=True)


def render_import(api, store) -> None:
    st.subheader("Importar")
    kind = st.radio("Contenido del archivo", ["Alertas pendientes", "Tickets procesados"])
    st.caption("Alertas: formato original Deloitte, status=new. Tickets: esquema oficial. Se admiten objeto JSON, lista JSON y JSONL.")
    upload = st.file_uploader("Archivo JSON o JSONL", type=["json", "jsonl"])
    if st.button("Validar e importar", disabled=upload is None, type="primary"):
        result = import_records(upload.getvalue(), kind="alerts" if kind == "Alertas pendientes" else "tickets",
                                jsonl=upload.name.lower().endswith(".jsonl"), store=store, api=api,
                                references=ReferenceRepository(PROJECT_ROOT / "RepositoriDeloitte"))
        st.session_state["import_result"] = result
        st.rerun()
    if "import_result" in st.session_state:
        result = st.session_state["import_result"]
        st.success(f"{result['imported']} importadas · {result['duplicates']} duplicadas · {result['rejected']} rechazadas")
        for error in result["errors"][:30]:
            st.error(error)


def render_dashboard(api, service, store) -> None:
    st.title("Tarvia · Centro de triaje SOC")
    st.caption("Nivel 1 asistido por IA · Evidencias verificables · Decisión humana")
    view = st.sidebar.radio("Navegación", ["Alertas pendientes", "Tickets e investigación", "Importar"], key="navigation")
    if st.sidebar.button("Actualizar catálogo de alertas"):
        load_alert_index.clear()
        st.rerun()
    st.sidebar.caption("Catálogo de alertas en caché durante 5 minutos. Puedes actualizarlo manualmente.")
    complete = True
    try:
        index = [{**a, "source": "API Deloitte"} for a in load_alert_index(api.base_url)]
    except Exception:
        logger.warning("No se pudo consultar el catálogo de la API SOC")
        st.warning("API SOC no disponible. Inicia la API o actualiza para reintentar. Puedes consultar tickets y revisiones guardados; las cifras de pendientes solo incluyen importaciones locales.")
        index, complete = [], False
    index.extend({**a, "source": "Importada"} for a in store.list_imported_alerts())
    # IDs únicos: la importación ya impide duplicados, también proteger la vista.
    index = list({a["alert_id"]: a for a in index}.values())
    processed = store.processed_alert_ids()
    stats = store.stats()
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Alertas pendientes" if complete else "Pendientes locales", sum(a["alert_id"] not in processed for a in index))
    c2.metric("Alertas con ticket", stats["processed"])
    c3.metric("Tickets sin revisión", stats["pending_review"])
    c4.metric("Tickets high / critical", stats["high_critical"])
    if stats["legacy"]:
        with st.expander(f"{stats['legacy']} registros anteriores conservados sin ticket oficial"):
            st.caption("Se conservan para consulta. No cuentan como alertas procesadas ni como tickets validados.")
            legacy = [r for r in store.list_recent(limit=500, include_legacy=True) if not r["details"].get("ticket")]
            st.json(legacy)
    if "batch_results" in st.session_state:
        with st.expander("Resultado del último lote", expanded=True):
            rows = st.session_state["batch_results"]
            success = sum(r["Resultado"] == "Completada" for r in rows)
            st.write(f"{len(rows)} seleccionadas · {success} completadas · {len(rows) - success} fallidas")
            st.dataframe(rows, hide_index=True, use_container_width=True)
            st.button("Abrir último ticket generado", disabled=not st.session_state.get("ticket_id"),
                      on_click=lambda: st.session_state.update(navigation="Tickets e investigación"))
            with st.expander("Progreso registrado"):
                render_progress(st.session_state.get("progress_events", []))
    if view == "Alertas pendientes":
        render_queue(api, store, index, service)
    elif view == "Tickets e investigación":
        render_processed(store, api, service)
    else:
        render_import(api, store)


def main() -> None:
    load_dotenv(PROJECT_ROOT / ".env")
    st.set_page_config(page_title="Tarvia SOC · Triaje N1", page_icon="🛡️", layout="wide")
    log_path = PROJECT_ROOT / "logs"
    log_path.mkdir(exist_ok=True)
    logging.basicConfig(level=logging.INFO, handlers=[logging.FileHandler(log_path / "soc.log", encoding="utf-8")])
    try:
        store = TicketRepository(os.getenv("SOC_DB_PATH") or None)
        api = SOCAPIClient(os.getenv("SOC_API_URL") or "http://127.0.0.1:8000", store=store)
        try:
            render_dashboard(api, None, store)
        finally:
            api.close()
    except Exception as exc:
        logger.error("Error en el panel (%s)", type(exc).__name__)
        st.error("No se pudo completar la operación. Revisa la configuración o el acceso a SQLite y vuelve a intentarlo.")
        if st.button("Reintentar"):
            st.rerun()


if __name__ == "__main__":
    main()
