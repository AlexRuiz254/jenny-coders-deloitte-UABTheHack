"""Vistas N2–N4 del dashboard. Las operaciones pertenecen a ProductServices."""
from __future__ import annotations

import json
import os
from pathlib import Path
from urllib.parse import urlsplit

import streamlit as st

from src.orchestrator.product_services import ProductServices, demo_reviewers
from src.triage.level4.response_planner import report_fingerprint

STAGES = {
    "load_n1": "Recuperando investigación N1 guardada", "group_incidents": "Buscando relaciones verificables",
    "decide_incident": "Validando veredicto, severidad y escalado del incidente",
    "save_incident": "Guardando incidente y referencias N1", "load_incident": "Recuperando antecedentes N1 y N2",
    "expand_investigation": "Ampliando búsquedas por entidades y ventana temporal",
    "reconstruct_attack": "Ordenando eventos y reconstruyendo relaciones",
    "assess_scope": "Evaluando alcance e impacto con evidencias",
    "build_report": "Construyendo informe de incidente", "report_validated": "Esquema oficial validado",
    "report_saved": "Informe guardado y disponible para respuesta N4",
}
STATUS = {"pending": "Pendiente", "approved": "Aprobada", "rejected": "Rechazada",
          "executing": "En ejecución / pendiente de conciliación", "succeeded": "Ejecutada", "failed": "Fallida / revisar"}


@st.cache_resource(show_spinner=False)
def _services(api_url, n1_path, n2_path, response_path, dataset_root, demo_mode):
    # Los tokens permanecen en el servidor entre reruns; nunca en session_state.
    return ProductServices(api_url=api_url, n1_path=n1_path, n2_path=n2_path,
                           response_path=response_path, dataset_root=dataset_root, demo_mode=demo_mode)


def product_services(api, store):
    root = Path(__file__).resolve().parents[2]
    n1_path = Path(store.db_path).resolve()

    def path(name, default):
        value = Path(os.getenv(name) or n1_path.parent / default)
        return str(value if value.is_absolute() else root / value)

    return _services(api.base_url, str(n1_path), path("SOC_N2_DB_PATH", "tickets_n2.sqlite3"),
                     path("SOC_RESPONSE_DB_PATH", "soc_response.sqlite3"), str(root / "RepositoriDeloitte"),
                     os.getenv("SOC_DEMO_MODE", "false").casefold() in {"true", "1", "yes"})


def _navigate(view, incident_id=None):
    st.session_state["navigation"] = view
    if incident_id:
        st.session_state["workflow_incident"] = incident_id


def _error(exc, *, response=False):
    if response and not isinstance(exc, (ValueError, PermissionError, LookupError)):
        st.error(f"La operación de respuesta no se completó ({type(exc).__name__}). Consulta la auditoría; una ejecución de resultado incierto requiere conciliación manual.")
    else:
        st.error(f"{type(exc).__name__}: {str(exc).splitlines()[0][:350]}")


def _run(label, operation):
    with st.status(label, expanded=True) as status:
        line = st.empty()
        def progress(event):
            text = STAGES.get(event["stage"], event["stage"])
            line.write(text + (f" · {event['alert_id']}" if event.get("alert_id") else ""))
        try:
            result = operation(progress)
        except Exception as exc:
            status.update(label="Operación incompleta; consulta los registros guardados", state="error")
            _error(exc)
            return None
        status.update(label="Resultado validado y guardado", state="complete")
        return result


def _incident_picker(records, label, key):
    ids = [record["id"] for record in records]
    current = st.session_state.get("workflow_incident")
    if not ids:
        st.info("Todavía no hay incidentes N2. Selecciona investigaciones guardadas en Incidentes · N2.")
        return None
    names = {record["id"]: record["details"]["ticket"]["title"] for record in records}
    return st.selectbox(label, ids, index=ids.index(current) if current in ids else 0,
                        format_func=lambda value: f"{value} · {names[value]}", key=key)


def render_level2(product):
    from src.interficie.dashboard import render_ticket
    st.subheader("Incidentes · N2")
    st.write("Selecciona investigaciones N1 guardadas. El sistema explica cada relación y mantiene separados los grupos sin vínculo suficiente.")
    records = product.n1.list_recent(limit=500)
    latest = {}
    for record in records:
        data = record["details"]
        if all(data.get(field) is not None for field in ("analysis", "context", "evidence", "alert")):
            latest.setdefault(data["alert"]["alert_id"], record)
    names = {key: f"{key} · {record['details']['ticket']['title']}" for key, record in latest.items()}
    with st.expander("Investigaciones N1 disponibles", expanded=not bool(product.n2.stats()["tickets"])):
        st.caption("Se utiliza la última versión completa de cada alerta. Los tickets importados sin investigación deben completarse en N1.")
        selected = st.multiselect("Alertas N1 para correlacionar", list(latest), format_func=names.get, key="n2_selection")
        window = st.selectbox("Ventana máxima de agrupación (horas)", [24, 48, 168], key="n2_window")
        if st.button("Correlacionar y guardar incidentes", type="primary", disabled=not selected):
            result = _run("Correlacionando investigaciones…", lambda progress:
                          product.correlate(selected, window_hours=window, on_event=progress))
            if result:
                st.session_state["n2_result"] = [ticket.ticket_id for ticket in result]
                st.session_state["workflow_incident"] = result[0].ticket_id
                st.success(f"{len(result)} grupos guardados. Los tickets N1 originales se conservan.")
    search = st.text_input("Buscar incidente o alerta N2", key="n2_search")
    incidents = product.n2.list_recent(limit=100, search=search)
    st.dataframe([{"Incidente": r["id"], "Alertas": ", ".join(r["details"]["ticket"]["alert_ids"]),
                   "Severidad": r["details"]["ticket"]["severity"], "Veredicto": r["details"]["ticket"]["verdict"],
                   "Escalar": r["details"]["ticket"]["escalation"]["escalate"]} for r in incidents],
                 hide_index=True, width="stretch")
    key = _incident_picker(incidents, "Abrir incidente consolidado", "n2_incident")
    if key:
        from src.triage.output.validation import validate_ticket
        record = product.n2.get(key)
        st.markdown("**Por qué se agrupan**")
        st.write(record["details"].get("group_justification"))
        st.caption("Tickets N1 originales: " + ", ".join(record["details"]["source_ticket_ids"]))
        render_ticket(validate_ticket(record["details"]["ticket"]), record["details"], record["trace"])
        st.button("Continuar a investigación N3", on_click=_navigate, args=("Investigación · N3", key))


def _reference_summary(references, limit=10):
    values = [f"{r.source}/{r.event_id}" for r in references]
    return ", ".join(values[:limit]) + (f" … ({len(values)} referencias; todas en el JSON)" if len(values) > limit else "")


def _paged_notes(label, notes, key):
    if not notes:
        st.caption("Sin elementos registrados.")
        return
    pages = (len(notes) + 24) // 25
    page = st.number_input(f"Página de {label}", min_value=1, max_value=pages, value=1, step=1, key=key)
    st.caption(f"{len(notes)} elementos · Página {page} de {pages} · Contenido completo en el JSON.")
    st.dataframe({label: notes[(page - 1) * 25:page * 25]}, hide_index=True, width="stretch")


def render_report(report):
    st.subheader(report.title)
    st.caption(f"{report.incident_id} · {len(report.alert_ids)} alertas · {len(report.evidence)} evidencias · Resultado persistido")
    st.write(report.summary)
    st.markdown("**Origen y reconstrucción**")
    for name, value in (("Paciente cero", report.patient_zero), ("Acceso inicial", report.initial_access), ("Causa raíz", report.root_cause)):
        st.write(f"**{name}:** {value}")
    st.caption("Ventana consultada: " + " → ".join(report.investigation_window.values()))
    st.markdown("**Cronología con referencias**")
    search = st.text_input("Filtrar cronología por evento, fuente o descripción", key="n3_timeline_search")
    rows = [{"Fecha UTC": item.timestamp, "Evento": item.event_id, "Descripción": item.description,
             "Estado": item.status, "Referencias": ", ".join(f"{r.source}/{r.event_id}" for r in item.evidence),
             "MITRE": item.mitre or ""} for item in report.timeline]
    if search:
        rows = [row for row in rows if search.casefold() in str(row).casefold()]
    pages = max(1, (len(rows) + 99) // 100)
    page = st.number_input("Página de cronología", min_value=1, max_value=pages, value=1, step=1)
    st.caption(f"{len(rows)} eventos coinciden · Página {page} de {pages} · La descarga conserva la cronología completa.")
    st.dataframe(rows[(page - 1) * 100:page * 100], hide_index=True, width="stretch")
    st.markdown("**Alcance e impacto**")
    scope = report.scope_analysis
    st.dataframe([{"Tipo": label, "Entidad": item.statement, "Estado": item.status,
                   "Evidencias": _reference_summary(item.evidence)}
                  for label, items in (("Equipo", scope.hosts), ("Usuario", scope.users), ("Servicio", scope.services))
                  for item in items], hide_index=True, width="stretch")
    st.write("**Datos:** " + report.scope.data)
    st.write("**Negocio:** " + report.scope.business_impact)
    with st.expander("Búsquedas, fuentes y límites", expanded=False):
        st.write("Fuentes: " + ", ".join(report.consulted_sources))
        st.dataframe(report.searches, hide_index=True, width="stretch")
        _paged_notes("limitaciones", report.limitations, "n3_limits_page")
    with st.expander("Propuestas, recuperación y notificaciones"):
        st.dataframe([item.model_dump(mode="json", exclude={"evidence"}) for item in report.containment_plan],
                     hide_index=True, width="stretch")
        for line in [*report.eradication_and_recovery, *report.notifications]:
            st.write(line)
    with st.expander("Preguntas pendientes"):
        _paged_notes("preguntas pendientes", report.open_questions, "n3_questions_page")
    st.download_button("Descargar informe N3 JSON oficial",
                       lambda: report.model_dump_json(indent=2, exclude_none=True),
                       file_name=f"{report.incident_id}.n3.json", mime="application/json", on_click="ignore")
    with st.expander("Informe completo y procedencia"):
        if st.checkbox("Mostrar JSON completo del informe (puede ser grande)"):
            st.json(report.to_dict(), expanded=False)


def render_level3(product):
    st.subheader("Investigación · N3")
    records = product.n2.list_recent(limit=100)
    key = _incident_picker(records, "Incidente N2 para investigar", "n3_incident")
    if not key:
        return
    previous = product.responses.load_report(key)
    if previous:
        st.info("Ya existe un informe guardado. Consultarlo o cambiar de sección no vuelve a investigar.")
    with st.expander("Iniciar o ampliar investigación", expanded=previous is None):
        with st.form(f"n3_investigation_{key}"):
            c1, c2 = st.columns(2)
            before = c1.number_input("Días anteriores", min_value=0, max_value=21, value=7)
            after = c2.number_input("Días posteriores", min_value=0, max_value=7, value=2)
            st.caption("Consultas por entidades observadas; máximo 31 días, 48 búsquedas y 2.000 eventos adicionales. Los límites y truncamientos quedan en el informe.")
            ticket = product.n2.get(key)["details"]["ticket"]
            reason = st.text_input("Motivo del analista para investigar un caso no escalado") if not ticket["escalation"]["escalate"] else ""
            new_version = st.checkbox("Crear otra versión conservando los informes anteriores", key="n3_new_version") if previous else False
            submitted = st.form_submit_button("Investigar y guardar informe N3", type="primary")
        if submitted and previous and not new_version:
            st.error("Confirma que deseas crear otra versión; el informe anterior se conserva.")
        elif submitted:
            report = _run("Investigando incidente…", lambda progress: product.investigate(
                key, before_days=before, after_days=after, new_version=new_version,
                analyst_reason=reason, on_event=progress))
            if report:
                previous = report
    versions = product.responses.list_reports(incident_id=key)
    if versions:
        digest = st.selectbox("Versión del informe guardado", [r["digest"] for r in versions],
                              format_func=lambda d: d[:12] + (" · actual" if next(r["current"] for r in versions if r["digest"] == d) else " · histórica"))
        render_report(product.responses.load_report(key, digest=digest))
        st.button("Abrir respuesta N4", on_click=_navigate, args=("Respuesta · N4", key))


def render_level4(product):
    st.subheader("Respuesta · N4")
    if product.demo_mode:
        st.warning("MODO DEMOSTRACIÓN · Identidades simuladas, sin autenticación humana real. Las decisiones de ensayo y las acciones solo afectan a la API SOC local simulada.")
    else:
        st.info("Solo planificación. Las aprobaciones requieren autenticación real o activar SOC_DEMO_MODE para un ensayo con identidades simuladas.")
    reports = [row for row in product.responses.list_reports() if row["current"]]
    ids = [row["incident_id"] for row in reports]
    if not ids:
        st.info("Genera y guarda un informe N3 antes de preparar la respuesta.")
        return
    current = st.session_state.get("workflow_incident")
    key = st.selectbox("Informe N3 para respuesta", ids, index=ids.index(current) if current in ids else 0)
    report = product.responses.load_report(key)
    st.write(report.title)
    if st.button("Preparar plan de respuesta", type="primary"):
        try:
            with st.spinner("Contrastando objetivos y permisos con la política SOC…"):
                proposals = product.level4.prepare(key)
            st.success(f"{len(proposals)} propuestas guardadas; ninguna acción se ha ejecutado.")
        except Exception as exc:
            _error(exc, response=True)
    states = product.responses.list_states(incident_id=key)
    if not states:
        st.info("Prepara el plan. Si N3 no acredita objetivos para contención, revisa sus limitaciones y amplía la investigación.")
        return
    st.dataframe([{"Propuesta": s.proposal.proposal_id, "Acción": s.proposal.action or "Coordinación manual",
                   "Objetivo": s.proposal.target, "Estado": STATUS[s.status],
                   "Aprobadores": ", ".join(s.proposal.required_approvals)} for s in states], hide_index=True, width="stretch")
    proposal_id = st.selectbox("Abrir propuesta", [s.proposal.proposal_id for s in states],
        format_func=lambda value: next(f"{s.proposal.action or 'Manual'} · {s.proposal.target} · {s.proposal.proposal_id[-8:]} · N3 {s.proposal.report_digest[:8]}" for s in states if s.proposal.proposal_id == value),
        key=f"n4_proposal_{key}")
    state = product.level4.get_state(proposal_id)
    proposal = state.proposal
    if st.session_state.pop("n4_reset_confirmation", None) == proposal_id:
        st.session_state[f"decision_confirm_{proposal_id}"] = False
        st.session_state[f"execute_{proposal_id}"] = False
    st.write("**Estado:** " + STATUS[state.status])
    st.write("**Justificación:** " + proposal.justification)
    st.write("**Impacto operativo:** " + proposal.operational_impact)
    st.write("**Aprobaciones exigidas:** " + ", ".join(proposal.required_approvals))
    st.caption("Referencias N3: " + _reference_summary(proposal.evidence))
    for risk in proposal.risks:
        st.warning(risk)
    stale = proposal.report_digest != report_fingerprint(report)
    if stale:
        st.warning("Esta propuesta pertenece a una versión anterior del informe. Prepara y revisa el plan del informe actual.")
    if state.approval:
        st.write(f"Roles recibidos: {', '.join(state.approval.approved_roles) or 'ninguno'}")
        if state.approval.expires_at:
            st.caption("Vigencia de autorización UTC: " + state.approval.expires_at.isoformat())
    if product.demo_mode and proposal.executable and state.status in {"pending", "approved"} and not stale:
        with st.form(f"decision_{proposal_id}"):
            reviewers = demo_reviewers(proposal)
            actor = st.selectbox("Identidad de ensayo", list(reviewers), format_func=reviewers.get)
            reason = st.text_area("Motivo de la decisión")
            confirmed = st.checkbox("Confirmo esta decisión de ensayo para la acción y el objetivo mostrados",
                                    key=f"decision_confirm_{proposal_id}")
            c1, c2 = st.columns(2)
            approve = c1.form_submit_button("Aprobar propuesta", disabled=state.status == "approved")
            reject = c2.form_submit_button("Rechazar propuesta")
            restart = st.form_submit_button("Renovar solicitud y repetir aprobaciones", disabled=state.status != "approved")
            if approve or reject or restart:
                if not confirmed or not reason.strip():
                    st.error("Confirma la decisión e indica su motivo.")
                else:
                    try:
                        product.decide(proposal_id, actor=actor, approved=approve, reason=reason, restart=restart)
                        st.session_state["n4_reset_confirmation"] = proposal_id
                        st.rerun()
                    except Exception as exc:
                        _error(exc, response=True)
        st.caption("Tras reiniciar el servidor o caducar la autorización, renueva la solicitud y repite todos los votos. Un rechazo no puede reabrirse.")
    can_execute = product.demo_mode and proposal.executable and state.status == "approved" and not stale
    confirmed = st.checkbox("Confirmo ejecutar esta acción en la API SOC simulada", key=f"execute_{proposal_id}", disabled=not can_execute)
    if st.button("Ejecutar acción autorizada", type="primary", disabled=not can_execute or not confirmed):
        try:
            product.level4.execute_approved(proposal_id)
            st.rerun()
        except Exception as exc:
            _error(exc, response=True)
    if state.status != "approved":
        st.caption("Ejecución bloqueada: " + STATUS[state.status] + ".")
    if state.result:
        st.success("La API simulada confirmó la ejecución." if state.result.success else "La ejecución requiere revisión.")
        st.json(state.result.model_dump(mode="json"))
    if state.last_error:
        st.warning(state.last_error)
    with st.expander("Auditoría de esta propuesta", expanded=True):
        st.dataframe(state.history, hide_index=True, width="stretch")
        st.download_button("Descargar auditoría sin tokens", state.model_dump_json(indent=2),
                           file_name=proposal_id + ".audit.json", mime="application/json")
    with st.expander("Historial de contención de la API simulada"):
        if st.button("Consultar historial de la API"):
            try:
                # La API oficial guarda tokens: solo presentar campos públicos.
                response = product.api.session.get(product.api.base_url + "/containment/log", timeout=30, allow_redirects=False)
                response.raise_for_status()
                fields = {"timestamp", "action", "target", "ticket_id", "result", "justification"}
                st.dataframe([{k: v for k, v in row.items() if k in fields} for row in response.json()], hide_index=True, width="stretch")
            except Exception as exc:
                _error(exc, response=True)


def render_configuration(product):
    st.subheader("Configuración y estado")
    st.write("**API SOC:** " + product.api.base_url)
    st.write("**Proveedor IA:** " + (urlsplit(os.getenv("ORNITH_API_URL", "https://api.ornith.cc/v1")).hostname or "sin configurar"))
    st.write("**Modelo:** " + os.getenv("ORNITH_MODEL", "uncensored"))
    st.write("**Clave configurada:** " + ("Sí" if os.getenv("ORNITH_API_KEY") else "No"))
    st.caption("La presencia de una clave no garantiza disponibilidad. Una investigación N1 verifica la conexión real.")
    st.write("**Modo de respuesta:** " + ("Demostración con identidades simuladas" if product.demo_mode else "Planificación, sin autenticación real"))
    st.write("**Persistencia N1:** " + str(product.n1.db_path))
    st.write("**Persistencia N2:** " + str(product.n2.db_path))
    st.write("**Informes, respuesta y aprobaciones:** " + str(product.responses.db_path))
    with st.expander("Operaciones N2 / N3 y estados parciales", expanded=True):
        for operation in product.responses.list_operations():
            st.write(f"{operation['level']} · {operation['status']} · {operation['started_at']} · {operation['target']}")
            if operation.get("error_type"):
                st.warning("Fallo: " + operation["error_type"] + ". Los resultados guardados en etapas anteriores se conservan.")
            st.caption(" → ".join(STAGES.get(e["stage"], e["stage"]) for e in operation["events"]))
