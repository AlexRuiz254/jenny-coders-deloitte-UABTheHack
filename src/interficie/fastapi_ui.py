import streamlit as st
import requests
import json

st.set_page_config(page_title="Triage – FastAPI UI", layout="centered")
st.title("🛠️ Triage – UI vía FastAPI")
st.caption("Pega aquí el JSON de la alerta y pulsa **Procesar**")

alert_json = st.text_area("JSON de la alerta", height=200)

if st.button("🚀 Procesar"):
    if not alert_json.strip():
        st.error("❗ Debes pegar el JSON de la alerta.")
    else:
        try:
            data = json.loads(alert_json)        # validar JSON
            resp = requests.post(
                "http://127.0.0.1:8000/process",
                json=data,
                timeout=10
            )
            resp.raise_for_status()
            ticket = resp.json()
            st.success("✅ Ticket creado")
            st.json(ticket)
        except json.JSONDecodeError as e:
            st.error(f"❌ JSON inválido: {e}")
        except requests.RequestException as e:
            st.exception(e)