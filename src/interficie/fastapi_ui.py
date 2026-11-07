import streamlit as st
import requests
import json

API_URL = "http://127.0.0.1:8000"    

st.set_page_config(page_title="Ticket UI", layout="centered")

st.title("🎫 Ticket Manager")

with st.expander("Crear nuevo ticket (JSON)"):
    json_input = st.text_area(
        "Ticket JSON (ej: {\"alert_id\": \"A1\", \"severity\": \"high\", \"description\": \"...\"})",
        height=200,
    )
    if st.button("Crear ticket"):
        if not json_input.strip():
            st.error("Introduce el JSON del ticket")
        else:
            try:
                payload = json.loads(json_input)       
                r = requests.post(f"{API_URL}/process", json=payload)
                r.raise_for_status()
                ticket = r.json()
                st.success("✅ Ticket creado")
                st.json(ticket)                           
            except json.JSONDecodeError as jde:
                st.error(f"JSON inválido: {jde}")
            except Exception as e:
                st.error(f"Error al crear el ticket: {e}")

st.markdown("---")
st.subheader("📋 Tickets recientes")

limit = st.slider("Cuántos tickets mostrar", min_value=5, max_value=50, value=25)

if st.button("Refrescar lista"):
    try:
        r = requests.get(f"{API_URL}/tickets", params={"limit": limit})
        r.raise_for_status()
        tickets = r.json()
        if tickets:
            for t in tickets:
                st.markdown(
                    f"""
                    **ID:** `{t["id"]}`  
                    **Alert ID:** `{t["alert_id"]}`  
                    **Estado:** `{t["status"]}`  
                    **Creado:** `{t["created_at"]}`  
                    **Detalles:**  
                    ```json
                    {json.dumps(t["details"], ensure_ascii=False, indent=2)}
                    ```
                    """
                )
                st.divider()
        else:
            st.info("No hay tickets todavía.")
    except Exception as e:
        st.error(f"Error al obtener la lista: {e}")