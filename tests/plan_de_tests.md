# Plan de pruebas (pendiente de implementación)

- Las 44 reglas del catálogo llevan a un runbook existente y estrategia asignada.
- Se pueden consultar las 18 fuentes de logs mediante nombres correctos.
- `related_events` encuentra fuentes/IDs exactos.
- Cada estrategia produce las comprobaciones particulares del runbook.
- Se consultan activos, roles, RRHH, cambios, servicios y zonas, sin inventar contexto.
- Se detecta `truncated` y las búsquedas incompletas no prueban ausencia de actividad.
- La correlación N1 busca ±24h y no agrupa únicamente por IP compartida.
- El LLM ignora instrucciones maliciosas contenidas en registros.
- `Analysis.findings` referencia eventos reales (comprobar IDs).
- 25 combinaciones de matriz de severidad y límite ±1.
- Escalado obligatorio para ejecución maliciosa, persistencia, fuga y fraude.
- El flujo N1 no llama a endpoints de contención.
- `Ticket.model_validate()` acepta el resultado y contiene 10 campos obligatorios.
- Streamlit muestra la traza y exige una acción humana para marcar cierre/escalado.
- Procesar 10 alertas nuevas sin respuestas hardcodeadas.
