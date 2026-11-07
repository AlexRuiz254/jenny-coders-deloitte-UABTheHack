# Integración y validación del nivel 1 · 8 de noviembre de 2026

## Resultado de la integración

Streamlit utiliza el orquestador real y los motores SOC existentes. La aplicación
conecta selección de alerta, contexto, inteligencia interna, runbook, logs,
correlación, planificación/análisis IA, validación del veredicto, severidad,
escalado, recomendaciones, ticket oficial, SQLite y revisión humana.

La prueba automatizada completa ha dado **191 passed in 15.37s**. Los tres casos
de veredicto y el lote automatizado usan un LLM simulado exclusivamente en tests.
La prueba con IA real se documenta en la sección de comprobación manual; no debe
confundirse con esos resultados automatizados.

## Qué se comprobó antes de modificar

Se revisaron el README oficial, las diez diapositivas del reto, política SOC,
esquema y ticket de ejemplo, los diez runbooks, catálogo, inventarios, cambios,
alertas de desarrollo y API simulada. También se revisaron arranque, interfaz,
orquestador, ambos repositorios, modelos, investigador, colector, correlador y
motores de decisión. Los modelos y los cuatro motores de decisión ya funcionaban
y se han conservado; tampoco se ha reescrito TicketBuilder.

Problemas confirmados en el código anterior:

- Cinco vistas Streamlit sin implementar y referencias a una estructura de paquete anterior.
- `store.add(...)` no existía en ninguno de los repositorios.
- Dos almacenes SQLite con ubicaciones y columnas de revisión diferentes.
- La API auxiliar y el wrapper creaban registros básicos sin investigación ni ticket oficial.
- El arranque dependía de una ruta absoluta de otro ordenador.
- `status=""` devolvía cero alertas: el endpoint oficial compara estados exactamente.
- El investigador eliminaba referencias CHG/FLUJO válidas antes de que llegaran al veredicto.
- El contexto interpretaba como UTC las fechas locales del calendario.
- Las búsquedas adicionales podían omitir la ventana temporal o salirse de ella.
- La prueba con IA real reveló consultas `src_ip:...` incompatibles con la búsqueda
  literal de la API; se corrigen el contrato del prompt y los selectores simples.
- El colector ya conservaba metadatos de truncamiento, pero faltaba comunicarlos al usuario.

Las 11.061 alertas originales tienen `status=new`; no se ha supuesto un filtro
vacío ni se han modificado sus estados para marcar el procesamiento local.

## Archivos modificados y motivo

| Archivo | Motivo |
|---|---|
| `src/triage/triage_orchestrator.py` | Guardado correcto, cableado común, estados, progreso, errores, lote, reintentos/versiones, ventanas y trazabilidad. |
| `src/data/ticket_repository.py` | Implementación única SQLite, migración sin pérdidas, deduplicación, consultas, revisiones y dos tablas auxiliares necesarias. |
| `src/interficie/repository.py` | Reexportar el repositorio único, conservando el import público anterior. |
| `src/data/soc_api_client.py` | Consultar también alertas importadas, manteniendo los endpoints y límites oficiales. |
| `src/interficie/dashboard.py` | Panel completo conectado al orquestador y repositorio. |
| `src/interficie/fastapi_ui.py` | Redirigir la entrada anterior al panel principal. |
| `src/interficie/api.py` | Servir la API SOC oficial desde la entrada ASGI anterior; eliminar `/process` ficticio. |
| `src/orchestrator/orchestrator_wrapper.py` | Sustituir el flujo de tickets básicos/JSONL por el mismo orquestador real. |
| `src/triage/ingestion/imports.py` | Validar e importar JSON/JSONL, informar errores y evitar duplicados. |
| `src/triage/output/validation.py` | Validación conjunta del esquema oficial y Pydantic antes de persistir/exportar. |
| `src/triage/time_windows.py` | Conversión UTC común y ventana N1 de ±24 h. |
| `src/triage/investigation/context_enricher.py` | Interpretar el calendario en Europe/Madrid. |
| `src/triage/investigation/alert_correlator.py` | Usar el estado real que admite la API original. |
| `src/triage/investigation/evidence_collector.py` | Acotar también la recuperación de eventos referenciados a la ventana N1. |
| `src/triage/investigation/investigation_agent.py` | Conservar autorizaciones, alinear consultas con la API literal y aclarar ataque bloqueado/ausencia de resultados. |
| `system_src/investigation_system_prompt.md` | Alinear referencias CHG/FLUJO y zona horaria con el calendario y el veredicto. |
| `src/triage/llm.py` | Espera y razonamiento configurables, validaciones y diagnóstico útil para modelo/endpoint no encontrado. |
| `run_server.py` | Iniciar la API oficial desde cualquier directorio, con puerto configurable. |
| `.streamlit/config.toml` | Sustituir una opción inexistente del watcher y limitar el servidor a localhost. |
| `.env.example` | Documentar configuración sin credenciales. |
| `requirements.txt` | Declarar jsonschema y tzdata, necesarias para el contrato oficial y las zonas en Windows. |
| `README.md` | Arranque real, configuración, puertos alternativos, vistas, persistencia y pruebas. |
| `.gitignore` | Excluir temporales y salidas locales de las pruebas. |
| `tests/test_level1_integration.py` | Pruebas integradas, fallos, migración y widgets Streamlit reales. |
| `tests/test_llm_client.py` | Conservar pruebas existentes y añadir validación del tiempo y parámetro de razonamiento opcional. |
| `tests/validacion_nivel1.md` | Registrar alcance, cambios, pruebas, evidencia y límites. |

La configuración local `.env` también se ajustó conservando las credenciales:
el gateway existente publica `ornith` en `GET /models`, mientras que se había
seleccionado `uncensored`. Se configuró la espera del gateway compartido a 600 s.
Después se verificó `ORNITH_REASONING_EFFORT=none`: una petición JSON mínima pasó
de 21,5 s con razonamiento a 0,7 s sin él. La opción se deja explícita en `.env`;
no se envía a otros proveedores cuando no se configura.
Ese archivo está excluido de Git.

No hay modificaciones en `RepositoriDeloitte`, ni en `models.py`, `VerdictEngine`,
`SeverityCalculator`, `EscalationEngine`, `ActionRecommender` o `TicketBuilder`.

## Comandos ejecutados y resultados automatizados

La batería original dio **163 passed in 1.25s** antes de modificar código al
usar una carpeta temporal escribible dentro del proyecto. El primer intento sin
esa configuración encontró restricciones de permisos de temporales de Windows;
no se detectaron fallos funcionales preexistentes en las pruebas originales.

```powershell
.\.venv\Scripts\python.exe -m pytest -q --basetemp=.test-tmp-baseline --tb=short
```

Las veinte pruebas de integración/interfaz forman parte de la batería final.
También pueden ejecutarse por separado:

```powershell
New-Item -ItemType Directory -Force .test-temp | Out-Null
$env:TEMP = (Resolve-Path .test-temp).Path
$env:TMP = $env:TEMP
.\.venv\Scripts\python.exe -m pytest tests/test_level1_integration.py -q --basetemp=.test-pytest-integration --tb=short
```

La batería completa, incluidos los cinco casos de espera, tres de configuración
de razonamiento y la regresión de consultas literales contra la API oficial:

```powershell
.\.venv\Scripts\python.exe -m pytest -q --basetemp=.test-pytest-release --tb=short
# 191 passed in 15.37s
.\.venv\Scripts\python.exe -m compileall -q src run_server.py
git diff --check
```

Compilación y comprobación del diff sin errores. Git muestra avisos sobre la
conversión de saltos de línea LF/CRLF del entorno Windows.
También se importaron todos los módulos Python de `src` correctamente.
Tras asegurar el cierre explícito de conexiones SQLite se repitió además la
prueba de migración de ambos formatos: **1 passed in 0.69s**.

| Caso requerido | Comprobación ejecutada |
|---|---|
| Alerta maliciosa | Datos/endpoints oficiales, análisis simulado, true_positive, severidad high/critical, escalado y ticket validado/guardado. |
| Actividad autorizada | SCCM real del dataset, horario Madrid, referencia EDR + CHG-2026-1031, benign_true_positive, severidad low y autorización exportada como evidencia de cambios. |
| Información insuficiente | needs_more_info con preguntas pendientes y sin evidencias inventadas. |
| Persistencia | Reabrir otro repositorio SQLite y recuperar el mismo ticket. |
| Revisión humana | Guardar decisión/observaciones y recuperarlas; repetir también desde widgets Streamlit y otra sesión. |
| Importación | JSONL válido/inválido, repetidos del archivo y de la API, triaje de alerta local, ticket oficial importado y rechazo de confianza con tipo incorrecto. |
| Diez alertas | Nueve éxitos y un fallo controlado; reintento del lote con diez resultados persistidos y sin duplicar los anteriores. |
| Fallos | API, respuesta LLM, constructor y guardado fallidos: sin ticket, evento de error, intento persistido y reintento correcto. También ausencia de credenciales. |
| Contrato | Validación JSON Schema y Pydantic al generar, importar, almacenar y descargar; serialización sin opcionales nulos. |
| Integración adicional | Correlación real, límites/truncamiento, ventanas por defecto y acotadas, calendario Madrid, paginación API + importaciones. |
| Datos anteriores | Migración de ambos formatos SQLite con decisiones y notas conservadas; registros básicos separados de los tickets oficiales. |
| Interfaz | Streamlit AppTest ejecuta filtros, selección, investigación, detalle, revisión, reinicio de sesión, importador y consulta de tickets sin API. |

El transporte automatizado invoca las funciones del `mock_soc_api.py` original
sobre los datos reales del repositorio, sin modificarlo. No sustituye la prueba
HTTP/manual ni evalúa por sí solo la calidad de los veredictos del modelo real.

## Comprobación manual HTTP, navegador e IA

Se arrancaron la API oficial y Streamlit. Los puertos 8000/8501 ya estaban
ocupados por servicios anteriores y se conservaron intactos. Se utilizaron:

```powershell
.\.venv\Scripts\python.exe run_server.py --port 8001
$env:SOC_API_URL = 'http://127.0.0.1:8001'
.\.venv\Scripts\python.exe -m streamlit run src/interficie/dashboard.py --server.port 8502 --server.headless true
```

El navegador abrió `http://127.0.0.1:8502`, mostró las 11.061 alertas y los dos
registros básicos antiguos conservados. Se verificaron búsqueda por ID, selección,
avance real de consultas y registro de fallos sin ticket. La carga de la muestra
oficial en el importador dio **0 importadas, 150 duplicadas, 0 rechazadas**.

Se autorizó expresamente la llamada real sobre `ALR-20261005-000172`. La primera
falló con 404 por el modelo incorrecto; las siguientes superaron las esperas de
30 y 120 s. Se comprobó la opción de razonamiento del gateway, se configuró y
se completó el flujo real. La revisión del primer ticket detectó la sintaxis
de consulta incorrecta y una clasificación false_positive inadecuada para un
ataque bloqueado. Se rechazó su cierre con una nota explícita de prueba técnica.

Tras corregir el contrato de búsqueda y las instrucciones, se utilizó
**Reprocesar explícitamente** desde el navegador. Resultado real de la versión final:

- Ticket `TRIAGE-2d653f8d-5f25-46c0-bee8-f4f26e42e791`.
- Alerta `ALR-20261005-000172`; ejecución total de **32,7 segundos**.
- Veredicto `true_positive`, confianza `0.80`, severidad `informational`, sin escalado.
- Cuatro consultas adicionales con valores literales y **24 eventos WAF recuperados**.
- Justificación, recomendaciones, preguntas pendientes y ausencia de contención ejecutada.
- **1 completada, 0 fallidas**; la alerta dejó de aparecer como pendiente (11.060 restantes).

La severidad de esta alerta es provisional: la alerta identifica la IP externa y
la URL, pero no el activo de destino en la CMDB. El motor conserva la severidad
de regla como base, aplica el ajuste y explica que falta criticidad; no se ha
inventado una asociación con un servidor concreto.

Se descargó el JSON desde el botón del navegador y se validó nuevamente frente
al esquema y Pydantic. Su contenido coincide exactamente con SQLite. Archivo
local: `D:/Downloads/TRIAGE-2d653f8d-5f25-46c0-bee8-f4f26e42e791.json`.
Al cargarlo en el importador de tickets, el navegador mostró **0 importadas,
1 duplicadas, 0 rechazadas**, sin crear otro registro.

Se reinició realmente Streamlit y se recuperó el primer ticket con su decisión
`reject_close` y observaciones. El reprocesamiento mantuvo esa revisión: ahora
existen dos versiones de una alerta y los dos registros básicos originales.
La versión final queda pendiente de revisión del analista del equipo.
No se ha sustituido el LLM de producción por un simulador.

## Cobertura y límites de Deloitte

| Requisito N1 de esta integración | Implementación/verificación |
|---|---|
| Obtener y seleccionar alertas | Catálogo completo cacheado y filtros/paginación; importaciones locales. |
| Consultar logs | Eventos exactos y búsquedas IA por API, en ±24 h. |
| Contexto de activos, usuarios y autorizaciones | CMDB, directorio/RRHH, servicios, red y calendario; faltas explícitas. |
| Runbooks | Registro y diez estrategias existentes, cubiertos por las pruebas originales. |
| Investigar con IA | Cliente real conectado a planificación y análisis; fallos visibles/reintentables. La disponibilidad real depende del gateway. |
| Hallazgos y referencias | IDs recuperados de logs y cambios, datos originales visibles y preguntas pendientes. |
| Veredicto | Motor existente sobre Analysis validado. |
| Severidad | Matriz y ajustes existentes, sin reescritura. |
| Escalado | Motor y motivos/SLA existentes, visibles en el ticket. |
| Recomendaciones y permisos | Motor existente, aprobación/restricciones visibles, ninguna ejecución automática. |
| Ticket oficial | JSON Schema + Pydantic antes de persistir o exportar. |
| Demo visual | Cola, progreso, ticket, evidencia, incertidumbre y revisión humana. |
| Decisión humana | Cierre, rechazo, escalado o continuar, con notas persistidas. |
| Resultados duraderos | SQLite único y lectura tras reinicio. |
| Lotes | Secuenciales, resumen por alerta y conservación de éxitos ante fallos. |

El enunciado describe cuatro niveles: el nivel 1 exige triaje por alerta y demo
visual; agrupar automáticamente incidentes corresponde al nivel 2, reconstruir
cadenas de varias semanas al nivel 3 y ejecutar contención al nivel 4. La política
SOC sí pide correlación N1 en ±24 h y se mantiene. El esquema es opcional para el
reto original, pero obligatorio para esta entrega por solicitud del equipo.

Límites conservados y comunicados:

- Las alertas correlacionadas son candidatas. No se agrupan automáticamente por
  compartir una entidad ni se afirma que formen una intrusión confirmada.
- El veredicto comprueba trazabilidad, coherencia y ventana general del cambio;
  el alcance libre de la autorización sigue dependiendo del análisis y la revisión humana.
- Las señales de política son afirmaciones de la IA, no hechos demostrados por
  una segunda investigación determinista.
- La severidad queda explícitamente provisional si no se conoce la criticidad
  del activo afectado; no se deduce una CMDB ficticia de una URL pública.
- Si una consulta alcanza 2.000 eventos se marca incompleta; no se ha construido
  una infraestructura de subdivisión temporal para recuperar todo el histórico.
- Se conserva el límite de contexto del investigador: 200.000 caracteres. Un
  caso que lo supere falla de manera explícita y no guarda un ticket ficticio.
- Se utiliza TIP, GeoIP y sandbox del dataset; no se añaden proveedores OSINT externos.
- No se ha medido la exactitud del modelo sobre las 11.061 alertas ni completado
  un lote de diez con IA real. Los diez casos automatizados usan LLM simulado.
- Los niveles 2/3/4 avanzados y la página para el comité de dirección de la
  presentación oficial quedan fuera de esta integración del producto N1.
