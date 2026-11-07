# jenny-coders-deloitte-UABTheHack

Panel SOC N1 de Tarvia para el reto Deloitte. Streamlit ejecuta el `TriageOrchestrator`
real, consulta la API oficial del dataset y usa el cliente de IA existente (Ornith).
El analista revisa los tickets y decide el cierre o escalado. El panel no ejecuta contención.

## Preparación (PowerShell, Python 3.11 o posterior)

Desde la raíz del repositorio:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
Copy-Item .env.example .env
```

Si ya tienes `.env`, consérvalo. Configura `ORNITH_API_KEY` con tu clave real;
`ORNITH_API_URL` y `ORNITH_MODEL` permiten usar el endpoint/modelo de tu cuenta.
No publiques `.env`. Sin clave puedes consultar, importar y revisar tickets,
pero investigar muestra un error de configuración reintentable, sin generar tickets ficticios.

Si utilizas el gateway UAB configurado para la hackathon, usa `ORNITH_MODEL=ornith`.
El endpoint directo de Ornith usa `uncensored`; el nombre debe coincidir con el
modelo que publica `GET /models` en el servidor elegido.
`ORNITH_TIMEOUT_SECONDS` configura el tiempo máximo de cada llamada (120 segundos
por defecto), útil cuando el modelo compartido está ocupado.
En el gateway compartido de UAB puede ser necesario elevarlo a `600`. Esta espera
no acelera el modelo: el tiempo del lote depende del proveedor y se muestra en el panel.
El gateway UAB también admite `ORNITH_REASONING_EFFORT=none`, comprobado durante
la integración para reducir su latencia. Es opcional: si se omite, el cliente
conserva el comportamiento del proveedor. No lo actives en otro endpoint sin
comprobar antes que admite ese parámetro.

## Arranque

Terminal 1, API SOC original (conserva `RepositoriDeloitte` íntegro):

```powershell
.\.venv\Scripts\python.exe run_server.py
```

Terminal 2, interfaz principal:

```powershell
.\.venv\Scripts\python.exe -m streamlit run src/interficie/dashboard.py --server.port 8501
```

Abre [el panel](http://localhost:8501) y, si necesitas inspeccionar los endpoints,
[la documentación de la API](http://localhost:8000/docs). Ambos comandos pueden usar
rutas absolutas desde otro directorio. `run_server.py` solo arranca la API Deloitte;
el servidor adicional de creación de tickets básicos ya no se utiliza.

Si los puertos están ocupados, conserva los servicios que ya estén ejecutándose y elige otros:

```powershell
# Terminal 1
.\.venv\Scripts\python.exe run_server.py --port 8001
# Terminal 2
$env:SOC_API_URL = 'http://127.0.0.1:8001'
.\.venv\Scripts\python.exe -m streamlit run src/interficie/dashboard.py --server.port 8502
```

También puedes procesar una alerta desde consola:

```powershell
.\.venv\Scripts\python.exe -m src.triage.triage_orchestrator ALR-20261005-000301 --api-url http://127.0.0.1:8000
```

## Uso

- **Alertas pendientes**: métricas persistidas, búsqueda global por ID, filtros de
  severidad, producto, regla, estado y fuente; ordenación y páginas de 25/50/100.
  Selecciona una o varias alertas, o las primeras diez, y pulsa **Investigar selección**.
  El progreso muestra las etapas reales. Un fallo individual no pierde los tickets del lote.
- **Tickets e investigación**: búsqueda y filtros por decisión, severidad, escalado y
  revisión. El detalle muestra el ticket final, evidencias, contexto, cambios, consultas,
  runbook, señales de la IA, preguntas pendientes y restricciones de las recomendaciones.
  Descarga el JSON oficial de un ticket o una selección.
- **Revisión humana**: confirma o rechaza el cierre, decide escalar o continuar la
  investigación y guarda observaciones. La revisión queda separada de la recomendación IA.
  El reprocesamiento exige una elección explícita y crea una nueva versión; conserva la revisión anterior.
- **Importar**: JSON (objeto o lista) o JSONL, con resumen de importadas, duplicadas y
  rechazadas. Las alertas requieren el formato Deloitte, `status=new`, fecha con zona y
  regla/runbook del catálogo. Se guardan localmente y se investigan con los mismos servicios.
  La API debe estar disponible para comprobar IDs duplicados. Los tickets se validan
  contra `ticket_salida.schema.json` y Pydantic; pueden importarse sin API.

La API original no admite filtros por severidad ni inserción de alertas. El panel
recupera su catálogo mediante páginas de 500 y conserva **solo un índice compacto en
caché durante cinco minutos**, compartido entre recargas. Así los filtros y las métricas
abarcan todo el catálogo, sin descargar las 11.061 alertas en cada interacción. Los logs
se consultan únicamente al investigar. **Actualizar catálogo** fuerza la recarga.

## Persistencia y trazabilidad

La única implementación es `src/data/ticket_repository.py`. Por defecto usa
`tickets.sqlite3` en la raíz; `SOC_DB_PATH` permite cambiarla. Los imports antiguos
siguen apuntando a esa implementación. Las revisiones de ambos formatos SQLite
anteriores se conservan y, al usar la ubicación predeterminada, se recuperan sin
borrar ni sobrescribir registros de `data/tickets.sqlite3`, si existe.

Los registros básicos antiguos se conservan para consulta y no cuentan como tickets
oficiales ni ocultan alertas pendientes. Los tickets válidos almacenan su JSON completo,
contexto, análisis, consultas, evidencias y runbook. Las dos tablas auxiliares guardan
alertas importadas y el último intento por alerta; no se modifican datasets oficiales.
Los fallos permiten reintentar y se registran también en `logs/soc.log`.

La correlación y las búsquedas de logs se acotan a ±24 h. Las fechas sin zona del
calendario se interpretan en `Europe/Madrid`; los logs usan UTC. Las consultas que
alcanzan 2.000 resultados se identifican como incompletas en las evidencias, el progreso
y las preguntas pendientes. No se presentan como prueba de ausencia de actividad.

## Pruebas

```powershell
# TEMP local evita restricciones de escritura de algunos entornos Windows.
New-Item -ItemType Directory -Force .test-temp | Out-Null
$env:TEMP = (Resolve-Path .test-temp).Path
$env:TMP = $env:TEMP
.\.venv\Scripts\python.exe -m pytest -q --basetemp=.test-pytest --tb=short
.\.venv\Scripts\python.exe -m compileall -q src run_server.py
```

Las pruebas existentes se mantienen. `tests/test_level1_integration.py` añade flujos
con datos y funciones de la API oficial (transporte en memoria), un LLM simulado solo
en pruebas, validación del esquema, persistencia, revisión, importación, diez alertas,
fallos y reintentos, ventanas, cambios y ejecución de widgets reales con Streamlit AppTest.
Las comprobaciones con HTTP, navegador e IA real se describen en `tests/validacion_nivel1.md`.

## Alcance

Nivel 1: contexto e inteligencia interna, investigación IA, evidencias verificables,
veredicto validado, matriz de severidad, escalado, recomendaciones, ticket, interfaz y
revisión humana. Las alertas relacionadas se muestran como candidatas: compartir una
entidad no demuestra una misma intrusión. La agrupación automática de incidentes de
nivel 2, la investigación de varias semanas de nivel 3 y la ejecución de contención
de nivel 4 quedan fuera. La página para el comité de dirección mencionada en la defensa
es un entregable de presentación y no se genera en esta integración.
