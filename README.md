# Tarvia · SOC Deloitte N1–N4

Producto integrado para la hackathon Deloitte UAB: investigación de alertas con IA,
correlación de incidentes, investigación ampliada y respuesta con aprobación explícita.
La interfaz principal es Streamlit y utiliza los servicios reales del repositorio y
la API oficial simulada de `RepositoriDeloitte`.

La respuesta de demostración usa **identidades simuladas**, indicadas en pantalla y
registradas en la auditoría. No hay autenticación humana de producción. Las acciones
solo se admiten contra una API local de loopback; el simulador registra la acción,
sin aislar equipos ni modificar identidades reales.

## Instalación en Windows

Python 3.11 o posterior. La instalación limpia y las pruebas de entrega se comprobaron
con Python 3.13.9. Desde la raíz del repositorio:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m pip check
# Solo si todavía no existe .env:
Copy-Item .env.example .env
```

Conserva tu `.env` existente. Configura `ORNITH_API_KEY` con una clave válida. Nunca
publiques este archivo. El ejemplo usa el gateway UAB y `ORNITH_MODEL=ornith`.
`ORNITH_API_URL` y `ORNITH_MODEL` deben corresponder al proveedor elegido. El endpoint
directo de Ornith puede utilizar otro nombre de modelo.

`ORNITH_TIMEOUT_SECONDS=600` tolera esperas del gateway compartido; no acelera las
respuestas. `ORNITH_REASONING_EFFORT=none` es opcional y se comprobó con el gateway
UAB; omítelo en un proveedor que no lo admita. Sin clave se puede consultar lo
persistido, pero una investigación N1 nueva falla con un error recuperable.

## Arranque

Terminal 1, API oficial simulada:

```powershell
.\.venv\Scripts\python.exe run_server.py --port 8000
```

Terminal 2, dashboard:

```powershell
$env:SOC_API_URL = 'http://127.0.0.1:8000'
$env:SOC_DEMO_MODE = 'true'
.\.venv\Scripts\python.exe -m streamlit run src/interficie/dashboard.py --server.port 8501
```

Abre [el dashboard](http://127.0.0.1:8501) y, para inspeccionar la API,
[su documentación](http://127.0.0.1:8000/docs). Ejecuta desde la raíz del repositorio.
No es necesario arrancar ningún servidor adicional de tickets.

Si esos puertos están ocupados, conserva los procesos existentes y elige otros:

```powershell
# Terminal 1
.\.venv\Scripts\python.exe run_server.py --port 8001
# Terminal 2
$env:SOC_API_URL = 'http://127.0.0.1:8001'
$env:SOC_DEMO_MODE = 'true'
.\.venv\Scripts\python.exe -m streamlit run src/interficie/dashboard.py --server.port 8503
```

En la validación de entrega se utilizaron API 8001 y dashboard 8503.

## Recorrido desde la interfaz

1. **Alertas pendientes · N1.** Busca un ID o filtra por regla, severidad, producto,
   fuente y estado. Selecciona alertas y pulsa **Investigar selección**. El progreso
   muestra consultas, IA, validación y guardado. Los fallos individuales no pierden
   los demás resultados del lote.
2. **Tickets e investigación.** Abre el ticket y sus evidencias, contexto, runbook,
   análisis original, correcciones y preguntas. Guarda una revisión explícita de
   cierre, escalado o continuación. Reprocesar requiere elegirlo expresamente y
   conserva los tickets anteriores. Las acciones de N1 son recomendaciones.
3. **Incidentes · N2.** Selecciona investigaciones N1 completas y correlaciónalas.
   Revisa las razones de agrupación, tickets de origen, veredicto, severidad y
   escalado. Una IP o un evento de contexto compartido no bastan para unir ataques.
   N2 reutiliza la investigación guardada; no vuelve a llamar al LLM.
4. **Investigación · N3.** Elige el incidente y la ventana temporal, y pulsa
   **Investigar y guardar informe N3**. Un caso no escalado exige un motivo del
   analista. Consulta origen, cronología, alcance, impacto, fuentes y límites.
   Las hipótesis conservan ese estado; una conexión no demuestra exfiltración.
   Filtra y pagina la cronología y las notas. Descarga el JSON oficial completo.
   Para investigar otra vez, marca **Crear otra versión**: las anteriores permanecen.
5. **Respuesta · N4.** Prepara el plan; revisa la acción, objetivo, impacto,
   evidencias y roles exigidos. La preparación no ejecuta acciones. Una propuesta
   manual permanece bloqueada. Las propuestas de un informe anterior no pueden
   ejecutarse contra la versión actual.
6. **Decisión de ensayo.** Con `SOC_DEMO_MODE=true`, selecciona una identidad
   simulada, escribe un motivo y confirma la decisión. **Aprobar** y **Rechazar**
   quedan auditados. Un rol insuficiente se deniega; un rechazo no puede reabrirse.
   Una aprobación parcial sigue pendiente hasta recibir todos los roles exigidos.
7. **Ejecución.** Tras completar las aprobaciones, confirma expresamente la acción
   en la API simulada y pulsa **Ejecutar acción autorizada**. Comprueba el resultado,
   la auditoría sin tokens y **Consultar historial de la API**. El resultado guardado
   impide repetir la misma ejecución. Un resultado incierto exige conciliación.
8. **Configuración.** Comprueba API, modelo, presencia de clave, rutas de datos y
   estado de operaciones parciales. La clave nunca se muestra.

**Después de reiniciar el servidor o caducar la autorización:** los tickets,
informes, decisiones y resultados permanecen, pero la sesión que valida los tokens
no sobrevive al reinicio. En una propuesta aprobada, utiliza **Renovar solicitud y repetir aprobaciones**
con el rol exigido; después emite todos los votos otra vez. Renovar no aprueba.

`SOC_DEMO_MODE=false` permite consultar y planificar, sin votar ni ejecutar desde
el producto. Para una implantación real hay que integrar un proveedor de identidad
que autentique al revisor y sus atribuciones sobre cada servicio.

## Demostración recomendada

Investiga estas tres alertas, fijadas antes de consultar sus resultados:

- `ALR-20261009-011790`: adjunto de correo.
- `ALR-20261009-011791`: ejecución sospechosa en `WS-BCN-1770`.
- `ALR-20261009-011792`: comunicaciones posteriores del mismo equipo.

Correlaciona las tres en N2. Si está investigada, añade
`ALR-20261005-000427` (WAF) para mostrar que queda en un incidente independiente.
En N3 utiliza siete días anteriores y uno posterior. Muestra que el mecanismo de
acceso inicial sigue sin determinarse con certeza y que los usuarios observados
no pasan automáticamente a cuentas comprometidas.

En N4, `WS-BCN-1770` admite propuesta de aislamiento con aprobación N2. FS01 queda
manual porque el inventario oficial no identifica al responsable de su servicio.
No inventes ese responsable. Para enseñar un rechazo y una ejecución, rechaza el
primer plan y crea otra versión N3 con una ventana distinta antes de preparar un
nuevo plan. Un rechazo nunca se elimina ni se reutiliza como aprobación.

La validación real completada, sus IDs, resultados y capturas están en
[el informe de entrega](reports/product_validation_20261108/INFORME.md).
Los IDs exactos de nuevos tickets o propuestas pueden cambiar al volver a investigar.

## Arquitectura y persistencia

`dashboard.py` y `workflow_views.py` muestran el trabajo. `ProductServices` conecta
los orquestadores existentes; la interfaz no replica sus motores de decisión.

| Etapa | Servicio y resultado | Persistencia predeterminada |
|---|---|---|
| N1 | `TriageOrchestrator`: IA, evidencias, contexto, decisión, ticket oficial | `tickets.sqlite3` |
| N2 | `Level2Orchestrator`: grupos justificados y ticket consolidado | `tickets_n2.sqlite3` |
| N3 | `Level3Orchestrator`: ampliación, reconstrucción, alcance e informe oficial | `soc_response.sqlite3` |
| N4 | `Level4Orchestrator`: plan, ApprovalService, ejecutor y auditoría | `soc_response.sqlite3` |

Configura `SOC_DB_PATH`, `SOC_N2_DB_PATH` y `SOC_RESPONSE_DB_PATH` para cambiar las
rutas. Deben ser distintas para N1, N2 y respuesta. Las rutas relativas se resuelven
desde la raíz del proyecto. Conserva juntos los tres archivos al trasladar la demo.

Los registros anteriores se mantienen. Los tickets básicos sin investigación
completa pueden consultarse, pero no alimentan N2. Reprocesar N1 y cambiar sus
fuentes o razones de agrupación crea una versión N2 distinta. N3 guarda informes
por huella del contenido, con una versión actual y acceso a las históricas. Los
planes N4 vinculan exactamente informe, política, objetivo y evidencias.

Las operaciones N2/N3 registran etapas, finalización y tipo de fallo. Una operación
interrumpida no borra resultados de etapas previas. Revisa su estado en Configuración
antes de repetirla. SQLite protege transiciones concurrentes y reserva la ejecución.
La sesión criptográfica vive en el servidor; los estados visibles y las auditorías
exportadas excluyen los tokens.

El repositorio nativo de aprobaciones conserva el token en su base local, y la API
oficial lo incluye en su log interno de contención. No son almacenes cifrados:
ambos archivos están ignorados por Git y el panel muestra únicamente campos públicos.
No publiques `.env`, bases de datos ni ese log. Los datos oficiales no se reescriben;
el simulador añade su registro normal cuando ejecutas una acción.

## Cobertura y límites

- N1 acota las búsquedas a ±24 horas. Las fechas del calendario sin zona se
  interpretan en `Europe/Madrid`; la cronología usa UTC.
- N3 permite hasta 21 días anteriores y 7 posteriores desde la interfaz. El servicio
  impone un máximo de 31 días, 48 búsquedas ampliadas y 2.000 eventos adicionales.
  También conserva las evidencias N1 originales: el total puede ser mayor.
- Los truncamientos, fuentes no disponibles y límites quedan explícitos. Un 404 o
  cero resultados no demuestra ausencia de actividad. No se investigan automáticamente
  todas las alertas históricas; se comparan los incidentes N2 que estén guardados.
- La reconstrucción conserva todos los eventos, pero resume las relaciones repetidas
  en casos grandes. No presenta una coincidencia temporal como causalidad demostrada.
- La calidad del texto de N1 depende del modelo. Se conservan el original y los
  hallazgos rechazados; revisa las citas y las incertidumbres antes de decidir.
  Consultar un ticket histórico no aplica retroactivamente las correcciones nuevas.
- Los IOCs de uso dual, equipos de negocio y servidores mantienen requisitos
  adicionales. OT solo admite coordinación manual con Operaciones.
- No hay autenticación de producción, integración con controles de seguridad reales,
  reintentos automáticos de ejecuciones inciertas ni una vista ejecutiva adicional.

El catálogo de alertas se recupera en páginas de 500, con un índice compacto en
caché durante cinco minutos. **Actualizar catálogo** fuerza la recarga. Importar
acepta JSON/JSONL local con validación del contrato; no inserta datos en la API oficial.

## Verificación

```powershell
New-Item -ItemType Directory -Force .test-temp | Out-Null
$env:TEMP = (Resolve-Path .test-temp).Path
$env:TMP = $env:TEMP
.\.venv\Scripts\python.exe -m pytest -q --basetemp=.test-pytest --tb=short
.\.venv\Scripts\python.exe -m compileall -q src run_server.py
```

Las pruebas automatizadas separan los dobles de LLM/identidad del transporte real
o aislado contra la API oficial. Incluyen contratos, decisiones, ventanas, versiones,
fallos, interfaz, aprobación múltiple, rechazos, expiración, recuperación y ejecución
idempotente. La prueba positiva de doble aprobación de FS01 utiliza un propietario
complementario **solo en la fixture**, sin alterar el inventario oficial.

Consulta [el mapa de pruebas](tests/plan_de_tests.md) y
[la validación de entrega](reports/product_validation_20261108/INFORME.md) para distinguir
las pruebas automatizadas de las acciones realizadas en un navegador con IA y HTTP reales.
