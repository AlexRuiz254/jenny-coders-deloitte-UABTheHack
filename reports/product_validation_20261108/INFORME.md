# Entrega del producto SOC Deloitte N1–N4

Validación del 8 de noviembre de 2026. Repositorio de trabajo:
`D:/Documents/Hackathon 26/jenny-coders-deloitte-UABTheHack`.

## 1. Resumen ejecutivo

Los cuatro niveles están conectados a la aplicación. Se completó en un navegador
interactivo un recorrido con tres investigaciones N1 y el proveedor IA real,
agrupación N2, generación y ampliación N3, rechazo, controles de autorización y una
acción N4 confirmada por HTTP contra la API oficial simulada. El resultado se
conserva tras reiniciar el panel.

El producto está preparado para defender este recorrido como **prototipo de
hackathon con respuesta simulada y revisión del analista**. No es un SOC desplegado
en producción ni dispone de autenticación humana real. El texto histórico del
modelo no se certifica como verdad: en el caso revisado, N3 corrige el exceso de
certeza de algunos resúmenes N1 sobre el acceso inicial y las cuentas afectadas.
La sección 10 detalla los límites y qué comprobaciones no se han realizado.

La suite final pasó **434 pruebas**, con dos advertencias de deprecación del
simulador oficial. Una comprobación independiente validó contratos, fechas y
**4.445 comparaciones de evidencias**, sin discrepancias con los registros originales.
Esta cifra incluye evidencia repetida entre tickets; no representa eventos únicos.
El criterio de cierre incluye las acciones observadas en el navegador y su resultado
persistido, además de las pruebas automatizadas.

## 2. Arquitectura final

`Streamlit → TriageOrchestrator → N1 guardado → Level2Orchestrator → incidente N2 →
Level3Orchestrator → informe N3 validado/versionado → Level4Orchestrator →
ApprovalService → ContainmentExecutor → API SOC simulada`.

`src/orchestrator/product_services.py` compone los servicios originales. La interfaz
llama a esa composición; no implementa un motor alternativo de análisis o respuesta.
N2 recupera las investigaciones N1 completas sin otra llamada al LLM. El ticket
consolidado mantiene los IDs N1 y la justificación del grupo. Si las fuentes o las
razones cambian, crea otra versión del incidente.

N3 amplía búsquedas sobre entidades y tiempo, reconstruye con referencias exactas,
calcula alcance con soporte estructurado y valida el esquema oficial. El almacén
conserva versiones por huella del contenido y una cabecera actual por incidente.
La consulta de un informe no vuelve a investigar. N4 vincula cada propuesta al
informe, la política y el objetivo exactos; un informe cambiado invalida la ejecución
de sus propuestas anteriores.

Hay tres almacenes separados: `tickets.sqlite3` (N1), `tickets_n2.sqlite3` (N2) y
`soc_response.sqlite3` (informes, operaciones, decisiones y respuesta). Las transiciones
usan control de versión y reserva atómica para evitar ejecutar dos veces una propuesta.
Los errores de N2/N3 conservan sus etapas y resultados anteriores.

La demostración utiliza un registro cerrado de identidades simuladas y verifica el
rol y su ámbito por propuesta. El modo normal sin autenticación solo permite
planificar. La contención exige loopback, desactiva proxies del entorno y redirecciones,
y llama a los servicios de aprobación y ejecución existentes. La sesión de validación
de tokens es efímera; reiniciar obliga a renovar y repetir las aprobaciones.

## 3. Errores corregidos

| Problema | Módulo | Causa | Corrección | Verificación |
|---|---|---|---|---|
| N2–N4 no eran accesibles como producto | Interfaz / composición | Servicios aislados | Vistas y composición común, navegación entre niveles | Navegador y AppTest |
| Fallo de N2 con evidencia sin event_id | Decisión N2 | `.strip()` sobre `None` y metadatos de búsqueda tratados como evento | Exclusión de metadatos y manejo de ID opcional | Suite N2 y recorrido real |
| Validaciones N1 se perdían en N2 | Decisión N2 | No se entregaba la alerta original al motor | Conservación de alerta y autorización por ámbito | Casos WAF/cloud y autorización mixta |
| Incidentes unidos por contexto incidental | Agrupador N2 | Un evento recuperado por ambas búsquedas bastaba | Exigir anclaje en una alerta original o relación fuerte | Regresión de contexto compartido; WAF separado |
| Reutilización de un ticket de otro incidente o de fuentes antiguas | Tickets / orquestador N2 | Búsqueda por alerta y falta de versión de fuentes | Coincidencia de incidente y sufijo de versión | Pruebas de reproceso y persistencia |
| Origen confirmado a partir de clics ordinarios | Reconstrucción N3 | Clasificación demasiado amplia y progresión temporal como causalidad | Veredicto malicioso y vínculo directo de evento/artefacto hacia ejecución no bloqueada | Defecto observado en navegador, regresión y dos informes nuevos |
| Grafos muy grandes y metadatos anónimos | Reconstrucción N3 | Relaciones repetidas y query_summary tratado como evento | Índices y relaciones representativas; exclusión de metadatos | Caso real de más de 1.600 eventos |
| Alcance sin conclusiones utilizables por N4 | Alcance / constructor N3 | Adaptación de contratos sin soporte de entidades | Conclusiones confirmed/hypothesis/unknown con fuente e ID | Esquema oficial, auditoría y plan real |
| Informes grandes bloqueaban la página | Interfaz N3 | Miles de widgets de notas y serialización innecesaria | Paginación, referencias resumidas y descarga diferida | Dos generaciones/descarga en navegador y regresión con 3.000 notas |
| N4 cambiaba la propuesta seleccionada al aprobar | Interfaz N4 | Etiqueta variable según el estado | Identidad y etiqueta estables por propuesta/versión | Navegador y AppTest de transiciones |
| Una confirmación podía sobrevivir a renovar | Interfaz N4 | Estado del checkbox reutilizado | Limpiar confirmaciones tras decisiones y renovación | AppTest de aprobación/renovación |
| No había recorrido de recuperación tras reinicio | Orquestador N4 | Estado aprobado persistido sin sesión de token válida | Revocar solicitud y crear una nueva, sin heredar votos | Reinicio real y pruebas de persistencia |
| Servidor sin responsable podía proponerse como ejecutable | Planificador N4 | Dato de propietario ausente | Mantener coordinación manual con motivo visible | FS01 real; prueba positiva de doble aprobación solo con fixture |
| Recomendaciones disruptivas sin soporte de ese objetivo | N1 / acciones | Señal global aplicada a otras entidades | Exigir evidencia del objetivo y soporte específico; tareas manuales si falta | Regresiones de identidad/cloud y flujo integrado |
| Usuarios agregados y afirmaciones de fuente/fecha indebidas | N1 / investigador / ticket | Etiqueta “12 cuentas” y narración no contrastada | Identidades de eventos reales y validación de afirmaciones por fuente | Pruebas de coherencia y registros guardados |
| Instalación/configuración incompletas | Dependencias / documentación | Versiones mínimas insuficientes y documentación N1 antigua | Dependencias comprobadas y guía N1–N4 | Entorno limpio, pip check, suite y arranque |

No se cambiaron el catálogo, los inventarios, los diez runbooks, la política ni los
logs originales del dataset. El simulador añadió su registro normal al ejecutar la
acción de ensayo.

## 4. Funcionalidades completadas

- **N1:** investigación IA real, consultas de evidencia/contexto, controles de
  veredicto, severidad y escalado, ticket oficial, revisión, importación, fallos y
  reprocesamiento versionado. Las recomendaciones no ejecutan contención.
- **N2:** selección de investigaciones completas, agrupación justificada, separación
  de incidentes, consolidación, autorización por ámbito y conservación de fuentes.
- **N3:** ventana ampliada, progreso, reconstrucción con incertidumbre explícita,
  cronología, alcance, impacto potencial, consultas/límites, versiones y descarga.
- **N4:** plan persistido, revisión de riesgos, aprobación/rechazo explícitos por
  rol/ámbito, renovación, ejecución simulada autorizada, resultado y auditoría.
- **Dashboard:** acceso a N1–N4, importación y configuración; filtros y paginación;
  indicación visible del modo de ensayo y de que las identidades no están autenticadas.
- **Persistencia:** recuperación tras recarga/reinicio, informes históricos,
  operaciones parciales y decisiones/resultados sin sobrescribir su historia.

## 5. Archivos modificados

Rutas relativas a la raíz indicada al comienzo:

| Archivos | Motivo |
|---|---|
| `src/interficie/dashboard.py`, `src/interficie/workflow_views.py` | Navegación N1–N4, formularios, informes grandes, configuración, aprobación, ejecución y exportaciones |
| `src/orchestrator/product_services.py` | Componer servicios, persistencia, progreso y modo de ensayo explícito |
| `src/triage/triage_orchestrator.py`, `src/triage/decision/action_recommender.py` | Soporte por objetivo para las recomendaciones y uso de inteligencia interna |
| `src/triage/investigation/investigation_agent.py`, `src/triage/output/ticket_builder.py` | Coherencia de fuentes/fechas e identidades reales de eventos |
| `src/triage/level2/incident_decision_service.py` | IDs opcionales y conservación de controles de alerta/autorización |
| `src/triage/level2/incident_grouper.py` | Correlación anclada a alertas, sin unión por contexto incidental |
| `src/triage/level2/incident_ticket_service.py`, `src/triage/level2/level2_orchestrator.py` | Identidad del incidente, versiones de fuentes y progreso |
| `src/triage/level3/attack_reconstructor.py` | Causalidad, origen hipotético y reducción de relaciones repetidas |
| `src/triage/level3/scope_analyzer.py`, `src/triage/level3/scope_evidence.py` | Alcance e impacto sustentados y diferenciados por certeza |
| `src/triage/level3/incident_report_builder.py`, `src/triage/level3/level3_orchestrator.py` | Adaptación de contratos, cronología y progreso |
| `src/triage/level4/response_planner.py`, `src/triage/level4/level4_orchestrator.py` | Responsable desconocido, almacenamiento, modo de identidad y renovación auditada |
| `tests/test_incident_decision_service.py`, `tests/test_incident_grouper.py`, `tests/test_level2_integration.py` | Regresiones N2, UTF-8 y transporte POST aislado |
| `tests/test_attack_reconstructor.py`, `tests/level3/test_incident_report_builder.py` | Causalidad y contrato estricto real del informe |
| `tests/test_ticket_coherence.py`, `tests/test_product_workflow.py` | Defectos de N1, flujo completo, permisos, reinicio y formularios reales |
| `README.md`, `.env.example`, `requirements.txt`, `.gitignore`, `tests/plan_de_tests.md` | Arranque, dependencias, rutas, límites y exclusión de secretos/archivos locales |
| `reports/product_validation_20261108/` | Este informe, resultados, auditorías saneadas, validación de procedencia y capturas |

No se hizo commit ni publicación en GitHub. Se conservaron los cambios en el
checkout actual y los resultados en las bases locales ignoradas por Git.

## 6. Tests

| Comprobación | Resultado |
|---|---|
| Línea base de esta integración | 409 pasadas, 15 fallidas; mezcla de defectos reales y fixtures incompatibles con los contratos actuales |
| Suite tras integración, antes de ajustes finales de interfaz | 432 pasadas, dos advertencias |
| Pruebas de producto y regresión del panel final | 6 pasadas, dos advertencias |
| Suite final en entorno limpio | **434 pasadas, 0 fallidas**, dos advertencias; 95,05 s |
| Instalación desde requirements en `.venv-product-check` | Correcta; `pip check`: sin dependencias rotas |
| Compilación de `src` y `run_server.py` | Correcta |
| `git diff --check` | Correcto; aviso de normalización LF/CRLF de Windows en una prueba |
| Contratos y procedencia de artefactos reales | Tickets N1/N2 e informe N3 válidos; 4.445 comparaciones sin errores y fechas de cronología coincidentes |

Las fixtures antiguas del constructor de informes admitían conclusiones sin cita,
IDs artificiales y otros campos obsoletos. Se adaptaron al contrato estricto y se
conservaron pruebas de rechazo de procedencia, IDs y fechas incorrectos. La fixture
de mantenimiento N2 se corrigió para acreditar el objetivo/ámbito del cambio, en
vez de declarar autorización solo mediante una frase.

Los tests de integración automatizados simulan el LLM y las identidades. La API se
ejecuta en memoria con su código oficial y los registros de contención se redirigen
a temporales. La prueba de doble aprobación de servidor utiliza un propietario
complementario solo en la fixture. No cambia el inventario real.

Las dos advertencias finales proceden de `datetime.utcnow()` del simulador oficial;
no causaron fallos y no se modificó ese código para eliminarlas. Los resultados
completos están en [test-results.txt](test-results.txt) y el mapa en
[plan_de_tests.md](../../tests/plan_de_tests.md).

## 7. Pruebas reales de navegador

Se utilizó el navegador integrado interactivo contra `http://127.0.0.1:8503`,
Streamlit real y la API oficial HTTP en `http://127.0.0.1:8001`. Las investigaciones
N1 llamaron al proveedor configurado `ornith` del gateway UAB, con la clave existente.
No se sustituyó ese proveedor ni se fabricaron tickets para estas acciones.

| Alerta seleccionada antes del análisis | Ticket generado con IA real | Resultado N1 |
|---|---|---|
| `ALR-20261009-011790` | `TRIAGE-e8aebf61-4b93-4f6b-b6a9-92db1726b102` | true_positive / high |
| `ALR-20261009-011791` | `TRIAGE-6d0bb903-98af-4471-a9ed-e376bee031ae` | true_positive / critical |
| `ALR-20261009-011792` | `TRIAGE-f4026f47-8a2b-4f9f-816f-67339dc4465f` | true_positive / high |

Se abrieron detalles y se guardó una revisión explícita de ensayo para escalar el
último ticket; la nota aclara que el asistente no representa una identidad humana
autenticada. En N2 se seleccionaron los tres casos más el WAF previamente investigado
`ALR-20261005-000427`. El panel produjo dos grupos: cadena
`INC-5a04411da2f121ff1cc6` y WAF independiente `INC-365bd3ebdf52b6fa67f7`.
Se inspeccionaron justificación y fuentes.

Tras endurecer el agrupador se creó con el servicio real una versión de la cadena,
`INC-5a04411da2f121ff1cc6-vd2d89109ec56`, conservando las investigaciones N1 y el
incidente anterior. Esa creación concreta se hizo mediante el servicio con HTTP;
no se atribuye a un nuevo clic N2. La generación y ampliación de los informes de esa
versión sí se ejecutaron desde el navegador:

| Informe | Ventana elegida | Evidencias | Cronología | Estado |
|---|---|---:|---:|---|
| `704889645509…` | 7 días anteriores / 2 posteriores | 1.657 | 1.627 | Histórico; plan rechazado conservado |
| `dd524bedc906…` | 7 días anteriores / 1 posterior | 1.646 | 1.616 | Actual; plan ejecutado conservado |

Se descargó el JSON N3 y se comprobó su lectura e ID. Tras corregir el renderizado
se pudo llegar a los controles finales, ampliar el informe y pasar a N4 desde el
propio panel. La segunda huella completa figura en
[evidence_validation.json](evidence_validation.json).

Comprobaciones N4 realizadas desde la interfaz:

1. Preparar plan: dos propuestas, sin ejecución automática. FS01 quedó manual por
   responsable ausente; su control de ejecución estaba deshabilitado.
2. Intentar aprobar el aislamiento de WS con `analyst_n1`: denegado por rol.
3. Rechazar con `analyst_n2`: propuesta
   `RSP-3db44c1ae597a27ecf78cbba6fe282b5`, estado persistido `rejected`.
4. Generar otra versión N3 y preparar su plan. Aprobar con N2.
5. Reiniciar el servidor e intentar ejecutar la aprobación persistida: denegado por
   sesión/token no validable. Renovar con N1 también se denegó.
6. Renovar con N2: solicitud nueva sin votos. Aprobar nuevamente de forma explícita.
7. Confirmar por separado y ejecutar
   `RSP-b121703628d7b122f0b4d5f98caa3b83`: **isolate_host / WS-BCN-1770**.
8. La API confirmó `result: "ok (simulado)"`, fecha
   `2026-11-08T07:22:41.977841Z`. El estado es `succeeded`, el botón quedó bloqueado
   y el historial HTTP contiene **una sola acción** de este incidente.
9. Descargar la auditoría sin tokens y consultar el historial saneado. Reiniciar
   nuevamente y recuperar el resultado ejecutado, sin repetir la acción.

Estas decisiones usan identidades **simuladas**, no autenticación de personas reales.
La llamada HTTP, la validación y el registro de contención son reales dentro de la
API ficticia; no se aislaron equipos ni se cambiaron cuentas reales.

Se encontraron y corrigieron el origen causal erróneo, el bloqueo visual con miles
de notas y el cambio involuntario de selección N4. El intento anterior de usar Opera
quedó interrumpido al no poder verificar su URL; esta entrega completó la validación
con el navegador integrado.

Evidencias de la sesión:

- [Reconstrucción N3](n3_reconstruccion.jpg).
- [Resultado N4 recuperado tras reinicio](n4_ejecucion.jpg).
- [Historial de la API](n4_historial.jpg).
- [Auditoría de rechazo](RSP-3db44c1ae597a27ecf78cbba6fe282b5.audit.json).
- [Auditoría de ejecución](RSP-b121703628d7b122f0b4d5f98caa3b83.audit.json).

## 8. Coherencia de los resultados

La cadena EDR/proxy acredita ejecución en WS-BCN-1770, persistencia y comunicaciones
posteriores. El informe vigente conserva las fechas y referencias reales. Los dos
hosts confirmados en alcance son WS-BCN-1770 y FS01; los tres alias de usuario
observados permanecen como hipótesis y los servicios como impacto potencial.
No se acredita indisponibilidad ni pérdida económica ni exfiltración a partir del
tráfico observado.

El primer informe de la versión antigua del incidente había atribuido el paciente
cero a clics ordinarios de otro día/mensaje. Ese resultado se detectó y se conserva
como histórico de evaluación, sin editar sus conclusiones. Los informes nuevos
mantienen **paciente cero hipotético**, **acceso inicial desconocido** y **causa raíz
hipotética**. El mecanismo exacto de entrada necesita más telemetría.

Algunos textos N1 guardados antes de las últimas correcciones son más categóricos
sobre el adjunto como vector o sobre credenciales robadas. No se han reescrito para
mejorar la evaluación ni se presentan como hechos validados. El informe N3 posterior
reduce esa certeza con evidencias y N4 planifica desde su alcance sustentado. Las
recomendaciones N1 originales no son autorizaciones ejecutables. Las nuevas reglas
por objetivo se verificaron con regresiones; no se repitieron las tres llamadas
reales al modelo después de cada ajuste final.

La agrupación conserva WAF aparte y no convierte la actividad autorizada en ataque
por una señal global. Las divergencias de severidad entre alertas e incidente se
conservan con la evaluación de impacto y escalado del conjunto. Los usuarios agregados
se resuelven desde eventos reales; no se inventan cuentas para completar el esquema.

Las 4.445 comparaciones prueban procedencia y las fechas comprobadas prueban
consistencia temporal. No prueban por sí mismas la interpretación causal del texto.

## 9. Documentación

`README.md` incluye instalación, arranque, configuración del modelo y API, rutas de
persistencia, recorrido N1–N4, demostración, aprobaciones de ensayo, recuperación,
historial y límites. `.env.example` incluye rutas separadas y `SOC_DEMO_MODE` sin
claves. `requirements.txt` está instalado y comprobado en un entorno limpio.
`.gitignore` excluye entornos, bases, temporales y el log sensible del simulador.
`tests/plan_de_tests.md` deja de ser una lista pendiente y documenta la cobertura real.

## 10. Limitaciones pendientes

- No existe autenticación humana de producción. El modo de ensayo es visible y
  exporta `identity_mode=demo_simulated`; no se permite presentarlo como identidad
  humana verificada. Con demo desactivada no se vota ni se ejecuta desde el producto.
- El proveedor compartido puede tardar o fallar. Sus resúmenes pueden sobrerinterpretar
  relaciones y los históricos no reciben correcciones retroactivas. El analista debe
  revisar evidencia y usar el informe avanzado vigente para decidir.
- Solo se ejecutaron con IA real los tres casos indicados en esta sesión; las 44
  reglas y los diez runbooks no se certifican con una investigación real de navegador
  por cada combinación. Su cobertura adicional es automatizada.
- N3 tiene límites de 31 días, 48 consultas ampliadas y 2.000 eventos adicionales.
  El caso real alcanzó el límite de consultas: cobertura parcial explícita. El
  adaptador de API no distingue una fuente 404 de una lista vacía; no prueba ausencia.
- El grafo de casos grandes resume relaciones repetidas, aunque conserva todos los
  eventos del informe. Las notas repetidas pueden ser numerosas; la interfaz las
  pagina, no elimina información de los JSON.
- FS01 no tiene responsable documentado: no se demostró doble aprobación positiva
  de ese servidor en el navegador. Sí se comprobó su bloqueo real y el mecanismo de
  doble aprobación mediante una fixture explícita, sin modificar datos oficiales.
- El repositorio nativo de aprobaciones guarda tokens en la base local y el simulador
  oficial los incluye en su log interno. Ambos se excluyen de Git; el dashboard y las
  auditorías exportadas los omiten. No son almacenamiento cifrado ni deben publicarse.
  La sesión criptográfica no persiste, por lo que reiniciar exige renovar y votar.
- Un fallo de red después de enviar una acción puede dejar resultado incierto;
  no hay reintento automático. Conciliar con el historial antes de otra operación.
  La API oficial es un simulador sin garantías de control de acceso de producción.
- No hay una página adicional para comité ejecutivo ni integración con controles de
  seguridad reales. No se ejecutó ningún control real externo a loopback.

No quedó un bloqueo funcional reproducido en el recorrido entregado. Esto no equivale
a certificar ausencia de errores en todos los datos o toda respuesta futura del LLM.

## 11. Instrucciones para la defensa

Desde la raíz, instalar y configurar una vez:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
# Si todavía no existe .env:
Copy-Item .env.example .env
# Configurar en .env la clave y el modelo válidos del gateway.
```

Terminal 1:

```powershell
.\.venv\Scripts\python.exe run_server.py --port 8001
```

Terminal 2:

```powershell
$env:SOC_API_URL = 'http://127.0.0.1:8001'
$env:SOC_DEMO_MODE = 'true'
.\.venv\Scripts\python.exe -m streamlit run src/interficie/dashboard.py --server.port 8503
```

Abrir [el dashboard](http://127.0.0.1:8503). Si ya están ejecutándose ambos servicios,
utilizarlos; no arrancar una segunda instancia en el mismo puerto.

Para una defensa breve, empezar por los tickets y resultados guardados de esta
sesión: mostrar la evidencia N1, los dos grupos N2, el informe N3 `dd524bedc906…` y la
propuesta ejecutada. Mostrar el rechazo anterior y el FS01 manual. Explicar que N1
es IA con revisión y N3 conserva incertidumbres.

Para generar un recorrido nuevo: investigar las tres alertas de la sección 7,
correlacionarlas, generar N3 con 7/1 días y preparar N4. Elegir la propuesta de WS,
probar el rol N1, seleccionar **Analista N2 · simulado**, escribir motivo, marcar la
confirmación y aprobar. Revisar el estado; marcar la confirmación de ejecución y
pulsar **Ejecutar acción autorizada**. Consultar el resultado y abrir **Historial de
contención de la API simulada → Consultar historial de la API**. Descargar la auditoría.

Para demostrar rechazo, usar una propuesta distinta de otra versión N3. No intentar
reabrir la rechazada. Para demostrar recuperación de aprobación pendiente tras
reiniciar, renovar con N2 y repetir todos los votos antes de ejecutar. El estado
`succeeded` ya guardado es solo de consulta y no ejecuta otra vez la acción.

Para repetir las comprobaciones locales, usar los comandos de tests del README y
`reports/product_validation_20261108/validate_artifacts.py`. El script de auditoría
solo lee los artefactos de esta sesión; no llama al modelo ni realiza contención.
