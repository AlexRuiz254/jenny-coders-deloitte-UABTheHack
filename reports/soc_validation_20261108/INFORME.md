# Evaluación SOC N1 · 8 de noviembre de 2026

Se completaron **tres iteraciones y nueve investigaciones con el proveedor real**. Se corrigieron causas generales y la suite final pasó **223 pruebas**. Sin embargo, **no se obtuvieron tres tickets suficientemente coherentes**: la última evaluación conserva errores semánticos importantes. Se respeta el máximo de tres iteraciones; no se ha ejecutado una cuarta ni editado los JSON para mejorar sus resultados.

La validación utilizó los **widgets reales de `src/interficie/dashboard.py` mediante Streamlit AppTest**, con HTTP real contra la API Deloitte y el modelo `ornith` de `https://dcc-llm-gw.uab.cat`. Seleccionó alertas, pulsó «Investigar selección»/«Reprocesar alerta» y abrió el detalle de cada ticket. **No fue una sesión de navegador interactivo**: el control de Opera terminó porque no podía verificar la URL con suficiente confianza. Esta limitación impide dar por completada la validación visual en navegador solicitada. No se llamó directamente al agente para fabricar tickets ni se simuló el LLM en estas evaluaciones.

## A. Resumen de cambios

- **Veredictos WAF:** `VerdictEngine` contrasta reglas declaradas, eventos originales y hallazgos aceptados. Un bloqueo no implica falso positivo. Ante un `false_positive` incompatible con un escaneo/intento real documentado, devuelve `needs_more_info`, sin convertir todos los bloqueos en verdaderos positivos. Sigue siendo posible un falso positivo auténtico.
- **Títulos:** se elimina el recorte de `findings[0].statement[:140]`. Se conserva un título válido y se recurre a información estructurada cuando deja de serlo. Los títulos sustitutos son frases completas; el constructor evita prefijos que alargaban el título innecesariamente.
- **Preguntas y confianza:** se separan avisos técnicos de preguntas para el analista; se deduplican preguntas y se contrastan los truncamientos con su fuente. Una consulta completa con cero resultados no se considera incompleta. Se elimina la copia automática de todo el checklist del runbook y la penalización adicional de confianza por cada pregunta.
- **Bloqueo y cobertura:** desaparece la regla del orquestador que anulaba `blocked_before_effect` por cualquier consulta truncada. Se conserva el contrato de once señales. La señal compuesta sigue exigiendo cobertura para aplicar −1, mientras el bloqueo de una solicitud permanece como hecho documentable. Una frase mixta rechazada puede conservar su hecho WAF directamente verificable.
- **Cierres:** se revisan con el veredicto final, la severidad, las señales de compromiso y la cobertura pertinente. RB-05 conserva la posibilidad de cerrar un intento web bloqueado y documentado. Las justificaciones de cierre se limitan a los hechos validados; no se certifica ausencia universal de compromiso.
- **Identidad:** una `New-InboxRule` ordinaria de organización de correo ya no basta para validar `persistence`. Se distingue de reenvíos o reglas sobre contenido financiero sospechoso. También se distinguen consentimientos verificados y altas MFA corporativas. Se aplica la criticidad documentada del servicio IdP/AD en la matriz.
- **Cloud y tareas manuales:** un `PutBucketPolicy` exitoso, sin pruebas adicionales, no demuestra malicia; Terraform tampoco demuestra autorización. Se conserva la revisión de varios recursos conocidos en una tarea manual. Si falta soporte de compromiso, las propuestas de desactivar claves o aislar el runner se orientan a verificar el cambio cloud.
- **Trazabilidad:** cada registro nuevo conserva el `Analysis` original del modelo, correcciones, hallazgos rechazados y cobertura del prompt, además del análisis normalizado, `VerdictDecision`, contexto, búsquedas, eventos y traza.

No se añadieron dependencias ni agentes LLM, ni se cambiaron los modelos públicos. Los parámetros añadidos a los motores son opcionales. Se conservaron límites de búsquedas y tiempo, identificadores permitidos, defensa frente a instrucciones de los logs, restricciones OT, controles de servicios de uso dual y aprobaciones de contención. `EscalationEngine` se revisó y se conservó.

## B. Archivos modificados

Rutas de implementación y pruebas, todas bajo `D:/Documents/Hackathon 26/jenny-coders-deloitte-UABTheHack/`:

1. `src/triage/investigation/investigation_agent.py`
2. `src/triage/decision/verdict_engine.py`
3. `src/triage/decision/severity_calculator.py`
4. `src/triage/decision/action_recommender.py`
5. `src/triage/triage_orchestrator.py`
6. `src/triage/output/ticket_builder.py`
7. `tests/test_ticket_coherence.py`

Artefactos nuevos de evaluación, fuera del dataset:

- `reports/soc_validation_20261108/INFORME.md` — este informe.
- `reports/soc_validation_20261108/selection.json` — selección fijada antes de conocer veredictos.
- `reports/soc_validation_20261108/evaluate_dashboard.py` — ejecución reproducible de los widgets reales, sin sustituir servicios.
- `reports/soc_validation_20261108/audit_evidence.py` — comparación con eventos y consultas oficiales.
- `reports/soc_validation_20261108/iteration_1/`, `iteration_2/`, `iteration_3/` — JSON oficiales, registros completos, manifiestos con hashes del código y auditorías.

Los nueve registros se añadieron normalmente a `D:/Documents/Hackathon 26/jenny-coders-deloitte-UABTheHack/tickets.sqlite3`. No se modificaron documentos, inventarios ni logs originales de `RepositoriDeloitte`.

## C. Pruebas realizadas y límites

| Comprobación | Resultado |
|---|---|
| Primera corrida de pruebas existentes | Avanzó, pero las pruebas de interfaz quedaron bloqueadas por las restricciones locales. Se detuvieron únicamente los procesos de pytest de esta tarea. No se presenta como una corrida completa aprobada. |
| Primera verificación de las correcciones | Cuatro fallos de la misma prueba parametrizada: se descartaba un aviso DNS de truncamiento sin que existiera consulta DNS para contradecirlo. Se corrigió el alcance del filtro; no se modificó esa prueba existente. |
| Suite completa tras las primeras correcciones | **221 passed**, 29,33 s. |
| Regresiones e investigador antes de la segunda evaluación | **74 passed**, 6,20 s. |
| Integración e interfaz después de la segunda corrección | **20 passed**, 23,65 s. |
| Regresiones e investigador antes de la tercera evaluación | **74 passed**, 7,16 s. |
| Suite completa final | **223 passed**, 30,80 s; sin fallos finales. |
| Compilación de `src`, arranque y scripts de evaluación | Sin errores. |
| `git diff --check` | Sin errores; solo avisos de conversión LF/CRLF de Windows. |
| API real | HTTP 200, catálogo de 11.061 alertas en `http://127.0.0.1:8001`. |
| Streamlit real | HTTP 200 en `http://127.0.0.1:8502/_stcore/health`; servidor reiniciado para cargar los cambios. |
| Investigaciones con IA real | **9/9** completadas y persistidas mediante widgets. |
| Esquema oficial y Pydantic | Los nueve tickets son válidos. |
| Procedencia de eventos y consultas | **351 comparaciones de eventos y 66 consultas reproducidas**, sin discrepancias. Son 117 eventos por iteración; los mismos casos se repitieron para comparar versiones. |
| Versiones y revisión | 25 registros totales: 16 anteriores y 9 nuevos. Los nueve nuevos siguen presentes y sin decisión humana registrada. |

Se añadieron ocho pruebas agrupadas: seis para los defectos conocidos y dos para fallos nuevos confirmados de identidad y tareas manuales. Las pruebas automatizadas usan simulación del proveedor exclusivamente en tests; las nueve evaluaciones usan la configuración real existente. Los valores de confianza son heurísticos, no probabilidades calibradas.

La revisión automática del entorno rechazó inicialmente el envío al gateway y la persistencia. Después de la confirmación explícita del usuario para estos datos, destino y hasta tres iteraciones, se ejecutaron las evaluaciones. No se cambiaron credenciales ni configuración permanente.

## D. Resultados de cada iteración

Las alertas se eligieron por ser las primeras pendientes de sus categorías en el dataset, antes de ejecutar el modelo. Se excluyeron las tres alertas WAF del análisis anterior. Se reutilizaron exactamente los mismos tres casos para comparar versiones, conservando todos sus resultados. La variabilidad del modelo impide atribuir cada diferencia entre ejecuciones únicamente al cambio de código.

### Iteración 1

| Alerta | Tipo | Veredicto | Severidad | Escalado | Evaluación |
|---|---|---|---|---|---|
| ALR-20261005-000427 | WAF/LuCI | true_positive | medium | No | Parcial: veredicto y matriz coherentes; afirmaciones de backend y alertas relacionadas insuficientemente citadas. |
| ALR-20261005-000272 | Identidad/spray | true_positive | medium | Sí | Incorrecto: una regla ordinaria de Jira se interpreta como persistencia maliciosa y motiva contención. |
| ALR-20261005-000450 | Cloud/S3 | needs_more_info | high | Sí | Autorización pendiente correctamente conservada; se pierde una tarea manual útil por su objetivo compuesto. |

Confianzas, en ese orden: **0,80 / 0,80 / 0,44**.

El falso soporte de persistencia se originaba en `_claim_support`, que aceptaba la operación `New-InboxRule` sin atender a su configuración; `EscalationEngine` propagaba correctamente esa señal incorrecta. Se corrigió la validación de la señal. El descarte de la tarea cloud procedía del normalizador de objetivos, que exigía una sola coincidencia; se permitió conservar varios recursos conocidos para tareas manuales. Se añadió la relación del servicio IdP con su criticidad oficial y se redujeron preguntas repetidas. Los hallazgos sobre alertas candidatas se separaron de consultas de logs.

### Iteración 2

| Alerta | Tipo | Veredicto | Severidad | Escalado | Evaluación |
|---|---|---|---|---|---|
| ALR-20261005-000427 | WAF/LuCI | true_positive | medium | No | Parcial: la acción aún mezcla SQLi con RCE y conserva una pregunta de ATO no aplicable. |
| ALR-20261005-000272 | Identidad/spray | true_positive | high | Sí | Mejoran señales y matriz; se eliminan las acciones anteriores, pero preguntas y una conclusión negativa conservan premisas no verificadas. |
| ALR-20261005-000450 | Cloud/S3 | true_positive | high | Sí | Incorrecto: la ausencia de aprobación se interpreta como prueba de malicia y se propone desactivar la clave. |

Confianzas: **0,80 / 0,80 / 0,74**.

Se corrigieron en el investigador la mezcla SQLi/regla concreta, preguntas sobre ramas no aplicables y algunas preguntas dependientes de persistencia descartada. Se añadió una comprobación de cobertura para conclusiones negativas sobre todas las cuentas. `VerdictEngine` pasó a impedir un true positive cloud apoyado solo en la operación de configuración pública sin resolver su autorización/clasificación. `ActionRecommender` conservó el seguimiento manual cloud y evitó equiparar ese cambio a compromiso del runner o la clave. También se corrigió una interpretación de negación que rechazaba «queda sin demostrar» como si fuera una afirmación positiva.

### Iteración 3 — última

| Alerta | Tipo | Veredicto | Severidad | Escalado | Evaluación |
|---|---|---|---|---|---|
| ALR-20261005-000427 | WAF/LuCI | needs_more_info | medium | No | Prudente ante una propuesta benigna sin autorización, pero insuficiente: persisten afirmaciones no probadas sobre backend y coordinación. |
| ALR-20261005-000272 | Identidad/spray | true_positive | high | Sí | Veredicto, señales y matriz coherentes; insuficiente por una propuesta de deshabilitar una cuenta sin soporte. |
| ALR-20261005-000450 | Cloud/S3 | needs_more_info | high | Sí | Veredicto y revisión manual razonables; persisten título demasiado concluyente, una ventana mezclada entre fuentes y redundancia. |

Confianzas: **0,50 / 0,80 / 0,44**. La caída del WAF responde a la contradicción de autorización del modelo, no al número de preguntas. El descuento adicional cloud corresponde a contexto de identidad/recurso no resuelto. No se han cambiado estos valores ni los tickets manualmente.

### Evaluación individual de la última versión

**WAF — ALR-20261005-000427.** `WAF-0001904` registra GET a `/cgi-bin/luci/;stok=/locale`, regla 932150, `Remote Command Execution`, `action=blocked`, HTTP 403. La consulta por origen devuelve un registro completo en la ventana. Esto acredita un intento/escaneo bloqueado, sin acreditar explotación. El modelo propone `benign_true_positive` pese a no aportar autorización; la normalización lo convierte en `needs_more_info`, que es el veredicto validado finalmente utilizado. La matriz `low × critical = medium` es correcta; no se aplica −1 por falta de cobertura del backend. No escalar una incertidumbre medium sin señales de compromiso es coherente. Sin embargo, la frase «sin salida exitosa al backend» y la atribución de escaneo «coordinado» a 22 orígenes no están sustentadas por el evento citado. La recomendación manual arrastra esa coordinación. No se recomienda cerrar ni ejecutar contención en esta versión.

**Identidad — ALR-20261005-000272.** Los doce eventos `SIGN-0003615` a `SIGN-0003626` corresponden a doce cuentas, un mismo origen y fallos por `blocked_by_smart_lockout`; sustentan un spray real bloqueado. `AUD-0000019` mueve correo que contiene `jira@` a una carpeta y no demuestra persistencia maliciosa ni compromiso. Las señales finales de persistencia, robo de credenciales y cadena son falsas. La matriz `high × critical = critical`, con −1 por el bloqueo y la revisión del origen, produce high; por tanto, el escalado obligatorio a N2, misma jornada y SLA de 30 minutos se debe a la severidad, no a la regla ordinaria ni al número de preguntas. Las consultas negativas de auditoría se describen por cuenta, fuente y ventana, sin garantizar ausencia global. Aun así, se conserva `disable_user` sobre `ferran.reyes@tarvia.example` con una justificación de «regla sospechosa»: es una propuesta desproporcionada no respaldada por los hallazgos aceptados. Exige N2 y no se ejecutó, pero impide aceptar el ticket como suficientemente coherente. `affected.users` conserva además el marcador original «(12 cuentas)» en lugar de mostrar las identidades ya recuperadas.

**Cloud — ALR-20261005-000450.** Los 72 eventos CloudTrail contienen **25 PutObject, 27 GetObject, 15 ListObjects y 5 PutBucketPolicy**; no son 72 descargas. La política concede lectura a `Principal *` y el origen es el runner interno documentado. Esto no prueba autorización de la política, robo de clave ni fuga de datos personales. El veredicto final `needs_more_info` refleja correctamente la aprobación y clasificación pendientes. No hay criticidad conocida del bucket: se mantiene medium como base provisional y se aplica +1 por acceso/operación realmente realizada, con resultado high y escalado preventivo explícito. Las acciones finales verifican política y aprobación; la desactivación de clave se sustituye por revisión manual. Persisten, sin embargo, «runner CI autorizado» en el título y «actividad normal» en el resumen sin resolver la autorización concreta. El resumen lleva CloudTrail hasta las 09:01 UTC del 6 de octubre, aunque su último evento es **08:54:31 UTC**; las 09:01 proceden de CI/CD. Las recomendaciones de revisión cloud también se solapan.

## E. Tickets generados y JSON conservados

Cada enlace contiene el JSON oficial completo e inalterado. A su lado hay un archivo `.record.json` con análisis original, normalización, decisión, contexto, consultas y trazas.

| Iteración | Alerta | Ticket / JSON |
|---|---|---|
| 1 | ALR-20261005-000427 | [TRIAGE-e162b12c-8efc-4cbf-afe2-63211663a026](iteration_1/ALR-20261005-000427.ticket.json) |
| 1 | ALR-20261005-000272 | [TRIAGE-e36fec3a-473a-473a-8e52-ce30bc7a311f](iteration_1/ALR-20261005-000272.ticket.json) |
| 1 | ALR-20261005-000450 | [TRIAGE-729a873f-2e96-4491-a14c-be55d056786d](iteration_1/ALR-20261005-000450.ticket.json) |
| 2 | ALR-20261005-000427 | [TRIAGE-32cf24fd-1793-45c7-bd27-56f05f487a09](iteration_2/ALR-20261005-000427.ticket.json) |
| 2 | ALR-20261005-000272 | [TRIAGE-86a61e8d-9a6c-488c-a670-4b483757f264](iteration_2/ALR-20261005-000272.ticket.json) |
| 2 | ALR-20261005-000450 | [TRIAGE-600307cd-1f15-4f23-9415-0d40e1a84b10](iteration_2/ALR-20261005-000450.ticket.json) |
| 3 | ALR-20261005-000427 | [TRIAGE-eca47bbb-7ea2-411b-b5e9-6341f51cd34a](iteration_3/ALR-20261005-000427.ticket.json) |
| 3 | ALR-20261005-000272 | [TRIAGE-d89a5d3c-c42e-4fd0-9757-077bf1f0d1ff](iteration_3/ALR-20261005-000272.ticket.json) |
| 3 | ALR-20261005-000450 | [TRIAGE-b715a6e2-90f7-442d-bc05-0c4c7b083306](iteration_3/ALR-20261005-000450.ticket.json) |

Los manifiestos fijan la versión mediante hashes de todos los módulos Python y del prompt. Se comprobó que no hubo cambios en ese código después de iniciar la tercera evaluación. Las tres auditorías `evidence_audit.json` verifican procedencia y reproducción; no certifican el significado de cada frase.

## F. Problemas restantes

| Problema confirmado | Impacto | Origen localizado |
|---|---|---|
| `disable_user` sobre Ferran sigue pasando tras descartar la persistencia | Recomendación disruptiva sin fundamento suficiente, aunque requiere aprobación y no fue ejecutada | La justificación del LLM usa otra formulación; la normalización y `ActionRecommender` no vinculan completamente cada acción a los hallazgos finales. |
| WAF conserva ausencia de salida al backend y coordinación de orígenes | Resumen y recomendación exceden lo que prueba el evento | El LLM formula variantes que no cubren las comprobaciones de `_claim_issues`; `VerdictEngine` no valida toda la semántica de la prosa. |
| Autorización cloud aún aparece en el título tras quedar pendiente en las señales | Contradicción de presentación | La normalización no neutraliza todas las formulaciones de autorización del título al cambiar el veredicto. |
| Ventana CloudTrail contaminada por el último evento CI/CD | Cronología incorrecta en el resumen | El LLM mezcla agregados de fuentes; el control de soporte no comprueba todos los rangos temporales narrados. |
| Revisiones cloud parcialmente redundantes | Menor claridad para N1/N2 | `ActionRecommender` deduplica acciones por nombre y objetivo, pero no por equivalencia semántica de tareas. |
| Marcador «(12 cuentas)» en `affected.users` | Alcance menos útil pese a disponer de los usuarios en evidencias/contexto | `TicketBuilder` conserva las entidades originales sin sustituir ese marcador por identidades recuperadas. |
| Aviso de «propuesta descartada» para una tarea manual compuesta que sí se conserva | Diagnóstico de normalización impreciso | La comparación textual usada para registrar avisos no reconoce siempre el objetivo compuesto normalizado. |

Son problemas observados, no hipótesis. No se ocultan ni se atribuyen exclusivamente al modelo: faltan controles de integración entre hallazgos, preguntas, acciones y presentación. No se modificó el comportamiento después de la última evaluación para aparentar una validación que no se ha realizado. Quedan agotadas las tres iteraciones autorizadas en este trabajo.

Además, la API sigue limitada a 2.000 resultados por consulta y el contexto del modelo se puede muestrear; no se construyó una recuperación exhaustiva global. La cobertura WAF sin backend no permite reducir automáticamente severidad ni descartar compromiso. El proveedor puede variar su salida; esta muestra no mide exactitud sobre las 11.061 alertas. La validación visual interactiva en navegador continúa pendiente.

## G. Revisión final

- Se revisaron los cambios, firmas, modelos, manejo de señales y compatibilidad entre componentes; la suite completa final y la compilación pasan.
- Se mantuvieron la arquitectura y dependencias, y no se introdujeron excepciones por ID de alerta en el código de triaje.
- Se verificaron API, dashboard, fases del orquestador, salida `Analysis`, decisión validada, matriz, escalado, recomendaciones, JSON y persistencia.
- Se conservaron los 16 registros anteriores y las nueve versiones nuevas. Ningún ticket nuevo fue marcado como revisado por una persona.
- No se alteraron credenciales, documentos oficiales, inventarios ni logs originales; no se ejecutó ninguna acción de contención. Los nueve `executed_actions` están vacíos.
- El panel permanece disponible en **http://127.0.0.1:8502** y la API en **http://127.0.0.1:8001**. Se conservaron los servicios ajenos.

La aplicación mejora en controles y trazabilidad, pero **no debe considerarse completamente corregida ni deben aceptarse automáticamente las recomendaciones de estos tickets**. Los fallos de la última evaluación necesitan trabajo adicional en el investigador/normalización, `ActionRecommender` y presentación.
