# Mapa de pruebas del producto SOC N1–N4

Validación de entrega del 8 de noviembre de 2026: **434 passed, 2 warnings** en
95,05 segundos, con instalación limpia de dependencias. Las dos advertencias
proceden de `datetime.utcnow()` en la API oficial simulada. No hay fallos finales.

| Área | Cobertura automatizada | Archivos principales |
|---|---|---|
| Catálogo y runbooks | 44 reglas, diez estrategias, nombres de fuentes y planes particulares | `test_runbook_registry.py`, `investigation/strategies/` |
| API y evidencias | Eventos exactos, ventanas, consultas incompletas, contexto y procedencia | `test_investigation_regressions.py`, `test_level1_integration.py` |
| LLM | Configuración, transporte y fallos controlados; instrucciones no fiables en entradas | `test_llm_client.py`, `investigation/test_investigation_agent.py` |
| N1 | Veredicto, severidad, escalado, autorización, coherencia de hallazgos y acciones por objetivo | `test_ticket_coherence.py`, `test_level1_integration.py` |
| N2 | Agrupación anclada a la alerta, separación de incidentes, autorización por ámbito y versiones | `test_incident_grouper.py`, `test_incident_decision_service.py`, `test_incident_ticket_service.py`, `test_level2_orchestrator.py`, `test_level2_integration.py` |
| N3 | Reconstrucción causal, clic ordinario y bloqueo, alcance, referencias, fechas y esquema oficial | `test_attack_reconstructor.py`, `level3/` |
| N4 | Roles, integridad, expiración, revocación, separación de funciones, restricciones OT, API y ejecutor | `level4/` |
| Producto integrado | N1 guardado → N2 → N3 → N4, rechazos, reinicio, doble aprobación y ejecución idempotente | `test_product_workflow.py` |
| Interfaz | Investigación, filtros, revisión, importación y fallos; informes con miles de notas; selección y confirmaciones N4 | `test_level1_integration.py`, `test_product_workflow.py` |

## Qué es real y qué se simula

Los tests automatizados usan un LLM de ensayo. La mayoría de integraciones ejecutan
las funciones reales de FastAPI en memoria y escriben SQLite y registros de contención
solo en carpetas temporales. No demuestran disponibilidad ni calidad del proveedor IA.
La prueba de doble aprobación añade un propietario **solo a su fixture**: FS01 carece
de ese dato en el inventario oficial y permanece manual en el producto real.

La [validación en navegador](../reports/product_validation_20261108/INFORME.md)
utilizó Streamlit real, HTTP contra la API oficial local y tres investigaciones con
el proveedor `ornith` configurado. Creó dos versiones N3 desde el panel, comprobó
rechazo, permisos insuficientes y renovación, y ejecutó un único aislamiento simulado.
La autenticación humana sigue siendo de ensayo, explícitamente identificada.

Una auditoría adicional comprobó 4.445 evidencias de los tickets y del último informe
contra los ficheros originales, además de fechas de cronología y contratos oficiales.
Esto comprueba procedencia; no convierte cualquier narración del modelo en un hecho.

## Repetir

Desde la raíz del repositorio, con dependencias instaladas:

```powershell
.\.venv\Scripts\python.exe -m pytest -q --basetemp=.test-pytest --tb=short
.\.venv\Scripts\python.exe -m compileall -q src run_server.py
.\.venv\Scripts\python.exe -m pip check
```

Para repetir la auditoría de los artefactos de esta sesión, conserva las tres bases
locales y la API 8001 disponible:

```powershell
.\.venv\Scripts\python.exe reports/product_validation_20261108/validate_artifacts.py
```

El script es de lectura, no llama al modelo ni ejecuta contención. Si vuelves a
investigar los casos, los nuevos IDs pueden diferir: usa los del nuevo recorrido.
