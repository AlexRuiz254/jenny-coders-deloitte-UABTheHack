class TriageOrchestrator:

    def run(self, alert_id):

        started_at = start_timer()

        # 1. Obtener y normalizar alerta
        raw_alert = self.alert_loader.load_alert(alert_id)
        alert = self.normalizer.normalize(raw_alert)

        # 2. Seleccionar procedimiento
        runbook = self.runbook_registry.get_runbook_for_rule(
            alert.rule_id
        )

        # 3. Planificar investigación
        plan = self.planner.create_plan(alert, runbook)

        # 4. Obtener contexto
        context = self.context_enricher.enrich(alert)

        # 5. Enriquecer indicadores
        intel = self.intel_enricher.enrich(
            alert.entities.indicators
        )

        # 6. Obtener eventos iniciales
        evidence = self.evidence_collector.collect_related_events(
            alert
        )

        # 7. Investigación con IA
        # Puede pedir consultas adicionales
        investigation = self.investigation_agent.investigate(
            alert=alert,
            plan=plan,
            context=context,
            intel=intel,
            initial_evidence=evidence
        )

        # 8. Buscar alertas relacionadas
        related = self.correlator.find_related_alerts(alert)

        # Incorporar relaciones fundamentadas
        investigation.add_related_alerts(related)

        # 9. Determinar veredicto
        verdict = self.verdict_engine.decide(investigation)

        # 10. Calcular severidad
        severity = self.severity_calculator.calculate(
            alert, context, investigation, verdict
        )

        # 11. Determinar escalado
        escalation = self.escalation_engine.decide(
            verdict, severity, investigation
        )

        # 12. Recomendar acciones
        actions = self.action_recommender.recommend(
            verdict, severity, investigation, context
        )

        # 13. Crear ticket
        ticket = self.ticket_builder.build(
            alert=alert,
            investigation=investigation,
            verdict=verdict,
            severity=severity,
            escalation=escalation,
            actions=actions,
            elapsed_seconds=elapsed_time(started_at)
        )

        # 14. Validar
        self.ticket_validator.validate_complete_ticket(
            ticket, context
        )

        # 15. Guardar
        self.ticket_repository.save_ticket(ticket)

        return ticket