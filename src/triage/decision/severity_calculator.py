"""Cálculo determinista según el apartado 2 de politica_soc.md."""

from typing import cast
from urllib.parse import urlsplit
from src.triage.investigation.context_enricher import ContextEnricher

from src.triage.models import (
    RawAlert,
    ContextSnapshot,
    Analysis,
    VerdictDecision,
    SeverityDecision,
    Severity,
)


SEVERITY_LEVELS = ("informational", "low", "medium", "high", "critical")
SEVERITY_MATRIX = {
    "informational": {"low": "informational", "medium": "informational", "high": "low", "critical": "low"},
    "low": {"low": "informational", "medium": "low", "high": "low", "critical": "medium"},
    "medium": {"low": "low", "medium": "medium", "high": "medium", "critical": "high"},
    "high": {"low": "medium", "medium": "high", "high": "high", "critical": "critical"},
    "critical": {"low": "high", "medium": "critical", "high": "critical", "critical": "critical"},
}
CRITICALITIES = {
    "baja": "low", "media": "medium", "alta": "high", "crítica": "critical",
    "low": "low", "medium": "medium", "high": "high", "critical": "critical",
}


class SeverityCalculator:
    def calculate(
        self,
        alert: RawAlert,
        context: ContextSnapshot,
        analysis: Analysis,
        verdict: VerdictDecision,
    ) -> SeverityDecision:
        """Cruce severidad regla/criticidad y excepciones autorizadas."""
        if verdict.verdict == "benign_true_positive":
            return SeverityDecision(
                severity="low",
                rationale=(
                    "Excepción de benign_true_positive validada por VerdictEngine. "
                    "Severidad final: low, por la convención conservadora "
                    "adoptada para la actividad autorizada."
                ),
            )

        rule_severity = alert.get("severity")
        if not isinstance(rule_severity, str) or rule_severity not in SEVERITY_LEVELS:
            raise ValueError(f"Severidad inicial ausente o inválida: {rule_severity!r}")

        criticality = self._get_criticality(alert, context)
        reasons = [f"Severidad inicial: {rule_severity}."]
        base_severity = rule_severity
        if criticality is not None:
            base_severity = SEVERITY_MATRIX[rule_severity][criticality]
            reasons.append(f"Mayor criticidad conocida de activos o servicios vinculados a la alerta: {criticality}.")
            reasons.append(f"Resultado de la matriz: {base_severity}.")
        else:
            reasons.append(
                "Sin criticidad conocida de entidades afectadas: no se puede "
                "aplicar la matriz completa; se conserva la severidad inicial como base provisional."
            )
        severity, adjustment = self._apply_adjustments(base_severity, analysis)
        reasons.extend((adjustment, f"Severidad final: {severity}."))

        return SeverityDecision(
            severity=cast(Severity, severity),
            rationale=" ".join(reasons),
        )

    @staticmethod
    def _get_criticality(
        alert: RawAlert, context: ContextSnapshot,
    ) -> str | None:
        """Mayor criticidad conocida entre los activos de las entidades explícitas."""
        entities = alert.get("entities", {})
        entities = entities if isinstance(entities, dict) else {}

        def identifiers(records: object) -> set[str]:
            if not isinstance(records, list):
                return set()
            values = set()
            for record in records:
                candidates = (
                    (record.get(field) for field in ("asset_id", "hostname", "ip"))
                    if isinstance(record, dict) else (record,)
                )
                values.update(value.strip().casefold() for value in candidates if isinstance(value, str) and value.strip())
            return values

        affected_ids = identifiers(entities.get("hosts")) | identifiers(entities.get("ips"))
        known = []
        for asset in context.assets:
            if affected_ids & identifiers([asset]):
                value = asset.get("criticality")
                criticality = CRITICALITIES.get(value.strip().casefold()) if isinstance(value, str) else None
                if criticality is not None:
                    known.append(criticality)
        domains = identifiers(entities.get("domains"))
        for url in entities.get("urls", []):
            value = url.get("url") if isinstance(url, dict) else url
            try:
                if isinstance(value, str) and urlsplit(value).hostname:
                    domains.add(urlsplit(value).hostname.casefold())
            except ValueError:
                continue
        linked_names = {str(a.get("business_service", "")).split(" (≈", 1)[0].casefold()
                        for a in context.assets if affected_ids & identifiers([a])}
        if alert.get("source_product") in {"IDP", "AD"}:
            linked_names.add("identidad y directorio activo")
        if "www.tarvia.example" in domains and alert.get("source_product") in {"WAF", "ECOM"}:
            linked_names.add("tienda online y app")
        for service in context.services:
            if (str(service.get("servicio", "")).casefold() in linked_names
                    or affected_ids and ContextEnricher._scope_matches(service.get("activos", ""), list(affected_ids))):
                criticality = CRITICALITIES.get(str(service.get("criticidad", "")).casefold())
                if criticality:
                    known.append(criticality)
        return max(known, key=SEVERITY_LEVELS.index, default=None)

    def _apply_adjustments(
        self, base_severity: str, analysis: Analysis,
    ) -> tuple[str, str]:
        """Aplicar como máximo ±1 usando los resultados de la investigación.

        blocked_before_effect representa bloqueo antes del efecto y ausencia de
        actividad posterior relevante, confirmados por las etapas anteriores.
        """
        signals = analysis.signals
        factors = [
            reason for active, reason in (
                (signals.execution_or_access_confirmed, "ejecución o acceso confirmado"),
                (signals.privileged_or_vip, "identidad privilegiada o VIP"),
                (signals.sensitive_or_payment_data, "datos personales o de pagos implicados"),
            ) if active
        ]
        index = SEVERITY_LEVELS.index(base_severity)

        if factors:
            adjusted_index = min(index + 1, len(SEVERITY_LEVELS) - 1)
            reason = "Ajuste +1 no acumulativo según analysis.signals por: " + "; ".join(factors) + "."
            if signals.blocked_before_effect:
                reason += (
                    " También se comunica bloqueo; por convención conservadora "
                    "se prioriza la subida, sin compensar ni acumular ajustes."
                )
            if adjusted_index == index:
                reason += " Se mantiene critical por el límite superior."
        elif signals.blocked_before_effect:
            adjusted_index = max(index - 1, 0)
            reason = (
                "Ajuste -1 según analysis.signals por bloqueo confirmado antes "
                "de producir efecto y ausencia de actividad posterior relevante."
            )
            if adjusted_index == index:
                reason += " Se mantiene informational por el límite inferior."
        else:
            adjusted_index = index
            reason = "Sin ajuste: analysis.signals no indica factores de subida ni bloqueo completo."
        return SEVERITY_LEVELS[adjusted_index], reason
