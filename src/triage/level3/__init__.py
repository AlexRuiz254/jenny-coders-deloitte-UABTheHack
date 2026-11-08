"""Módulo de Nivel 3 (N3): Análisis de alcance, impacto e informe de incidente."""
from __future__ import annotations

from src.triage.level3.scope_analyzer import ScopeAnalysis, ScopeAnalyzer
from src.triage.level3.incident_report_builder import IncidentReport, IncidentReportBuilder

__all__ = [
    "ScopeAnalysis",
    "ScopeAnalyzer",
    "IncidentReport",
    "IncidentReportBuilder",
]
