"""Módulo principal de triaje SOC (compatible con imports tarvia_soc y src.triage)."""
from __future__ import annotations

import importlib
import importlib.abc
import importlib.machinery
import sys
from types import ModuleType


class _TarviaSocAliasLoader(importlib.abc.Loader):
    """Carga módulos de tarvia_soc.* reutilizando exactamente el módulo de src.triage.* o src.data.*."""

    def __init__(self, target_name: str) -> None:
        self.target_name = target_name

    def create_module(self, spec: importlib.machinery.ModuleSpec) -> ModuleType:
        module = importlib.import_module(self.target_name)
        sys.modules[spec.name] = module
        return module

    def exec_module(self, module: ModuleType) -> None:
        pass


class _TarviaSocAliasFinder(importlib.abc.MetaPathFinder):
    """Redirige cualquier importación de tarvia_soc.* hacia los módulos únicos de src.*."""

    def find_spec(
        self,
        fullname: str,
        path: object = None,
        target: ModuleType | None = None,
    ) -> importlib.machinery.ModuleSpec | None:
        if fullname == "tarvia_soc":
            target_name = "src.triage"
        elif fullname.startswith("tarvia_soc.data"):
            suffix = fullname[len("tarvia_soc.data"):]
            target_name = f"src.data{suffix}"
        elif fullname.startswith("tarvia_soc.orchestration"):
            suffix = fullname[len("tarvia_soc.orchestration"):]
            target_name = f"src.triage{suffix}"
        elif fullname.startswith("tarvia_soc."):
            suffix = fullname[len("tarvia_soc."):]
            target_name = f"src.triage.{suffix}"
        else:
            return None

        loader = _TarviaSocAliasLoader(target_name)
        return importlib.machinery.ModuleSpec(fullname, loader)


if not any(isinstance(f, _TarviaSocAliasFinder) for f in sys.meta_path):
    sys.meta_path.insert(0, _TarviaSocAliasFinder())

sys.modules.setdefault("tarvia_soc", sys.modules[__name__])
