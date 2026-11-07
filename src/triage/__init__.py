"""Módulo principal de triaje SOC (compatible con imports tarvia_soc)."""
import importlib
import sys

sys.modules.setdefault("tarvia_soc", sys.modules[__name__])
sys.modules.setdefault("tarvia_soc.orchestration", sys.modules[__name__])
try:
    sys.modules.setdefault("tarvia_soc.data", importlib.import_module("src.data"))
except ModuleNotFoundError:
    pass
