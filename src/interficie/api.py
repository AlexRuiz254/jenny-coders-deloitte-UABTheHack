"""Entrada ASGI anterior: sirve la API SOC oficial, sin crear tickets ficticios."""
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path

path = Path(__file__).resolve().parents[2] / "RepositoriDeloitte/06_herramientas/mock_soc_api.py"
spec = spec_from_file_location("tarvia_mock_soc_api", path)
module = module_from_spec(spec)
spec.loader.exec_module(module)
app = module.app
