"""Arrancar exclusivamente la API simulada Deloitte, sin modificar sus datos."""
from pathlib import Path
import argparse

import uvicorn


def main() -> None:
    parser = argparse.ArgumentParser(description="API SOC simulada Deloitte")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()
    uvicorn.run("mock_soc_api:app", host="127.0.0.1", port=args.port,
                app_dir=str(Path(__file__).resolve().parent / "RepositoriDeloitte/06_herramientas"))


if __name__ == "__main__":
    main()
