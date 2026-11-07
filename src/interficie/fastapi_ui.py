"""Entrada anterior de Streamlit; abre el panel SOC integrado."""
from pathlib import Path
import sys

root = Path(__file__).resolve().parents[2]
if str(root) not in sys.path:
    sys.path.insert(0, str(root))

from src.interficie.dashboard import main

if __name__ == "__main__":
    main()
