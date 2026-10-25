"""Application launcher using Streamlit's CLI entry point."""

from pathlib import Path
import sys


def main() -> None:
    try:
        from streamlit.web import cli as streamlit_cli
    except ImportError as exc:
        raise RuntimeError("Install dashboard dependencies with: python -m pip install -r requirements.txt") from exc
    dashboard = Path(__file__).with_name("dashboard.py")
    sys.argv = ["streamlit", "run", str(dashboard)]
    streamlit_cli.main()


if __name__ == "__main__":
    main()
