"""Configure application logging without configuring the root logger."""

import logging
from pathlib import Path


def configure_app_logging(path: str | Path = "soc_data/application.log") -> logging.Logger:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger("soc_toolkit")
    logger.setLevel(logging.INFO)
    if not any(getattr(handler, "baseFilename", None) == str(target.resolve()) for handler in logger.handlers):
        handler = logging.FileHandler(target, encoding="utf-8")
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s"))
        logger.addHandler(handler)
    return logger
