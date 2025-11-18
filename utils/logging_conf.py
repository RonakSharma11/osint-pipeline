# utils/logging_conf.py
import logging
from logging.config import dictConfig
from .config import Config

def setup_logging():
    level = getattr(logging, Config.LOG_LEVEL.upper(), logging.INFO)
    dictConfig({
        "version": 1,
        "formatters": {
            "default": {"format": "%(asctime)s | %(levelname)s | %(name)s | %(message)s"}
        },
        "handlers": {
            "console": {"class": "logging.StreamHandler", "formatter": "default"}
        },
        "root": {"handlers": ["console"], "level": level}
    })
