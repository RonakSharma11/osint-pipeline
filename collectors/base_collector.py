# collectors/base_collector.py
import logging

logger = logging.getLogger(__name__)

class BaseCollector:
    def __init__(self, demo=False):
        self.demo = demo

    def collect(self):
        raise NotImplementedError("Collect method must be implemented in subclass")
