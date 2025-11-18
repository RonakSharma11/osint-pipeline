# utils/cache.py
import os
import json
import time
try:
    import redis
except Exception:
    redis = None

from .config import Config

class Cache:
    """
    Simple cache wrapper: uses Redis if configured, otherwise simple on-disk JSON cache.
    Methods: get(key) -> value or None, set(key, value, ttl_seconds)
    """
    def __init__(self):
        self.cache_dir = "./.cache"
        os.makedirs(self.cache_dir, exist_ok=True)
        self.use_redis = False
        if redis and Config.REDIS_HOST:
            try:
                self.r = redis.Redis(host=Config.REDIS_HOST, port=Config.REDIS_PORT, db=0, socket_connect_timeout=2)
                self.r.ping()
                self.use_redis = True
            except Exception:
                self.use_redis = False

    def _path(self, key):
        safe = key.replace("/", "_").replace(":", "_")
        return os.path.join(self.cache_dir, f"{safe}.json")

    def get(self, key):
        if self.use_redis:
            val = self.r.get(key)
            if not val:
                return None
            try:
                return json.loads(val)
            except Exception:
                return None
        else:
            p = self._path(key)
            if not os.path.exists(p):
                return None
            try:
                with open(p, "r") as f:
                    data = json.load(f)
                expiry = data.get("_expiry")
                if expiry and time.time() > expiry:
                    try:
                        os.remove(p)
                    except Exception:
                        pass
                    return None
                return data.get("value")
            except Exception:
                return None

    def set(self, key, value, ttl=3600):
        if self.use_redis:
            self.r.setex(key, ttl, json.dumps(value))
        else:
            p = self._path(key)
            with open(p, "w") as f:
                json.dump({"_expiry": time.time() + ttl, "value": value}, f)
