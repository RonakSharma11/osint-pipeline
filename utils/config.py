# utils/config.py
import os
from dotenv import load_dotenv

load_dotenv()  # Load .env file

# Module-level DEMO_MODE for easy imports
DEMO_MODE = os.getenv("DEMO_MODE", "True").lower() in ("1", "true", "yes")

class Config:
    """Central configuration class for the OSINT pipeline"""
    DEMO_MODE = DEMO_MODE
    LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
    APP_HOST = os.getenv("APP_HOST", "0.0.0.0")
    APP_PORT = int(os.getenv("APP_PORT", 8080))
    REDIS_HOST = os.getenv("REDIS_HOST", "")
    REDIS_PORT = int(os.getenv("REDIS_PORT") or 6379)
    OPENSEARCH_HOST = os.getenv("OPENSEARCH_HOST", "http://opensearch:9200")
    OPENSEARCH_INDEX = os.getenv("OPENSEARCH_INDEX", "osint-iocs")
    GEOIP_DB_PATH = os.getenv("GEOIP_DB_PATH", "geolite2/GeoLite2-City.mmdb")
    OTX_API_KEY = os.getenv("OTX_API_KEY", "")
    ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
    SCHEDULE_INTERVAL_MIN = int(os.getenv("SCHEDULE_INTERVAL_MINUTES") or 15)
    STIX_TLP = os.getenv("STIX_TLP", "AMBER")
    ALLOW_PUBLIC_FETCH = os.getenv("ALLOW_PUBLIC_FETCH", "true").lower() in ("1", "true", "yes")
