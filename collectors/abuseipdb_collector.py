# collectors/abuseipdb_collector.py
import requests
from collectors.base_collector import BaseCollector
from utils.config import Config

class AbuseIPDBCollector(BaseCollector):
    API_URL = "https://api.abuseipdb.com/api/v2/blacklist"

    def collect(self):
        headers = {
            "Key": Config.ABUSEIPDB_API_KEY,
            "Accept": "application/json"
        }
        iocs = []
        try:
            response = requests.get(self.API_URL, headers=headers, params={"confidenceMinimum": 50})
            response.raise_for_status()
            data = response.json()
            for entry in data.get("data", []):
                iocs.append({"type": "ip", "value": entry["ipAddress"], "source": "AbuseIPDB"})
        except Exception as e:
            print(f"AbuseIPDBCollector error: {e}")
        return iocs
