# collectors/otx_collector.py
import requests
from collectors.base_collector import BaseCollector
from utils.config import Config

class OTXCollector(BaseCollector):
    API_URL = "https://otx.alienvault.com/api/v1/indicators/export"

    def collect(self):
        headers = {"X-OTX-API-KEY": Config.OTX_API_KEY}
        iocs = []
        try:
            response = requests.get(self.API_URL, headers=headers, params={"limit": 50})
            response.raise_for_status()
            data = response.json()
            for entry in data.get("results", []):
                if entry["type"] in ("IPv4", "IPv6"):
                    iocs.append({"type": "ip", "value": entry["indicator"], "source": "OTX"})
                elif entry["type"] == "domain":
                    iocs.append({"type": "domain", "value": entry["indicator"], "source": "OTX"})
        except Exception as e:
            print(f"OTXCollector error: {e}")
        return iocs
