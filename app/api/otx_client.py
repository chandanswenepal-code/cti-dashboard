import requests
import os
from dotenv import load_dotenv

load_dotenv()

OTX_KEY = os.getenv("OTX_API_KEY")
BASE_URL = "https://otx.alienvault.com/api/v1"

def get_recent_pulses(limit=20):
    headers = {"X-OTX-API-KEY": OTX_KEY}
    try:
        r = requests.get(
            f"{BASE_URL}/pulses/subscribed",
            headers=headers,
            params={"limit": limit},
            timeout=15
        )
        r.raise_for_status()
        return r.json().get("results", [])
    except Exception as e:
        print(f"OTX Error: {e}")
        return []

def extract_iocs(pulse):
    iocs = []
    for ind in pulse.get("indicators", []):
        iocs.append({
            "indicator": ind.get("indicator", ""),
            "ioc_type": ind.get("type", "unknown"),
            "pulse_name": pulse.get("name", "Unknown"),
            "threat_actor": pulse.get("author_name", "Unknown"),
            "tags": ",".join(pulse.get("tags", [])),
        })
    return iocs

def test_connection():
    pulses = get_recent_pulses(limit=2)
    if pulses:
        print(f"OTX Connected! Got {len(pulses)} pulses.")
        return True
    print("OTX connection failed.")
    return False