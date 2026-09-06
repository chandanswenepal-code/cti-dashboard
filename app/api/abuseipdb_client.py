import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

import requests

try:
    import streamlit as st
    ABUSE_KEY = st.secrets["ABUSEIPDB_API_KEY"]
except Exception:
    from dotenv import load_dotenv
    load_dotenv()
    ABUSE_KEY = os.getenv("ABUSEIPDB_API_KEY")

BASE_URL = "https://api.abuseipdb.com/api/v2"

def check_ip(ip_address):
    headers = {
        "Key": ABUSE_KEY,
        "Accept": "application/json"
    }
    try:
        r = requests.get(
            f"{BASE_URL}/check",
            headers=headers,
            params={
                "ipAddress": ip_address,
                "maxAgeInDays": 90,
                "verbose": True
            },
            timeout=10
        )
        r.raise_for_status()
        data = r.json().get("data", {})
        return {
            "ip": ip_address,
            "abuse_score": data.get("abuseConfidenceScore", 0),
            "country": data.get("countryCode", "Unknown"),
            "isp": data.get("isp", "Unknown"),
            "total_reports": data.get("totalReports", 0),
            "is_tor": data.get("isTor", False),
            "domain": data.get("domain", "Unknown")
        }
    except Exception as e:
        print(f"AbuseIPDB Error: {e}")
        return {
            "ip": ip_address,
            "abuse_score": 0,
            "country": "Unknown",
            "isp": "Unknown",
            "total_reports": 0,
            "is_tor": False,
            "domain": "Unknown"
        }