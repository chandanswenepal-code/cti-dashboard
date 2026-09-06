from apscheduler.schedulers.blocking import BlockingScheduler
from app.api.otx_client import get_recent_pulses, extract_iocs
from app.api.abuseipdb_client import check_ip
from app.api.mitre_mapper import map_tags_to_mitre
from app.data.database import init_db, get_session, IOC
from datetime import datetime

def fetch_and_store():
    print(f"\n[{datetime.now()}] Fetching threat intelligence...")
    session = get_session()
    pulses = get_recent_pulses(limit=20)
    added = 0

    for pulse in pulses:
        iocs = extract_iocs(pulse)
        for ioc_data in iocs:
            if ioc_data["ioc_type"] not in ["IPv4", "IPv6", "domain", "hostname", "URL"]:
                continue
            existing = session.query(IOC).filter_by(
                indicator=ioc_data["indicator"]
            ).first()
            if existing:
                continue
            abuse_data = {"abuse_score": 0, "country": "Unknown",
                         "isp": "Unknown", "total_reports": 0}
            if ioc_data["ioc_type"] in ["IPv4", "IPv6"]:
                abuse_data = check_ip(ioc_data["indicator"])

            new_ioc = IOC(
                indicator=ioc_data["indicator"],
                ioc_type=ioc_data["ioc_type"],
                pulse_name=ioc_data["pulse_name"],
                threat_actor=ioc_data["threat_actor"],
                tags=ioc_data["tags"],
                abuse_score=abuse_data.get("abuse_score", 0),
                country=abuse_data.get("country", "Unknown"),
                isp=abuse_data.get("isp", "Unknown"),
                total_reports=abuse_data.get("total_reports", 0),
                mitre_tactic=map_tags_to_mitre(ioc_data["tags"])
            )
            session.add(new_ioc)
            added += 1

    session.commit()
    session.close()
    print(f"Done! Added {added} new IOCs.")

if __name__ == "__main__":
    init_db()
    fetch_and_store()
    scheduler = BlockingScheduler()
    scheduler.add_job(fetch_and_store, "interval", hours=6)
    print("Scheduler running — fetching every 6 hours.")
    scheduler.start()