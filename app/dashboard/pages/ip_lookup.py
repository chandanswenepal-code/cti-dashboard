import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..'))
import streamlit as st
from app.api.abuseipdb_client import check_ip
from app.data.database import get_session, IOC

st.set_page_config(page_title="IP Lookup", page_icon="🔍", layout="wide")
st.title("🔍 IP Reputation Lookup")
st.caption("Real-time IP analysis using AbuseIPDB")
st.divider()

ip_input = st.text_input(
    "Enter IP Address to analyze",
    placeholder="e.g. 45.33.32.156",
    help="Enter any IPv4 address to check its threat reputation"
)

col1, col2 = st.columns([1, 4])
with col1:
    analyze = st.button("🔍 Analyze IP", use_container_width=True)

if analyze and ip_input:
    with st.spinner(f"Querying threat intelligence for {ip_input}..."):
        result = check_ip(ip_input)

    st.divider()
    score = result["abuse_score"]

    if score >= 75:
        st.error(f"🚨 HIGH RISK — Abuse Score: {score}/100")
        recommendation = "BLOCK immediately at firewall. Do not allow any connections."
    elif score >= 25:
        st.warning(f"⚠️ MEDIUM RISK — Abuse Score: {score}/100")
        recommendation = "Monitor closely. Investigate source and purpose of traffic."
    else:
        st.success(f"✅ LOW RISK — Abuse Score: {score}/100")
        recommendation = "No significant threat signals. Continue normal monitoring."

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Abuse Score", f"{score}/100")
    col2.metric("Country", result["country"])
    col3.metric("Total Reports", result["total_reports"])
    col4.metric("Tor Exit Node", "Yes ⚠️" if result["is_tor"] else "No ✅")

    st.info(f"**ISP:** {result['isp']}  |  **Domain:** {result['domain']}")
    st.subheader("Analyst Recommendation")
    st.write(recommendation)

    # Check if IOC is in our database
    session = get_session()
    existing = session.query(IOC).filter_by(indicator=ip_input).first()
    session.close()

    if existing:
        st.subheader("🗺️ MITRE ATT&CK Mapping")
        st.info(f"This IP is linked to: **{existing.mitre_tactic}**")
        st.write(f"**Threat Actor:** {existing.threat_actor}")
        st.write(f"**Pulse:** {existing.pulse_name}")
    else:
        st.info("This IP is not in our current IOC database.")

elif analyze and not ip_input:
    st.error("Please enter an IP address.")