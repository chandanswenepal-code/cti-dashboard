import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..')))

import streamlit as st
import plotly.graph_objects as go
from app.api.abuseipdb_client import check_ip
from app.data.database import get_session, IOC

st.set_page_config(page_title="IP Lookup", page_icon="🔍", layout="wide")

st.markdown("""
<style>
[data-testid="stMetric"] {
    background:white;border-radius:10px;
    padding:1rem;box-shadow:0 2px 8px rgba(0,0,0,0.06);
}
.block-container { padding-top: 1rem; }
</style>
""", unsafe_allow_html=True)

st.markdown("""
<div style="background:linear-gradient(135deg,#0f0c29,#302b63);
            padding:1.5rem 2rem;border-radius:15px;margin-bottom:1.5rem">
    <h1 style="color:white;margin:0;font-size:2rem">🔍 IP Reputation Lookup</h1>
    <p style="color:#aaa;margin:0.3rem 0 0">Real-time IP threat analysis · AbuseIPDB · MITRE ATT&CK Mapping</p>
</div>
""", unsafe_allow_html=True)

col_input, col_btn = st.columns([4,1])
with col_input:
    ip_input = st.text_input(
        "IP Address",
        placeholder="Enter any IPv4 address — e.g. 185.220.101.1",
        label_visibility="collapsed"
    )
with col_btn:
    analyze = st.button("🔍 Analyze", use_container_width=True, type="primary")

st.markdown("""
> **Quick test IPs:** `185.220.101.1` (Tor exit node) · `198.235.24.1` (Scanner) · `8.8.8.8` (Google — Clean)
""")

if analyze and ip_input:
    with st.spinner(f"Querying threat intelligence for **{ip_input}**..."):
        result = check_ip(ip_input.strip())

    score = result["abuse_score"]

    if score >= 75:
        risk_level, risk_color, bg_color = "🔴 HIGH RISK", "#e74c3c", "#fff5f5"
        recommendation = "BLOCK immediately at firewall level. Do not allow any connections."
        action = "Escalate to Tier 2. Create firewall block rule. Document in incident log."
        badge = "🚨 CRITICAL"
    elif score >= 25:
        risk_level, risk_color, bg_color = "🟡 MEDIUM RISK", "#f39c12", "#fffbf0"
        recommendation = "Monitor closely. Investigate the source and purpose of this traffic."
        action = "Add to watchlist. Review associated logs. Check for lateral movement."
        badge = "⚠️ SUSPICIOUS"
    else:
        risk_level, risk_color, bg_color = "🟢 LOW RISK", "#27ae60", "#f0fff4"
        recommendation = "No significant threat signals. Continue standard monitoring."
        action = "No immediate action required. Log for baseline reference."
        badge = "✅ CLEAN"

    st.markdown(f"""
    <div style="background:{bg_color};border-left:6px solid {risk_color};
                border-radius:10px;padding:1rem 1.5rem;margin-bottom:1rem">
        <h2 style="color:{risk_color};margin:0">{risk_level} — Score: {score}/100</h2>
        <p style="color:#555;margin:0.3rem 0 0">🔎 {recommendation}</p>
    </div>
    """, unsafe_allow_html=True)

    col_gauge, col_info = st.columns([1, 1.5])

    with col_gauge:
        fig = go.Figure(go.Indicator(
            mode="gauge+number",
            value=score,
            domain={"x":[0,1],"y":[0,1]},
            title={"text":"Abuse Confidence Score","font":{"size":15}},
            number={"suffix":"/100","font":{"color":risk_color,"size":36}},
            gauge={
                "axis":{"range":[0,100],"tickwidth":1,"tickcolor":"#ccc"},
                "bar":{"color":risk_color,"thickness":0.25},
                "bgcolor":"white",
                "steps":[
                    {"range":[0,25],"color":"#d5f5e3"},
                    {"range":[25,75],"color":"#fef9e7"},
                    {"range":[75,100],"color":"#fadbd8"},
                ],
                "threshold":{
                    "line":{"color":"black","width":3},
                    "thickness":0.75,"value":score
                }
            }
        ))
        fig.update_layout(
            height=280, margin=dict(l=20,r=20,t=60,b=20),
            paper_bgcolor="rgba(0,0,0,0)"
        )
        st.plotly_chart(fig, use_container_width=True)

    with col_info:
        st.markdown("#### 📋 IP Intelligence Report")
        r1, r2 = st.columns(2)
        r1.metric("🌍 Country", result["country"])
        r2.metric("📊 Abuse Reports", f"{result['total_reports']:,}")
        r1.metric("🏢 ISP", result["isp"][:22]+"..." if len(result["isp"])>22 else result["isp"])
        r2.metric("🧅 Tor Node", "YES ⚠️" if result["is_tor"] else "No ✅")
        st.markdown(f"**Domain:** `{result['domain']}`")
        st.markdown(f"**Risk Badge:** {badge}")

        if result["is_tor"]:
            st.error("🧅 Known **Tor exit node** — traffic is anonymized and commonly malicious")

    st.markdown("#### 🎯 SOC Analyst Action Plan")
    st.info(f"**Recommended Action:** {action}")

    col_t1, col_t2, col_t3 = st.columns(3)
    reports = result["total_reports"]
    report_level = "Critical" if reports > 100 else ("Moderate" if reports > 10 else "Low")
    tor_status = "Anonymous (Tor)" if result["is_tor"] else "Standard"

    with col_t1:
        st.markdown(f"""
        <div style="background:#f8f9fa;border-radius:10px;padding:1.2rem;text-align:center;border-top:3px solid {risk_color}">
            <div style="font-size:2rem">🔥</div>
            <div style="font-weight:600;color:#555;font-size:0.85rem">THREAT SCORE</div>
            <div style="font-size:1.8rem;color:{risk_color};font-weight:700">{score}/100</div>
        </div>
        """, unsafe_allow_html=True)
    with col_t2:
        st.markdown(f"""
        <div style="background:#f8f9fa;border-radius:10px;padding:1.2rem;text-align:center;border-top:3px solid #3498db">
            <div style="font-size:2rem">📝</div>
            <div style="font-weight:600;color:#555;font-size:0.85rem">REPORT VOLUME</div>
            <div style="font-size:1.8rem;font-weight:700">{reports}</div>
            <div style="font-size:0.75rem;color:#888">{report_level} activity</div>
        </div>
        """, unsafe_allow_html=True)
    with col_t3:
        st.markdown(f"""
        <div style="background:#f8f9fa;border-radius:10px;padding:1.2rem;text-align:center;border-top:3px solid #9b59b6">
            <div style="font-size:2rem">🧅</div>
            <div style="font-weight:600;color:#555;font-size:0.85rem">TRAFFIC TYPE</div>
            <div style="font-size:1.1rem;font-weight:700">{tor_status}</div>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("---")
    session = get_session()
    existing = session.query(IOC).filter_by(indicator=ip_input.strip()).first()
    session.close()

    if existing:
        st.markdown("#### 🗺️ MITRE ATT&CK Intelligence")
        st.markdown(f"""
        <div style="background:#eaf4fb;border-radius:10px;padding:1.2rem;border-left:5px solid #2980b9">
            <table style="width:100%;font-size:0.95rem">
                <tr><td style="color:#888;width:140px">ATT&CK Tactic</td><td><b>{existing.mitre_tactic}</b></td></tr>
                <tr><td style="color:#888">Threat Actor</td><td><b>{existing.threat_actor}</b></td></tr>
                <tr><td style="color:#888">Campaign</td><td>{existing.pulse_name}</td></tr>
                <tr><td style="color:#888">Tags</td><td><code>{existing.tags}</code></td></tr>
            </table>
        </div>
        """, unsafe_allow_html=True)
    else:
        st.info("ℹ️ This IP is not in our current IOC database — may be a new or unlisted indicator.")

elif analyze and not ip_input:
    st.error("⚠️ Please enter a valid IP address.")