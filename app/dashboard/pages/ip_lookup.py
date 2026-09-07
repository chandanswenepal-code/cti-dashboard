import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..')))

import streamlit as st
import plotly.graph_objects as go
import requests
from app.api.abuseipdb_client import check_ip
from app.data.database import get_session, IOC

st.set_page_config(page_title="IP Lookup", page_icon="🔍", layout="wide")

st.markdown("""
<style>
    .lookup-header {
        background: linear-gradient(135deg, #0f0c29, #302b63);
        padding: 1.5rem 2rem;
        border-radius: 15px;
        margin-bottom: 1.5rem;
        color: white;
    }
    .lookup-header h1 { color: white; margin: 0; font-size: 2rem; }
    .lookup-header p { color: #aaa; margin: 0.3rem 0 0; }
    .result-card {
        background: white;
        border-radius: 12px;
        padding: 1.5rem;
        box-shadow: 0 2px 15px rgba(0,0,0,0.08);
        margin-bottom: 1rem;
    }
    .risk-high { border-left: 6px solid #e74c3c; }
    .risk-medium { border-left: 6px solid #f39c12; }
    .risk-low { border-left: 6px solid #27ae60; }
    .info-grid {
        display: grid;
        grid-template-columns: 1fr 1fr;
        gap: 1rem;
    }
    .info-item { padding: 0.5rem; }
    .info-label { font-size: 0.75rem; color: #888; text-transform: uppercase; letter-spacing: 1px; }
    .info-value { font-size: 1.1rem; font-weight: 600; color: #2c3e50; }
    div[data-testid="stMetric"] {
        background: white;
        border-radius: 10px;
        padding: 1rem;
        box-shadow: 0 2px 8px rgba(0,0,0,0.06);
    }
</style>
""", unsafe_allow_html=True)

st.markdown("""
<div class="lookup-header">
    <h1>🔍 IP Reputation Lookup</h1>
    <p>Real-time IP threat analysis · AbuseIPDB · Geolocation · MITRE ATT&CK Mapping</p>
</div>
""", unsafe_allow_html=True)

col_input, col_btn = st.columns([4, 1])
with col_input:
    ip_input = st.text_input(
        "Enter IP Address",
        placeholder="e.g. 45.33.32.156  |  Try known malicious IPs for demo",
        label_visibility="collapsed"
    )
with col_btn:
    analyze = st.button("🔍 Analyze", use_container_width=True, type="primary")

st.markdown("""
**Quick test IPs:** 
`185.220.101.1` (Tor) · `198.235.24.1` (Scanner) · `8.8.8.8` (Google - Clean)
""")

if analyze and ip_input:
    with st.spinner(f"🔍 Querying threat intelligence databases for {ip_input}..."):
        result = check_ip(ip_input.strip())

    score = result["abuse_score"]

    if score >= 75:
        risk_level = "🔴 HIGH RISK"
        risk_color = "#e74c3c"
        risk_class = "risk-high"
        bg_color = "#fff5f5"
        recommendation = "🚨 BLOCK immediately at firewall level. Do not allow any inbound or outbound connections from this IP."
        action = "Escalate to Tier 2 analyst. Create firewall block rule. Document in incident log."
    elif score >= 25:
        risk_level = "🟡 MEDIUM RISK"
        risk_color = "#f39c12"
        risk_class = "risk-medium"
        bg_color = "#fffbf0"
        recommendation = "⚠️ Monitor closely. Investigate the source and purpose of traffic from this IP."
        action = "Add to watchlist. Review associated logs. Check for lateral movement."
    else:
        risk_level = "🟢 LOW RISK"
        risk_color = "#27ae60"
        risk_class = "risk-low"
        bg_color = "#f0fff4"
        recommendation = "✅ No significant threat signals detected. Continue standard monitoring."
        action = "No immediate action required. Log for baseline reference."

    st.markdown(f"""
    <div style="background:{bg_color}; border-left:6px solid {risk_color}; 
                border-radius:10px; padding:1rem 1.5rem; margin-bottom:1rem">
        <h2 style="color:{risk_color}; margin:0">{risk_level} — Score: {score}/100</h2>
        <p style="color:#555; margin:0.3rem 0 0">{recommendation}</p>
    </div>
    """, unsafe_allow_html=True)

    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=score,
        domain={"x": [0, 1], "y": [0, 1]},
        title={"text": "Abuse Confidence Score", "font": {"size": 16}},
        gauge={
            "axis": {"range": [0, 100], "tickwidth": 1},
            "bar": {"color": risk_color},
            "steps": [
                {"range": [0, 25], "color": "#d5f5e3"},
                {"range": [25, 75], "color": "#fef9e7"},
                {"range": [75, 100], "color": "#fadbd8"},
            ],
            "threshold": {
                "line": {"color": "black", "width": 3},
                "thickness": 0.75,
                "value": score
            }
        }
    ))
    fig.update_layout(height=280, margin=dict(l=20, r=20, t=40, b=20),
                      paper_bgcolor="rgba(0,0,0,0)")

    col_gauge, col_details = st.columns([1, 1.5])

    with col_gauge:
        st.plotly_chart(fig, use_container_width=True)

    with col_details:
        st.markdown("#### 📋 IP Intelligence Report")
        c1, c2 = st.columns(2)
        c1.metric("🌍 Country", result["country"])
        c2.metric("📊 Total Reports", f"{result['total_reports']:,}")
        c1.metric("🏢 ISP", result["isp"][:20] + "..." if len(result["isp"]) > 20 else result["isp"])
        c2.metric("🧅 Tor Exit Node", "YES ⚠️" if result["is_tor"] else "No ✅")

        if result["is_tor"]:
            st.error("🧅 This IP is a known **Tor exit node** — commonly used to anonymize malicious activity")

        st.markdown(f"**Domain:** `{result['domain']}`")

    st.markdown("#### 🎯 Analyst Action Plan")
    st.info(f"**Recommended Action:** {action}")

    col_t1, col_t2, col_t3 = st.columns(3)
    with col_t1:
        st.markdown(f"""
        <div style="background:#f8f9fa; border-radius:10px; padding:1rem; text-align:center">
            <div style="font-size:2rem">🔥</div>
            <div style="font-weight:600">Threat Score</div>
            <div style="font-size:1.5rem; color:{risk_color}; font-weight:700">{score}/100</div>
        </div>
        """, unsafe_allow_html=True)
    with col_t2:
        reports = result["total_reports"]
        report_level = "Critical" if reports > 100 else ("Moderate" if reports > 10 else "Low")
        st.markdown(f"""
        <div style="background:#f8f9fa; border-radius:10px; padding:1rem; text-align:center">
            <div style="font-size:2rem">📝</div>
            <div style="font-weight:600">Report Volume</div>
            <div style="font-size:1.5rem; font-weight:700">{reports} ({report_level})</div>
        </div>
        """, unsafe_allow_html=True)
    with col_t3:
        tor_status = "Anonymous" if result["is_tor"] else "Standard"
        st.markdown(f"""
        <div style="background:#f8f9fa; border-radius:10px; padding:1rem; text-align:center">
            <div style="font-size:2rem">🧅</div>
            <div style="font-weight:600">Traffic Type</div>
            <div style="font-size:1.5rem; font-weight:700">{tor_status}</div>
        </div>
        """, unsafe_allow_html=True)

    session = get_session()
    existing = session.query(IOC).filter_by(indicator=ip_input.strip()).first()
    session.close()

    if existing:
        st.markdown("#### 🗺️ MITRE ATT&CK Intelligence")
        st.markdown(f"""
        <div style="background:#eaf4fb; border-radius:10px; padding:1rem; border-left:5px solid #2980b9">
            <b>ATT&CK Tactic:</b> {existing.mitre_tactic}<br>
            <b>Threat Actor:</b> {existing.threat_actor}<br>
            <b>Campaign:</b> {existing.pulse_name}<br>
            <b>Tags:</b> {existing.tags}
        </div>
        """, unsafe_allow_html=True)
    else:
        st.info("ℹ️ This IP is not currently in our IOC database — it may be a new or unlisted indicator.")

elif analyze and not ip_input:
    st.error("⚠️ Please enter an IP address to analyze.")