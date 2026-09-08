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
@import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Orbitron:wght@400;700;900&display=swap');
html, body, [data-testid="stAppViewContainer"] {
    background-color: #010b13 !important; color: #00ff41 !important;
}
[data-testid="stSidebar"] {
    background: #010b13 !important;
    border-right: 1px solid #00ff4133 !important;
}
[data-testid="stSidebar"] * { color: #00ff41 !important; }
#MainMenu, footer, header { visibility: hidden; }
.block-container { padding-top: 1rem !important; }
[data-testid="stMetric"] {
    background: #0a1628 !important;
    border: 1px solid #00ff4155 !important;
    border-radius: 8px !important;
    padding: 1rem !important;
    box-shadow: 0 0 15px #00ff4122 !important;
}
[data-testid="stMetricLabel"] p {
    color: #00ff4199 !important;
    font-family: 'Share Tech Mono', monospace !important;
    font-size: 0.7rem !important;
    letter-spacing: 2px !important;
    text-transform: uppercase !important;
}
[data-testid="stMetricValue"] {
    color: #00ff41 !important;
    font-family: 'Orbitron', monospace !important;
}
[data-testid="stButton"] button {
    background: transparent !important;
    border: 1px solid #00ff41 !important;
    color: #00ff41 !important;
    font-family: 'Share Tech Mono', monospace !important;
    letter-spacing: 2px !important;
}
[data-testid="stButton"] button:hover {
    background: #00ff4122 !important;
    box-shadow: 0 0 20px #00ff4155 !important;
}
[data-testid="stTextInput"] input {
    background: #0a1628 !important;
    border: 1px solid #00ff4155 !important;
    color: #00ff41 !important;
    font-family: 'Share Tech Mono', monospace !important;
}
hr { border-color: #00ff4133 !important; }
::-webkit-scrollbar { width: 4px; }
::-webkit-scrollbar-thumb { background: #00ff41; }
</style>
""", unsafe_allow_html=True)

st.markdown("""
<div style="border:1px solid #00ff4144;border-radius:8px;
            background:linear-gradient(135deg,#010b13,#0a1628);
            padding:1.5rem 2rem;margin-bottom:1.5rem;
            box-shadow:0 0 30px #00ff4122;position:relative">
    <div style="position:absolute;top:0;left:0;right:0;height:2px;
                background:linear-gradient(90deg,transparent,#00ff41,transparent)"></div>
    <div style="font-family:'Orbitron',monospace;font-size:1.5rem;
                font-weight:900;color:#00ff41;letter-spacing:4px;
                text-shadow:0 0 20px #00ff4177">
        🔍 IP REPUTATION LOOKUP
    </div>
    <div style="font-family:'Share Tech Mono',monospace;font-size:0.75rem;
                color:#00ff4199;letter-spacing:3px;margin-top:6px">
        REAL-TIME THREAT ANALYSIS · ABUSEIPDB · GEOLOCATION · MITRE ATT&CK
    </div>
    <div style="position:absolute;bottom:0;left:0;right:0;height:2px;
                background:linear-gradient(90deg,transparent,#00ff41,transparent)"></div>
</div>
""", unsafe_allow_html=True)

col_input, col_btn = st.columns([4, 1])
with col_input:
    ip_input = st.text_input("IP", placeholder="TARGET IP — e.g. 185.220.101.1",
                              label_visibility="collapsed")
with col_btn:
    analyze = st.button("⟳ SCAN", use_container_width=True)

st.markdown("""
<div style="font-family:'Share Tech Mono',monospace;font-size:0.75rem;
            color:#00ff4199;padding:0.5rem 0;letter-spacing:1px">
    QUICK TEST: 
    <code style="color:#00ff41;background:#0a1628;padding:2px 8px;border-radius:3px">185.220.101.1</code> TOR ·
    <code style="color:#00ff41;background:#0a1628;padding:2px 8px;border-radius:3px">198.235.24.1</code> SCANNER ·
    <code style="color:#00ff41;background:#0a1628;padding:2px 8px;border-radius:3px">8.8.8.8</code> CLEAN
</div>
""", unsafe_allow_html=True)

if analyze and ip_input:
    with st.spinner("SCANNING TARGET..."):
        result = check_ip(ip_input.strip())

    score = result["abuse_score"]

    if score >= 75:
        risk_label = "CRITICAL THREAT"
        risk_color = "#ff4444"
        border_color = "#ff444488"
        bg_color = "#1a0000"
        action = "BLOCK · ESCALATE TO TIER 2 · LOG INCIDENT"
        gauge_color = "#ff4444"
    elif score >= 25:
        risk_label = "SUSPICIOUS"
        risk_color = "#ffaa00"
        border_color = "#ffaa0088"
        bg_color = "#1a1000"
        action = "MONITOR · ADD TO WATCHLIST · REVIEW LOGS"
        gauge_color = "#ffaa00"
    else:
        risk_label = "CLEAR"
        risk_color = "#00ff41"
        border_color = "#00ff4188"
        bg_color = "#001a00"
        action = "LOG FOR BASELINE · NO ACTION REQUIRED"
        gauge_color = "#00ff41"

    st.markdown(f"""
    <div style="border:1px solid {border_color};border-radius:8px;
                background:{bg_color};padding:1rem 1.5rem;margin-bottom:1rem;
                box-shadow:0 0 20px {border_color};position:relative">
        <div style="position:absolute;top:0;left:0;right:0;height:2px;
                    background:linear-gradient(90deg,transparent,{risk_color},transparent)"></div>
        <div style="font-family:'Orbitron',monospace;font-size:1.3rem;
                    color:{risk_color};font-weight:700;letter-spacing:3px;
                    text-shadow:0 0 15px {risk_color}88">
            ◈ STATUS: {risk_label} — SCORE: {score}/100
        </div>
    </div>
    """, unsafe_allow_html=True)

    col_gauge, col_info = st.columns([1, 1.5])

    with col_gauge:
        fig = go.Figure(go.Indicator(
            mode="gauge+number",
            value=score,
            domain={"x":[0,1],"y":[0,1]},
            title={"text":"THREAT SCORE",
                   "font":{"size":13,"color":"#00ff41","family":"Share Tech Mono"}},
            number={"suffix":"/100",
                    "font":{"color":gauge_color,"size":40,"family":"Orbitron"}},
            gauge={
                "axis":{"range":[0,100],"tickwidth":1,
                        "tickcolor":"#00ff4144",
                        "tickfont":{"color":"#00ff4199","family":"Share Tech Mono"}},
                "bar":{"color":gauge_color,"thickness":0.2},
                "bgcolor":"#010b13",
                "borderwidth":1,
                "bordercolor":"#00ff4133",
                "steps":[
                    {"range":[0,25],"color":"#001a00"},
                    {"range":[25,75],"color":"#1a1000"},
                    {"range":[75,100],"color":"#1a0000"},
                ],
                "threshold":{
                    "line":{"color":gauge_color,"width":3},
                    "thickness":0.75,"value":score
                }
            }
        ))
        fig.update_layout(
            height=280,
            margin=dict(l=20,r=20,t=60,b=20),
            paper_bgcolor="rgba(0,0,0,0)",
            font=dict(color="#00ff41",family="Share Tech Mono")
        )
        st.plotly_chart(fig, use_container_width=True)

    with col_info:
        st.markdown("""<div style="font-family:'Share Tech Mono',monospace;color:#00ff41;
                    font-size:0.8rem;letter-spacing:3px;margin-bottom:12px">
                    ▸ IP INTELLIGENCE REPORT</div>""", unsafe_allow_html=True)
        r1, r2 = st.columns(2)
        r1.metric("COUNTRY", result["country"])
        r2.metric("ABUSE REPORTS", f"{result['total_reports']:,}")
        r1.metric("ISP", result["isp"][:18]+"..." if len(result["isp"])>18 else result["isp"])
        r2.metric("TOR NODE", "YES ⚠" if result["is_tor"] else "NO ✓")

        st.markdown(f"""
        <div style="font-family:'Share Tech Mono',monospace;font-size:0.8rem;
                    color:#00ff4199;margin-top:8px;line-height:2">
            DOMAIN: <span style="color:#00ff41">{result['domain']}</span>
        </div>
        """, unsafe_allow_html=True)

        if result["is_tor"]:
            st.markdown("""
            <div style="border:1px solid #ff444455;border-radius:6px;
                        background:#1a0000;padding:0.75rem;margin-top:8px;
                        font-family:'Share Tech Mono',monospace;font-size:0.8rem;color:#ff4444">
                ⚠ TOR EXIT NODE DETECTED — TRAFFIC IS ANONYMIZED
            </div>
            """, unsafe_allow_html=True)

    st.markdown("""<div style="height:1px;background:linear-gradient(90deg,transparent,#00ff41,transparent);margin:1rem 0"></div>""", unsafe_allow_html=True)

    st.markdown(f"""
    <div style="border:1px solid #00ff4133;border-radius:8px;
                background:#0a1628;padding:1rem 1.5rem;margin-bottom:1rem">
        <div style="font-family:'Share Tech Mono',monospace;font-size:0.75rem;
                    color:#00ff4199;letter-spacing:3px;margin-bottom:6px">
            ▸ SOC ANALYST ACTION PLAN
        </div>
        <div style="font-family:'Orbitron',monospace;font-size:0.9rem;
                    color:{risk_color};letter-spacing:2px;
                    text-shadow:0 0 10px {risk_color}66">
            ◈ {action}
        </div>
    </div>
    """, unsafe_allow_html=True)

    col_t1, col_t2, col_t3 = st.columns(3)
    reports = result["total_reports"]
    report_level = "CRITICAL" if reports > 100 else ("MODERATE" if reports > 10 else "LOW")
    tor_status = "ANONYMOUS" if result["is_tor"] else "STANDARD"

    for col, icon, label, value, color in [
        (col_t1, "🔥", "THREAT SCORE", f"{score}/100", risk_color),
        (col_t2, "📡", "REPORT VOLUME", f"{reports} ({report_level})", "#00ff41"),
        (col_t3, "🧅", "TRAFFIC TYPE", tor_status, "#00ff41"),
    ]:
        with col:
            st.markdown(f"""
            <div style="border:1px solid #00ff4133;border-radius:8px;
                        background:#0a1628;padding:1rem;text-align:center;
                        box-shadow:0 0 10px #00ff4111">
                <div style="font-size:1.5rem">{icon}</div>
                <div style="font-family:'Share Tech Mono',monospace;font-size:0.65rem;
                            color:#00ff4199;letter-spacing:2px;margin:4px 0">{label}</div>
                <div style="font-family:'Orbitron',monospace;font-size:1rem;
                            color:{color};font-weight:700">{value}</div>
            </div>
            """, unsafe_allow_html=True)

    session = get_session()
    existing = session.query(IOC).filter_by(indicator=ip_input.strip()).first()
    session.close()

    if existing:
        st.markdown("""<div style="height:1px;background:linear-gradient(90deg,transparent,#00ff41,transparent);margin:1rem 0"></div>""", unsafe_allow_html=True)
        st.markdown(f"""
        <div style="border:1px solid #00ff4155;border-radius:8px;
                    background:#0a1628;padding:1.2rem;
                    box-shadow:0 0 15px #00ff4122">
            <div style="font-family:'Share Tech Mono',monospace;font-size:0.75rem;
                        color:#00ff4199;letter-spacing:3px;margin-bottom:12px">
                ▸ MITRE ATT&CK INTELLIGENCE
            </div>
            <table style="width:100%;font-family:'Share Tech Mono',monospace;font-size:0.8rem">
                <tr><td style="color:#00ff4166;padding:4px 12px 4px 0;width:140px">ATT&CK TACTIC</td>
                    <td style="color:#00ff41">{existing.mitre_tactic}</td></tr>
                <tr><td style="color:#00ff4166;padding:4px 12px 4px 0">THREAT ACTOR</td>
                    <td style="color:#00ff41">{existing.threat_actor}</td></tr>
                <tr><td style="color:#00ff4166;padding:4px 12px 4px 0">CAMPAIGN</td>
                    <td style="color:#00ff41">{existing.pulse_name}</td></tr>
                <tr><td style="color:#00ff4166;padding:4px 12px 4px 0">TAGS</td>
                    <td style="color:#00ff4199"><code>{existing.tags}</code></td></tr>
            </table>
        </div>
        """, unsafe_allow_html=True)
    else:
        st.markdown("""
        <div style="border:1px solid #00ff4133;border-radius:6px;background:#0a1628;
                    padding:0.75rem;font-family:'Share Tech Mono',monospace;
                    font-size:0.8rem;color:#00ff4199">
            ℹ NOT IN LOCAL IOC DATABASE — MAY BE NEW OR UNLISTED INDICATOR
        </div>
        """, unsafe_allow_html=True)

elif analyze and not ip_input:
    st.markdown("""
    <div style="border:1px solid #ff444455;border-radius:6px;background:#1a0000;
                padding:0.75rem;font-family:'Share Tech Mono',monospace;
                font-size:0.8rem;color:#ff4444">
        ⚠ ERROR: NO TARGET SPECIFIED — ENTER VALID IP ADDRESS
    </div>
    """, unsafe_allow_html=True)