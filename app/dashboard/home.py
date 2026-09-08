import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

import streamlit as st
import plotly.express as px
import plotly.graph_objects as go
import pandas as pd
from app.data.database import engine, init_db

init_db()

st.set_page_config(
    page_title="CTI Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Orbitron:wght@400;700;900&display=swap');

/* ── Global reset ── */
html, body, [data-testid="stAppViewContainer"] {
    background-color: #010b13 !important;
    color: #00ff41 !important;
}
[data-testid="stSidebar"] {
    background: #010b13 !important;
    border-right: 1px solid #00ff4133 !important;
}
[data-testid="stSidebar"] * { color: #00ff41 !important; }

/* ── Hide Streamlit branding ── */
#MainMenu, footer, header { visibility: hidden; }
.block-container { padding-top: 1rem !important; }

/* ── Scrollbar ── */
::-webkit-scrollbar { width: 4px; }
::-webkit-scrollbar-track { background: #010b13; }
::-webkit-scrollbar-thumb { background: #00ff41; border-radius: 2px; }

/* ── Metric cards ── */
[data-testid="stMetric"] {
    background: #0a1628 !important;
    border: 1px solid #00ff4155 !important;
    border-radius: 8px !important;
    padding: 1rem 1.5rem !important;
    box-shadow: 0 0 15px #00ff4122, inset 0 0 15px #00ff4108 !important;
    transition: all 0.3s ease;
}
[data-testid="stMetric"]:hover {
    border-color: #00ff41 !important;
    box-shadow: 0 0 25px #00ff4155 !important;
}
[data-testid="stMetricLabel"] p {
    color: #00ff4199 !important;
    font-family: 'Share Tech Mono', monospace !important;
    font-size: 0.75rem !important;
    letter-spacing: 2px !important;
    text-transform: uppercase !important;
}
[data-testid="stMetricValue"] {
    color: #00ff41 !important;
    font-family: 'Orbitron', monospace !important;
    font-size: 1.8rem !important;
}
[data-testid="stMetricDelta"] {
    color: #00ff4199 !important;
    font-size: 0.75rem !important;
}

/* ── Dataframe ── */
[data-testid="stDataFrame"] {
    border: 1px solid #00ff4133 !important;
    border-radius: 8px !important;
    overflow: hidden;
}
.dvn-scroller { background: #010b13 !important; }

/* ── Buttons ── */
[data-testid="stButton"] button {
    background: transparent !important;
    border: 1px solid #00ff41 !important;
    color: #00ff41 !important;
    font-family: 'Share Tech Mono', monospace !important;
    letter-spacing: 2px !important;
    border-radius: 4px !important;
    transition: all 0.3s ease !important;
}
[data-testid="stButton"] button:hover {
    background: #00ff4122 !important;
    box-shadow: 0 0 20px #00ff4155 !important;
}

/* ── Divider ── */
hr { border-color: #00ff4133 !important; }

/* ── Selectbox / inputs ── */
[data-testid="stSelectbox"] > div,
[data-testid="stTextInput"] > div > div {
    background: #0a1628 !important;
    border-color: #00ff4133 !important;
    color: #00ff41 !important;
}

/* ── Plotly chart backgrounds ── */
.js-plotly-plot { background: transparent !important; }
</style>
""", unsafe_allow_html=True)

# ── Sidebar ──
with st.sidebar:
    st.markdown("""
    <div style="text-align:center;padding:1rem 0 0.5rem">
        <div style="font-family:'Orbitron',monospace;font-size:1.1rem;
                    color:#00ff41;letter-spacing:3px;font-weight:900">
            ██ CTI DASHBOARD
        </div>
        <div style="font-size:0.65rem;color:#00ff4177;letter-spacing:4px;margin-top:4px">
            THREAT INTELLIGENCE SYSTEM
        </div>
    </div>
    <div style="height:1px;background:linear-gradient(90deg,transparent,#00ff41,transparent);margin:0.5rem 0"></div>
    """, unsafe_allow_html=True)

    st.markdown("""
    <div style="font-family:'Share Tech Mono',monospace;font-size:0.75rem;
                color:#00ff4199;line-height:2;padding:0.5rem 0">
        <div style="color:#00ff41;margin-bottom:4px">[ DATA SOURCES ]</div>
        ▸ AlienVault OTX<br>
        ▸ AbuseIPDB<br>
        ▸ MITRE ATT&CK<br>
        <br>
        <div style="color:#00ff41;margin-bottom:4px">[ OPERATOR ]</div>
        ▸ Chandan Yadav<br>
        ▸ Python · Streamlit<br>
        ▸ SQLite · Plotly
    </div>
    <div style="height:1px;background:linear-gradient(90deg,transparent,#00ff41,transparent);margin:0.5rem 0"></div>
    """, unsafe_allow_html=True)

    if st.button("⟳  REFRESH FEED", use_container_width=True):
        st.cache_data.clear()
        st.rerun()

# ── Header ──
st.markdown("""
<div style="border:1px solid #00ff4144;border-radius:8px;
            background:linear-gradient(135deg,#010b13,#0a1628);
            padding:1.5rem 2rem;margin-bottom:1.5rem;
            box-shadow:0 0 30px #00ff4122;position:relative;overflow:hidden">
    <div style="position:absolute;top:0;left:0;right:0;height:2px;
                background:linear-gradient(90deg,transparent,#00ff41,transparent)"></div>
    <div style="font-family:'Orbitron',monospace;font-size:1.8rem;
                font-weight:900;color:#00ff41;letter-spacing:4px;
                text-shadow:0 0 20px #00ff4177">
        🛡️ CYBER THREAT INTELLIGENCE
    </div>
    <div style="font-family:'Share Tech Mono',monospace;font-size:0.8rem;
                color:#00ff4199;letter-spacing:3px;margin-top:6px">
        REAL-TIME THREAT MONITORING · ALIENVAULT OTX · ABUSEIPDB · MITRE ATT&CK
    </div>
    <div style="position:absolute;bottom:0;left:0;right:0;height:2px;
                background:linear-gradient(90deg,transparent,#00ff41,transparent)"></div>
</div>
""", unsafe_allow_html=True)

# ── Load data ──
@st.cache_data(ttl=300)
def load_data():
    try:
        with engine.connect() as conn:
            df = pd.read_sql("SELECT * FROM iocs", conn)
        return df
    except Exception:
        return pd.DataFrame()

df = load_data()

if df.empty:
    st.markdown("""
    <div style="border:1px solid #ff000055;border-radius:8px;background:#1a0000;
                padding:1.5rem;text-align:center;font-family:'Share Tech Mono',monospace">
        <div style="color:#ff4444;font-size:1.2rem">⚠ DATABASE EMPTY</div>
        <div style="color:#ff444499;margin-top:8px">Run scheduler.py to populate threat data</div>
    </div>
    """, unsafe_allow_html=True)
    st.stop()

total = len(df)
high_risk = len(df[df["abuse_score"] >= 75])
medium_risk = len(df[(df["abuse_score"] >= 25) & (df["abuse_score"] < 75)])
low_risk = len(df[df["abuse_score"] < 25])
countries = df["country"].nunique()
tactics = df["mitre_tactic"].nunique()
actors = df["threat_actor"].nunique()

# ── KPI Cards ──
c1, c2, c3, c4, c5 = st.columns(5)
c1.metric("TOTAL IOCs", f"{total:,}", "LIVE FEED")
c2.metric("HIGH RISK", f"{high_risk:,}", f"{round(high_risk/total*100)}% CRITICAL")
c3.metric("MEDIUM RISK", f"{medium_risk:,}", "MONITOR")
c4.metric("COUNTRIES", f"{countries}", "TRACKED")
c5.metric("THREAT ACTORS", f"{actors}", "IDENTIFIED")

st.markdown("<div style='height:1px;background:linear-gradient(90deg,transparent,#00ff41,transparent);margin:1rem 0'></div>", unsafe_allow_html=True)

# ── Charts Row 1 ──
def cyber_layout(fig, height=380):
    fig.update_layout(
        plot_bgcolor="#010b13",
        paper_bgcolor="rgba(0,0,0,0)",
        font=dict(color="#00ff41", family="Share Tech Mono, monospace", size=11),
        height=height,
        margin=dict(l=10, r=50, t=20, b=10),
        xaxis=dict(gridcolor="#00ff4122", zerolinecolor="#00ff4133",
                   tickfont=dict(color="#00ff4199")),
        yaxis=dict(gridcolor="#00ff4122", zerolinecolor="#00ff4133",
                   tickfont=dict(color="#00ff4199")),
        coloraxis_showscale=False,
    )
    return fig

col_left, col_right = st.columns([1.2, 1])

with col_left:
    st.markdown("""<div style="font-family:'Share Tech Mono',monospace;color:#00ff41;
                font-size:0.8rem;letter-spacing:3px;margin-bottom:8px">
                ▸ MITRE ATT&CK TACTIC DISTRIBUTION</div>""", unsafe_allow_html=True)
    tactic_df = df["mitre_tactic"].value_counts().reset_index()
    tactic_df.columns = ["Tactic", "Count"]
    tactic_df = tactic_df[tactic_df["Tactic"] != "Unknown"]
    fig1 = px.bar(tactic_df, x="Count", y="Tactic", orientation="h",
                  color="Count",
                  color_continuous_scale=["#003300","#00aa33","#00ff41"],
                  text="Count")
    fig1.update_traces(textposition="outside",
                       textfont=dict(color="#00ff41", family="Share Tech Mono"),
                       marker_line_color="#00ff4133", marker_line_width=0.5)
    fig1.update_layout(**cyber_layout(fig1).__dict__["layout"].__dict__["_props"] if False else {})
    fig1 = cyber_layout(fig1)
    fig1.update_layout(yaxis=dict(categoryorder="total ascending",
                                   gridcolor="#00ff4122",
                                   tickfont=dict(color="#00ff4199")))
    st.plotly_chart(fig1, use_container_width=True)

with col_right:
    st.markdown("""<div style="font-family:'Share Tech Mono',monospace;color:#00ff41;
                font-size:0.8rem;letter-spacing:3px;margin-bottom:8px">
                ▸ IOC TYPE BREAKDOWN</div>""", unsafe_allow_html=True)
    type_df = df["ioc_type"].value_counts().reset_index()
    type_df.columns = ["Type", "Count"]
    fig2 = px.pie(type_df, values="Count", names="Type", hole=0.6,
                  color_discrete_sequence=["#00ff41","#00cc33","#009922","#006611","#003308"])
    fig2.update_traces(textposition="outside", textinfo="percent+label",
                       textfont=dict(color="#00ff41", family="Share Tech Mono", size=10),
                       marker=dict(line=dict(color="#010b13", width=2)))
    fig2.update_layout(paper_bgcolor="rgba(0,0,0,0)",
                       plot_bgcolor="#010b13",
                       showlegend=False,
                       font=dict(color="#00ff41"),
                       height=380,
                       margin=dict(l=10,r=10,t=20,b=10))
    st.plotly_chart(fig2, use_container_width=True)

# ── Charts Row 2 ──
col3a, col3b = st.columns(2)

with col3a:
    st.markdown("""<div style="font-family:'Share Tech Mono',monospace;color:#00ff41;
                font-size:0.8rem;letter-spacing:3px;margin-bottom:8px">
                ▸ TOP COUNTRIES BY IOC COUNT</div>""", unsafe_allow_html=True)
    country_df = df[df["country"] != "Unknown"]["country"].value_counts().head(10).reset_index()
    country_df.columns = ["Country","Count"]
    fig3 = px.bar(country_df, x="Country", y="Count",
                  color="Count",
                  color_continuous_scale=["#003300","#00ff41"],
                  text="Count")
    fig3.update_traces(textposition="outside",
                       textfont=dict(color="#00ff41"),
                       marker_line_color="#00ff4133", marker_line_width=0.5)
    fig3 = cyber_layout(fig3, height=300)
    st.plotly_chart(fig3, use_container_width=True)

with col3b:
    st.markdown("""<div style="font-family:'Share Tech Mono',monospace;color:#00ff41;
                font-size:0.8rem;letter-spacing:3px;margin-bottom:8px">
                ▸ RISK LEVEL DISTRIBUTION</div>""", unsafe_allow_html=True)
    fig4 = go.Figure(go.Bar(
        x=[high_risk, medium_risk, low_risk],
        y=["HIGH RISK  ≥75", "MEDIUM RISK 25-74", "LOW RISK  <25"],
        orientation="h",
        marker_color=["#ff4444","#ffaa00","#00ff41"],
        marker_line_color=["#ff444433","#ffaa0033","#00ff4133"],
        marker_line_width=0.5,
        text=[high_risk, medium_risk, low_risk],
        textposition="outside",
        textfont=dict(color="#00ff41", family="Share Tech Mono")
    ))
    fig4 = cyber_layout(fig4, height=300)
    st.plotly_chart(fig4, use_container_width=True)

# ── Threat Actors ──
st.markdown("""<div style="font-family:'Share Tech Mono',monospace;color:#00ff41;
            font-size:0.8rem;letter-spacing:3px;margin:0.5rem 0 8px">
            ▸ TOP THREAT ACTORS</div>""", unsafe_allow_html=True)
actor_df = df["threat_actor"].value_counts().head(10).reset_index()
actor_df.columns = ["Threat Actor","IOC Count"]
actor_df["Share %"] = (actor_df["IOC Count"]/total*100).round(1).astype(str)+"%"
st.dataframe(actor_df, use_container_width=True, hide_index=True)

# ── Recent IOCs ──
st.markdown("""<div style="font-family:'Share Tech Mono',monospace;color:#00ff41;
            font-size:0.8rem;letter-spacing:3px;margin:1rem 0 8px">
            ▸ LIVE IOC FEED — RECENT INDICATORS</div>""", unsafe_allow_html=True)
recent = df.sort_values("created_at", ascending=False).head(25)
st.dataframe(
    recent[["indicator","ioc_type","threat_actor","mitre_tactic","abuse_score","country","created_at"]],
    use_container_width=True, hide_index=True,
    column_config={
        "abuse_score": st.column_config.ProgressColumn(
            "Abuse Score", min_value=0, max_value=100, format="%d"),
        "indicator": st.column_config.TextColumn("Indicator", width="large"),
        "mitre_tactic": st.column_config.TextColumn("MITRE Tactic", width="medium"),
    }
)

st.markdown("""
<div style="height:1px;background:linear-gradient(90deg,transparent,#00ff41,transparent);margin:1rem 0"></div>
<div style="text-align:center;font-family:'Share Tech Mono',monospace;
            color:#00ff4166;font-size:0.7rem;letter-spacing:3px;padding:0.5rem">
    [ CTI DASHBOARD · CHANDAN YADAV · ALIENVAULT OTX · ABUSEIPDB · MITRE ATT&CK ]
</div>
""", unsafe_allow_html=True)