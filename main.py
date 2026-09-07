import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

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
    .main-header {
        background: linear-gradient(135deg, #0f0c29, #302b63, #24243e);
        padding: 2rem;
        border-radius: 15px;
        margin-bottom: 2rem;
        text-align: center;
        color: white;
    }
    .main-header h1 { font-size: 2.5rem; margin: 0; color: white; }
    .main-header p { color: #aaa; margin: 0.5rem 0 0; font-size: 1rem; }
    .metric-container {
        background: white;
        border-radius: 12px;
        padding: 1.5rem;
        text-align: center;
        border-left: 5px solid #e74c3c;
        box-shadow: 0 2px 10px rgba(0,0,0,0.08);
    }
    .metric-value { font-size: 2.5rem; font-weight: 700; color: #2c3e50; }
    .metric-label { font-size: 0.85rem; color: #888; text-transform: uppercase; letter-spacing: 1px; }
    .section-header {
        font-size: 1.2rem;
        font-weight: 600;
        color: #2c3e50;
        border-left: 4px solid #e74c3c;
        padding-left: 0.75rem;
        margin: 1.5rem 0 1rem;
    }
    .ioc-tag {
        display: inline-block;
        padding: 2px 10px;
        border-radius: 20px;
        font-size: 0.75rem;
        font-weight: 600;
        margin: 2px;
    }
    div[data-testid="stMetric"] {
        background: white;
        border-radius: 12px;
        padding: 1rem 1.5rem;
        box-shadow: 0 2px 8px rgba(0,0,0,0.06);
        border-top: 3px solid #e74c3c;
    }
    div[data-testid="stMetricValue"] { font-size: 2rem !important; }
    .stDataFrame { border-radius: 10px; overflow: hidden; }
    .sidebar-info {
        background: #f8f9fa;
        border-radius: 10px;
        padding: 1rem;
        font-size: 0.85rem;
        color: #666;
    }
</style>
""", unsafe_allow_html=True)

st.markdown("""
<div class="main-header">
    <h1>🛡️ Cyber Threat Intelligence Dashboard</h1>
    <p>Real-time threat intelligence · AlienVault OTX · AbuseIPDB · MITRE ATT&CK Framework</p>
</div>
""", unsafe_allow_html=True)

with st.sidebar:
    st.image("https://upload.wikimedia.org/wikipedia/commons/thumb/1/17/Warning.svg/156px-Warning.svg.png", width=50)
    st.markdown("### 🛡️ CTI Dashboard")
    st.markdown("---")
    st.markdown("""
    <div class="sidebar-info">
    <b>Data Sources:</b><br>
    🟠 AlienVault OTX<br>
    🔴 AbuseIPDB<br>
    🔵 MITRE ATT&CK<br><br>
    <b>Built by:</b> Chandan Yadav<br>
    <b>Stack:</b> Python · Streamlit · SQLite
    </div>
    """, unsafe_allow_html=True)
    st.markdown("---")
    if st.button("🔄 Refresh Data", use_container_width=True):
        st.cache_data.clear()
        st.rerun()

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
    st.warning("⚠️ No data loaded yet. The database will populate on first run of scheduler.py")
    st.stop()

total = len(df)
high_risk = len(df[df["abuse_score"] >= 75])
medium_risk = len(df[(df["abuse_score"] >= 25) & (df["abuse_score"] < 75)])
low_risk = len(df[df["abuse_score"] < 25])
countries = df["country"].nunique()
tactics = df["mitre_tactic"].nunique()
threat_actors = df["threat_actor"].nunique()

col1, col2, col3, col4, col5 = st.columns(5)
col1.metric("📊 Total IOCs", f"{total:,}", "Live feed")
col2.metric("🔴 High Risk", f"{high_risk:,}", f"{round(high_risk/total*100)}% critical")
col3.metric("🟡 Medium Risk", f"{medium_risk:,}")
col4.metric("🌍 Countries", f"{countries}")
col5.metric("👤 Threat Actors", f"{threat_actors}")

st.markdown("---")

col_left, col_right = st.columns([1.2, 1])

with col_left:
    st.markdown('<div class="section-header">MITRE ATT&CK Tactic Distribution</div>', unsafe_allow_html=True)
    tactic_df = df["mitre_tactic"].value_counts().reset_index()
    tactic_df.columns = ["Tactic", "Count"]
    tactic_df = tactic_df[tactic_df["Tactic"] != "Unknown"]
    fig1 = px.bar(
        tactic_df, x="Count", y="Tactic", orientation="h",
        color="Count", color_continuous_scale=["#fff5f5","#e74c3c","#7b0000"],
        height=380, text="Count"
    )
    fig1.update_traces(textposition="outside")
    fig1.update_layout(
        plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)",
        coloraxis_showscale=False, yaxis={"categoryorder":"total ascending"},
        margin=dict(l=10, r=30, t=10, b=10),
        xaxis_title="", yaxis_title=""
    )
    st.plotly_chart(fig1, use_container_width=True)

with col_right:
    st.markdown('<div class="section-header">IOC Type Breakdown</div>', unsafe_allow_html=True)
    type_df = df["ioc_type"].value_counts().reset_index()
    type_df.columns = ["Type", "Count"]
    fig2 = px.pie(
        type_df, values="Count", names="Type",
        color_discrete_sequence=["#c0392b","#e74c3c","#f39c12","#e67e22","#d35400"],
        height=380, hole=0.5
    )
    fig2.update_traces(textposition="outside", textinfo="percent+label")
    fig2.update_layout(
        plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)",
        showlegend=False, margin=dict(l=10, r=10, t=10, b=10)
    )
    st.plotly_chart(fig2, use_container_width=True)

col3a, col3b = st.columns(2)

with col3a:
    st.markdown('<div class="section-header">Top 10 Countries by IOC Count</div>', unsafe_allow_html=True)
    country_df = df[df["country"] != "Unknown"]["country"].value_counts().head(10).reset_index()
    country_df.columns = ["Country", "Count"]
    fig3 = px.bar(
        country_df, x="Country", y="Count",
        color="Count", color_continuous_scale=["#fff5f5","#e74c3c"],
        height=300, text="Count"
    )
    fig3.update_traces(textposition="outside")
    fig3.update_layout(
        plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)",
        coloraxis_showscale=False, margin=dict(l=10, r=10, t=10, b=10),
        xaxis_title="", yaxis_title=""
    )
    st.plotly_chart(fig3, use_container_width=True)

with col3b:
    st.markdown('<div class="section-header">Risk Score Distribution</div>', unsafe_allow_html=True)
    risk_data = {
        "Risk Level": ["🔴 High Risk (≥75)", "🟡 Medium Risk (25-74)", "🟢 Low Risk (<25)"],
        "Count": [high_risk, medium_risk, low_risk],
        "Color": ["#e74c3c", "#f39c12", "#27ae60"]
    }
    fig4 = go.Figure(go.Bar(
        x=risk_data["Count"], y=risk_data["Risk Level"],
        orientation="h",
        marker_color=risk_data["Color"],
        text=risk_data["Count"], textposition="outside"
    ))
    fig4.update_layout(
        plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)",
        height=300, margin=dict(l=10, r=50, t=10, b=10),
        xaxis_title="", yaxis_title=""
    )
    st.plotly_chart(fig4, use_container_width=True)

st.markdown('<div class="section-header">Top Threat Actors</div>', unsafe_allow_html=True)
actor_df = df["threat_actor"].value_counts().head(10).reset_index()
actor_df.columns = ["Threat Actor", "IOC Count"]
actor_df["Risk %"] = (actor_df["IOC Count"] / total * 100).round(1).astype(str) + "%"
st.dataframe(actor_df, use_container_width=True, hide_index=True)

st.markdown('<div class="section-header">Recent IOCs — Live Feed</div>', unsafe_allow_html=True)
recent = df.sort_values("created_at", ascending=False).head(25)
st.dataframe(
    recent[["indicator","ioc_type","threat_actor","mitre_tactic","abuse_score","country","created_at"]],
    use_container_width=True, hide_index=True,
    column_config={
        "abuse_score": st.column_config.ProgressColumn(
            "Abuse Score", min_value=0, max_value=100, format="%d"
        ),
        "indicator": st.column_config.TextColumn("Indicator", width="large"),
        "mitre_tactic": st.column_config.TextColumn("MITRE Tactic", width="medium"),
    }
)

st.markdown("---")
st.markdown("""
<div style="text-align:center; color:#888; font-size:0.8rem; padding:1rem">
    🛡️ CTI Dashboard · Built by Chandan Yadav · 
    Powered by AlienVault OTX, AbuseIPDB & MITRE ATT&CK
</div>
""", unsafe_allow_html=True)