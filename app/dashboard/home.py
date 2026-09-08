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
[data-testid="stMetric"] {
    background: white;
    border-radius: 12px;
    padding: 1rem 1.5rem;
    box-shadow: 0 2px 8px rgba(0,0,0,0.06);
    border-top: 3px solid #e74c3c;
}
[data-testid="stMetricValue"] { font-size: 2rem !important; }
.block-container { padding-top: 1rem; }
</style>
""", unsafe_allow_html=True)

with st.sidebar:
    st.markdown("## 🛡️ CTI Dashboard")
    st.markdown("---")
    st.markdown("""
    **Data Sources**
    - 🟠 AlienVault OTX
    - 🔴 AbuseIPDB  
    - 🔵 MITRE ATT&CK
    
    ---
    **Built by:** Chandan Yadav  
    **Stack:** Python · Streamlit · SQLite
    """)
    st.markdown("---")
    if st.button("🔄 Refresh Data", use_container_width=True):
        st.cache_data.clear()
        st.rerun()

st.markdown("""
<div style="background:linear-gradient(135deg,#0f0c29,#302b63,#24243e);
            padding:2rem;border-radius:15px;margin-bottom:1.5rem;text-align:center">
    <h1 style="color:white;margin:0;font-size:2.2rem">🛡️ Cyber Threat Intelligence Dashboard</h1>
    <p style="color:#aaa;margin:0.5rem 0 0">Real-time threat intelligence · AlienVault OTX · AbuseIPDB · MITRE ATT&CK</p>
</div>
""", unsafe_allow_html=True)

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
    st.warning("⚠️ No data loaded yet. Run scheduler.py to populate the database.")
    st.stop()

total = len(df)
high_risk = len(df[df["abuse_score"] >= 75])
medium_risk = len(df[(df["abuse_score"] >= 25) & (df["abuse_score"] < 75)])
low_risk = len(df[df["abuse_score"] < 25])
countries = df["country"].nunique()
tactics = df["mitre_tactic"].nunique()
actors = df["threat_actor"].nunique()

c1, c2, c3, c4, c5 = st.columns(5)
c1.metric("📊 Total IOCs", f"{total:,}", "Live feed")
c2.metric("🔴 High Risk", f"{high_risk:,}", f"{round(high_risk/total*100)}% critical")
c3.metric("🟡 Medium Risk", f"{medium_risk:,}")
c4.metric("🌍 Countries", f"{countries}")
c5.metric("👤 Threat Actors", f"{actors}")

st.markdown("---")

col_left, col_right = st.columns([1.2, 1])

with col_left:
    st.markdown("#### 🗺️ MITRE ATT&CK Tactic Distribution")
    tactic_df = df["mitre_tactic"].value_counts().reset_index()
    tactic_df.columns = ["Tactic", "Count"]
    tactic_df = tactic_df[tactic_df["Tactic"] != "Unknown"]
    fig1 = px.bar(
        tactic_df, x="Count", y="Tactic", orientation="h",
        color="Count",
        color_continuous_scale=["#fff5f5","#e74c3c","#7b0000"],
        height=380, text="Count"
    )
    fig1.update_traces(textposition="outside")
    fig1.update_layout(
        plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)",
        coloraxis_showscale=False,
        yaxis={"categoryorder":"total ascending"},
        margin=dict(l=10,r=50,t=10,b=10),
        xaxis_title="", yaxis_title=""
    )
    st.plotly_chart(fig1, use_container_width=True)

with col_right:
    st.markdown("#### 📊 IOC Type Breakdown")
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
        showlegend=False, margin=dict(l=10,r=10,t=10,b=10)
    )
    st.plotly_chart(fig2, use_container_width=True)

col3a, col3b = st.columns(2)

with col3a:
    st.markdown("#### 🌍 Top Countries by IOC Count")
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
        coloraxis_showscale=False,
        margin=dict(l=10,r=10,t=10,b=10),
        xaxis_title="", yaxis_title=""
    )
    st.plotly_chart(fig3, use_container_width=True)

with col3b:
    st.markdown("#### ⚠️ Risk Score Breakdown")
    fig4 = go.Figure(go.Bar(
        x=[high_risk, medium_risk, low_risk],
        y=["🔴 High (≥75)", "🟡 Medium (25-74)", "🟢 Low (<25)"],
        orientation="h",
        marker_color=["#e74c3c","#f39c12","#27ae60"],
        text=[high_risk, medium_risk, low_risk],
        textposition="outside"
    ))
    fig4.update_layout(
        plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)",
        height=300, margin=dict(l=10,r=60,t=10,b=10),
        xaxis_title="", yaxis_title=""
    )
    st.plotly_chart(fig4, use_container_width=True)

st.markdown("#### 👤 Top Threat Actors")
actor_df = df["threat_actor"].value_counts().head(10).reset_index()
actor_df.columns = ["Threat Actor", "IOC Count"]
actor_df["Share"] = (actor_df["IOC Count"] / total * 100).round(1).astype(str) + "%"
st.dataframe(actor_df, use_container_width=True, hide_index=True)

st.markdown("#### 🕐 Recent IOCs — Live Feed")
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

st.markdown("---")
st.markdown("""
<div style="text-align:center;color:#888;font-size:0.8rem;padding:1rem">
🛡️ CTI Dashboard · Built by Chandan Yadav · Powered by AlienVault OTX, AbuseIPDB & MITRE ATT&CK
</div>
""", unsafe_allow_html=True)