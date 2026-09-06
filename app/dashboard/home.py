import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
import streamlit as st
import plotly.express as px
import plotly.graph_objects as go
import pandas as pd
from sqlalchemy import text
from app.data.database import engine, init_db

#init_db()

st.set_page_config(
    page_title="CTI Dashboard",
    page_icon="🛡️",
    layout="wide"
)

st.markdown("""
    <style>
    .metric-card {
        background: #1e1e2e;
        border-radius: 10px;
        padding: 15px;
        border-left: 4px solid #e74c3c;
    }
    </style>
""", unsafe_allow_html=True)

st.title("🛡️ Cyber Threat Intelligence Dashboard")
st.caption("Live threat intelligence from AlienVault OTX · AbuseIPDB · MITRE ATT&CK")
st.divider()

# Load data
@st.cache_data(ttl=300)
def load_data():
    with engine.connect() as conn:
        df = pd.read_sql(text("SELECT * FROM iocs"), conn)
    return df

df = load_data()

if df.empty:
    st.warning("No data yet. Run scheduler.py first.")
    st.stop()

# KPI Cards
col1, col2, col3, col4 = st.columns(4)
total = len(df)
high_risk = len(df[df["abuse_score"] >= 75])
countries = df["country"].nunique()
tactics = df["mitre_tactic"].nunique()

col1.metric("🔴 Total IOCs", f"{total:,}", "Live feed")
col2.metric("⚠️ High Risk (≥75)", f"{high_risk:,}", f"{round(high_risk/total*100)}% of total")
col3.metric("🌍 Countries", countries)
col4.metric("🗺️ MITRE Tactics", tactics)

st.divider()

# Charts row
col_left, col_right = st.columns(2)

with col_left:
    st.subheader("IOCs by MITRE ATT&CK Tactic")
    tactic_df = df["mitre_tactic"].value_counts().reset_index()
    tactic_df.columns = ["Tactic", "Count"]
    fig1 = px.bar(
        tactic_df, x="Count", y="Tactic",
        orientation="h",
        color="Count",
        color_continuous_scale="Reds",
        height=350
    )
    fig1.update_layout(
        plot_bgcolor="rgba(0,0,0,0)",
        paper_bgcolor="rgba(0,0,0,0)",
        showlegend=False,
        coloraxis_showscale=False,
        yaxis={"categoryorder": "total ascending"}
    )
    st.plotly_chart(fig1, use_container_width=True)

with col_right:
    st.subheader("IOCs by Type")
    type_df = df["ioc_type"].value_counts().reset_index()
    type_df.columns = ["Type", "Count"]
    fig2 = px.pie(
        type_df, values="Count", names="Type",
        color_discrete_sequence=px.colors.sequential.RdBu,
        height=350,
        hole=0.4
    )
    fig2.update_layout(
        plot_bgcolor="rgba(0,0,0,0)",
        paper_bgcolor="rgba(0,0,0,0)"
    )
    st.plotly_chart(fig2, use_container_width=True)

# Abuse score distribution
st.subheader("Abuse Score Distribution")
fig3 = px.histogram(
    df[df["abuse_score"] > 0],
    x="abuse_score",
    nbins=20,
    color_discrete_sequence=["#e74c3c"],
    labels={"abuse_score": "Abuse Score", "count": "Number of IOCs"},
    height=250
)
fig3.update_layout(
    plot_bgcolor="rgba(0,0,0,0)",
    paper_bgcolor="rgba(0,0,0,0)"
)
st.plotly_chart(fig3, use_container_width=True)

# Top threat actors
st.subheader("Top Threat Actors")
actor_df = df["threat_actor"].value_counts().head(10).reset_index()
actor_df.columns = ["Threat Actor", "IOC Count"]
st.dataframe(actor_df, use_container_width=True, hide_index=True)

# Recent IOCs
st.subheader("Recent IOCs")
recent = df.sort_values("created_at", ascending=False).head(20)
st.dataframe(
    recent[["indicator", "ioc_type", "threat_actor",
            "mitre_tactic", "abuse_score", "country", "created_at"]],
    use_container_width=True,
    hide_index=True
)