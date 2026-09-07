import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..'))
import streamlit as st
import pandas as pd
import plotly.express as px
from app.data.database import engine, init_db

init_db()
st.set_page_config(page_title="IOC Explorer", page_icon="📋", layout="wide")
st.title("📋 IOC Explorer")
st.caption("Search, filter and analyze all collected Indicators of Compromise")
st.divider()

@st.cache_data(ttl=300)
def load_data():
    with engine.connect() as conn:
        df = pd.read_sql("SELECT * FROM iocs", conn)
    return df

df = load_data()

with st.sidebar:
    st.header("🔎 Filters")

    search = st.text_input("Search indicator", placeholder="IP, domain, URL...")

    ioc_types = ["All"] + sorted(df["ioc_type"].dropna().unique().tolist())
    selected_type = st.selectbox("IOC Type", ioc_types)

    score_min = st.slider("Min Abuse Score", 0, 100, 0)

    tactics = ["All"] + sorted(df["mitre_tactic"].dropna().unique().tolist())
    selected_tactic = st.selectbox("MITRE Tactic", tactics)

    countries = ["All"] + sorted(df["country"].dropna().unique().tolist())
    selected_country = st.selectbox("Country", countries)

    st.divider()
    if st.button("🔄 Refresh Data"):
        st.cache_data.clear()
        st.rerun()

# Apply filters
filtered = df.copy()
if search:
    filtered = filtered[filtered["indicator"].str.contains(search, case=False, na=False)]
if selected_type != "All":
    filtered = filtered[filtered["ioc_type"] == selected_type]
if selected_tactic != "All":
    filtered = filtered[filtered["mitre_tactic"] == selected_tactic]
if selected_country != "All":
    filtered = filtered[filtered["country"] == selected_country]
filtered = filtered[filtered["abuse_score"] >= score_min]

st.info(f"Showing **{len(filtered)}** of **{len(df)}** total IOCs")

# Risk breakdown
col1, col2, col3 = st.columns(3)
col1.metric("🔴 High Risk (≥75)", len(filtered[filtered["abuse_score"] >= 75]))
col2.metric("🟡 Medium Risk (25-74)", len(filtered[(filtered["abuse_score"] >= 25) & (filtered["abuse_score"] < 75)]))
col3.metric("🟢 Low Risk (<25)", len(filtered[filtered["abuse_score"] < 25]))

st.divider()

# Country chart
if not filtered.empty:
    country_df = filtered["country"].value_counts().head(10).reset_index()
    country_df.columns = ["Country", "Count"]
    fig = px.bar(
        country_df, x="Country", y="Count",
        color="Count",
        color_continuous_scale="Reds",
        title="Top 10 Countries by IOC Count",
        height=250
    )
    fig.update_layout(
        plot_bgcolor="rgba(0,0,0,0)",
        paper_bgcolor="rgba(0,0,0,0)",
        coloraxis_showscale=False
    )
    st.plotly_chart(fig, use_container_width=True)

# Main data table
st.subheader("IOC Data Table")
display_cols = ["indicator", "ioc_type", "threat_actor",
                "mitre_tactic", "abuse_score", "country", "tags"]
st.dataframe(
    filtered[display_cols].sort_values("abuse_score", ascending=False),
    use_container_width=True,
    hide_index=True,
    column_config={
        "abuse_score": st.column_config.ProgressColumn(
            "Abuse Score",
            min_value=0,
            max_value=100,
            format="%d"
        )
    }
)

# Export
csv = filtered.to_csv(index=False)
st.download_button(
    "⬇️ Export as CSV",
    csv,
    "iocs_export.csv",
    "text/csv"
)