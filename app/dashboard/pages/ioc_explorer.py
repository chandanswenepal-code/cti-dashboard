import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..')))

import streamlit as st
import pandas as pd
import plotly.express as px
from app.data.database import engine, init_db

init_db()
st.set_page_config(page_title="IOC Explorer", page_icon="📋", layout="wide")

st.markdown("""
<style>
[data-testid="stMetric"] {
    border-radius:10px;padding:0.8rem;
    box-shadow:0 2px 8px rgba(0,0,0,0.06);
}
.block-container { padding-top: 1rem; }
</style>
""", unsafe_allow_html=True)

st.markdown("""
<div style="background:linear-gradient(135deg,#0f0c29,#302b63);
            padding:1.5rem 2rem;border-radius:15px;margin-bottom:1.5rem">
    <h1 style="color:white;margin:0;font-size:2rem">📋 IOC Explorer</h1>
    <p style="color:#aaa;margin:0.3rem 0 0">Search, filter and analyze all collected Indicators of Compromise</p>
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

with st.sidebar:
    st.markdown("### 🔎 Filters")
    search = st.text_input("Search indicator", placeholder="IP, domain, URL...")
    ioc_types = ["All"] + sorted(df["ioc_type"].dropna().unique().tolist())
    selected_type = st.selectbox("IOC Type", ioc_types)
    score_min = st.slider("Min Abuse Score", 0, 100, 0)
    tactics = ["All"] + sorted(df["mitre_tactic"].dropna().unique().tolist())
    selected_tactic = st.selectbox("MITRE Tactic", tactics)
    countries = ["All"] + sorted(df["country"].dropna().unique().tolist())
    selected_country = st.selectbox("Country", countries)
    actors = ["All"] + sorted(df["threat_actor"].dropna().unique().tolist())
    selected_actor = st.selectbox("Threat Actor", actors)
    st.markdown("---")
    if st.button("🔄 Refresh", use_container_width=True):
        st.cache_data.clear()
        st.rerun()

filtered = df.copy()
if search:
    filtered = filtered[filtered["indicator"].str.contains(search, case=False, na=False)]
if selected_type != "All":
    filtered = filtered[filtered["ioc_type"] == selected_type]
if selected_tactic != "All":
    filtered = filtered[filtered["mitre_tactic"] == selected_tactic]
if selected_country != "All":
    filtered = filtered[filtered["country"] == selected_country]
if selected_actor != "All":
    filtered = filtered[filtered["threat_actor"] == selected_actor]
filtered = filtered[filtered["abuse_score"] >= score_min]

total = len(df)
f_total = len(filtered)
high = len(filtered[filtered["abuse_score"] >= 75])
medium = len(filtered[(filtered["abuse_score"] >= 25) & (filtered["abuse_score"] < 75)])
low = len(filtered[filtered["abuse_score"] < 25])

filter_active = ' — <b style="color:#e74c3c">Filter active</b>' if f_total < total else ""
st.markdown(f"""
<div style="background:#eaf4fb;border-radius:10px;padding:0.8rem 1.2rem;
            margin-bottom:1rem;border-left:5px solid #2980b9">
    Showing <b>{f_total:,}</b> of <b>{total:,}</b> total IOCs{filter_active}
</div>
""", unsafe_allow_html=True)

c1, c2, c3, c4 = st.columns(4)
c1.metric("📊 Total Shown", f"{f_total:,}")
c2.metric("🔴 High Risk", f"{high:,}")
c3.metric("🟡 Medium Risk", f"{medium:,}")
c4.metric("🟢 Low Risk", f"{low:,}")

st.markdown("---")

col_left, col_right = st.columns(2)

with col_left:
    tactic_df = filtered["mitre_tactic"].value_counts().head(8).reset_index()
    tactic_df.columns = ["Tactic","Count"]
    fig1 = px.bar(
        tactic_df, x="Count", y="Tactic", orientation="h",
        color="Count", color_continuous_scale=["#fff5f5","#e74c3c"],
        title="IOCs by MITRE Tactic", height=320, text="Count"
    )
    fig1.update_traces(textposition="outside")
    fig1.update_layout(
        plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)",
        coloraxis_showscale=False,
        yaxis={"categoryorder":"total ascending"},
        margin=dict(l=10,r=40,t=40,b=10)
    )
    st.plotly_chart(fig1, use_container_width=True)

with col_right:
    country_df = filtered[filtered["country"] != "Unknown"]["country"].value_counts().head(10).reset_index()
    country_df.columns = ["Country","Count"]
    fig2 = px.bar(
        country_df, x="Country", y="Count",
        color="Count", color_continuous_scale=["#fff5f5","#e74c3c"],
        title="Top Countries", height=320, text="Count"
    )
    fig2.update_traces(textposition="outside")
    fig2.update_layout(
        plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)",
        coloraxis_showscale=False,
        margin=dict(l=10,r=10,t=40,b=10)
    )
    st.plotly_chart(fig2, use_container_width=True)

st.markdown("#### 📊 IOC Data Table")
st.dataframe(
    filtered[["indicator","ioc_type","threat_actor","mitre_tactic",
              "abuse_score","country","tags","created_at"]]
    .sort_values("abuse_score", ascending=False),
    use_container_width=True,
    hide_index=True,
    column_config={
        "abuse_score": st.column_config.ProgressColumn(
            "Abuse Score", min_value=0, max_value=100, format="%d"),
        "indicator": st.column_config.TextColumn("Indicator", width="large"),
        "mitre_tactic": st.column_config.TextColumn("MITRE Tactic", width="medium"),
        "tags": st.column_config.TextColumn("Tags", width="medium"),
    }
)

col_dl1, col_dl2 = st.columns(2)
with col_dl1:
    st.download_button(
        "⬇️ Export as CSV",
        filtered.to_csv(index=False),
        "iocs_export.csv", "text/csv",
        use_container_width=True
    )
with col_dl2:
    st.download_button(
        "⬇️ Export as JSON",
        filtered.to_json(orient="records", indent=2),
        "iocs_export.json", "application/json",
        use_container_width=True
    )