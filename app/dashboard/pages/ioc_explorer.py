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
}
[data-testid="stMetricValue"] {
    color: #00ff41 !important;
    font-family: 'Orbitron', monospace !important;
}
[data-testid="stSelectbox"] > div > div,
[data-testid="stTextInput"] > div > div input {
    background: #0a1628 !important;
    border-color: #00ff4133 !important;
    color: #00ff41 !important;
    font-family: 'Share Tech Mono', monospace !important;
}
[data-testid="stSlider"] > div > div > div {
    background: #00ff41 !important;
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
hr { border-color: #00ff4133 !important; }
::-webkit-scrollbar { width: 4px; }
::-webkit-scrollbar-thumb { background: #00ff41; }
[data-testid="stDownloadButton"] button {
    background: transparent !important;
    border: 1px solid #00ff4155 !important;
    color: #00ff41 !important;
    font-family: 'Share Tech Mono', monospace !important;
}
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
        📋 IOC EXPLORER
    </div>
    <div style="font-family:'Share Tech Mono',monospace;font-size:0.75rem;
                color:#00ff4199;letter-spacing:3px;margin-top:6px">
        SEARCH · FILTER · ANALYZE ALL INDICATORS OF COMPROMISE
    </div>
    <div style="position:absolute;bottom:0;left:0;right:0;height:2px;
                background:linear-gradient(90deg,transparent,#00ff41,transparent)"></div>
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
    st.markdown("""<div style="font-family:'Share Tech Mono',monospace;color:#00ff41;
                font-size:0.8rem;letter-spacing:3px;margin-bottom:12px">
                ▸ FILTER CONTROLS</div>""", unsafe_allow_html=True)
    search = st.text_input("SEARCH", placeholder="IP, domain, URL...")
    ioc_types = ["All"] + sorted(df["ioc_type"].dropna().unique().tolist())
    selected_type = st.selectbox("IOC TYPE", ioc_types)
    score_min = st.slider("MIN ABUSE SCORE", 0, 100, 0)
    tactics = ["All"] + sorted(df["mitre_tactic"].dropna().unique().tolist())
    selected_tactic = st.selectbox("MITRE TACTIC", tactics)
    countries = ["All"] + sorted(df["country"].dropna().unique().tolist())
    selected_country = st.selectbox("COUNTRY", countries)
    actors = ["All"] + sorted(df["threat_actor"].dropna().unique().tolist())
    selected_actor = st.selectbox("THREAT ACTOR", actors)
    st.markdown("<div style='height:1px;background:#00ff4133;margin:8px 0'></div>", unsafe_allow_html=True)
    if st.button("⟳ REFRESH", use_container_width=True):
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

filter_tag = ' <span style="color:#ff4444">[ FILTER ACTIVE ]</span>' if f_total < total else ' <span style="color:#00ff41">[ ALL RECORDS ]</span>'
st.markdown(f"""
<div style="border:1px solid #00ff4133;border-radius:6px;background:#0a1628;
            padding:0.75rem 1.2rem;margin-bottom:1rem;
            font-family:'Share Tech Mono',monospace;font-size:0.85rem">
    SHOWING <span style="color:#00ff41;font-size:1.1rem">{f_total:,}</span>
    OF <span style="color:#00ff4199">{total:,}</span> RECORDS{filter_tag}
</div>
""", unsafe_allow_html=True)

c1, c2, c3, c4 = st.columns(4)
c1.metric("TOTAL SHOWN", f"{f_total:,}")
c2.metric("HIGH RISK", f"{high:,}")
c3.metric("MEDIUM RISK", f"{medium:,}")
c4.metric("LOW RISK", f"{low:,}")

st.markdown("<div style='height:1px;background:linear-gradient(90deg,transparent,#00ff41,transparent);margin:1rem 0'></div>", unsafe_allow_html=True)

def cyber_chart(fig, height=300):
    fig.update_layout(
        plot_bgcolor="#010b13",
        paper_bgcolor="rgba(0,0,0,0)",
        font=dict(color="#00ff41", family="Share Tech Mono, monospace", size=11),
        height=height,
        margin=dict(l=10, r=50, t=40, b=10),
        xaxis=dict(gridcolor="#00ff4122", tickfont=dict(color="#00ff4199")),
        yaxis=dict(gridcolor="#00ff4122", tickfont=dict(color="#00ff4199"),
                   categoryorder="total ascending"),
        coloraxis_showscale=False,
        title_font=dict(color="#00ff41", family="Share Tech Mono", size=12),
    )
    return fig

col_left, col_right = st.columns(2)

with col_left:
    tactic_df = filtered["mitre_tactic"].value_counts().head(8).reset_index()
    tactic_df.columns = ["Tactic","Count"]
    fig1 = px.bar(tactic_df, x="Count", y="Tactic", orientation="h",
                  color="Count",
                  color_continuous_scale=["#003300","#00ff41"],
                  title="▸ MITRE TACTIC BREAKDOWN", text="Count")
    fig1.update_traces(textposition="outside",
                       textfont=dict(color="#00ff41"),
                       marker_line_color="#00ff4133", marker_line_width=0.5)
    fig1 = cyber_chart(fig1)
    st.plotly_chart(fig1, use_container_width=True)

with col_right:
    country_df = filtered[filtered["country"] != "Unknown"]["country"].value_counts().head(10).reset_index()
    country_df.columns = ["Country","Count"]
    fig2 = px.bar(country_df, x="Country", y="Count",
                  color="Count",
                  color_continuous_scale=["#003300","#00ff41"],
                  title="▸ TOP COUNTRIES", text="Count")
    fig2.update_traces(textposition="outside",
                       textfont=dict(color="#00ff41"),
                       marker_line_color="#00ff4133", marker_line_width=0.5)
    fig2 = cyber_chart(fig2)
    fig2.update_layout(yaxis=dict(categoryorder="total descending"))
    st.plotly_chart(fig2, use_container_width=True)

st.markdown("""<div style="font-family:'Share Tech Mono',monospace;color:#00ff41;
            font-size:0.8rem;letter-spacing:3px;margin:0.5rem 0 8px">
            ▸ IOC DATABASE TABLE</div>""", unsafe_allow_html=True)

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

st.markdown("<div style='height:1px;background:linear-gradient(90deg,transparent,#00ff41,transparent);margin:0.5rem 0'></div>", unsafe_allow_html=True)

col_dl1, col_dl2 = st.columns(2)
with col_dl1:
    st.download_button("⬇ EXPORT CSV", filtered.to_csv(index=False),
                       "iocs_export.csv", "text/csv", use_container_width=True)
with col_dl2:
    st.download_button("⬇ EXPORT JSON",
                       filtered.to_json(orient="records", indent=2),
                       "iocs_export.json", "application/json", use_container_width=True)