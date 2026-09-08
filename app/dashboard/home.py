import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

import streamlit as st
import plotly.express as px
import plotly.graph_objects as go
import pandas as pd
from datetime import datetime
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

html, body, [data-testid="stAppViewContainer"] {
    background-color: #0d0d0d !important;
    color: #e0e0e0 !important;
}
.block-container { padding-top: 0.5rem !important; max-width: 100% !important; }
#MainMenu, footer, header { visibility: hidden; }
::-webkit-scrollbar { width: 4px; }
::-webkit-scrollbar-track { background: #0d0d0d; }
::-webkit-scrollbar-thumb { background: #00ff41; border-radius: 2px; }

/* ── Sidebar ── */
[data-testid="stSidebar"] {
    background: #0a0a0a !important;
    border-right: 1px solid #1a1a2e !important;
    padding: 0 !important;
}
[data-testid="stSidebarContent"] { padding: 0 !important; }

/* ── Metrics ── */
[data-testid="stMetric"] {
    background: #111827 !important;
    border: 1px solid #1f2937 !important;
    border-radius: 8px !important;
    padding: 1rem 1.2rem !important;
    transition: all 0.3s ease;
    position: relative;
    overflow: hidden;
}
[data-testid="stMetric"]:hover {
    border-color: #3b82f6 !important;
    box-shadow: 0 0 20px #3b82f622 !important;
}
[data-testid="stMetricLabel"] p {
    color: #6b7280 !important;
    font-family: 'Share Tech Mono', monospace !important;
    font-size: 0.7rem !important;
    letter-spacing: 2px !important;
    text-transform: uppercase !important;
}
[data-testid="stMetricValue"] {
    color: #f9fafb !important;
    font-family: 'Orbitron', monospace !important;
    font-size: 1.6rem !important;
    font-weight: 700 !important;
}
[data-testid="stMetricDelta"] { color: #6b7280 !important; font-size: 0.7rem !important; }

/* ── Dataframe ── */
[data-testid="stDataFrame"] {
    border: 1px solid #1f2937 !important;
    border-radius: 8px !important;
}

/* ── Buttons ── */
[data-testid="stButton"] button {
    background: transparent !important;
    border: 1px solid #374151 !important;
    color: #9ca3af !important;
    font-family: 'Share Tech Mono', monospace !important;
    letter-spacing: 1px !important;
    border-radius: 6px !important;
    transition: all 0.2s !important;
    font-size: 0.75rem !important;
}
[data-testid="stButton"] button:hover {
    border-color: #00ff41 !important;
    color: #00ff41 !important;
    box-shadow: 0 0 15px #00ff4133 !important;
}

/* ── Divider ── */
hr { border-color: #1f2937 !important; }

/* ── Selectbox ── */
[data-testid="stSelectbox"] > div > div {
    background: #111827 !important;
    border-color: #374151 !important;
    color: #e0e0e0 !important;
}
</style>
""", unsafe_allow_html=True)

# ── Sidebar ──
with st.sidebar:
    st.markdown("""
    <div style="background:#111827;border-bottom:1px solid #1f2937;padding:1.2rem 1rem">
        <div style="font-family:'Orbitron',monospace;font-size:0.95rem;
                    font-weight:900;color:#00ff41;letter-spacing:2px">
            🛡 CTI DASHBOARD
        </div>
        <div style="font-size:0.6rem;color:#4b5563;letter-spacing:3px;margin-top:3px;
                    font-family:'Share Tech Mono',monospace">
            THREAT INTELLIGENCE v2.0
        </div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("""
    <div style="padding:1rem;font-family:'Share Tech Mono',monospace">
        <div style="font-size:0.65rem;color:#4b5563;letter-spacing:3px;
                    margin-bottom:10px;border-bottom:1px solid #1f2937;padding-bottom:6px">
            NAVIGATION
        </div>
    </div>
    """, unsafe_allow_html=True)

    pages = {
        "🏠  HOME": None,
        "🔍  IP LOOKUP": "ip_lookup",
        "📋  IOC EXPLORER": "ioc_explorer",
    }
    for label in pages:
        is_active = label == "🏠  HOME"
        bg = "#1f2937" if is_active else "transparent"
        color = "#00ff41" if is_active else "#6b7280"
        border = "border-left:2px solid #00ff41;" if is_active else "border-left:2px solid transparent;"
        st.markdown(f"""
        <div style="padding:0.6rem 1rem;background:{bg};cursor:pointer;
                    {border}margin:2px 0;border-radius:0 6px 6px 0;
                    font-family:'Share Tech Mono',monospace;font-size:0.78rem;
                    color:{color};letter-spacing:1px">
            {label}
        </div>
        """, unsafe_allow_html=True)

    st.markdown("""
    <div style="padding:0 1rem;margin-top:1.5rem;font-family:'Share Tech Mono',monospace">
        <div style="font-size:0.65rem;color:#4b5563;letter-spacing:3px;
                    margin-bottom:10px;border-bottom:1px solid #1f2937;padding-bottom:6px">
            FEED STATUS
        </div>
        <div style="display:flex;align-items:center;gap:8px;margin-bottom:8px">
            <div style="width:7px;height:7px;border-radius:50%;background:#00ff41;
                        box-shadow:0 0 8px #00ff41;animation:pulse 2s infinite"></div>
            <span style="font-size:0.72rem;color:#9ca3af">AlienVault OTX</span>
            <span style="margin-left:auto;font-size:0.65rem;color:#00ff41">LIVE</span>
        </div>
        <div style="display:flex;align-items:center;gap:8px;margin-bottom:8px">
            <div style="width:7px;height:7px;border-radius:50%;background:#00ff41;
                        box-shadow:0 0 8px #00ff41"></div>
            <span style="font-size:0.72rem;color:#9ca3af">AbuseIPDB</span>
            <span style="margin-left:auto;font-size:0.65rem;color:#00ff41">LIVE</span>
        </div>
        <div style="display:flex;align-items:center;gap:8px;margin-bottom:8px">
            <div style="width:7px;height:7px;border-radius:50%;background:#3b82f6;
                        box-shadow:0 0 8px #3b82f6"></div>
            <span style="font-size:0.72rem;color:#9ca3af">MITRE ATT&CK</span>
            <span style="margin-left:auto;font-size:0.65rem;color:#3b82f6">MAPPED</span>
        </div>
        <div style="display:flex;align-items:center;gap:8px">
            <div style="width:7px;height:7px;border-radius:50%;background:#f59e0b;
                        box-shadow:0 0 8px #f59e0b"></div>
            <span style="font-size:0.72rem;color:#9ca3af">VirusTotal</span>
            <span style="margin-left:auto;font-size:0.65rem;color:#f59e0b">READY</span>
        </div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("""
    <div style="padding:0 1rem;margin-top:1.5rem;font-family:'Share Tech Mono',monospace">
        <div style="font-size:0.65rem;color:#4b5563;letter-spacing:3px;
                    margin-bottom:10px;border-bottom:1px solid #1f2937;padding-bottom:6px">
            OPERATOR
        </div>
        <div style="font-size:0.72rem;color:#9ca3af;line-height:2">
            <div style="color:#e0e0e0">Chandan Yadav</div>
            <div>SOC Analyst</div>
            <div style="color:#00ff41;margin-top:4px">● ONLINE</div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("<div style='height:40px'></div>", unsafe_allow_html=True)
    if st.button("⟳  REFRESH FEED", use_container_width=True):
        st.cache_data.clear()
        st.rerun()

# ── Header ──
now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
st.markdown(f"""
<div style="background:#111827;border:1px solid #1f2937;border-radius:10px;
            padding:1.2rem 1.5rem;margin-bottom:1rem;
            display:flex;align-items:center;justify-content:space-between">
    <div>
        <div style="font-family:'Orbitron',monospace;font-size:1.4rem;
                    font-weight:900;color:#f9fafb;letter-spacing:3px">
            🛡️ CYBER THREAT INTELLIGENCE
        </div>
        <div style="font-family:'Share Tech Mono',monospace;font-size:0.72rem;
                    color:#4b5563;letter-spacing:2px;margin-top:4px">
            REAL-TIME IOC MONITORING · MITRE ATT&CK MAPPING · THREAT ACTOR PROFILING
        </div>
    </div>
    <div style="text-align:right;font-family:'Share Tech Mono',monospace">
        <div style="font-size:0.65rem;color:#4b5563;letter-spacing:2px">LAST UPDATED</div>
        <div style="font-size:0.8rem;color:#00ff41;margin-top:2px">{now} UTC</div>
        <div style="display:flex;align-items:center;justify-content:flex-end;
                    gap:6px;margin-top:4px">
            <div style="width:6px;height:6px;border-radius:50%;background:#00ff41;
                        box-shadow:0 0 8px #00ff41"></div>
            <span style="font-size:0.65rem;color:#00ff41">SYSTEM OPERATIONAL</span>
        </div>
    </div>
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
    <div style="border:1px solid #ef444433;border-radius:8px;background:#1c0a0a;
                padding:1.5rem;text-align:center;font-family:'Share Tech Mono',monospace">
        <div style="color:#ef4444;font-size:1rem;letter-spacing:2px">⚠ DATABASE EMPTY</div>
        <div style="color:#6b7280;margin-top:8px;font-size:0.8rem">
            Run scheduler.py to populate threat intelligence data
        </div>
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
c1, c2, c3, c4, c5, c6 = st.columns(6)
c1.metric("TOTAL IOCs", f"{total:,}", "LIVE")
c2.metric("HIGH RISK", f"{high_risk:,}", f"{round(high_risk/total*100)}%")
c3.metric("MEDIUM RISK", f"{medium_risk:,}", "WATCH")
c4.metric("LOW RISK", f"{low_risk:,}", "CLEAR")
c5.metric("COUNTRIES", f"{countries}", "TRACKED")
c6.metric("ACTORS", f"{actors}", "PROFILED")

st.markdown("<div style='height:1px;background:#1f2937;margin:1rem 0'></div>", unsafe_allow_html=True)

# ── Chart helpers ──
def dark_layout(fig, height=360, title=""):
    fig.update_layout(
        plot_bgcolor="#111827",
        paper_bgcolor="rgba(0,0,0,0)",
        font=dict(color="#9ca3af", family="Share Tech Mono, monospace", size=10),
        height=height,
        margin=dict(l=10, r=50, t=30, b=10),
        xaxis=dict(gridcolor="#1f2937", zerolinecolor="#1f2937",
                   tickfont=dict(color="#6b7280"), title=""),
        yaxis=dict(gridcolor="#1f2937", zerolinecolor="#1f2937",
                   tickfont=dict(color="#6b7280"), title=""),
        coloraxis_showscale=False,
        title=dict(text=title, font=dict(color="#9ca3af", size=11,
                   family="Share Tech Mono"), x=0, xanchor="left")
    )
    return fig

# ── Row 1 Charts ──
col_left, col_right = st.columns([1.3, 1])

with col_left:
    tactic_df = df["mitre_tactic"].value_counts().reset_index()
    tactic_df.columns = ["Tactic","Count"]
    tactic_df = tactic_df[tactic_df["Tactic"] != "Unknown"]
    colors = ["#ef4444","#f97316","#f59e0b","#84cc16","#22c55e","#06b6d4","#6366f1","#a855f7"]
    fig1 = go.Figure(go.Bar(
        x=tactic_df["Count"], y=tactic_df["Tactic"],
        orientation="h",
        marker=dict(
            color=colors[:len(tactic_df)],
            line=dict(color="#0d0d0d", width=0.5)
        ),
        text=tactic_df["Count"],
        textposition="outside",
        textfont=dict(color="#9ca3af", size=10)
    ))
    fig1 = dark_layout(fig1, 380, "▸ MITRE ATT&CK TACTICS")
    fig1.update_layout(yaxis=dict(categoryorder="total ascending",
                                   gridcolor="#1f2937",
                                   tickfont=dict(color="#9ca3af")))
    st.plotly_chart(fig1, use_container_width=True)

with col_right:
    type_df = df["ioc_type"].value_counts().reset_index()
    type_df.columns = ["Type","Count"]
    fig2 = px.pie(type_df, values="Count", names="Type", hole=0.6,
                  color_discrete_sequence=["#3b82f6","#8b5cf6","#ec4899","#f59e0b","#10b981"])
    fig2.update_traces(
        textposition="outside", textinfo="percent+label",
        textfont=dict(color="#9ca3af", size=10),
        marker=dict(line=dict(color="#0d0d0d", width=2))
    )
    fig2.update_layout(
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="#111827",
        showlegend=False, height=380,
        margin=dict(l=10,r=10,t=30,b=10),
        font=dict(color="#9ca3af"),
        title=dict(text="▸ IOC TYPE DISTRIBUTION",
                   font=dict(color="#9ca3af", size=11), x=0)
    )
    st.plotly_chart(fig2, use_container_width=True)

# ── Row 2 Charts ──
col3a, col3b = st.columns(2)

with col3a:
    country_df = df[df["country"] != "Unknown"]["country"].value_counts().head(10).reset_index()
    country_df.columns = ["Country","Count"]
    fig3 = px.bar(country_df, x="Country", y="Count",
                  color="Count",
                  color_continuous_scale=["#1e3a5f","#3b82f6","#93c5fd"],
                  text="Count")
    fig3.update_traces(textposition="outside",
                       textfont=dict(color="#9ca3af"),
                       marker_line_color="#0d0d0d", marker_line_width=0.5)
    fig3 = dark_layout(fig3, 300, "▸ TOP COUNTRIES")
    st.plotly_chart(fig3, use_container_width=True)

with col3b:
    fig4 = go.Figure()
    risk_labels = ["HIGH ≥75","MEDIUM 25-74","LOW <25"]
    risk_values = [high_risk, medium_risk, low_risk]
    risk_colors = ["#ef4444","#f59e0b","#22c55e"]
    for i, (label, value, color) in enumerate(zip(risk_labels, risk_values, risk_colors)):
        fig4.add_trace(go.Bar(
            x=[value], y=[label],
            orientation="h",
            marker=dict(color=color, line=dict(color="#0d0d0d", width=0.5)),
            text=[value], textposition="outside",
            textfont=dict(color="#9ca3af", size=10),
            name=label, showlegend=False
        ))
    fig4 = dark_layout(fig4, 300, "▸ RISK DISTRIBUTION")
    st.plotly_chart(fig4, use_container_width=True)

# ── Stats Row ──
st.markdown("<div style='height:1px;background:#1f2937;margin:0.5rem 0'></div>", unsafe_allow_html=True)
col_s1, col_s2, col_s3 = st.columns(3)

with col_s1:
    st.markdown("""<div style="font-family:'Share Tech Mono',monospace;color:#6b7280;
                font-size:0.7rem;letter-spacing:2px;margin-bottom:8px">
                ▸ IOC TIMELINE</div>""", unsafe_allow_html=True)
    if "created_at" in df.columns:
        df["date"] = pd.to_datetime(df["created_at"]).dt.date
        timeline = df.groupby("date").size().reset_index(name="Count")
        fig5 = px.area(timeline, x="date", y="Count",
                       color_discrete_sequence=["#3b82f6"])
        fig5.update_traces(fill="tozeroy", fillcolor="#3b82f622",
                           line=dict(color="#3b82f6", width=1.5))
        fig5 = dark_layout(fig5, 200)
        st.plotly_chart(fig5, use_container_width=True)

with col_s2:
    st.markdown("""<div style="font-family:'Share Tech Mono',monospace;color:#6b7280;
                font-size:0.7rem;letter-spacing:2px;margin-bottom:8px">
                ▸ TOP THREAT ACTORS</div>""", unsafe_allow_html=True)
    actor_df = df["threat_actor"].value_counts().head(5).reset_index()
    actor_df.columns = ["Actor","Count"]
    for _, row in actor_df.iterrows():
        pct = int(row["Count"]/total*100)
        st.markdown(f"""
        <div style="margin-bottom:8px">
            <div style="display:flex;justify-content:space-between;
                        font-family:'Share Tech Mono',monospace;font-size:0.72rem;
                        color:#9ca3af;margin-bottom:3px">
                <span>{row['Actor'][:25]}</span>
                <span style="color:#6b7280">{row['Count']}</span>
            </div>
            <div style="height:4px;background:#1f2937;border-radius:2px">
                <div style="height:4px;width:{min(pct*3,100)}%;background:#3b82f6;
                            border-radius:2px;box-shadow:0 0 8px #3b82f655"></div>
            </div>
        </div>
        """, unsafe_allow_html=True)

with col_s3:
    st.markdown("""<div style="font-family:'Share Tech Mono',monospace;color:#6b7280;
                font-size:0.7rem;letter-spacing:2px;margin-bottom:8px">
                ▸ THREAT SUMMARY</div>""", unsafe_allow_html=True)
    summary_items = [
        ("TOTAL IOCs TRACKED", f"{total:,}", "#f9fafb"),
        ("HIGH SEVERITY", f"{high_risk:,}", "#ef4444"),
        ("MEDIUM SEVERITY", f"{medium_risk:,}", "#f59e0b"),
        ("LOW SEVERITY", f"{low_risk:,}", "#22c55e"),
        ("COUNTRIES AFFECTED", f"{countries}", "#3b82f6"),
        ("MITRE TACTICS", f"{tactics}", "#8b5cf6"),
        ("THREAT ACTORS", f"{actors}", "#ec4899"),
    ]
    for label, value, color in summary_items:
        st.markdown(f"""
        <div style="display:flex;justify-content:space-between;
                    font-family:'Share Tech Mono',monospace;font-size:0.72rem;
                    padding:5px 0;border-bottom:1px solid #1f2937">
            <span style="color:#6b7280">{label}</span>
            <span style="color:{color};font-weight:600">{value}</span>
        </div>
        """, unsafe_allow_html=True)

# ── Live Feed ──
st.markdown("<div style='height:1px;background:#1f2937;margin:1rem 0'></div>", unsafe_allow_html=True)
st.markdown("""<div style="font-family:'Share Tech Mono',monospace;color:#6b7280;
            font-size:0.7rem;letter-spacing:2px;margin-bottom:8px">
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
<div style="text-align:center;font-family:'Share Tech Mono',monospace;
            color:#374151;font-size:0.65rem;letter-spacing:2px;
            padding:1rem 0;margin-top:0.5rem;border-top:1px solid #1f2937">
    CTI DASHBOARD · CHANDAN YADAV · ALIENVAULT OTX · ABUSEIPDB · MITRE ATT&CK
</div>
""", unsafe_allow_html=True)