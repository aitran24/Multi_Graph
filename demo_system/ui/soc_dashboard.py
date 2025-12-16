"""
MultiKG SOC Dashboard - Optimized Version
Less lag, cleaner UI, no demo buttons
"""

import streamlit as st
import pandas as pd
import json
from datetime import datetime
from pathlib import Path

# Page config - sidebar cannot be collapsed
st.set_page_config(
    page_title="MultiKG SOC",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Paths
DATA_FILE = Path(__file__).parent.parent / "logs" / "realtime_data.json"

# MITRE Data
TACTICS = {
    "TA0001": "Initial Access", "TA0002": "Execution", "TA0003": "Persistence",
    "TA0004": "Privilege Escalation", "TA0005": "Defense Evasion", "TA0006": "Credential Access",
    "TA0007": "Discovery", "TA0008": "Lateral Movement", "TA0009": "Collection",
    "TA0010": "Exfiltration", "TA0011": "Command & Control"
}

TECHNIQUE_TACTICS = {
    "T1059.001": ["TA0002"], "T1112": ["TA0005"], "T1003.001": ["TA0006"],
    "T1547.001": ["TA0003", "TA0004"], "T1218.011": ["TA0005"], "T1482": ["TA0007"],
}

# Optimized CSS - minimal, no animations that cause reflow
st.markdown("""
<style>
    /* Dark Theme */
    .stApp { background: #0d1117; }
    #MainMenu, footer, header { visibility: hidden; }
    div[data-testid="stToolbar"], div[data-testid="stDecoration"], 
    div[data-testid="stStatusWidget"], .stDeployButton { display: none; }
    
    /* Force sidebar ALWAYS visible */
    [data-testid="stSidebar"] { 
        background: #161b22 !important;
        border-right: 1px solid #30363d !important;
        min-width: 280px !important;
        width: 280px !important;
        display: block !important;
        visibility: visible !important;
        transform: none !important;
        left: 0 !important;
    }
    
    [data-testid="stSidebar"] > div:first-child {
        background: #161b22 !important;
        padding-top: 2rem;
    }
    
    /* Prevent sidebar collapse */
    [data-testid="stSidebar"][aria-expanded="false"] {
        min-width: 280px !important;
        width: 280px !important;
        margin-left: 0 !important;
        transform: none !important;
        display: block !important;
    }
    
    /* Hide collapse button completely */
    button[kind="header"], 
    [data-testid="collapsedControl"],
    .css-1rs6os, .css-17ziqus {
        display: none !important;
    }
    
    /* All text white */
    .stApp, .stApp *, [data-testid="stSidebar"] * { color: #e6edf3 !important; }
    h1, h2, h3 { color: #ffffff !important; }
    
    /* Code blocks - DARK background */
    .stCodeBlock, pre, code, .stCodeBlock code, 
    [data-testid="stCodeBlock"], 
    div[data-testid="stCodeBlock"] pre {
        background: #161b22 !important;
        color: #7ee787 !important;
        border: 1px solid #30363d !important;
    }
    
    /* JSON viewer dark */
    .stJson, [data-testid="stJson"] {
        background: #161b22 !important;
    }
    .stJson *, [data-testid="stJson"] * {
        color: #7ee787 !important;
    }
    
    /* Expander dark */
    .streamlit-expanderHeader {
        background: #21262d !important;
        color: #e6edf3 !important;
    }
    .streamlit-expanderContent {
        background: #161b22 !important;
        border: 1px solid #30363d !important;
    }
    
    /* Metric cards */
    .metric-card {
        background: #161b22;
        border: 1px solid #30363d;
        border-radius: 8px;
        padding: 16px;
        text-align: center;
        margin-bottom: 8px;
    }
    .metric-value { font-size: 28px; font-weight: 700; }
    .metric-value.blue { color: #58a6ff; }
    .metric-value.red { color: #f85149; }
    .metric-value.orange { color: #d29922; }
    .metric-value.green { color: #3fb950; }
    .metric-label { color: #8b949e; font-size: 11px; text-transform: uppercase; margin-top: 4px; }
    
    /* Status */
    .status-secure { background: #238636; color: white; padding: 6px 16px; border-radius: 16px; font-weight: 600; font-size: 12px; }
    .status-threat { background: #da3633; color: white; padding: 6px 16px; border-radius: 16px; font-weight: 600; font-size: 12px; }
    
    /* Alert list - scrollable container */
    .alert-container {
        max-height: 500px;
        overflow-y: auto;
        padding-right: 8px;
    }
    
    .alert-item {
        background: #161b22;
        border: 1px solid #30363d;
        border-left: 4px solid #f85149;
        border-radius: 6px;
        padding: 12px;
        margin-bottom: 8px;
    }
    .alert-item.high { border-left-color: #f85149; }
    .alert-item.medium { border-left-color: #d29922; }
    .alert-item.low { border-left-color: #58a6ff; }
    
    .alert-tech { 
        background: #1f6feb; 
        color: white; 
        padding: 2px 8px; 
        border-radius: 4px; 
        font-size: 11px; 
        font-family: monospace;
        display: inline-block;
    }
    
    .alert-title { color: #e6edf3; font-weight: 600; font-size: 13px; margin-top: 6px; }
    .alert-meta { color: #8b949e; font-size: 11px; margin-top: 4px; }
    
    /* Tactic box */
    .tactic-box {
        background: #161b22;
        border: 1px solid #30363d;
        border-radius: 6px;
        padding: 10px;
        text-align: center;
        margin: 2px;
    }
    .tactic-box.active { border-color: #f85149; background: rgba(248,81,73,0.15); }
    .tactic-count { color: #fff; font-size: 20px; font-weight: 700; }
    .tactic-name { color: #8b949e; font-size: 8px; text-transform: uppercase; }
    
    /* Tabs */
    .stTabs [data-baseweb="tab-list"] { gap: 4px; }
    .stTabs [data-baseweb="tab"] { background: #21262d; border-radius: 6px; color: #8b949e; border: 1px solid #30363d; }
    .stTabs [aria-selected="true"] { background: #1f6feb !important; color: white !important; }
    
    /* Inputs */
    .stTextInput input, .stSelectbox > div > div { background: #0d1117 !important; border-color: #30363d !important; }
    
    /* Online dot */
    .online { color: #3fb950; }
    .offline { color: #f85149; }
    
    /* Scrollbar */
    ::-webkit-scrollbar { width: 6px; }
    ::-webkit-scrollbar-track { background: #0d1117; }
    ::-webkit-scrollbar-thumb { background: #30363d; border-radius: 3px; }
</style>
""", unsafe_allow_html=True)

# ============ HELPERS ============
@st.cache_data(ttl=2)
def load_data():
    try:
        if DATA_FILE.exists():
            with open(DATA_FILE, 'r') as f:
                return json.load(f)
    except: pass
    return {"updated": None, "stats": {}, "events": [], "detections": []}

def get_severity(conf):
    if conf >= 80: return ("CRITICAL", "#f85149", "high")
    elif conf >= 60: return ("HIGH", "#d29922", "high")
    elif conf >= 40: return ("MEDIUM", "#d29922", "medium")
    return ("LOW", "#58a6ff", "low")

def format_uptime(sec):
    if not sec: return "0s"
    if sec < 60: return f"{sec}s"
    elif sec < 3600: return f"{sec//60}m"
    return f"{sec//3600}h {(sec%3600)//60}m"

def parse_ts(ts):
    if not ts: return None
    for fmt in ["%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S"]:
        try: return datetime.strptime(ts, fmt)
        except: continue
    return None

# ============ LOAD DATA ============
data = load_data()
stats = data.get("stats", {})
events = data.get("events", [])
detections = data.get("detections", [])
last_update = data.get("updated")

is_online = False
if last_update:
    try:
        ut = datetime.strptime(last_update, "%Y-%m-%d %H:%M:%S")
        is_online = (datetime.now() - ut).total_seconds() < 5
    except: pass

has_threat = any(
    parse_ts(d.get("timestamp")) and (datetime.now() - parse_ts(d.get("timestamp"))).total_seconds() < 300
    for d in detections
)

# ============ SIDEBAR ============
with st.sidebar:
    st.markdown("## MultiKG SOC")
    st.markdown("---")
    
    page = st.radio("Navigation", ["Dashboard", "Alerts", "MITRE ATT&CK", "Search"], label_visibility="collapsed")
    
    st.markdown("---")
    st.markdown("**Status**")
    status_icon = "● Online" if is_online else "○ Offline"
    status_class = "online" if is_online else "offline"
    st.markdown(f'<span class="{status_class}">{status_icon}</span>', unsafe_allow_html=True)
    
    st.caption(f"Events: {stats.get('total_events', 0)}")
    st.caption(f"Alerts: {len(detections)}")
    st.caption(f"Uptime: {format_uptime(stats.get('uptime_seconds', 0))}")
    
    st.markdown("---")
    
    # Manual refresh button
    if st.button("Refresh", use_container_width=True):
        st.cache_data.clear()
        st.rerun()
    
    # Auto-refresh option - ON by default
    auto_refresh = st.checkbox("Auto (3s)", value=True)
    
    st.markdown("---")
    st.caption(f"Updated: {last_update or 'N/A'}")

# ============ HEADER ============
c1, c2, c3 = st.columns([3, 4, 2])
with c1: 
    st.markdown("## Security Operations Center")
with c2:
    if is_online:
        st.markdown(f'<div style="padding-top:12px;text-align:center;"><span class="online">●</span> LIVE - {last_update}</div>', unsafe_allow_html=True)
with c3:
    badge = "status-threat" if has_threat else "status-secure"
    text = "THREAT" if has_threat else "SECURE"
    st.markdown(f'<div style="text-align:right;padding-top:8px;"><span class="{badge}">{text}</span></div>', unsafe_allow_html=True)

st.markdown("---")

# ============ DASHBOARD ============
if page == "Dashboard":
    # Metrics row
    cols = st.columns(6)
    metrics = [
        (stats.get("total_events", 0), "Events", "blue"),
        (len(detections), "Alerts", "red" if detections else "blue"),
        (len([d for d in detections if d.get("confidence", 0) >= 80]), "Critical", "red"),
        (len([d for d in detections if 60 <= d.get("confidence", 0) < 80]), "High", "orange"),
        (len(set(d.get("technique_id") for d in detections)), "Techniques", "orange"),
        (format_uptime(stats.get("uptime_seconds", 0)), "Uptime", "green"),
    ]
    for i, (val, label, color) in enumerate(metrics):
        with cols[i]:
            st.markdown(f'<div class="metric-card"><div class="metric-value {color}">{val}</div><div class="metric-label">{label}</div></div>', unsafe_allow_html=True)
    
    st.markdown("<br>", unsafe_allow_html=True)
    
    # Two columns
    c1, c2 = st.columns(2)
    
    with c1:
        st.markdown("### Recent Alerts")
        if detections:
            # Use expanders for each alert - click to see details
            for det in reversed(detections[-10:]):
                sev, color, cls = get_severity(det.get("confidence", 0))
                tech_id = det.get("technique_id", "N/A")
                tech_name = det.get("technique_name", "Unknown")
                conf = det.get("confidence", 0)
                ts = det.get("timestamp", "N/A")
                
                with st.expander(f"{tech_id} - {tech_name} ({sev})", expanded=False):
                    st.markdown(f"**Severity:** {sev} ({conf}%)")
                    st.markdown(f"**Time:** {ts}")
                    st.markdown(f"**Patterns matched:** {', '.join(det.get('patterns', []))}")
                    
                    # Show source/evidence
                    source = det.get("source", det.get("evidence", ""))
                    if source:
                        st.markdown("**Source:**")
                        st.code(source[:200], language=None)
                    
                    # Show matched events details
                    matched = det.get("matched_events", [])
                    if matched:
                        st.markdown("**Matched Events:**")
                        for evt in matched[:3]:
                            cmd = evt.get("command_line", evt.get("commandline", evt.get("target_filename", "N/A")))
                            proc = evt.get("image", "N/A")
                            eid = evt.get("event_id", "?")
                            st.code(f"[Event {eid}] {proc}\nCmd: {cmd}", language=None)
                    
                    # Show raw JSON as code block (not nested expander)
                    st.markdown("**Raw Data:**")
                    st.code(json.dumps(det, indent=2, default=str)[:500], language="json")
        else:
            st.info("No alerts")
    
    with c2:
        st.markdown("### Event Stream")
        if events:
            valid_events = [e for e in events if e.get("image") != "N/A"][-20:]
            if valid_events:
                df = pd.DataFrame([{
                    "Time": (e.get("timestamp", "") or "")[-8:],
                    "Type": {1: "PROC", 5: "END", 10: "ACCESS", 11: "FILE", 13: "REG"}.get(e.get("event_id"), "?"),
                    "Process": ((e.get("image") or "N/A")[-35:])
                } for e in reversed(valid_events)])
                st.dataframe(df, hide_index=True, height=400)
            else:
                st.info("Waiting for events...")
        else:
            st.info("Waiting for events...")

# ============ ALERTS ============
elif page == "Alerts":
    st.markdown("### Alert Queue")
    
    c1, c2 = st.columns(2)
    with c1: 
        sev_filter = st.selectbox("Severity", ["All", "Critical", "High", "Medium", "Low"])
    with c2: 
        tech_list = ["All"] + list(set(d.get("technique_id") for d in detections))
        tech_filter = st.selectbox("Technique", tech_list)
    
    st.markdown("---")
    
    if detections:
        # Filter alerts
        filtered_dets = []
        for d in reversed(detections[-50:]):
            sev, _, _ = get_severity(d.get("confidence", 0))
            if sev_filter != "All" and sev.lower() != sev_filter.lower():
                continue
            if tech_filter != "All" and d.get("technique_id") != tech_filter:
                continue
            filtered_dets.append((d, sev))
        
        if filtered_dets:
            for det, sev in filtered_dets:
                tech_id = det.get("technique_id", "N/A")
                tech_name = det.get("technique_name", "Unknown")
                conf = det.get("confidence", 0)
                ts = det.get("timestamp", "N/A")
                patterns = det.get("patterns", [])
                
                with st.expander(f"[{sev}] {tech_id} - {tech_name} | {ts}", expanded=False):
                    col1, col2 = st.columns(2)
                    with col1:
                        st.markdown(f"**Technique:** {tech_id}")
                        st.markdown(f"**Name:** {tech_name}")
                        st.markdown(f"**Confidence:** {conf}%")
                    with col2:
                        st.markdown(f"**Severity:** {sev}")
                        st.markdown(f"**Time:** {ts}")
                        st.markdown(f"**Patterns:** {', '.join(patterns)}")
                    
                    st.markdown("---")
                    st.markdown("**Event Details:**")
                    
                    matched = det.get("matched_events", [])
                    if matched:
                        for evt in matched:
                            eid = evt.get("event_id", "?")
                            proc = evt.get("image", "N/A")
                            cmd = evt.get("command_line", "")
                            target = evt.get("target_filename", "") or evt.get("target_image", "")
                            details = evt.get("details", "")
                            user = evt.get("user", "")
                            parent = evt.get("parent_image", "")
                            
                            st.markdown(f"**Event ID:** {eid}")
                            st.markdown(f"**Process:** `{proc}`")
                            if cmd:
                                st.markdown("**Command Line:**")
                                st.code(cmd, language="powershell")
                            if parent:
                                st.markdown(f"**Parent:** `{parent}`")
                            if target:
                                st.markdown(f"**Target:** `{target}`")
                            if details:
                                st.markdown(f"**Details:** {details}")
                            if user:
                                st.markdown(f"**User:** {user}")
                    
                    with st.expander("Raw JSON Data"):
                        st.json(det)
        else:
            st.info("No matching alerts")
    else:
        st.info("No alerts")

# ============ MITRE ATT&CK ============
elif page == "MITRE ATT&CK":
    st.markdown("### MITRE ATT&CK Coverage")
    
    # Count per tactic
    tactic_counts = {t: 0 for t in TACTICS}
    for d in detections:
        for t in TECHNIQUE_TACTICS.get(d.get("technique_id", ""), []):
            if t in tactic_counts: 
                tactic_counts[t] += 1
    
    # Heatmap grid
    cols = st.columns(6)
    for i, (tid, tname) in enumerate(TACTICS.items()):
        with cols[i % 6]:
            cnt = tactic_counts.get(tid, 0)
            active = "active" if cnt > 0 else ""
            st.markdown(f'<div class="tactic-box {active}"><div class="tactic-count">{cnt}</div><div class="tactic-name">{tname}</div></div>', unsafe_allow_html=True)
    
    st.markdown("---")
    st.markdown("### Detected Techniques")
    
    techs = set(d.get("technique_id") for d in detections)
    if techs:
        for t in techs:
            tactics = ", ".join([TACTICS.get(x, x) for x in TECHNIQUE_TACTICS.get(t, [])])
            count = len([d for d in detections if d.get("technique_id") == t])
            st.markdown(f"**{t}** - {tactics} ({count} detections)")
    else:
        st.info("No techniques detected")

# ============ SEARCH ============
elif page == "Search":
    st.markdown("### Search")
    
    query = st.text_input("Search Query", placeholder="Enter search term (process, pattern, technique)...", label_visibility="collapsed")
    
    if query:
        q = query.lower()
        results = []
        
        for e in events:
            if q in str(e).lower():
                results.append(("Event", e))
        
        for d in detections:
            if q in str(d).lower():
                results.append(("Alert", d))
        
        st.markdown(f"**{len(results)} results found**")
        
        for rtype, rdata in results[:20]:
            with st.expander(f"{rtype}: {str(rdata)[:60]}..."):
                st.json(rdata)

# ============ FOOTER ============
st.markdown("---")
st.caption("MultiKG SOC • Real-time Threat Detection")

# Auto-refresh - always on by default (every 3 seconds)
if auto_refresh:
    import time
    time.sleep(3)
    st.cache_data.clear()
    st.rerun()
    st.cache_data.clear()
    st.rerun()
