"""
TRUSTGATE Streamlit SOC Analyst Dashboard (SENTINEL-X)
White Main Theme with Olive Green Aesthetic
"""
import streamlit as st
import pandas as pd
import requests
import json
import os

API_BASE = os.environ.get("TRUSTGATE_API_URL", "http://127.0.0.1:8000/api")

st.set_page_config(
    page_title="TRUSTGATE SOC Console",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom White + Sage Green Minimal Styling
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');
    html, body, [class*="css"] {
        font-family: 'Inter', sans-serif;
    }
    :root {
        --primary-color: #B8BC86;
        --background-color: #FFFFFF;
        --secondary-background-color: #F7F8F3;
        --text-color: #25271F;
    }
    .main {
        background-color: #F7F8F3;
    }
    .stButton>button {
        background-color: #B8BC86 !important;
        color: #25271F !important;
        border-radius: 8px !important;
        border: none !important;
        font-weight: 600 !important;
    }
    .stButton>button:hover {
        background-color: #a8ac74 !important;
    }
    .metric-card {
        background: #FFFFFF;
        border: 1px solid #E7E8DC;
        border-radius: 10px;
        padding: 16px;
        box-shadow: 0 1px 3px rgba(37, 39, 31, 0.04);
    }
    .sage-badge {
        background-color: #EEF0E3;
        color: #25271F;
        border: 1px solid #B8BC86;
        padding: 2px 8px;
        border-radius: 4px;
        font-size: 0.75rem;
        font-family: monospace;
        font-weight: bold;
    }
</style>
""", unsafe_allow_html=True)

# Sidebar Navigation
st.sidebar.title("🛡️ TRUSTGATE Console")
st.sidebar.caption("SENTINEL-X Hybrid Security Gateway")

page = st.sidebar.radio(
    "Navigation",
    ["1. Security Overview", "2. Event Explorer", "3. Alert Investigation", "4. Simulation Lab", "5. Model & Comparison"]
)

st.sidebar.markdown("---")
st.sidebar.markdown("**Theme:** `White & Sage-Green Minimal`")
st.sidebar.markdown("**System Mode:** `SIMULATION / SHADOW`")
st.sidebar.markdown("**Decision Rule:** `ML NEVER GRANTS PERMISSION`")

# Helper Functions
def fetch_api(endpoint):
    try:
        r = requests.get(f"{API_BASE}{endpoint}", timeout=5)
        if r.status_code == 200:
            return r.json()
    except Exception as e:
        st.sidebar.warning(f"Backend API offline: {e}")
    return None

def post_api(endpoint, data):
    try:
        r = requests.post(f"{API_BASE}{endpoint}", json=data, timeout=15)
        if r.status_code == 200:
            return r.json()
    except Exception as e:
        st.error(f"API Error: {e}")
    return None

# --- PAGE 1: SECURITY OVERVIEW ---
if page == "1. Security Overview":
    st.title("🛡️ Security Operations Overview")
    st.info("💡 **Core Architecture Invariant:** Deterministic policy and human approval verification remain authoritative. Machine learning anomaly scores enrich risk context but can never grant permission.")

    events = fetch_api("/events?limit=200") or []
    total = len(events)
    held = sum(1 for e in events if e.get("final_action") == "HOLD")
    blocked = sum(1 for e in events if e.get("final_action") in ("BLOCK", "INVALID"))
    anoms = sum(1 for e in events if e.get("is_anomaly") or (e.get("risk_score") and e.get("risk_score") >= 0.65))

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total Events Processed", total)
    col2.metric("Held for Review", held, delta=f"{held/total*100:.1f}%" if total else "0%")
    col3.metric("Blocked Operations", blocked)
    col4.metric("High Anomaly Signals", anoms)

    st.markdown("---")
    st.subheader("Recent API Event Stream")
    if events:
        df = pd.DataFrame(events)
        cols_to_show = ["timestamp", "request_id", "api_key_id", "method", "endpoint", "vendor_id", "final_action", "risk_score"]
        existing_cols = [c for c in cols_to_show if c in df.columns]
        st.dataframe(df[existing_cols], use_container_width=True)
    else:
        st.write("No events recorded yet. Go to **Simulation Lab** to generate transactions.")

# --- PAGE 2: EVENT EXPLORER ---
elif page == "2. Event Explorer":
    st.title("🔍 API Event Explorer")
    search_q = st.text_input("Search by Request ID, Vendor, or Endpoint:")
    action_filter = st.selectbox("Filter by Final Action:", ["ALL", "ALLOW", "HOLD", "BLOCK"])

    url = "/events?limit=100"
    if action_filter != "ALL":
        url += f"&action={action_filter}"

    events = fetch_api(url) or []
    if search_q:
        events = [e for e in events if search_q.lower() in json.dumps(e).lower()]

    st.write(f"Displaying **{len(events)}** matching transactions:")
    if events:
        df = pd.DataFrame(events)
        cols = ["timestamp", "request_id", "api_key_id", "source_ip", "method", "endpoint", "vendor_id", "final_action", "risk_score"]
        existing_cols = [c for c in cols if c in df.columns]
        st.dataframe(df[existing_cols], use_container_width=True)

# --- PAGE 3: ALERT INVESTIGATION ---
elif page == "3. Alert Investigation":
    st.title("🚨 Alert Investigation & Triage")
    events = fetch_api("/events?limit=100") or []
    alerts = [e for e in events if e.get("final_action") in ("HOLD", "BLOCK", "INVALID")]

    st.write(f"Active Triage Queue: **{len(alerts)}** incidents requiring review")

    if alerts:
        selected_req = st.selectbox("Select Transaction to Inspect:", [f"{a['request_id']} ({a.get('vendor_id') or 'Global'} - {a['final_action']})" for a in alerts])
        req_id = selected_req.split(" ")[0]
        match = next((a for a in alerts if a["request_id"] == req_id), None)

        if match:
            detail = fetch_api(f"/events/{match['event_id']}")
            if detail:
                exp = detail.get("final_decision", {}).get("explanation", {})
                st.subheader(f"Incident: {match['request_id']}")
                st.write(f"**Action:** `{detail.get('final_decision', {}).get('final_action')}` | **Status:** `{detail.get('final_decision', {}).get('execution_status')}`")

                c1, c2 = st.columns(2)
                with c1:
                    st.markdown("#### 1. Observed Facts")
                    for f in exp.get("observed_facts", []):
                        st.write(f"- {f}")
                    st.markdown("#### 2. Deterministic Policy Findings")
                    for p in exp.get("policy_findings", []):
                        st.write(f"- {p}")

                with c2:
                    st.markdown("#### 3. Behavioral Findings (Isolation Forest)")
                    for m in exp.get("ml_behavioral_findings", []):
                        st.write(f"- {m}")
                    st.markdown("#### 4. Actionable Inference")
                    for inf in exp.get("actionable_inferences", []):
                        st.write(f"- {inf}")

# --- PAGE 4: SIMULATION LAB ---
elif page == "4. Simulation Lab":
    st.title("🧪 Interactive Attack & Traffic Simulator")
    st.caption("Generate synthetic enterprise API traffic to test deterministic policy boundaries and Isolation Forest anomaly detection.")

    col1, col2, col3 = st.columns(3)
    with col1:
        sc = st.selectbox("Scenario:", [
            "SCN-04: Bank Update with No Approval (Attack Replay)",
            "SCN-01: Normal Contact Update (Legitimate ALLOW)",
            "SCN-02: Normal Invoice Lookup (Legitimate ALLOW)",
            "SCN-03: Approved Bank Update (Verified Finance Approval)",
            "SCN-05: Prohibited Endpoint Access (/v2/admin/export)",
            "SCN-06: Unregistered Source Host Burst (Egress Anomaly)",
            "SCN-07: Rapid Reconnaissance Sequence (Recon -> Patch)",
            "SCN-08: Replayed Request Nonce (Duplicate Request ID)",
            "SCN-09: Malformed Event Payload (Schema Violation)",
            "SCN-10: Month-End Batch Job (High Volume Legitimate)",
            "SCN-11: Approval Service Timeout (Fail-Secure Hold)",
            "SCN-12: ML Service Unavailable (Degraded Policy-Only)"
        ])
        sc_id = sc.split(":")[0]
    with col2:
        seed = st.number_input("Random Seed:", value=42, min_value=1)
    with col3:
        count = st.number_input("Event Count (N):", value=10, min_value=1, max_value=500)

    if st.button("▶ Run Simulation Batch"):
        with st.spinner("Executing simulation batch through defensive gateway..."):
            res = post_api("/simulate", {
                "scenario_id": sc_id,
                "seed": int(seed),
                "num_events": int(count)
            })
            if res:
                stats = res.get("stats", {})
                st.success(f"Simulation Status: **{stats.get('simulation_status', 'COMPLETE')}** — {stats.get('status_message')}")

                m1, m2, m3, m4, m5, m6 = st.columns(6)
                m1.metric("Requested", stats.get("requested_events", count))
                m2.metric("Generated", stats.get("generated_events", 0))
                m3.metric("Processed", stats.get("processed_events", 0))
                m4.metric("Allowed", stats.get("allowed_events", 0))
                m5.metric("Blocked/Held", (stats.get("blocked_events", 0) + stats.get("held_events", 0)))
                m6.metric("Failed", stats.get("failed_events", 0))

                all_events = res.get("events", res.get("events_sample", []))
                st.subheader(f"Simulation Run Telemetry ({len(all_events)} / {count} Events Processed)")

                events_data = []
                for s in all_events:
                    events_data.append({
                        "Request ID": s["request_id"],
                        "Endpoint": s.get("endpoint", "—"),
                        "Method": s.get("method", "—"),
                        "Ground Truth": s.get("ground_truth", "—"),
                        "Policy": s.get("policy", {}).get("result", "—"),
                        "Risk Score": f"{s.get('ml', {}).get('normalized_risk_score', 0):.2f}" if s.get("ml", {}).get("normalized_risk_score") is not None else "—",
                        "Final Action": s.get("final_action", "—")
                    })
                st.dataframe(pd.DataFrame(events_data), use_container_width=True)

# --- PAGE 5: MODEL & COMPARISON ---
elif page == "5. Model & Comparison":
    st.title("⚖️ Policy-Only vs. Hybrid Architecture Comparison")
    st.markdown("Evaluating performance differences between Deterministic Policy alone and Policy combined with Isolation Forest behavioral scoring on identical balanced test streams.")

    status = fetch_api("/model/status") or {}
    st.sidebar.markdown(f"**Model Version:** `{status.get('model_version')}`")
    st.sidebar.markdown(f"**Anomaly Threshold:** `tau >= {status.get('threshold', 0.65)}`")

    if st.button("⚡ Run Full Comparative Benchmark Suite (N=100)"):
        with st.spinner("Running balanced multi-scenario benchmark (60% legitimate, 40% attack) on identical data streams..."):
            res = post_api("/benchmark", {
                "seed": 42,
                "num_events": 100
            })
            if res and "comparison" in res:
                cmp_data = res["comparison"]
                col_a, col_b = st.columns(2)

                with col_a:
                    st.markdown("### Model A: Deterministic Policy Only (Baseline)")
                    st.metric("Recall (Attacks Caught)", f"{cmp_data['policy_only']['recall']*100:.1f}%")
                    st.metric("Precision", f"{cmp_data['policy_only']['precision']*100:.1f}%")
                    st.metric("Accuracy", f"{cmp_data['policy_only']['accuracy']*100:.1f}%")
                    st.metric("F1-Score", f"{cmp_data['policy_only']['f1_score']:.4f}")
                    st.metric("False Positive Rate (FPR)", f"{cmp_data['policy_only']['false_positive_rate']*100:.1f}%")
                    st.metric("False Negative Rate (FNR)", f"{cmp_data['policy_only']['false_negative_rate']*100:.1f}%")
                    st.metric("Avg Decision Latency", f"{cmp_data['policy_only']['avg_latency_ms']:.2f} ms")

                    st.markdown("**Confusion Matrix (Model A):**")
                    cm_a = pd.DataFrame({
                        "Predicted Flagged": [cmp_data['policy_only']['tp'], cmp_data['policy_only']['fp']],
                        "Predicted Allowed": [cmp_data['policy_only']['fn'], cmp_data['policy_only']['tn']]
                    }, index=["Actual Attack", "Actual Normal"])
                    st.table(cm_a)

                with col_b:
                    st.markdown("### Model B: Hybrid (Policy + Isolation Forest)")
                    st.metric("Recall (Attacks Caught)", f"{cmp_data['hybrid']['recall']*100:.1f}%", delta=f"+{cmp_data['delta_analysis']['recall_gain_pct']}% Gain")
                    st.metric("Precision", f"{cmp_data['hybrid']['precision']*100:.1f}%")
                    st.metric("Accuracy", f"{cmp_data['hybrid']['accuracy']*100:.1f}%")
                    st.metric("F1-Score", f"{cmp_data['hybrid']['f1_score']:.4f}")
                    st.metric("False Positive Rate (FPR)", f"{cmp_data['hybrid']['false_positive_rate']*100:.1f}%")
                    st.metric("False Negative Rate (FNR)", f"{cmp_data['hybrid']['false_negative_rate']*100:.1f}%", delta=f"-{cmp_data['policy_only']['false_negative_rate']*100 - cmp_data['hybrid']['false_negative_rate']*100:.1f}% Missed", delta_color="inverse")
                    st.metric("Avg Decision Latency", f"{cmp_data['hybrid']['avg_latency_ms']:.2f} ms")

                    st.markdown("**Confusion Matrix (Model B):**")
                    cm_b = pd.DataFrame({
                        "Predicted Flagged": [cmp_data['hybrid']['tp'], cmp_data['hybrid']['fp']],
                        "Predicted Allowed": [cmp_data['hybrid']['fn'], cmp_data['hybrid']['tn']]
                    }, index=["Actual Attack", "Actual Normal"])
                    st.table(cm_b)

                st.info(f"**Differential Verdict:** {cmp_data['delta_analysis']['verdict']}")

                dt = cmp_data.get("dataset_transparency", {})
                st.markdown("---")
                st.subheader("📋 Dataset Transparency & Evaluation Methodology")
                tc1, tc2, tc3, tc4 = st.columns(4)
                tc1.metric("Total Evaluation Samples", f"{dt.get('total_samples', 100)} Events")
                tc2.metric("Attack Events", f"{dt.get('attack_samples', 40)} (40%)")
                tc3.metric("Normal Baseline Events", f"{dt.get('normal_samples', 60)} (60%)")
                tc4.metric("Training Samples", f"{dt.get('training_samples', 1500)}")

                st.warning(f"⚠️ **Scientific Evaluation Disclaimer:** *\"{dt.get('disclaimer')}\"*")
