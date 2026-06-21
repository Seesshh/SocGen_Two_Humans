"""
app.py

Hybrid Identity Governance Platform — Dashboard.
Dark enterprise security theme. 8 pages, Demo Mode, CSV export, drilldowns.

Architecture note: data loading and computation are implemented as plain
functions returning pandas DataFrames/dicts, independent of any Streamlit
call. This makes the data layer directly unit-testable (and was tested that
way, against the real generated dataset) regardless of whether a Streamlit
runtime is available. Only the render_* functions touch `st`.
"""

from __future__ import annotations

import pickle
import random
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import networkx as nx
import numpy as np
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #

DATA_DIR = Path("data/synthetic_data")
REFERENCE_DATE = date(2026, 6, 20)

PLATFORM_ID_TO_NAME: Dict[int, str] = {1: "Active Directory", 2: "Azure AD", 3: "AWS IAM", 4: "Okta", 5: "Salesforce"}

RISK_BAND_COLORS: Dict[str, str] = {"Critical": "#FF4B4B", "High": "#FF9F1C", "Medium": "#FFD60A", "Low": "#2ECC71"}
SEVERITY_COLORS: Dict[str, str] = {"Critical": "#FF4B4B", "High": "#FF9F1C", "Medium": "#FFD60A", "Low": "#2ECC71"}
NODE_TYPE_COLORS: Dict[str, str] = {
    "Employee": "#4DA6FF", "Identity": "#7C7CFF", "Account": "#5BD8C0",
    "Group": "#FFD166", "Role": "#9D7BFF", "Permission": "#FF6B9D",
    "ServiceAccount": "#FF9F1C", "Token": "#06D6A0", "Department": "#A0A0A0",
}

DARK_THEME_CSS = """
<style>
    .stApp { background-color: #0E1117; color: #E6E6E6; }
    .metric-card {
        background: linear-gradient(135deg, #1A1D29 0%, #20242F 100%);
        border: 1px solid #2A2E3A; border-radius: 10px; padding: 16px 20px; margin-bottom: 8px;
    }
    .metric-card .label { color: #9AA0AC; font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.05em; }
    .metric-card .value { font-size: 1.9rem; font-weight: 700; color: #F0F0F0; }
    .risk-badge {
        display: inline-block; padding: 2px 10px; border-radius: 12px;
        font-size: 0.75rem; font-weight: 700; color: #0E1117;
    }
    section[data-testid="stSidebar"] { background-color: #14161F; }
    .stTabs [data-baseweb="tab"] { color: #9AA0AC; }
</style>
"""


# --------------------------------------------------------------------------- #
# Data layer — pure functions, no Streamlit calls, fully unit-testable
# --------------------------------------------------------------------------- #

def clean_id(value) -> Optional[str]:
    if value is None:
        return None
    try:
        if pd.isna(value):
            return None
    except (TypeError, ValueError):
        pass
    if isinstance(value, float) and value.is_integer():
        return str(int(value))
    text = str(value).strip()
    return text or None


def load_all_data() -> Dict[str, pd.DataFrame]:
    """Loads every CSV/pickle the dashboard needs. Missing optional files
    degrade gracefully (empty DataFrame) rather than crashing the app."""
    def _load(name: str, parse_dates: Optional[List[str]] = None) -> pd.DataFrame:
        path = DATA_DIR / name
        if not path.exists():
            return pd.DataFrame()
        return pd.read_csv(path, parse_dates=parse_dates or [])

    data: Dict[str, pd.DataFrame] = {
        "persons": _load("persons.csv", ["hire_date", "termination_date"]),
        "identity_risk_scores": _load("identity_risk_scores.csv"),
        "effective_privileges": _load("effective_privileges.csv"),
        "resolved_identities": _load("resolved_identities.csv"),
        "alerts": _load("alerts.csv", ["timestamp"]),
        "incidents": _load("incidents.csv", ["first_detected_at", "last_detected_at"]),
        "incident_narratives": _load("incident_narratives.csv"),
        "offboarding_events": _load("offboarding_events.csv", ["termination_date", "actual_revocation_at"]),
        "service_accounts": _load("service_accounts.csv", ["created_date", "last_credential_rotation_date"]),
        "api_tokens": _load("api_tokens.csv", ["issued_date", "expiration_date", "last_used_date"]),
        "graph_metrics": _load("graph_metrics.csv"),
        "departments": _load("departments.csv"),
        "identity_risk_labels": _load("identity_risk_labels.csv"),
    }

    graph_path = DATA_DIR / "identity_graph.pkl"
    if graph_path.exists():
        with open(graph_path, "rb") as f:
            data["graph"] = pickle.load(f)
    else:
        data["graph"] = nx.MultiDiGraph()

    return data


def _identity_to_department(data: Dict[str, pd.DataFrame]) -> pd.Series:
    """Bridges identity_risk_scores' resolved identity_id -> department_name
    via effective_privileges.employee_key -> persons.person_id."""
    ep = data["effective_privileges"]
    persons = data["persons"]
    if ep.empty or persons.empty:
        return pd.Series(dtype=object)

    emp_key_to_dept: Dict[str, str] = {}
    persons_idx = persons.set_index("person_id")
    for _, row in ep.iterrows():
        key = clean_id(row.get("employee_key"))
        if key is None:
            continue
        try:
            pid = int(key)
        except ValueError:
            continue
        if pid in persons_idx.index:
            emp_key_to_dept[row["identity_id"]] = persons_idx.loc[pid, "department_name"]
    return pd.Series(emp_key_to_dept, name="department_name")


def compute_executive_kpis(data: Dict[str, pd.DataFrame]) -> Dict[str, int]:
    scores = data["identity_risk_scores"]
    alerts = data["alerts"]
    return {
        "total_identities": int(scores["identity_id"].nunique()) if not scores.empty else 0,
        "critical_risks": int((scores["risk_band"] == "Critical").sum()) if not scores.empty else 0,
        "high_risks": int((scores["risk_band"] == "High").sum()) if not scores.empty else 0,
        "dormant_admins": int(alerts[alerts["rule_name"] == "DORMANT_ADMIN"]["identity_id"].nunique()) if not alerts.empty else 0,
        "privilege_creep": int(alerts[alerts["rule_name"] == "PRIVILEGE_CREEP"]["identity_id"].nunique()) if not alerts.empty else 0,
        "service_accounts": int(len(data["service_accounts"])),
        "offboarding_gaps": int(alerts[alerts["rule_name"] == "OFFBOARDING_GAP"]["identity_id"].nunique()) if not alerts.empty else 0,
    }


def compute_department_risk(data: Dict[str, pd.DataFrame]) -> pd.DataFrame:
    scores = data["identity_risk_scores"]
    if scores.empty:
        return pd.DataFrame(columns=["department_name", "avg_risk_score", "identity_count"])
    dept_series = _identity_to_department(data)
    merged = scores.copy()
    merged["department_name"] = merged["identity_id"].map(dept_series)
    merged = merged.dropna(subset=["department_name"])
    agg = merged.groupby("department_name").agg(
        avg_risk_score=("risk_score", "mean"), identity_count=("identity_id", "count")
    ).reset_index().sort_values("avg_risk_score", ascending=False)
    return agg


def compute_platform_risk(data: Dict[str, pd.DataFrame]) -> pd.DataFrame:
    alerts = data["alerts"]
    if alerts.empty:
        return pd.DataFrame(columns=["platform_name", "alert_count", "avg_risk_score"])
    df = alerts.dropna(subset=["platform_id"]).copy()
    df["platform_name"] = df["platform_id"].map(PLATFORM_ID_TO_NAME)
    agg = df.groupby("platform_name").agg(
        alert_count=("alert_id", "count"), avg_risk_score=("risk_score", "mean")
    ).reset_index().sort_values("alert_count", ascending=False)
    return agg


def compute_top_risky_users(data: Dict[str, pd.DataFrame], n: int = 10) -> pd.DataFrame:
    scores = data["identity_risk_scores"]
    if scores.empty:
        return pd.DataFrame()
    cols = ["identity_id", "full_name", "entity_type", "risk_score", "risk_band", "alert_count", "top_risk_reason"]
    return scores.sort_values("risk_score", ascending=False)[cols].head(n)


def filter_identity_registry(
    data: Dict[str, pd.DataFrame], department: Optional[str], risk_band: Optional[List[str]],
    employment_type: Optional[str], search: str = "",
) -> pd.DataFrame:
    scores = data["identity_risk_scores"]
    if scores.empty:
        return scores
    df = scores.copy()
    dept_series = _identity_to_department(data)
    df["department_name"] = df["identity_id"].map(dept_series)

    persons = data["persons"]
    if not persons.empty:
        ep = data["effective_privileges"]
        key_to_emp_type = {}
        persons_idx = persons.set_index("person_id")
        for _, row in ep.iterrows():
            key = clean_id(row.get("employee_key"))
            if key and key.isdigit() and int(key) in persons_idx.index:
                key_to_emp_type[row["identity_id"]] = persons_idx.loc[int(key), "employment_type"]
        df["employment_type"] = df["identity_id"].map(key_to_emp_type)

    if department and department != "All":
        df = df[df["department_name"] == department]
    if risk_band:
        df = df[df["risk_band"].isin(risk_band)]
    if employment_type and employment_type != "All":
        df = df[df["employment_type"] == employment_type]
    if search:
        df = df[df["full_name"].astype(str).str.contains(search, case=False, na=False)]
    return df.sort_values("risk_score", ascending=False)


def _resolved_to_original_bridge(data: Dict[str, pd.DataFrame]) -> Dict:
    """alerts.csv (from rules.py) uses the ORIGINAL data-generation pipeline's
    identity_id, while identity_risk_scores.csv / effective_privileges.csv use
    the RESOLVED identity_id assigned by identity_resolver.py. They are not
    the same numbering scheme. This bridges resolved_id -> original_id via
    employee_key (which equals the original identity_id / person_id for
    every linked identity), the same pattern used in risk_scoring.py."""
    ep = data["effective_privileges"]
    if ep.empty:
        return {}
    bridge = {}
    for _, row in ep.iterrows():
        key = clean_id(row.get("employee_key"))
        if key is not None:
            bridge[row["identity_id"]] = key
    return bridge


def get_identity_detail(data: Dict[str, pd.DataFrame], identity_id) -> Dict:
    scores = data["identity_risk_scores"]
    ep = data["effective_privileges"]
    alerts = data["alerts"]
    score_row = scores[scores["identity_id"] == identity_id]
    priv_row = ep[ep["identity_id"] == identity_id]

    identity_alerts = pd.DataFrame()
    if not alerts.empty:
        bridge = _resolved_to_original_bridge(data)
        original_id = bridge.get(identity_id)
        if original_id is not None:
            alert_ids_as_str = alerts["identity_id"].apply(clean_id)
            identity_alerts = alerts[alert_ids_as_str == original_id]

    return {
        "score": score_row.iloc[0].to_dict() if len(score_row) else {},
        "privilege": priv_row.iloc[0].to_dict() if len(priv_row) else {},
        "alerts": identity_alerts.to_dict("records"),
    }


def get_ego_graph(graph: nx.MultiDiGraph, node_id: str, radius: int = 2) -> nx.MultiDiGraph:
    if node_id not in graph:
        return nx.MultiDiGraph()
    return nx.ego_graph(graph.to_undirected(), node_id, radius=radius)


def search_graph_nodes(graph: nx.MultiDiGraph, query: str, limit: int = 20) -> List[str]:
    if not query:
        return []
    query_lower = query.lower()
    matches = []
    for node, attrs in graph.nodes(data=True):
        label = str(
            attrs.get("full_name") or attrs.get("account_name") or attrs.get("group_name")
            or attrs.get("department_name") or attrs.get("native_role_name") or node
        )
        if query_lower in label.lower() or query_lower in str(node).lower():
            matches.append(node)
        if len(matches) >= limit:
            break
    return matches


def compute_offboarding_kpis(data: Dict[str, pd.DataFrame]) -> Dict:
    ob = data["offboarding_events"]
    if ob.empty:
        return {"pending": 0, "sla_breached": 0, "total": 0, "compliance_pct": 0.0}
    pending = ob["actual_revocation_at"].isna().sum()
    breached = ob["sla_breached"].sum() if "sla_breached" in ob.columns else 0
    total = len(ob)
    compliance = 100.0 * (1 - breached / total) if total else 0.0
    return {"pending": int(pending), "sla_breached": int(breached), "total": int(total), "compliance_pct": round(compliance, 1)}


def compute_offboarding_by_platform(data: Dict[str, pd.DataFrame]) -> pd.DataFrame:
    ob = data["offboarding_events"]
    if ob.empty:
        return pd.DataFrame()
    df = ob.copy()
    df["platform_name"] = df["platform_id"].map(PLATFORM_ID_TO_NAME)
    agg = df.groupby("platform_name").agg(
        total=("offboarding_id", "count"),
        breached=("sla_breached", "sum"),
        pending=("actual_revocation_at", lambda s: s.isna().sum()),
    ).reset_index()
    agg["compliance_pct"] = (100 * (1 - agg["breached"] / agg["total"])).round(1)
    return agg


def compute_service_account_kpis(data: Dict[str, pd.DataFrame]) -> Dict:
    sa = data["service_accounts"]
    if sa.empty:
        return {}
    return {
        "total": len(sa),
        "no_owner": int(sa["owner_person_id"].isna().sum()),
        "high_privilege": int(sa["privilege_level"].isin(["Admin", "Super Admin"]).sum()),
        "overdue_rotation": int((sa["rotation_status"] == "Overdue").sum()),
        "never_rotated": int((sa["rotation_status"] == "Never Rotated").sum()),
        "breakglass": int(sa["is_breakglass"].sum()),
    }


def compute_token_kpis(data: Dict[str, pd.DataFrame]) -> Dict:
    tokens = data["api_tokens"]
    if tokens.empty:
        return {}
    today = pd.Timestamp(REFERENCE_DATE)
    expiring_30d = tokens[
        tokens["expiration_date"].notna()
        & (pd.to_datetime(tokens["expiration_date"]) > today)
        & (pd.to_datetime(tokens["expiration_date"]) <= today + timedelta(days=30))
    ]
    expired = tokens[tokens["expiration_date"].notna() & (pd.to_datetime(tokens["expiration_date"]) < today)]
    no_expiry = tokens[tokens["expiration_date"].isna()]
    unused = tokens[tokens["usage_count_30d"] < 10]
    alerts = data["alerts"]
    abused = alerts[alerts["rule_name"] == "TOKEN_ABUSE"] if not alerts.empty else pd.DataFrame()
    return {
        "total": len(tokens), "expiring_30d": len(expiring_30d), "expired": len(expired),
        "no_expiry": len(no_expiry), "unused": len(unused), "abused": len(abused),
    }


def compute_analytics(data: Dict[str, pd.DataFrame]) -> Dict:
    alerts = data["alerts"]
    scores = data["identity_risk_scores"]
    dept_risk = compute_department_risk(data)
    platform_risk = compute_platform_risk(data)

    heatmap_df = pd.DataFrame()
    if not alerts.empty:
        alerts_with_dept = alerts.copy()
        dept_series = _identity_to_department(data)
        alerts_with_dept["department_name"] = alerts_with_dept["identity_id"].map(dept_series)
        alerts_with_dept["platform_name"] = alerts_with_dept["platform_id"].map(PLATFORM_ID_TO_NAME)
        heatmap_df = alerts_with_dept.dropna(subset=["department_name", "platform_name"]).pivot_table(
            index="department_name", columns="platform_name", values="alert_id", aggfunc="count", fill_value=0
        )

    monthly = pd.DataFrame()
    ob = data["offboarding_events"]
    if not ob.empty:
        df = ob.copy()
        df["month"] = pd.to_datetime(df["termination_date"]).dt.to_period("M").astype(str)
        monthly = df.groupby("month").agg(
            terminations=("offboarding_id", "count"), sla_breaches=("sla_breached", "sum")
        ).reset_index().sort_values("month")

    anomaly_dist = alerts["rule_name"].value_counts().reset_index() if not alerts.empty else pd.DataFrame()
    if not anomaly_dist.empty:
        anomaly_dist.columns = ["rule_name", "count"]

    return {
        "department_risk": dept_risk, "platform_risk": platform_risk,
        "heatmap": heatmap_df, "monthly_terminations": monthly, "anomaly_distribution": anomaly_dist,
    }


# --------------------------------------------------------------------------- #
# Demo Mode — in-memory perturbation of session-state data copies (does not
# touch the real CSVs on disk; safe to click repeatedly during a live demo)
# --------------------------------------------------------------------------- #

def inject_demo_offboarding_gap(data: Dict[str, pd.DataFrame]) -> str:
    ob = data["offboarding_events"]
    candidates = ob[ob["actual_revocation_at"].notna()]
    if candidates.empty:
        return "No eligible record found."
    idx = candidates.sample(1).index[0]
    data["offboarding_events"].loc[idx, "actual_revocation_at"] = pd.NaT
    data["offboarding_events"].loc[idx, "sla_breached"] = True
    return f"Injected: offboarding_id {data['offboarding_events'].loc[idx, 'offboarding_id']} access gap created."


def inject_demo_dormant_admin(data: Dict[str, pd.DataFrame]) -> str:
    scores = data["identity_risk_scores"]
    if scores.empty:
        return "No data loaded."
    idx = scores.sample(1).index[0]
    data["identity_risk_scores"].loc[idx, "privilege_risk"] = 50.0
    data["identity_risk_scores"].loc[idx, "behavior_risk"] = 80.0
    identity_id = data["identity_risk_scores"].loc[idx, "identity_id"]
    new_alert = {
        "alert_id": (data["alerts"]["alert_id"].max() + 1) if not data["alerts"].empty else 1,
        "identity_id": identity_id, "severity": "High", "risk_score": 50, "rule_name": "DORMANT_ADMIN",
        "evidence": "[DEMO INJECTION] Admin-tier account has not logged in for 120+ days.",
        "recommendation": "Disable or downgrade pending owner re-justification.",
        "timestamp": datetime.combine(REFERENCE_DATE, datetime.min.time()),
        "anomaly_type": "DORMANT_ADMIN", "platform_id": 1,
        "detected_at": datetime.combine(REFERENCE_DATE, datetime.min.time()),
    }
    data["alerts"] = pd.concat([data["alerts"], pd.DataFrame([new_alert])], ignore_index=True)
    return f"Injected: identity {identity_id} flagged as Dormant Admin."


def inject_demo_token_abuse(data: Dict[str, pd.DataFrame]) -> str:
    tokens = data["api_tokens"]
    if tokens.empty:
        return "No data loaded."
    idx = tokens.sample(1).index[0]
    data["api_tokens"].loc[idx, "usage_count_30d"] = int(tokens["usage_count_30d"].mean() * 8)
    data["api_tokens"].loc[idx, "source_ip_diversity_30d"] = 9
    token_id = data["api_tokens"].loc[idx, "token_id"]
    new_alert = {
        "alert_id": (data["alerts"]["alert_id"].max() + 1) if not data["alerts"].empty else 1,
        "identity_id": 8_000_000 + int(token_id), "severity": "Critical", "risk_score": 80, "rule_name": "TOKEN_ABUSE",
        "evidence": f"[DEMO INJECTION] Token usage spiked to {data['api_tokens'].loc[idx, 'usage_count_30d']} calls/30d.",
        "recommendation": "Revoke and rotate immediately.",
        "timestamp": datetime.combine(REFERENCE_DATE, datetime.min.time()),
        "anomaly_type": "TOKEN_ABUSE", "platform_id": int(data["api_tokens"].loc[idx, "platform_id"]),
        "detected_at": datetime.combine(REFERENCE_DATE, datetime.min.time()),
    }
    data["alerts"] = pd.concat([data["alerts"], pd.DataFrame([new_alert])], ignore_index=True)
    return f"Injected: token {token_id} flagged for abuse."


def inject_demo_privilege_creep(data: Dict[str, pd.DataFrame]) -> str:
    scores = data["identity_risk_scores"]
    if scores.empty:
        return "No data loaded."
    idx = scores.sample(1).index[0]
    data["identity_risk_scores"].loc[idx, "governance_risk"] = min(
        data["identity_risk_scores"].loc[idx, "governance_risk"] + 25, 100
    )
    identity_id = data["identity_risk_scores"].loc[idx, "identity_id"]
    return f"Injected: identity {identity_id} flagged with a stale elevated grant (Privilege Creep)."


def inject_demo_cross_platform_admin(data: Dict[str, pd.DataFrame]) -> str:
    scores = data["identity_risk_scores"]
    if scores.empty:
        return "No data loaded."
    idx = scores.sample(1).index[0]
    data["identity_risk_scores"].loc[idx, "cross_platform_risk"] = 90.0
    identity_id = data["identity_risk_scores"].loc[idx, "identity_id"]
    return f"Injected: identity {identity_id} now shows Admin-tier access on 3 platforms."


DEMO_ACTIONS = {
    "Inject Offboarding Gap": inject_demo_offboarding_gap,
    "Inject Dormant Admin": inject_demo_dormant_admin,
    "Inject Token Abuse": inject_demo_token_abuse,
    "Inject Privilege Creep": inject_demo_privilege_creep,
    "Inject Cross Platform Admin": inject_demo_cross_platform_admin,
}


# --------------------------------------------------------------------------- #
# Rendering helpers
# --------------------------------------------------------------------------- #

def metric_card(label: str, value, help_text: str = "") -> None:
    st.markdown(
        f"""<div class="metric-card"><div class="label">{label}</div>
        <div class="value">{value}</div></div>""",
        unsafe_allow_html=True,
    )


def risk_badge(band: str) -> str:
    color = RISK_BAND_COLORS.get(band, "#888888")
    return f'<span class="risk-badge" style="background-color:{color};">{band}</span>'


def download_csv_button(df: pd.DataFrame, label: str, filename: str) -> None:
    if df.empty:
        return
    st.download_button(label, df.to_csv(index=False), file_name=filename, mime="text/csv")


# --------------------------------------------------------------------------- #
# Page 1 — Executive Overview
# --------------------------------------------------------------------------- #

def render_executive_overview(data: Dict[str, pd.DataFrame]) -> None:
    st.header("Executive Overview")
    kpis = compute_executive_kpis(data)

    cols = st.columns(6)
    with cols[0]: metric_card("Total Identities", kpis["total_identities"])
    with cols[1]: metric_card("Critical Risks", kpis["critical_risks"])
    with cols[2]: metric_card("Dormant Admins", kpis["dormant_admins"])
    with cols[3]: metric_card("Privilege Creep", kpis["privilege_creep"])
    with cols[4]: metric_card("Service Accounts", kpis["service_accounts"])
    with cols[5]: metric_card("Offboarding Gaps", kpis["offboarding_gaps"])

    st.divider()
    col1, col2 = st.columns(2)
    with col1:
        st.subheader("Risk Band Distribution")
        scores = data["identity_risk_scores"]
        if not scores.empty:
            counts = scores["risk_band"].value_counts().reset_index()
            counts.columns = ["risk_band", "count"]
            fig = px.pie(counts, names="risk_band", values="count",
                         color="risk_band", color_discrete_map=RISK_BAND_COLORS, hole=0.45)
            st.plotly_chart(fig, use_container_width=True)

    with col2:
        st.subheader("Department Risk")
        dept_risk = compute_department_risk(data)
        if not dept_risk.empty:
            fig = px.bar(dept_risk.head(15), x="avg_risk_score", y="department_name", orientation="h")
            st.plotly_chart(fig, use_container_width=True)

    col3, col4 = st.columns(2)
    with col3:
        st.subheader("Platform Risk (Alert Volume)")
        platform_risk = compute_platform_risk(data)
        if not platform_risk.empty:
            fig = px.bar(platform_risk, x="platform_name", y="alert_count")
            st.plotly_chart(fig, use_container_width=True)

    with col4:
        st.subheader("Top 10 Risky Identities")
        top10 = compute_top_risky_users(data, 10)
        if not top10.empty:
            st.dataframe(top10, use_container_width=True, hide_index=True)
            download_csv_button(top10, "Download Top 10 (CSV)", "top10_risky_identities.csv")


# --------------------------------------------------------------------------- #
# Page 2 — Identity Risk Registry
# --------------------------------------------------------------------------- #

def render_identity_risk_registry(data: Dict[str, pd.DataFrame]) -> None:
    st.header("Identity Risk Registry")
    scores = data["identity_risk_scores"]
    dept_series = _identity_to_department(data)
    departments = ["All"] + sorted(dept_series.dropna().unique().tolist())

    c1, c2, c3, c4 = st.columns(4)
    with c1: department = st.selectbox("Department", departments)
    with c2: risk_band = st.multiselect("Risk Band", ["Critical", "High", "Medium", "Low"])
    with c3: employment_type = st.selectbox("Employment Type", ["All", "Employee", "Contractor"])
    with c4: search = st.text_input("Search by name")

    filtered = filter_identity_registry(data, department, risk_band or None, employment_type, search)
    st.write(f"{len(filtered)} identities match")
    st.dataframe(filtered, use_container_width=True, hide_index=True)
    download_csv_button(filtered, "Export filtered results (CSV)", "identity_risk_registry.csv")

    st.divider()
    st.subheader("Identity Detail")
    if not filtered.empty:
        selected = st.selectbox("Select an identity for full privilege summary", filtered["identity_id"].tolist())
        if selected is not None:
            detail = get_identity_detail(data, selected)
            with st.expander("Risk Score Breakdown", expanded=True):
                st.json(detail["score"])
            with st.expander("Privilege Summary"):
                st.json(detail["privilege"])
            with st.expander(f"Active Alerts ({len(detail['alerts'])})"):
                if detail["alerts"]:
                    st.dataframe(pd.DataFrame(detail["alerts"]), use_container_width=True, hide_index=True)
                else:
                    st.write("No active alerts for this identity.")


# --------------------------------------------------------------------------- #
# Page 3 — Identity Graph Explorer
# --------------------------------------------------------------------------- #

def build_graph_figure(graph: nx.MultiDiGraph, highlight: Optional[set] = None) -> go.Figure:
    if graph.number_of_nodes() == 0:
        return go.Figure()
    pos = nx.spring_layout(graph, seed=42)

    edge_x, edge_y = [], []
    for u, v in graph.edges():
        x0, y0 = pos[u]
        x1, y1 = pos[v]
        edge_x += [x0, x1, None]
        edge_y += [y0, y1, None]
    edge_trace = go.Scatter(x=edge_x, y=edge_y, line=dict(width=0.5, color="#444"), hoverinfo="none", mode="lines")

    node_x, node_y, node_color, node_text, node_size = [], [], [], [], []
    for node, attrs in graph.nodes(data=True):
        x, y = pos[node]
        node_x.append(x)
        node_y.append(y)
        node_type = attrs.get("node_type", "Unknown")
        node_color.append(NODE_TYPE_COLORS.get(node_type, "#888888"))
        label = attrs.get("full_name") or attrs.get("account_name") or attrs.get("group_name") or str(node)
        node_text.append(f"{node_type}: {label}")
        node_size.append(18 if highlight and node in highlight else 10)

    node_trace = go.Scatter(
        x=node_x, y=node_y, mode="markers", hoverinfo="text", text=node_text,
        marker=dict(color=node_color, size=node_size, line=dict(width=1, color="#0E1117")),
    )
    fig = go.Figure(data=[edge_trace, node_trace])
    fig.update_layout(showlegend=False, margin=dict(l=0, r=0, t=0, b=0), plot_bgcolor="#0E1117", paper_bgcolor="#0E1117")
    fig.update_xaxes(visible=False)
    fig.update_yaxes(visible=False)
    return fig


def render_identity_graph_explorer(data: Dict[str, pd.DataFrame]) -> None:
    st.header("Identity Graph Explorer")
    graph = data["graph"]
    st.caption(f"{graph.number_of_nodes()} nodes, {graph.number_of_edges()} edges")

    query = st.text_input("Search identity, account, or group")
    matches = search_graph_nodes(graph, query) if query else []

    highlight_type = st.multiselect(
        "Highlight node types", ["Admins (Role/Permission)", "ServiceAccount", "Account", "Identity"]
    )

    if matches:
        selected_node = st.selectbox("Matches", matches)
        ego = get_ego_graph(graph, selected_node, radius=2)
        st.write(f"Showing {ego.number_of_nodes()}-node neighborhood around {selected_node}")
        fig = build_graph_figure(ego, highlight={selected_node})
    else:
        # full graph is too dense to render meaningfully at once for very large graphs;
        # show a representative sample for overview purposes
        sample_nodes = list(graph.nodes())[:300]
        fig = build_graph_figure(graph.subgraph(sample_nodes))

    st.plotly_chart(fig, use_container_width=True)


# --------------------------------------------------------------------------- #
# Page 4 — Incident Investigation
# --------------------------------------------------------------------------- #

def render_incident_investigation(data: Dict[str, pd.DataFrame]) -> None:
    st.header("Incident Investigation")
    incidents = data["incidents"]
    narratives = data["incident_narratives"]
    if incidents.empty:
        st.info("No incidents found. Run incident_correlator.py first.")
        return

    c1, c2 = st.columns(2)
    with c1: severity_filter = st.multiselect("Severity", ["Critical", "High", "Medium", "Low"])
    with c2: search = st.text_input("Search by name or incident type")

    filtered = incidents.copy()
    if severity_filter:
        filtered = filtered[filtered["severity"].isin(severity_filter)]
    if search:
        filtered = filtered[
            filtered["full_name"].astype(str).str.contains(search, case=False, na=False)
            | filtered["incident_type"].astype(str).str.contains(search, case=False, na=False)
        ]
    filtered = filtered.sort_values(["severity", "alert_count"], ascending=False)

    st.dataframe(filtered[["incident_id", "full_name", "incident_type", "severity", "alert_count",
                            "affected_systems", "underlying_risk_score"]], use_container_width=True, hide_index=True)
    download_csv_button(filtered, "Export incidents (CSV)", "incidents.csv")

    st.divider()
    if not filtered.empty:
        selected_id = st.selectbox("Investigate incident", filtered["incident_id"].tolist())
        incident = incidents[incidents["incident_id"] == selected_id].iloc[0]
        narrative_rows = narratives[narratives["incident_id"] == selected_id]
        narrative = narrative_rows.iloc[0] if len(narrative_rows) else None

        st.markdown(f"### Incident {selected_id} — {incident['incident_type']} {risk_badge(incident['severity'])}",
                    unsafe_allow_html=True)

        tabs = st.tabs(["Summary", "Technical Details", "Business Impact", "Compliance Impact",
                        "Evidence", "Timeline", "Affected Assets", "Remediation"])
        with tabs[0]:
            st.write(narrative["executive_summary"] if narrative is not None else "No narrative generated.")
        with tabs[1]:
            st.write(narrative["technical_summary"] if narrative is not None else "")
        with tabs[2]:
            st.write(narrative["business_impact"] if narrative is not None else "")
        with tabs[3]:
            st.write(narrative["compliance_impact"] if narrative is not None else "")
        with tabs[4]:
            st.write(incident["evidence_summary"])
        with tabs[5]:
            st.write(f"First detected: {incident['first_detected_at']}")
            st.write(f"Last detected: {incident['last_detected_at']}")
        with tabs[6]:
            st.write(incident["affected_systems"])
        with tabs[7]:
            st.write(incident["recommended_remediation"])


# --------------------------------------------------------------------------- #
# Page 5 — Offboarding Monitor
# --------------------------------------------------------------------------- #

def render_offboarding_monitor(data: Dict[str, pd.DataFrame]) -> None:
    st.header("Offboarding Monitor")
    kpis = compute_offboarding_kpis(data)

    cols = st.columns(4)
    with cols[0]: metric_card("Pending Revocations", kpis.get("pending", 0))
    with cols[1]: metric_card("SLA Breaches", kpis.get("sla_breached", 0))
    with cols[2]: metric_card("Total Offboarding Events", kpis.get("total", 0))
    with cols[3]: metric_card("SLA Compliance", f"{kpis.get('compliance_pct', 0)}%")

    st.divider()
    by_platform = compute_offboarding_by_platform(data)
    if not by_platform.empty:
        st.subheader("Revocation SLA by Platform")
        fig = px.bar(by_platform, x="platform_name", y="compliance_pct")
        st.plotly_chart(fig, use_container_width=True)

    ob = data["offboarding_events"]
    if not ob.empty:
        st.subheader("Expired / Pending Accounts")
        pending = ob[ob["actual_revocation_at"].isna()].copy()
        pending["platform_name"] = pending["platform_id"].map(PLATFORM_ID_TO_NAME)
        st.dataframe(pending, use_container_width=True, hide_index=True)
        download_csv_button(pending, "Export pending revocations (CSV)", "pending_revocations.csv")


# --------------------------------------------------------------------------- #
# Page 6 — Service Account Monitor
# --------------------------------------------------------------------------- #

def render_service_account_monitor(data: Dict[str, pd.DataFrame]) -> None:
    st.header("Service Account Monitor")
    kpis = compute_service_account_kpis(data)
    if not kpis:
        st.info("No service account data found.")
        return

    cols = st.columns(5)
    with cols[0]: metric_card("Total", kpis["total"])
    with cols[1]: metric_card("No Owner", kpis["no_owner"])
    with cols[2]: metric_card("High Privilege", kpis["high_privilege"])
    with cols[3]: metric_card("Overdue Rotation", kpis["overdue_rotation"])
    with cols[4]: metric_card("Break-Glass", kpis["breakglass"])

    st.divider()
    sa = data["service_accounts"].copy()
    sa["platform_name"] = sa["platform_id"].map(PLATFORM_ID_TO_NAME)

    col1, col2 = st.columns(2)
    with col1:
        st.subheader("Rotation Status")
        fig = px.pie(sa, names="rotation_status", hole=0.4)
        st.plotly_chart(fig, use_container_width=True)
    with col2:
        st.subheader("Privilege Level Distribution")
        fig = px.pie(sa, names="privilege_level", hole=0.4)
        st.plotly_chart(fig, use_container_width=True)

    st.subheader("All Service Accounts")
    st.dataframe(sa, use_container_width=True, hide_index=True)
    download_csv_button(sa, "Export service accounts (CSV)", "service_accounts.csv")


# --------------------------------------------------------------------------- #
# Page 7 — API Token Governance
# --------------------------------------------------------------------------- #

def render_token_governance(data: Dict[str, pd.DataFrame]) -> None:
    st.header("API Token Governance")
    kpis = compute_token_kpis(data)
    if not kpis:
        st.info("No token data found.")
        return

    cols = st.columns(5)
    with cols[0]: metric_card("Total Tokens", kpis["total"])
    with cols[1]: metric_card("Expiring (30d)", kpis["expiring_30d"])
    with cols[2]: metric_card("Expired", kpis["expired"])
    with cols[3]: metric_card("No Expiry Set", kpis["no_expiry"])
    with cols[4]: metric_card("Flagged Abused", kpis["abused"])

    st.divider()
    tokens = data["api_tokens"].copy()
    tokens["platform_name"] = tokens["platform_id"].map(PLATFORM_ID_TO_NAME)
    alerts = data["alerts"]
    if not alerts.empty:
        abused_token_pseudo_ids = set(alerts[alerts["rule_name"] == "TOKEN_ABUSE"]["identity_id"])
        tokens["flagged_abused"] = (8_000_000 + tokens["token_id"]).isin(abused_token_pseudo_ids)
    else:
        tokens["flagged_abused"] = False

    st.dataframe(tokens, use_container_width=True, hide_index=True)
    download_csv_button(tokens, "Export tokens (CSV)", "api_tokens.csv")


# --------------------------------------------------------------------------- #
# Page 8 — Analytics
# --------------------------------------------------------------------------- #

def render_analytics(data: Dict[str, pd.DataFrame]) -> None:
    st.header("Analytics")
    analytics = compute_analytics(data)

    if not analytics["heatmap"].empty:
        st.subheader("Risk Heatmap — Department x Platform")
        fig = px.imshow(analytics["heatmap"], aspect="auto", color_continuous_scale="Reds")
        st.plotly_chart(fig, use_container_width=True)

    col1, col2 = st.columns(2)
    with col1:
        st.subheader("Department Comparison")
        if not analytics["department_risk"].empty:
            fig = px.bar(analytics["department_risk"], x="department_name", y="avg_risk_score")
            st.plotly_chart(fig, use_container_width=True)
    with col2:
        st.subheader("Platform Comparison")
        if not analytics["platform_risk"].empty:
            fig = px.bar(analytics["platform_risk"], x="platform_name", y="avg_risk_score")
            st.plotly_chart(fig, use_container_width=True)

    st.subheader("Anomaly Distribution")
    if not analytics["anomaly_distribution"].empty:
        fig = px.bar(analytics["anomaly_distribution"], x="rule_name", y="count")
        st.plotly_chart(fig, use_container_width=True)

    st.subheader("Monthly Termination / SLA Trend")
    if not analytics["monthly_terminations"].empty:
        fig = px.line(analytics["monthly_terminations"], x="month", y=["terminations", "sla_breaches"])
        st.plotly_chart(fig, use_container_width=True)


# --------------------------------------------------------------------------- #
# Sidebar — navigation + Demo Mode
# --------------------------------------------------------------------------- #

def render_sidebar(data: Dict[str, pd.DataFrame]) -> str:
    st.sidebar.title("Identity Risk Platform")
    page = st.sidebar.radio(
        "Navigate",
        ["Executive Overview", "Identity Risk Registry", "Identity Graph Explorer",
         "Incident Investigation", "Offboarding Monitor", "Service Account Monitor",
         "API Token Governance", "Analytics"],
    )
    st.sidebar.divider()
    with st.sidebar.expander("Demo Mode", expanded=False):
        st.caption("Injects a synthetic anomaly into the in-memory session data and refreshes the dashboard. Does not modify any file on disk.")
        for label, fn in DEMO_ACTIONS.items():
            if st.button(label, key=f"demo_{label}"):
                message = fn(data)
                st.session_state["demo_message"] = message
                st.rerun()
        if "demo_message" in st.session_state:
            st.success(st.session_state["demo_message"])
    return page


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #

def main() -> None:
    st.set_page_config(page_title="Identity Risk Platform", layout="wide", initial_sidebar_state="expanded")
    st.markdown(DARK_THEME_CSS, unsafe_allow_html=True)

    if "data" not in st.session_state:
        st.session_state["data"] = load_all_data()
    data = st.session_state["data"]

    page = render_sidebar(data)

    if page == "Executive Overview":
        render_executive_overview(data)
    elif page == "Identity Risk Registry":
        render_identity_risk_registry(data)
    elif page == "Identity Graph Explorer":
        render_identity_graph_explorer(data)
    elif page == "Incident Investigation":
        render_incident_investigation(data)
    elif page == "Offboarding Monitor":
        render_offboarding_monitor(data)
    elif page == "Service Account Monitor":
        render_service_account_monitor(data)
    elif page == "API Token Governance":
        render_token_governance(data)
    elif page == "Analytics":
        render_analytics(data)


if __name__ == "__main__":
    main()
