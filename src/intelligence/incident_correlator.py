"""
src/intelligence/incident_correlator.py

Incident Correlation Engine for the Hybrid Identity Governance platform
(Phase 4 Incident Correlation Engine component, Phase 5 MVP scope).

Groups raw alerts into investigation-ready incidents by identity, time
window, platform, and risk category — turning N disconnected alerts for the
same underlying situation into one correlated case file with computed
severity and evidence.

Input contract note: like risk_scoring.py, this module expects alerts.csv
(Rule Engine output). load_or_derive_alerts() falls back to deriving an
equivalent table from identity_risk_labels.csv when alerts.csv is absent —
see risk_scoring.py for the documented expected schema. Severity-bearing
fields (risk_score, risk_band) are pulled from identity_risk_scores.csv
(risk_scoring.py's output), so that module must run first.

Output: incidents.csv
"""

from __future__ import annotations

import logging
from datetime import date, timedelta
from pathlib import Path
from typing import Dict, List, Optional

import pandas as pd

# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #

DATA_DIR: Path = Path("data/synthetic_data")
OUTPUT_DIR: Path = Path("data/synthetic_data")
REFERENCE_DATE: date = date(2026, 6, 20)

ALERTS_FILE: str = "alerts.csv"
REQUIRED_INPUTS: Dict[str, str] = {
    "identity_risk_scores": "identity_risk_scores.csv",
    "authentication_events": "authentication_events.csv",
}
LABELS_FALLBACK_FILE: str = "identity_risk_labels.csv"

CORRELATION_WINDOW_HOURS: int = 72
SEVERITY_RANK: Dict[str, int] = {"Low": 0, "Medium": 1, "High": 2, "Critical": 3}
SEVERITY_BY_RANK: List[str] = ["Low", "Medium", "High", "Critical"]

REMEDIATION_BY_ANOMALY_TYPE: Dict[str, str] = {
    "OFFBOARDING_GAP": "Immediately revoke access on the affected platform(s); confirm no activity occurred during the gap window; root-cause the automation failure.",
    "DORMANT_ADMIN": "Disable or downgrade the dormant privileged account pending owner re-justification of continued business need.",
    "CROSS_PLATFORM_ADMIN": "Require documented business justification for multi-platform admin access; evaluate splitting into platform-scoped roles or converting to just-in-time elevation.",
    "PRIVILEGE_CREEP": "Execute targeted revocation of stale access tied to the prior role; enable automatic mover-triggered access review going forward.",
    "SERVICE_ACCOUNT_ABUSE": "Disable interactive login capability or the service account itself; investigate the actor who performed the interactive session; reassign ownership if the registered owner has departed.",
    "TOKEN_ABUSE": "Revoke and rotate the affected token immediately; review all actions taken during the anomalous usage window; investigate the exposure source.",
    "ORPHANED_CROSS_PLATFORM": "Investigate the account's origin; reconcile against the HR system of record; disable pending resolution.",
}
DEFAULT_REMEDIATION = "Escalate to the identity governance team for manual investigation and remediation."

LOGGER = logging.getLogger("incident_correlator")


# --------------------------------------------------------------------------- #
# Setup / IO helpers
# --------------------------------------------------------------------------- #

def configure_logging() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def load_required(key: str) -> pd.DataFrame:
    filename = REQUIRED_INPUTS[key]
    path = DATA_DIR / filename
    if not path.exists():
        raise FileNotFoundError(f"Required input '{filename}' not found in {DATA_DIR}")
    df = pd.read_csv(path)
    LOGGER.info("Loaded required input %s (%d rows)", filename, len(df))
    return df


def save_csv(df: pd.DataFrame, filename: str) -> Path:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    path = OUTPUT_DIR / filename
    df.to_csv(path, index=False)
    LOGGER.info("Saved %s (%d rows, %d columns)", path, len(df), len(df.columns))
    return path


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


def load_or_derive_alerts() -> pd.DataFrame:
    """See risk_scoring.py for the documented expected alerts.csv schema."""
    path = DATA_DIR / ALERTS_FILE
    if path.exists():
        df = pd.read_csv(path)
        LOGGER.info("Loaded real alerts.csv (%d rows)", len(df))
        return df

    labels_path = DATA_DIR / LABELS_FALLBACK_FILE
    if not labels_path.exists():
        raise FileNotFoundError(
            f"Neither '{ALERTS_FILE}' nor the fallback '{LABELS_FALLBACK_FILE}' was found in {DATA_DIR}"
        )
    LOGGER.warning(
        "alerts.csv not found — deriving a fallback alerts table from identity_risk_labels.csv. "
        "This is NOT real rule-engine output; replace with actual alerts.csv once rule_engine.py exists."
    )
    labels_df = pd.read_csv(labels_path)
    derived = labels_df.copy()
    derived["alert_id"] = range(1, len(derived) + 1)
    derived["platform_id"] = None
    derived["detected_at"] = REFERENCE_DATE.isoformat()
    derived["evidence"] = derived["explanation"]
    derived["rule_name"] = derived["anomaly_type"].astype(str) + "_RULE"
    return derived[["alert_id", "identity_id", "anomaly_type", "severity", "platform_id",
                     "detected_at", "evidence", "rule_name"]]


def build_employee_key_bridge(risk_scores_df: pd.DataFrame) -> Dict[str, object]:
    """identity_risk_scores.csv (risk_scoring.py output) doesn't carry
    employee_key directly, so the bridge is re-derived the same way
    risk_scoring.py derives it: via effective_privileges.csv if available,
    otherwise alerts are grouped under their raw original identity_id."""
    path = DATA_DIR / "effective_privileges.csv"
    bridge: Dict[str, object] = {}
    if not path.exists():
        LOGGER.warning("effective_privileges.csv not found — alerts will be grouped under raw identity_id values")
        return bridge
    ep_df = pd.read_csv(path)
    for _, row in ep_df.iterrows():
        key = clean_id(row.get("employee_key"))
        if key is not None:
            bridge[key] = row["identity_id"]
    return bridge


# --------------------------------------------------------------------------- #
# Correlation: group alerts by identity + time window, scoped further by
# platform and risk category for the evidence summary
# --------------------------------------------------------------------------- #

def attach_resolved_identity(alerts_df: pd.DataFrame, employee_key_bridge: Dict[str, object]) -> pd.DataFrame:
    df = alerts_df.copy()
    df["resolved_identity_id"] = df["identity_id"].apply(
        lambda v: employee_key_bridge.get(clean_id(v), clean_id(v))
    )
    df["detected_at"] = pd.to_datetime(df["detected_at"], errors="coerce")
    df["detected_at"] = df["detected_at"].fillna(pd.Timestamp(REFERENCE_DATE))
    return df


def correlate_alerts_into_incidents(alerts_df: pd.DataFrame) -> List[List[int]]:
    """Returns a list of alert-index groups, each group representing one
    incident: same resolved identity, alerts within a rolling
    CORRELATION_WINDOW_HOURS of each other (chained — A-B close and B-C close
    transitively joins A, B, C into one incident)."""
    LOGGER.info("Correlating alerts into incidents (window=%dh)", CORRELATION_WINDOW_HOURS)
    groups: List[List[int]] = []

    for resolved_id, identity_alerts in alerts_df.groupby("resolved_identity_id"):
        sorted_alerts = identity_alerts.sort_values("detected_at")
        current_group: List[int] = []
        last_time: Optional[pd.Timestamp] = None

        for idx, row in sorted_alerts.iterrows():
            if last_time is None or (row["detected_at"] - last_time) <= timedelta(hours=CORRELATION_WINDOW_HOURS):
                current_group.append(idx)
            else:
                groups.append(current_group)
                current_group = [idx]
            last_time = row["detected_at"]

        if current_group:
            groups.append(current_group)

    LOGGER.info("Correlated %d alerts into %d incidents", len(alerts_df), len(groups))
    return groups


def _compute_incident_severity(group_alerts: pd.DataFrame, base_risk_band: Optional[str]) -> str:
    component_max = max((SEVERITY_RANK.get(s, 0) for s in group_alerts["severity"]), default=0)
    distinct_types = group_alerts["anomaly_type"].nunique()
    distinct_platforms = group_alerts["platform_id"].nunique(dropna=True) if "platform_id" in group_alerts else 0

    bonus = 0
    if distinct_types >= 3:
        bonus = 2
    elif distinct_types == 2:
        bonus = 1
    if distinct_platforms >= 2:
        bonus += 1

    has_critical_component = component_max == SEVERITY_RANK["Critical"]
    rank = min(component_max + bonus, SEVERITY_RANK["Critical"])
    if has_critical_component:
        rank = max(rank, SEVERITY_RANK["Critical"])  # a Critical component sets a hard floor

    if base_risk_band == "Critical":
        rank = max(rank, SEVERITY_RANK["Critical"])
    elif base_risk_band == "High":
        rank = max(rank, SEVERITY_RANK["High"])

    return SEVERITY_BY_RANK[rank]


def build_incidents(
    alerts_df: pd.DataFrame, groups: List[List[int]], risk_scores_df: pd.DataFrame
) -> pd.DataFrame:
    LOGGER.info("Building incident case files")
    risk_context = risk_scores_df.set_index("identity_id")

    records = []
    incident_id = 1
    for index_group in groups:
        group_alerts = alerts_df.loc[index_group]
        resolved_id = group_alerts["resolved_identity_id"].iloc[0]

        risk_row = risk_context.loc[resolved_id] if resolved_id in risk_context.index else None
        base_risk_band = risk_row["risk_band"] if risk_row is not None else None
        full_name = risk_row["full_name"] if risk_row is not None else None

        distinct_types = sorted(group_alerts["anomaly_type"].unique())
        incident_type = distinct_types[0] if len(distinct_types) == 1 else f"Multi-Anomaly ({', '.join(distinct_types)})"

        severity = _compute_incident_severity(group_alerts, base_risk_band)

        affected_systems = sorted(
            {f"Platform-{int(p)}" for p in group_alerts["platform_id"].dropna().unique()}
        ) if "platform_id" in group_alerts and group_alerts["platform_id"].notna().any() else []
        if not affected_systems:
            affected_systems = ["Unspecified (alerts.csv did not carry platform_id)"]

        evidence_lines = [
            f"[{row['severity']}] {row['anomaly_type']}: {row.get('evidence', '')}"
            for _, row in group_alerts.iterrows()
        ]
        evidence_summary = " | ".join(evidence_lines)

        remediations = sorted({
            REMEDIATION_BY_ANOMALY_TYPE.get(t, DEFAULT_REMEDIATION) for t in distinct_types
        })

        records.append(
            {
                "incident_id": incident_id,
                "identity_id": resolved_id,
                "full_name": full_name,
                "incident_type": incident_type,
                "severity": severity,
                "alert_count": len(group_alerts),
                "first_detected_at": group_alerts["detected_at"].min(),
                "last_detected_at": group_alerts["detected_at"].max(),
                "evidence_summary": evidence_summary,
                "affected_systems": ";".join(affected_systems),
                "underlying_risk_score": risk_row["risk_score"] if risk_row is not None else None,
                "underlying_risk_band": base_risk_band,
                "recommended_remediation": " AND ".join(remediations),
            }
        )
        incident_id += 1

    df = pd.DataFrame.from_records(records)
    df["_severity_rank"] = df["severity"].map(SEVERITY_RANK)
    df = df.sort_values(["_severity_rank", "alert_count"], ascending=False).drop(columns=["_severity_rank"])
    df = df.reset_index(drop=True)
    df["incident_id"] = range(1, len(df) + 1)  # re-sequence after severity sort
    return df


# --------------------------------------------------------------------------- #
# Main execution block
# --------------------------------------------------------------------------- #

def main() -> None:
    configure_logging()
    LOGGER.info("Starting incident correlation")

    risk_scores_df = load_required("identity_risk_scores")
    _ = load_required("authentication_events")  # available for future evidence enrichment; not required for v1 grouping
    alerts_df = load_or_derive_alerts()

    employee_key_bridge = build_employee_key_bridge(risk_scores_df)
    alerts_df = attach_resolved_identity(alerts_df, employee_key_bridge)

    groups = correlate_alerts_into_incidents(alerts_df)
    incidents_df = build_incidents(alerts_df, groups, risk_scores_df)

    save_csv(incidents_df, "incidents.csv")

    LOGGER.info("Incident severity distribution:\n%s", incidents_df["severity"].value_counts())
    LOGGER.info(
        "Summary -> total incidents: %d | from %d raw alerts | multi-alert incidents: %d | avg alerts/incident: %.2f",
        len(incidents_df), len(alerts_df), (incidents_df["alert_count"] > 1).sum(),
        incidents_df["alert_count"].mean(),
    )
    LOGGER.info("Incident correlation complete")


if __name__ == "__main__":
    main()
