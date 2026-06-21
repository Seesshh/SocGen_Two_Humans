"""
src/intelligence/risk_scoring.py

Risk Scoring Engine for the Hybrid Identity Governance platform (Phase 4 Risk
Scoring Engine component, Phase 5 MVP scope).

Computes a 0-100 Identity Risk Score per identity from five weighted
components: Privilege Risk, Behavior Risk, Exposure Risk, Governance Risk,
and Cross-Platform Risk.

Input contract note: this module's specified inputs include alerts.csv, which
is the Rule Engine's output (src/intelligence/rule_engine.py is not part of
this delivery). Rather than fail when it's absent, load_or_derive_alerts()
falls back to deriving an equivalent alerts table from identity_risk_labels.csv
(the ground-truth anomaly labels), clearly logged as a fallback so it's never
mistaken for real rule-engine output. The expected alerts.csv schema is
documented at the top of that function so a future rule_engine.py can target
it directly.

A second bridging note: effective_privileges.csv (from privilege_engine.py)
uses identity_id values resolved fresh by identity_resolver.py, while
alerts.csv / identity_risk_labels.csv reference the original data-generation
pipeline's identity_id (which equals the underlying person_id for every
linked identity). Records are bridged via employee_key, exactly as in
privilege_engine.py; entities that cannot be bridged (most often service
accounts and tokens, which carry their own namespaced pseudo-identity IDs in
identity_risk_labels.csv) are still scored and reported, just flagged as
non-human entities rather than silently dropped.

Output: identity_risk_scores.csv
"""

from __future__ import annotations

import logging
from datetime import date, datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import numpy as np
import pandas as pd

# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #

DATA_DIR: Path = Path("data/synthetic_data")
OUTPUT_DIR: Path = Path("data/synthetic_data")
REFERENCE_DATE: date = date(2026, 6, 20)

REQUIRED_INPUTS: Dict[str, str] = {
    "effective_privileges": "effective_privileges.csv",
    "authentication_events": "authentication_events.csv",
    "identity_risk_labels": "identity_risk_labels.csv",
}
ALERTS_FILE: str = "alerts.csv"
OPTIONAL_INPUTS: Dict[str, str] = {"resolved_identities": "resolved_identities.csv"}

WEIGHTS: Dict[str, float] = {
    "privilege_risk": 0.30,
    "behavior_risk": 0.20,
    "exposure_risk": 0.20,
    "governance_risk": 0.20,
    "cross_platform_risk": 0.10,
}

TIER_BASE_SCORE: Dict[str, float] = {"Standard": 5, "Power User": 20, "Admin": 50, "Super Admin": 80, "None": 0}
SEVERITY_WEIGHT: Dict[str, float] = {"Low": 10, "Medium": 25, "High": 50, "Critical": 80}

RISK_BANDS: Tuple[Tuple[float, str], ...] = ((80, "Critical"), (55, "High"), (30, "Medium"), (0, "Low"))

RECOMMENDED_ACTION_BY_BAND: Dict[str, str] = {
    "Low": "Standard review cadence; no special action required.",
    "Medium": "Include in next standard access review cycle with explicit attestation required.",
    "High": "Expedited review within 5 business days; consider temporary access suspension pending confirmation.",
    "Critical": "Immediate access suspension; engage SecOps incident response; notify CISO; mandatory post-incident review.",
}

LOGGER = logging.getLogger("risk_scoring")


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


def load_optional(key: str) -> Optional[pd.DataFrame]:
    filename = OPTIONAL_INPUTS[key]
    path = DATA_DIR / filename
    if not path.exists():
        LOGGER.warning("Optional enrichment input '%s' not found", filename)
        return None
    df = pd.read_csv(path)
    LOGGER.info("Loaded optional input %s (%d rows)", filename, len(df))
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


def load_or_derive_alerts(labels_df: pd.DataFrame) -> pd.DataFrame:
    """Expected alerts.csv schema (for a future rule_engine.py to target):
        alert_id, identity_id, anomaly_type, severity, platform_id,
        detected_at, evidence, rule_name

    Falls back to deriving an equivalent table from identity_risk_labels.csv
    when alerts.csv doesn't exist yet, clearly flagged as a fallback.
    """
    path = DATA_DIR / ALERTS_FILE
    if path.exists():
        df = pd.read_csv(path)
        LOGGER.info("Loaded real alerts.csv (%d rows)", len(df))
        return df

    LOGGER.warning(
        "alerts.csv not found — deriving a fallback alerts table from identity_risk_labels.csv. "
        "This is NOT real rule-engine output; replace with actual alerts.csv once rule_engine.py exists."
    )
    derived = labels_df.copy()
    derived["alert_id"] = range(1, len(derived) + 1)
    derived["platform_id"] = None
    derived["detected_at"] = REFERENCE_DATE.isoformat()
    derived["evidence"] = derived["explanation"]
    derived["rule_name"] = derived["anomaly_type"].astype(str) + "_RULE"
    return derived[["alert_id", "identity_id", "anomaly_type", "severity", "platform_id",
                     "detected_at", "evidence", "rule_name"]]


def build_employee_key_bridge(effective_privileges_df: pd.DataFrame) -> Dict[str, object]:
    """employee_key -> resolved identity_id, sourced directly from
    effective_privileges.csv (itself produced from resolved_identities.csv)."""
    bridge: Dict[str, object] = {}
    for _, row in effective_privileges_df.iterrows():
        emp_key = clean_id(row.get("employee_key"))
        if emp_key is not None:
            bridge[emp_key] = row["identity_id"]
    LOGGER.info("Employee-key bridge built: %d entries", len(bridge))
    return bridge


def build_account_bridge(resolved_identities_df: Optional[pd.DataFrame]) -> Dict[Tuple[str, int], object]:
    """(platform_account_id, platform_id-agnostic) -> resolved identity_id,
    used to attribute authentication_events.csv rows (which only carry
    platform_account_id) back to a resolved identity."""
    bridge: Dict[Tuple[str, int], object] = {}
    if resolved_identities_df is None:
        return bridge
    for _, row in resolved_identities_df.iterrows():
        matched_accounts = row.get("matched_accounts")
        if not isinstance(matched_accounts, str) or not matched_accounts.strip():
            continue
        for chunk in matched_accounts.split(";"):
            if ":" not in chunk:
                continue
            _, account_id = chunk.split(":", 1)
            bridge[account_id.strip()] = row["identity_id"]
    LOGGER.info("Account bridge built: %d entries", len(bridge))
    return bridge


# --------------------------------------------------------------------------- #
# Component 1 — Privilege Risk
# --------------------------------------------------------------------------- #

def compute_privilege_risk(effective_privileges_df: pd.DataFrame) -> Dict[object, float]:
    LOGGER.info("Computing Privilege Risk")
    scores: Dict[object, float] = {}
    for _, row in effective_privileges_df.iterrows():
        tier_score = TIER_BASE_SCORE.get(row.get("highest_privilege_tier"), 0)
        admin_bonus = min(row.get("admin_permission_count", 0) * 5, 20)
        score = min(tier_score + admin_bonus, 100)
        scores[row["identity_id"]] = score
    return scores


# --------------------------------------------------------------------------- #
# Component 2 — Behavior Risk
# --------------------------------------------------------------------------- #

def compute_behavior_risk(
    auth_events_df: pd.DataFrame, account_bridge: Dict[str, object]
) -> Dict[object, float]:
    LOGGER.info("Computing Behavior Risk")
    if not account_bridge:
        LOGGER.warning(
            "No account bridge available (resolved_identities.csv missing) — "
            "Behavior Risk will default to 0 for all identities"
        )
        return {}

    df = auth_events_df.copy()
    df["identity_id"] = df["platform_account_id"].astype(str).map(account_bridge)
    df = df[df["identity_id"].notna()]
    if df.empty:
        return {}

    df["event_timestamp"] = pd.to_datetime(df["event_timestamp"], errors="coerce")
    df["is_weekend"] = df["event_timestamp"].dt.dayofweek >= 5
    df["is_failed"] = df["auth_result"] == "Failed"
    df["mfa_skipped"] = df["mfa_used"] == False  # noqa: E712

    scores: Dict[object, float] = {}
    for identity_id, group in df.groupby("identity_id"):
        n = len(group)
        if n == 0:
            continue
        failed_rate = group["is_failed"].mean()
        weekend_rate = group["is_weekend"].mean()
        mfa_skip_rate = group["mfa_skipped"].mean()
        distinct_countries = group["source_country"].nunique(dropna=True)
        country_signal = min(max(distinct_countries - 1, 0) / 3.0, 1.0)  # >1 country starts to matter

        score = (
            failed_rate * 100 * 0.40
            + country_signal * 100 * 0.30
            + weekend_rate * 100 * 0.15
            + mfa_skip_rate * 100 * 0.15
        )
        scores[identity_id] = min(score, 100.0)

    return scores


# --------------------------------------------------------------------------- #
# Component 3 — Exposure Risk
# --------------------------------------------------------------------------- #

def compute_exposure_risk(effective_privileges_df: pd.DataFrame) -> Dict[object, float]:
    LOGGER.info("Computing Exposure Risk")
    scores: Dict[object, float] = {}
    max_reach = max(effective_privileges_df["effective_permission_count"].max(), 1)
    for _, row in effective_privileges_df.iterrows():
        reach_component = (row.get("effective_permission_count", 0) / max_reach) * 50
        depth_component = min(row.get("privilege_depth", 0), 5) / 5 * 25
        blast_component = min(row.get("privilege_blast_radius", 0), 5) / 5 * 25
        scores[row["identity_id"]] = min(reach_component + depth_component + blast_component, 100.0)
    return scores


# --------------------------------------------------------------------------- #
# Component 4 — Governance Risk
# --------------------------------------------------------------------------- #

def compute_governance_risk(
    alerts_df: pd.DataFrame, employee_key_bridge: Dict[str, object]
) -> Tuple[Dict[object, float], Dict[object, List[Dict]]]:
    LOGGER.info("Computing Governance Risk")
    scores: Dict[object, float] = {}
    alert_detail: Dict[object, List[Dict]] = {}

    for _, alert in alerts_df.iterrows():
        original_key = clean_id(alert["identity_id"])
        resolved_id = employee_key_bridge.get(original_key, original_key)  # fall back to raw key if unbridged

        weight = SEVERITY_WEIGHT.get(alert.get("severity"), 10)
        alert_detail.setdefault(resolved_id, []).append(
            {
                "anomaly_type": alert.get("anomaly_type"),
                "severity": alert.get("severity"),
                "evidence": alert.get("evidence"),
                "weight": weight,
            }
        )

    for resolved_id, alerts in alert_detail.items():
        total = sum(a["weight"] for a in alerts)
        scores[resolved_id] = min(total, 100.0)

    return scores, alert_detail


# --------------------------------------------------------------------------- #
# Component 5 — Cross-Platform Risk
# --------------------------------------------------------------------------- #

def compute_cross_platform_risk(effective_privileges_df: pd.DataFrame) -> Dict[object, float]:
    LOGGER.info("Computing Cross-Platform Risk")
    scores: Dict[object, float] = {}
    for _, row in effective_privileges_df.iterrows():
        blast_radius = row.get("privilege_blast_radius", 0)
        admin_count = row.get("admin_permission_count", 0)
        if admin_count >= 2:
            score = min(50 + (admin_count - 2) * 15 + (blast_radius - 2) * 5, 100)
        elif blast_radius >= 2:
            score = min(blast_radius * 10, 60)
        else:
            score = 0.0
        scores[row["identity_id"]] = max(score, 0.0)
    return scores


# --------------------------------------------------------------------------- #
# Combination, banding, explanation
# --------------------------------------------------------------------------- #

def _risk_band(score: float) -> str:
    for threshold, band in RISK_BANDS:
        if score >= threshold:
            return band
    return "Low"


def _top_risk_reason(
    identity_id, component_scores: Dict[str, float], alert_detail: Dict[object, List[Dict]]
) -> str:
    top_component = max(component_scores, key=component_scores.get)
    top_value = component_scores[top_component]
    label = top_component.replace("_", " ").title()

    if top_component == "governance_risk" and identity_id in alert_detail:
        alerts = sorted(alert_detail[identity_id], key=lambda a: a["weight"], reverse=True)
        top_alert = alerts[0]
        return (
            f"{label} ({top_value:.1f}) — {len(alerts)} active alert(s), "
            f"most severe: {top_alert['severity']} {top_alert['anomaly_type']}"
        )
    return f"{label} ({top_value:.1f}) is the dominant contributor to this identity's overall score"


def combine_scores(
    all_ids: List[object],
    privilege: Dict[object, float],
    behavior: Dict[object, float],
    exposure: Dict[object, float],
    governance: Dict[object, float],
    cross_platform: Dict[object, float],
    alert_detail: Dict[object, List[Dict]],
    effective_privileges_df: pd.DataFrame,
) -> pd.DataFrame:
    LOGGER.info("Combining %d weighted components into final risk scores", len(WEIGHTS))
    context = effective_privileges_df.set_index("identity_id")

    records = []
    for identity_id in all_ids:
        component_scores = {
            "privilege_risk": privilege.get(identity_id, 0.0),
            "behavior_risk": behavior.get(identity_id, 0.0),
            "exposure_risk": exposure.get(identity_id, 0.0),
            "governance_risk": governance.get(identity_id, 0.0),
            "cross_platform_risk": cross_platform.get(identity_id, 0.0),
        }
        total = sum(component_scores[k] * WEIGHTS[k] for k in WEIGHTS)
        total = round(min(max(total, 0.0), 100.0), 1)
        band = _risk_band(total)

        is_known_identity = identity_id in context.index
        full_name = context.loc[identity_id, "full_name"] if is_known_identity else None
        entity_type = "Identity" if is_known_identity else "Non-Identity Entity (Service Account/Token/Unbridged)"

        records.append(
            {
                "identity_id": identity_id,
                "full_name": full_name,
                "entity_type": entity_type,
                "privilege_risk": round(component_scores["privilege_risk"], 1),
                "behavior_risk": round(component_scores["behavior_risk"], 1),
                "exposure_risk": round(component_scores["exposure_risk"], 1),
                "governance_risk": round(component_scores["governance_risk"], 1),
                "cross_platform_risk": round(component_scores["cross_platform_risk"], 1),
                "risk_score": total,
                "risk_band": band,
                "alert_count": len(alert_detail.get(identity_id, [])),
                "top_risk_reason": _top_risk_reason(identity_id, component_scores, alert_detail),
                "recommended_action": RECOMMENDED_ACTION_BY_BAND[band],
            }
        )

    df = pd.DataFrame.from_records(records).sort_values("risk_score", ascending=False).reset_index(drop=True)
    return df


# --------------------------------------------------------------------------- #
# Validation against ground truth
# --------------------------------------------------------------------------- #

def validate_against_labels(
    scores_df: pd.DataFrame, labels_df: pd.DataFrame, employee_key_bridge: Dict[str, object]
) -> None:
    flagged_resolved_ids = set()
    for raw_id in labels_df["identity_id"].unique():
        key = clean_id(raw_id)
        flagged_resolved_ids.add(employee_key_bridge.get(key, key))

    scores_df = scores_df.copy()
    scores_df["is_ground_truth_flagged"] = scores_df["identity_id"].isin(flagged_resolved_ids)

    flagged_avg = scores_df.loc[scores_df["is_ground_truth_flagged"], "risk_score"].mean()
    unflagged_avg = scores_df.loc[~scores_df["is_ground_truth_flagged"], "risk_score"].mean()
    flagged_in_high_or_critical = scores_df.loc[
        scores_df["is_ground_truth_flagged"], "risk_band"
    ].isin(["High", "Critical"]).mean()

    LOGGER.info(
        "Validation vs identity_risk_labels.csv -> avg score (flagged): %.1f | avg score (unflagged): %.1f | "
        "%% of ground-truth-flagged identities landing in High/Critical band: %.1f%%",
        flagged_avg, unflagged_avg, flagged_in_high_or_critical * 100,
    )


# --------------------------------------------------------------------------- #
# Main execution block
# --------------------------------------------------------------------------- #

def main() -> None:
    configure_logging()
    LOGGER.info("Starting identity risk scoring")

    effective_privileges_df = load_required("effective_privileges")
    auth_events_df = load_required("authentication_events")
    labels_df = load_required("identity_risk_labels")
    alerts_df = load_or_derive_alerts(labels_df)
    resolved_identities_df = load_optional("resolved_identities")

    employee_key_bridge = build_employee_key_bridge(effective_privileges_df)
    account_bridge = build_account_bridge(resolved_identities_df)

    privilege_scores = compute_privilege_risk(effective_privileges_df)
    behavior_scores = compute_behavior_risk(auth_events_df, account_bridge)
    exposure_scores = compute_exposure_risk(effective_privileges_df)
    governance_scores, alert_detail = compute_governance_risk(alerts_df, employee_key_bridge)
    cross_platform_scores = compute_cross_platform_risk(effective_privileges_df)

    all_ids = sorted(
        set(effective_privileges_df["identity_id"]) | set(governance_scores.keys()) | set(behavior_scores.keys()),
        key=lambda x: str(x),
    )

    scores_df = combine_scores(
        all_ids, privilege_scores, behavior_scores, exposure_scores,
        governance_scores, cross_platform_scores, alert_detail, effective_privileges_df,
    )
    save_csv(scores_df, "identity_risk_scores.csv")

    validate_against_labels(scores_df, labels_df, employee_key_bridge)

    LOGGER.info("Risk band distribution:\n%s", scores_df["risk_band"].value_counts())
    LOGGER.info(
        "Summary -> identities scored: %d | avg risk_score: %.1f | Critical: %d | High: %d",
        len(scores_df), scores_df["risk_score"].mean(),
        (scores_df["risk_band"] == "Critical").sum(), (scores_df["risk_band"] == "High").sum(),
    )
    LOGGER.info("Identity risk scoring complete")


if __name__ == "__main__":
    main()
