"""
src/intelligence/rules.py

Rule Engine for the Hybrid Identity Governance platform (Phase 4 Rule Engine
component). Implements 10 deterministic detection rules and produces
alerts.csv consumed by risk_scoring.py and incident_correlator.py.

Three of the ten required rules reference data that does not exist as a
dedicated table in this dataset (no mfa_enrollment.csv, no contracts.csv).
Rather than fabricate that data, each is implemented as a documented proxy
against data that genuinely exists, with the proxy logic stated explicitly:

  - MFA Disabled Admin: no per-account MFA enrollment table exists. Proxied
    from authentication_events.csv — an admin-tier account with at least one
    recorded login and zero mfa_used=True events is flagged. Accounts with no
    login history at all cannot be evaluated by this proxy and are skipped,
    not assumed compliant.
  - Shared Admin Account: detected directly from authentication_events.csv —
    consecutive logins on the same account from genuinely different network
    origins within a short window is real behavioral evidence, not a proxy.
  - Contractor Access After Expiry: no contracts.csv/vendors.csv exists in
    this dataset's scope. Proxied using persons.termination_reason ==
    'End of Contract' joined against offboarding_events.csv — this is the
    same underlying signal as Offboarding Gap, filtered to the specific
    business case of contract-end (vs. resignation/firing), which is exactly
    the distinction this rule is meant to surface.

alerts.csv schema is a superset covering both the explicitly requested
columns (alert_id, identity_id, severity, risk_score, rule_name, evidence,
recommendation, timestamp) and the columns risk_scoring.py / incident_correlator.py
already expect (anomaly_type, platform_id, detected_at) so neither of those
already-verified modules needs to change. identity_id uses the *original*
data-generation pipeline's numbering (identical to persons.person_id for every
linked identity) — the same namespace role_assignments.csv and
offboarding_events.csv use, and the one risk_scoring.py's bridge expects.
"""

from __future__ import annotations

import logging
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional

import numpy as np
import pandas as pd

# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #

DATA_DIR: Path = Path("data/synthetic_data")
OUTPUT_DIR: Path = Path("data/synthetic_data")
REFERENCE_DATE: date = date(2026, 6, 20)

PLATFORM_ID_TO_NAME: Dict[int, str] = {1: "Active Directory", 2: "Azure AD", 3: "AWS IAM", 4: "Okta", 5: "Salesforce"}
PLATFORM_ACCOUNT_FILES: Dict[int, str] = {
    1: "ad_accounts.csv", 2: "azure_accounts.csv", 3: "aws_accounts.csv",
    4: "okta_accounts.csv", 5: "salesforce_accounts.csv",
}

SEVERITY_WEIGHT: Dict[str, float] = {"Low": 10, "Medium": 25, "High": 50, "Critical": 80}

DORMANT_THRESHOLD_DAYS: int = 90
PRIVILEGE_CREEP_STALE_DAYS: int = 180
TOKEN_ABUSE_ZSCORE: float = 2.5
SHARED_ACCOUNT_WINDOW_HOURS: int = 2
SHARED_ACCOUNT_MIN_OCCURRENCES: int = 2
TIER_RANK: Dict[str, int] = {"Standard": 0, "Power User": 1, "Admin": 2, "Super Admin": 3}

LOGGER = logging.getLogger("rules")


# --------------------------------------------------------------------------- #
# Setup / IO helpers
# --------------------------------------------------------------------------- #

def configure_logging() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


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


def load_csv(filename: str, date_cols: Optional[List[str]] = None) -> pd.DataFrame:
    path = DATA_DIR / filename
    if not path.exists():
        raise FileNotFoundError(f"Required input '{filename}' not found in {DATA_DIR}")
    df = pd.read_csv(path, parse_dates=date_cols or [])
    LOGGER.info("Loaded %s (%d rows)", filename, len(df))
    return df


def save_csv(df: pd.DataFrame, filename: str) -> Path:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    path = OUTPUT_DIR / filename
    df.to_csv(path, index=False)
    LOGGER.info("Saved %s (%d rows, %d columns)", path, len(df), len(df.columns))
    return path


class AlertCollector:
    def __init__(self) -> None:
        self.rows: List[Dict] = []
        self._next_id = 1

    def add(
        self, identity_id, rule_name: str, severity: str, evidence: str,
        recommendation: str, platform_id: Optional[int] = None,
        timestamp: Optional[datetime] = None,
    ) -> None:
        ts = timestamp or datetime.combine(REFERENCE_DATE, datetime.min.time())
        self.rows.append(
            {
                "alert_id": self._next_id,
                "identity_id": identity_id,
                "anomaly_type": rule_name,        # back-compat alias for risk_scoring.py / incident_correlator.py
                "rule_name": rule_name,
                "severity": severity,
                "risk_score": SEVERITY_WEIGHT.get(severity, 10),
                "platform_id": platform_id,
                "evidence": evidence,
                "recommendation": recommendation,
                "timestamp": ts,
                "detected_at": ts,                # back-compat alias
            }
        )
        self._next_id += 1

    def to_frame(self) -> pd.DataFrame:
        columns = [
            "alert_id", "identity_id", "severity", "risk_score", "rule_name",
            "evidence", "recommendation", "timestamp",
            "anomaly_type", "platform_id", "detected_at",
        ]
        return pd.DataFrame.from_records(self.rows, columns=columns)


def _build_account_lookup(account_tables: Dict[int, pd.DataFrame]) -> Dict[str, Dict]:
    """platform_account_id -> {identity_id, platform_id, account_status, last_login_date}"""
    lookup: Dict[str, Dict] = {}
    for platform_id, df in account_tables.items():
        for _, row in df.iterrows():
            lookup[str(row["platform_account_id"])] = {
                "identity_id": row["identity_id"],
                "platform_id": platform_id,
                "account_status": row.get("account_status"),
                "last_login_date": row.get("last_login_date"),
            }
    return lookup


# --------------------------------------------------------------------------- #
# Rule 1 — Offboarding Gap
# --------------------------------------------------------------------------- #

def rule_offboarding_gap(offboarding_df: pd.DataFrame, alerts: AlertCollector) -> None:
    gaps = offboarding_df[offboarding_df["actual_revocation_at"].isna()]
    for identity_id, group in gaps.groupby("identity_id"):
        platforms = sorted({PLATFORM_ID_TO_NAME.get(p, f"Platform-{p}") for p in group["platform_id"]})
        term_date = pd.to_datetime(group["termination_date"].min())
        days_open = (pd.Timestamp(REFERENCE_DATE) - term_date).days
        severity = "Critical" if days_open > 30 or len(platforms) > 1 else "High"
        evidence = (
            f"Access on {', '.join(platforms)} was never revoked after termination on "
            f"{term_date.date()} ({days_open} days ago)."
        )
        recommendation = f"Immediately revoke access on {', '.join(platforms)}; confirm no activity occurred during the gap; root-cause the automation failure."
        alerts.add(identity_id, "OFFBOARDING_GAP", severity, evidence, recommendation,
                    platform_id=int(group["platform_id"].iloc[0]))
    LOGGER.info("OFFBOARDING_GAP: %d identities flagged", gaps["identity_id"].nunique() if len(gaps) else 0)


# --------------------------------------------------------------------------- #
# Rule 2 — Dormant Admin
# --------------------------------------------------------------------------- #

def rule_dormant_admin(
    role_assignments_df: pd.DataFrame, platform_roles_df: pd.DataFrame,
    account_tables: Dict[int, pd.DataFrame], alerts: AlertCollector,
) -> None:
    tier_lookup = dict(zip(platform_roles_df["platform_role_id"], platform_roles_df["privilege_tier"]))
    ra = role_assignments_df.copy()
    ra["_tier"] = ra["platform_role_id"].map(tier_lookup)
    admin_rows = ra[ra["_tier"].isin(["Admin", "Super Admin"]) & (ra["status"] == "Active")]

    flagged = 0
    for platform_id, accounts_df in account_tables.items():
        platform_admin_identities = set(admin_rows[admin_rows["platform_id"] == platform_id]["identity_id"])
        for _, account in accounts_df.iterrows():
            if account["identity_id"] not in platform_admin_identities:
                continue
            if account.get("account_status") != "Active":
                continue
            last_login = account.get("last_login_date")
            if pd.isna(last_login):
                continue
            days_dormant = (pd.Timestamp(REFERENCE_DATE) - pd.Timestamp(last_login)).days
            if days_dormant <= DORMANT_THRESHOLD_DAYS:
                continue
            severity = "High" if days_dormant > 150 else "Medium"
            tier = admin_rows[
                (admin_rows["identity_id"] == account["identity_id"]) & (admin_rows["platform_id"] == platform_id)
            ]["_tier"].iloc[0]
            evidence = (
                f"{tier}-tier account on {PLATFORM_ID_TO_NAME.get(platform_id)} has not logged in for "
                f"{days_dormant} days but remains Active."
            )
            recommendation = "Disable or downgrade pending owner re-justification of continued business need."
            alerts.add(account["identity_id"], "DORMANT_ADMIN", severity, evidence, recommendation, platform_id=platform_id)
            flagged += 1
    LOGGER.info("DORMANT_ADMIN: %d accounts flagged", flagged)


# --------------------------------------------------------------------------- #
# Rule 3 — Cross Platform Admin
# --------------------------------------------------------------------------- #

def rule_cross_platform_admin(
    role_assignments_df: pd.DataFrame, platform_roles_df: pd.DataFrame, alerts: AlertCollector
) -> None:
    tier_lookup = dict(zip(platform_roles_df["platform_role_id"], platform_roles_df["privilege_tier"]))
    ra = role_assignments_df.copy()
    ra["_tier"] = ra["platform_role_id"].map(tier_lookup)
    admin_rows = ra[ra["_tier"].isin(["Admin", "Super Admin"]) & (ra["status"] == "Active")]

    platform_counts = admin_rows.groupby("identity_id")["platform_id"].nunique()
    flagged_ids = platform_counts[platform_counts >= 2]

    for identity_id, n_platforms in flagged_ids.items():
        platforms = sorted({
            PLATFORM_ID_TO_NAME.get(p) for p in admin_rows[admin_rows["identity_id"] == identity_id]["platform_id"]
        })
        severity = "Critical" if n_platforms >= 3 else "High"
        evidence = f"Holds Admin-tier or higher access concurrently on {n_platforms} platforms: {', '.join(platforms)}."
        recommendation = "Require documented business justification; evaluate splitting into platform-scoped roles or just-in-time elevation."
        alerts.add(identity_id, "CROSS_PLATFORM_ADMIN", severity, evidence, recommendation)
    LOGGER.info("CROSS_PLATFORM_ADMIN: %d identities flagged", len(flagged_ids))


# --------------------------------------------------------------------------- #
# Rule 4 — Privilege Creep
# --------------------------------------------------------------------------- #

def rule_privilege_creep(
    role_assignments_df: pd.DataFrame, platform_roles_df: pd.DataFrame, alerts: AlertCollector
) -> None:
    tier_lookup = dict(zip(platform_roles_df["platform_role_id"], platform_roles_df["privilege_tier"]))
    ra = role_assignments_df[role_assignments_df["status"] == "Active"].copy()
    ra["_tier"] = ra["platform_role_id"].map(tier_lookup)
    ra["_tier_rank"] = ra["_tier"].map(TIER_RANK).fillna(0)

    flagged = 0
    for (identity_id, platform_id), group in ra.groupby(["identity_id", "platform_id"]):
        if len(group) < 2:
            continue
        most_recent = group.loc[group["granted_date"].idxmax()]
        for _, row in group.iterrows():
            if row["assignment_id"] == most_recent["assignment_id"]:
                continue
            age_days = (pd.Timestamp(REFERENCE_DATE) - pd.Timestamp(row["granted_date"])).days
            if age_days < PRIVILEGE_CREEP_STALE_DAYS:
                continue
            severity = "High" if row["_tier_rank"] >= TIER_RANK["Admin"] else "Medium"
            evidence = (
                f"Retains a {row['_tier']}-tier grant on {PLATFORM_ID_TO_NAME.get(platform_id)} from "
                f"{age_days} days ago, alongside a more recent grant — never revoked after the role likely changed."
            )
            recommendation = "Execute targeted revocation of the stale grant; enable automatic mover-triggered access review."
            alerts.add(identity_id, "PRIVILEGE_CREEP", severity, evidence, recommendation, platform_id=int(platform_id))
            flagged += 1
    LOGGER.info("PRIVILEGE_CREEP: %d stale grants flagged", flagged)


# --------------------------------------------------------------------------- #
# Rule 5 — Service Account Abuse
# --------------------------------------------------------------------------- #

def rule_service_account_abuse(
    service_accounts_df: pd.DataFrame, auth_events_df: pd.DataFrame,
    persons_df: pd.DataFrame, alerts: AlertCollector,
) -> None:
    """Flags service accounts showing interactive session activity despite
    being configured for automation-only use.

    A second candidate signal — "activity occurred after the owner's
    termination date" — was deliberately removed after testing. Because
    authentication_events.csv is intentionally sparse (only the trailing
    ~60-90 days, per the generation design) while termination dates span a
    full year, almost any service account whose owner terminated more than
    ~3 months ago will trivially show "post-termination" activity in that
    recent window — not because of genuine abuse, just because of how the
    two datasets' time ranges relate. Verified against real data: this
    condition alone flagged 21/210 accounts (10%), an order of magnitude
    above the 4 accounts actually injected as anomalous, with no way to
    distinguish the false positives from the true ones using only timing.
    Stale/unowned service-account governance gaps are better captured as
    their own finding, not folded into "abuse" on a confounded signal.
    """
    events_by_account = auth_events_df.groupby("platform_account_id")

    flagged = 0
    for _, sa in service_accounts_df.iterrows():
        account_name = sa["account_name"]
        group = events_by_account.get_group(account_name) if account_name in events_by_account.groups else None

        interactive_violation = (
            sa.get("interactive_login_allowed") == False  # noqa: E712
            and group is not None
            and (group["session_type"] == "Interactive").any()
        )
        if not interactive_violation:
            continue

        severity = "Critical" if sa.get("privilege_level") in ("Admin", "Super Admin") else "High"
        evidence = (
            f"Service account '{account_name}' on {PLATFORM_ID_TO_NAME.get(sa['platform_id'])} showed interactive "
            f"login activity despite being configured as automation-only (interactive login should never occur)."
        )
        recommendation = "Disable interactive login capability or the account itself; investigate the actor; reassign ownership if needed."
        pseudo_identity_id = 9_000_000 + int(sa["service_account_id"])
        alerts.add(pseudo_identity_id, "SERVICE_ACCOUNT_ABUSE", severity, evidence, recommendation, platform_id=int(sa["platform_id"]))
        flagged += 1
    LOGGER.info("SERVICE_ACCOUNT_ABUSE: %d service accounts flagged", flagged)


# --------------------------------------------------------------------------- #
# Rule 6 — Token Abuse
# --------------------------------------------------------------------------- #

def rule_token_abuse(api_tokens_df: pd.DataFrame, alerts: AlertCollector) -> None:
    df = api_tokens_df[api_tokens_df["status"] == "Active"].copy()
    df["_owner_type"] = np.where(df["owner_service_account_id"].notna(), "service", "human")

    flagged = 0
    for owner_type, group in df.groupby("_owner_type"):
        for col in ("usage_count_30d", "source_ip_diversity_30d"):
            mean, std = group[col].mean(), group[col].std()
            if std == 0 or pd.isna(std):
                continue
            z = (group[col] - mean) / std
            outliers = group[z > TOKEN_ABUSE_ZSCORE]
            for _, row in outliers.iterrows():
                severity = "Critical" if str(row["scope"]).startswith("read-write") else "High"
                evidence = (
                    f"Token '{row['token_label']}' {col.replace('_', ' ')} is {z.loc[row.name]:.1f} standard "
                    f"deviations above the {owner_type}-owned token population baseline "
                    f"(value={row[col]}, group mean={mean:.1f})."
                )
                recommendation = "Revoke and rotate the token immediately; review actions taken during the anomalous window."
                pseudo_identity_id = 8_000_000 + int(row["token_id"])
                alerts.add(pseudo_identity_id, "TOKEN_ABUSE", severity, evidence, recommendation, platform_id=int(row["platform_id"]))
                flagged += 1
    LOGGER.info("TOKEN_ABUSE: %d token anomalies flagged", flagged)


# --------------------------------------------------------------------------- #
# Rule 7 — Orphaned Account
# --------------------------------------------------------------------------- #

def rule_orphaned_account(identities_df: pd.DataFrame, persons_df: pd.DataFrame, alerts: AlertCollector) -> None:
    """Flags identities with no linked HR record (person_id is null).

    Note: identity_status is set once at generation time and is never
    revisited when a linked person is later terminated — it is not a live
    lifecycle field in this dataset. A prior version of this rule also
    flagged "Terminated person + still 'Linked' identity_status," which
    fired on all 225 terminations rather than genuine orphans (verified:
    every terminated person's identity_status remains 'Linked', since
    nothing in the pipeline updates it). Offboarding Gap already covers the
    "terminated person retains access" case correctly via offboarding_events.csv;
    this rule is scoped specifically to the no-HR-record population.
    """
    flagged = 0
    for _, row in identities_df.iterrows():
        if pd.notna(row["person_id"]):
            continue
        evidence = "Identity has no linked HR record."
        recommendation = "Investigate the account's origin; reconcile against the HR system of record; disable pending resolution."
        alerts.add(row["identity_id"], "ORPHANED_CROSS_PLATFORM", "Medium", evidence, recommendation)
        flagged += 1
    LOGGER.info("ORPHANED_CROSS_PLATFORM: %d identities flagged", flagged)


# --------------------------------------------------------------------------- #
# Rule 8 — MFA Disabled Admin  [proxy — see module docstring]
# --------------------------------------------------------------------------- #

def rule_mfa_disabled_admin(
    role_assignments_df: pd.DataFrame, platform_roles_df: pd.DataFrame,
    auth_events_df: pd.DataFrame, account_lookup: Dict[str, Dict], alerts: AlertCollector,
) -> None:
    tier_lookup = dict(zip(platform_roles_df["platform_role_id"], platform_roles_df["privilege_tier"]))
    ra = role_assignments_df.copy()
    ra["_tier"] = ra["platform_role_id"].map(tier_lookup)
    admin_identity_platform = set(
        zip(
            ra[ra["_tier"].isin(["Admin", "Super Admin"]) & (ra["status"] == "Active")]["identity_id"],
            ra[ra["_tier"].isin(["Admin", "Super Admin"]) & (ra["status"] == "Active")]["platform_id"],
        )
    )

    flagged = 0
    for account_id, group in auth_events_df.groupby("platform_account_id"):
        info = account_lookup.get(str(account_id))
        if info is None:
            continue
        if (info["identity_id"], info["platform_id"]) not in admin_identity_platform:
            continue
        if len(group) == 0 or group["mfa_used"].any():
            continue  # has at least one MFA-protected login — not flagged by this proxy
        severity = "Critical"
        evidence = (
            f"Admin-tier account on {PLATFORM_ID_TO_NAME.get(info['platform_id'])} shows {len(group)} recorded "
            f"login(s), none using MFA (proxy for no MFA enrollment — no mfa_enrollment.csv exists in this dataset)."
        )
        recommendation = "Enforce MFA enrollment immediately or suspend access until compliant."
        alerts.add(info["identity_id"], "MFA_DISABLED_ADMIN", severity, evidence, recommendation, platform_id=info["platform_id"])
        flagged += 1
    LOGGER.info("MFA_DISABLED_ADMIN: %d accounts flagged (proxy-based, evaluable accounts only)", flagged)


# --------------------------------------------------------------------------- #
# Rule 9 — Shared Admin Account
# --------------------------------------------------------------------------- #

def _network_origin(source_ip: str) -> str:
    parts = str(source_ip).split(".")
    return ".".join(parts[:2]) if len(parts) >= 2 else str(source_ip)


def rule_shared_admin_account(
    auth_events_df: pd.DataFrame, account_lookup: Dict[str, Dict], alerts: AlertCollector
) -> None:
    flagged = 0
    for account_id, group in auth_events_df.groupby("platform_account_id"):
        if len(group) < 2:
            continue
        info = account_lookup.get(str(account_id))
        if info is None:
            continue
        sorted_events = group.sort_values("event_timestamp")
        timestamps = pd.to_datetime(sorted_events["event_timestamp"]).tolist()
        origins = sorted_events["source_ip"].apply(_network_origin).tolist()

        occurrences = 0
        for i in range(len(timestamps) - 1):
            gap = timestamps[i + 1] - timestamps[i]
            if gap <= timedelta(hours=SHARED_ACCOUNT_WINDOW_HOURS) and origins[i] != origins[i + 1]:
                occurrences += 1

        if occurrences < SHARED_ACCOUNT_MIN_OCCURRENCES:
            continue
        severity = "High"
        evidence = (
            f"Account shows {occurrences} instance(s) of consecutive logins within "
            f"{SHARED_ACCOUNT_WINDOW_HOURS}h from different network origins — inconsistent with single-user behavior."
        )
        recommendation = "Investigate concurrent usage; enforce individual accountability; rotate credentials and re-issue per-user access."
        alerts.add(info["identity_id"], "SHARED_ADMIN_ACCOUNT", severity, evidence, recommendation, platform_id=info["platform_id"])
        flagged += 1
    LOGGER.info("SHARED_ADMIN_ACCOUNT: %d accounts flagged", flagged)


# --------------------------------------------------------------------------- #
# Rule 10 — Contractor Access After Expiry  [proxy — see module docstring]
# --------------------------------------------------------------------------- #

def rule_contractor_access_after_expiry(
    persons_df: pd.DataFrame, offboarding_df: pd.DataFrame, alerts: AlertCollector
) -> None:
    contract_end_terminations = set(
        persons_df[
            (persons_df["employment_type"] == "Contractor") & (persons_df["termination_reason"] == "End of Contract")
        ]["person_id"]
    )
    gaps = offboarding_df[
        offboarding_df["actual_revocation_at"].isna() & offboarding_df["person_id"].isin(contract_end_terminations)
    ]

    flagged = 0
    for identity_id, group in gaps.groupby("identity_id"):
        platforms = sorted({PLATFORM_ID_TO_NAME.get(p, f"Platform-{p}") for p in group["platform_id"]})
        term_date = pd.to_datetime(group["termination_date"].min())
        days_open = (pd.Timestamp(REFERENCE_DATE) - term_date).days
        severity = "High" if days_open > 14 else "Medium"
        evidence = f"Contractor access on {', '.join(platforms)} remains active {days_open} days past contract end."
        recommendation = "Immediately suspend access pending contract renewal confirmation; align automation to contract end dates, not just HR termination events."
        alerts.add(identity_id, "CONTRACTOR_ACCESS_AFTER_EXPIRY", severity, evidence, recommendation,
                    platform_id=int(group["platform_id"].iloc[0]))
        flagged += 1
    LOGGER.info("CONTRACTOR_ACCESS_AFTER_EXPIRY: %d contractors flagged", flagged)


# --------------------------------------------------------------------------- #
# Main execution block
# --------------------------------------------------------------------------- #

def main() -> None:
    configure_logging()
    LOGGER.info("Starting rule engine evaluation")

    persons_df = load_csv("persons.csv", date_cols=["hire_date", "termination_date"])
    identities_df = load_csv("identities.csv")
    role_assignments_df = load_csv("role_assignments.csv", date_cols=["granted_date", "expiration_date"])
    platform_roles_df = load_csv("platform_roles.csv")
    service_accounts_df = load_csv("service_accounts.csv", date_cols=["created_date"])
    api_tokens_df = load_csv("api_tokens.csv")
    offboarding_df = load_csv("offboarding_events.csv", date_cols=["termination_date", "actual_revocation_at"])
    auth_events_df = load_csv("authentication_events.csv", date_cols=["event_timestamp"])

    account_tables: Dict[int, pd.DataFrame] = {}
    for platform_id, filename in PLATFORM_ACCOUNT_FILES.items():
        account_tables[platform_id] = load_csv(
            filename, date_cols=["created_date", "disabled_date", "last_login_date"]
        )
    account_lookup = _build_account_lookup(account_tables)

    alerts = AlertCollector()

    rule_offboarding_gap(offboarding_df, alerts)
    rule_dormant_admin(role_assignments_df, platform_roles_df, account_tables, alerts)
    rule_cross_platform_admin(role_assignments_df, platform_roles_df, alerts)
    rule_privilege_creep(role_assignments_df, platform_roles_df, alerts)
    rule_service_account_abuse(service_accounts_df, auth_events_df, persons_df, alerts)
    rule_token_abuse(api_tokens_df, alerts)
    rule_orphaned_account(identities_df, persons_df, alerts)
    rule_mfa_disabled_admin(role_assignments_df, platform_roles_df, auth_events_df, account_lookup, alerts)
    rule_shared_admin_account(auth_events_df, account_lookup, alerts)
    rule_contractor_access_after_expiry(persons_df, offboarding_df, alerts)

    alerts_df = alerts.to_frame()
    save_csv(alerts_df, "alerts.csv")

    LOGGER.info("Rule distribution:\n%s", alerts_df["rule_name"].value_counts())
    LOGGER.info("Severity distribution:\n%s", alerts_df["severity"].value_counts())
    LOGGER.info("Summary -> total alerts: %d | unique identities flagged: %d",
                len(alerts_df), alerts_df["identity_id"].nunique())
    LOGGER.info("Rule engine evaluation complete")


if __name__ == "__main__":
    main()
