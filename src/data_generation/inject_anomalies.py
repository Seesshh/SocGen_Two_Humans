"""
src/data_generation/inject_anomalies.py

Injects the 7 MVP anomalies into the already-generated synthetic dataset and
produces identity_risk_labels.csv (ground truth) for the Hybrid Identity
Governance platform (Phase 5 MVP scope).

Two of the seven anomalies (Offboarding Gap, Orphaned Account) already occur
naturally as a designed side effect of upstream generation (generate_events.py's
"Failed" offboarding outcomes; generate_accounts.py's unlinked orphan identities)
and are identified/labeled here rather than re-injected. The remaining five are
actively mutated into the dataset by this module.

This module runs LAST in the generation pipeline, after every other
generate_*.py script.
"""

from __future__ import annotations

import logging
import random
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

import numpy as np
import pandas as pd

# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #

RANDOM_SEED: int = 42
DATA_DIR: Path = Path("data/synthetic_data")
REFERENCE_DATE: date = date(2026, 6, 20)

PLATFORM_NAMES: Dict[int, str] = {1: "Active Directory", 2: "Azure AD", 3: "AWS IAM", 4: "Okta", 5: "Salesforce"}
PLATFORM_ACCOUNT_FILES: Dict[int, str] = {
    1: "ad_accounts.csv", 2: "azure_accounts.csv", 3: "aws_accounts.csv",
    4: "okta_accounts.csv", 5: "salesforce_accounts.csv",
}

# Injection rates, taken directly from the Phase 3/5 blueprint
DORMANT_ADMIN_RATE: float = 0.03
CROSS_PLATFORM_ADMIN_TARGET_RATE: float = 0.04   # of all identities
PRIVILEGE_CREEP_RATE: float = 0.08               # of all identities
SERVICE_ACCOUNT_ABUSE_RATE: float = 0.02
TOKEN_ABUSE_RATE: float = 0.025

DORMANT_THRESHOLD_DAYS: int = 90
PRIVILEGE_CREEP_STALE_DAYS: int = 200

TIER_ORDER: List[str] = ["Standard", "Power User", "Admin", "Super Admin"]
TIER_RANK: Dict[str, int] = {t: i for i, t in enumerate(TIER_ORDER)}

LOGGER = logging.getLogger("inject_anomalies")


# --------------------------------------------------------------------------- #
# Setup helpers
# --------------------------------------------------------------------------- #

def configure_logging() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def set_seeds(seed: int = RANDOM_SEED) -> None:
    random.seed(seed)
    np.random.seed(seed)


def load_csv(filename: str, date_cols: Optional[List[str]] = None) -> pd.DataFrame:
    path = DATA_DIR / filename
    df = pd.read_csv(path, parse_dates=date_cols or [])
    LOGGER.info("Loaded %d rows from %s", len(df), filename)
    return df


def save_csv(df: pd.DataFrame, filename: str) -> Path:
    path = DATA_DIR / filename
    df.to_csv(path, index=False)
    LOGGER.info("Saved %s (%d rows, %d columns)", path, len(df), len(df.columns))
    return path


class LabelCollector:
    """Accumulates (identity_id, anomaly_type, severity, explanation) rows."""

    def __init__(self) -> None:
        self.rows: List[Dict] = []

    def add(self, identity_id: int, anomaly_type: str, severity: str, explanation: str) -> None:
        self.rows.append(
            {
                "identity_id": int(identity_id),
                "anomaly_type": anomaly_type,
                "severity": severity,
                "explanation": explanation,
            }
        )

    def to_frame(self) -> pd.DataFrame:
        return pd.DataFrame.from_records(
            self.rows, columns=["identity_id", "anomaly_type", "severity", "explanation"]
        )


# --------------------------------------------------------------------------- #
# Anomaly 1 — Offboarding Gap (identified, not injected — already produced by
# generate_events.py's "Failed" offboarding outcome population)
# --------------------------------------------------------------------------- #

def label_offboarding_gaps(offboarding_df: pd.DataFrame, labels: LabelCollector) -> None:
    failed = offboarding_df[offboarding_df["actual_revocation_at"].isna()]
    by_identity = failed.groupby("identity_id")
    for identity_id, group in by_identity:
        platforms = [PLATFORM_NAMES[p] for p in group["platform_id"].unique()]
        min_term_date = pd.to_datetime(group["termination_date"].min()).date()
        days_open = (REFERENCE_DATE - min_term_date).days
        severity = "Critical" if days_open > 30 or len(platforms) > 1 else "High"
        explanation = (
            f"Access on {', '.join(platforms)} was never revoked after termination "
            f"({days_open} days ago) — account(s) remain Active past the SLA deadline."
        )
        labels.add(identity_id, "OFFBOARDING_GAP", severity, explanation)
    LOGGER.info("Offboarding Gap: labeled %d identities", by_identity.ngroups if len(failed) else 0)


# --------------------------------------------------------------------------- #
# Anomaly 7 — Orphaned Account (identified, not injected — already produced by
# generate_accounts.py's unlinked orphan identity population)
# --------------------------------------------------------------------------- #

def label_orphaned_accounts(
    identities_df: pd.DataFrame, account_tables: Dict[int, pd.DataFrame], labels: LabelCollector
) -> None:
    orphans = identities_df[identities_df["identity_status"] == "Orphaned"]
    for _, row in orphans.iterrows():
        identity_id = row["identity_id"]
        active_platforms = []
        for platform_id, df in account_tables.items():
            match = df[(df["identity_id"] == identity_id) & (df["account_status"] == "Active")]
            if len(match) > 0:
                active_platforms.append(PLATFORM_NAMES[platform_id])
        severity = "High" if active_platforms else "Medium"
        explanation = (
            f"Identity has no linked HR record and "
            + (f"holds active access on {', '.join(active_platforms)}." if active_platforms
               else "all its accounts are currently disabled.")
        )
        labels.add(identity_id, "ORPHANED_CROSS_PLATFORM", severity, explanation)
    LOGGER.info("Orphaned Account: labeled %d identities", len(orphans))


# --------------------------------------------------------------------------- #
# Anomaly 2 — Dormant Admin (injected)
# --------------------------------------------------------------------------- #

def inject_dormant_admin(
    role_assignments_df: pd.DataFrame,
    platform_roles_df: pd.DataFrame,
    account_tables: Dict[int, pd.DataFrame],
    auth_events_df: pd.DataFrame,
    rng: np.random.Generator,
    labels: LabelCollector,
) -> pd.DataFrame:
    tier_lookup = dict(zip(platform_roles_df["platform_role_id"], platform_roles_df["privilege_tier"]))
    ra = role_assignments_df.copy()
    ra["_tier"] = ra["platform_role_id"].map(tier_lookup)
    admin_rows = ra[ra["_tier"].isin(["Admin", "Super Admin"]) & (ra["status"] == "Active")]

    unique_identities = admin_rows["identity_id"].unique()
    n_target = max(1, int(round(DORMANT_ADMIN_RATE * len(unique_identities))))
    targets = rng.choice(unique_identities, size=min(n_target, len(unique_identities)), replace=False)

    stale_date = REFERENCE_DATE - timedelta(days=DORMANT_THRESHOLD_DAYS + int(rng.integers(0, 60)))
    affected_rows = 0

    for identity_id in targets:
        identity_rows = admin_rows[admin_rows["identity_id"] == identity_id]
        platforms_hit = []
        for platform_id in identity_rows["platform_id"].unique():
            accounts_df = account_tables[platform_id]
            mask = (accounts_df["identity_id"] == identity_id) & (accounts_df["account_status"] == "Active")
            if mask.sum() == 0:
                continue
            accounts_df.loc[mask, "last_login_date"] = pd.Timestamp(stale_date)
            account_ids = accounts_df.loc[mask, "platform_account_id"].tolist()
            auth_events_df.drop(
                auth_events_df[
                    auth_events_df["platform_account_id"].isin(account_ids)
                    & (pd.to_datetime(auth_events_df["event_timestamp"]).dt.date > stale_date)
                ].index,
                inplace=True,
            )
            platforms_hit.append(PLATFORM_NAMES[platform_id])
            affected_rows += 1

        if platforms_hit:
            days_dormant = (REFERENCE_DATE - stale_date).days
            severity = "High" if days_dormant > 150 else "Medium"
            explanation = (
                f"Admin-tier access on {', '.join(platforms_hit)} has not been used in "
                f"{days_dormant} days, but the account remains Active."
            )
            labels.add(identity_id, "DORMANT_ADMIN", severity, explanation)

    LOGGER.info("Dormant Admin: injected into %d identities (%d account rows touched)", len(targets), affected_rows)
    return ra.drop(columns=["_tier"])


# --------------------------------------------------------------------------- #
# Anomaly 6 — Cross-Platform Admin (identified where natural, injected to reach target)
# --------------------------------------------------------------------------- #

def inject_cross_platform_admin(
    role_assignments_df: pd.DataFrame,
    platform_roles_df: pd.DataFrame,
    identities_df: pd.DataFrame,
    account_tables: Dict[int, pd.DataFrame],
    rng: np.random.Generator,
    labels: LabelCollector,
) -> pd.DataFrame:
    tier_lookup = dict(zip(platform_roles_df["platform_role_id"], platform_roles_df["privilege_tier"]))
    role_dept_lookup = dict(zip(platform_roles_df["platform_role_id"], platform_roles_df["platform_id"]))

    ra = role_assignments_df.copy()
    ra["_tier"] = ra["platform_role_id"].map(tier_lookup)
    admin_rows = ra[ra["_tier"].isin(["Admin", "Super Admin"]) & (ra["status"] == "Active")]

    platform_count_by_identity = admin_rows.groupby("identity_id")["platform_id"].nunique()
    natural_cross_platform = platform_count_by_identity[platform_count_by_identity >= 2]

    n_total_target = max(1, int(round(CROSS_PLATFORM_ADMIN_TARGET_RATE * len(identities_df))))
    n_to_inject = max(0, n_total_target - len(natural_cross_platform))

    # find a "generic Admin" role per platform to grant (department-agnostic fallback role)
    generic_admin_role: Dict[int, int] = {}
    for _, row in platform_roles_df[
        (platform_roles_df["privilege_tier"] == "Admin") & (platform_roles_df["department_name"].isna())
    ].iterrows() if "department_name" in platform_roles_df.columns else []:
        generic_admin_role[row["platform_id"]] = row["platform_role_id"]
    if not generic_admin_role:
        # platform_roles.csv as saved doesn't carry department_name; fall back to any Admin role per platform
        admin_catalog = platform_roles_df[platform_roles_df["privilege_tier"] == "Admin"]
        for platform_id, group in admin_catalog.groupby("platform_id"):
            generic_admin_role[platform_id] = group["platform_role_id"].iloc[0]

    single_platform_admins = set(platform_count_by_identity[platform_count_by_identity == 1].index)
    standard_identities = set(identities_df["identity_id"]) - set(admin_rows["identity_id"].unique())
    injection_pool = list(single_platform_admins) + list(standard_identities)
    rng.shuffle(injection_pool)

    new_rows: List[Dict] = []
    next_assignment_id = int(role_assignments_df["assignment_id"].max()) + 1
    injected_identities: Set[int] = set()

    for identity_id in injection_pool:
        if len(injected_identities) >= n_to_inject:
            break
        existing_platforms = set(ra[ra["identity_id"] == identity_id]["platform_id"].unique())
        candidate_platforms = [p for p in generic_admin_role if p not in existing_platforms]
        if not candidate_platforms:
            continue
        target_platform = candidate_platforms[int(rng.integers(0, len(candidate_platforms)))]

        # the identity must actually have an account on the target platform to receive a role
        accounts_df = account_tables[target_platform]
        match = accounts_df[(accounts_df["identity_id"] == identity_id) & (accounts_df["account_status"] == "Active")]
        if len(match) == 0:
            continue

        granted_date = REFERENCE_DATE - timedelta(days=int(rng.integers(10, 120)))
        new_rows.append(
            {
                "assignment_id": next_assignment_id,
                "identity_id": identity_id,
                "platform_id": target_platform,
                "platform_role_id": generic_admin_role[target_platform],
                "business_role_id": None,
                "assignment_type": "Requested",
                "granted_date": granted_date,
                "expiration_date": None,
                "approved_by_person_id": None,   # deliberately ungoverned — bypasses the normal approval chain
                "approval_ticket_ref": None,
                "status": "Active",
            }
        )
        next_assignment_id += 1
        injected_identities.add(identity_id)

    if new_rows:
        ra = pd.concat([ra, pd.DataFrame.from_records(new_rows)], ignore_index=True)

    all_flagged = set(natural_cross_platform.index) | injected_identities
    for identity_id in all_flagged:
        identity_rows = ra[(ra["identity_id"] == identity_id) & (ra["status"] == "Active")]
        admin_platforms = identity_rows[identity_rows["platform_role_id"].map(tier_lookup).isin(["Admin", "Super Admin"])]
        n_platforms = admin_platforms["platform_id"].nunique()
        platform_names = [PLATFORM_NAMES[p] for p in admin_platforms["platform_id"].unique()]
        severity = "Critical" if n_platforms >= 3 else "High"
        explanation = (
            f"Holds Admin-tier (or higher) access concurrently on {n_platforms} platforms "
            f"({', '.join(platform_names)}) — a single compromise would have multi-system impact."
        )
        labels.add(identity_id, "CROSS_PLATFORM_ADMIN", severity, explanation)

    LOGGER.info(
        "Cross-Platform Admin: %d natural + %d injected = %d total flagged",
        len(natural_cross_platform), len(injected_identities), len(all_flagged),
    )
    return ra.drop(columns=["_tier"])


# --------------------------------------------------------------------------- #
# Anomaly 4 — Privilege Creep (injected)
# --------------------------------------------------------------------------- #

def inject_privilege_creep(
    role_assignments_df: pd.DataFrame,
    platform_roles_df: pd.DataFrame,
    identities_df: pd.DataFrame,
    rng: np.random.Generator,
    labels: LabelCollector,
) -> pd.DataFrame:
    tier_lookup = dict(zip(platform_roles_df["platform_role_id"], platform_roles_df["privilege_tier"]))
    ra = role_assignments_df.copy()

    n_target = max(1, int(round(PRIVILEGE_CREEP_RATE * len(identities_df))))
    candidate_identities = ra["identity_id"].unique()
    targets = rng.choice(candidate_identities, size=min(n_target, len(candidate_identities)), replace=False)

    new_rows: List[Dict] = []
    next_assignment_id = int(ra["assignment_id"].max()) + 1
    injected_count = 0

    for identity_id in targets:
        identity_rows = ra[(ra["identity_id"] == identity_id) & (ra["status"] == "Active")]
        if len(identity_rows) == 0:
            continue
        base_row = identity_rows.sample(n=1, random_state=int(rng.integers(0, 1_000_000))).iloc[0]
        current_tier = tier_lookup.get(base_row["platform_role_id"], "Standard")
        current_rank = TIER_RANK.get(current_tier, 0)
        if current_rank >= len(TIER_ORDER) - 1:
            stale_role_id = base_row["platform_role_id"]  # already top tier; keep same role, just stale duplicate
            stale_tier = current_tier
        else:
            stale_tier = TIER_ORDER[current_rank + 1]
            same_platform_roles = platform_roles_df[
                (platform_roles_df["platform_id"] == base_row["platform_id"])
                & (platform_roles_df["privilege_tier"] == stale_tier)
            ]
            if len(same_platform_roles) == 0:
                continue
            stale_role_id = same_platform_roles["platform_role_id"].iloc[0]

        stale_granted = REFERENCE_DATE - timedelta(
            days=PRIVILEGE_CREEP_STALE_DAYS + int(rng.integers(0, 300))
        )
        new_rows.append(
            {
                "assignment_id": next_assignment_id,
                "identity_id": identity_id,
                "platform_id": base_row["platform_id"],
                "platform_role_id": stale_role_id,
                "business_role_id": None,
                "assignment_type": "Inherited",
                "granted_date": stale_granted,
                "expiration_date": None,
                "approved_by_person_id": None,
                "approval_ticket_ref": None,
                "status": "Active",  # the bug: this should have been revoked when the role changed
            }
        )
        next_assignment_id += 1
        injected_count += 1

        days_stale = (REFERENCE_DATE - stale_granted).days
        severity = "High" if TIER_RANK.get(stale_tier, 0) >= TIER_RANK["Admin"] else "Medium"
        explanation = (
            f"Retains a {stale_tier}-tier grant on {PLATFORM_NAMES[base_row['platform_id']]} "
            f"from {days_stale} days ago that was never revoked after a role/responsibility change."
        )
        labels.add(identity_id, "PRIVILEGE_CREEP", severity, explanation)

    if new_rows:
        ra = pd.concat([ra, pd.DataFrame.from_records(new_rows)], ignore_index=True)

    LOGGER.info("Privilege Creep: injected into %d identities", injected_count)
    return ra


# --------------------------------------------------------------------------- #
# Anomaly 5 — Service Account Abuse (injected)
# --------------------------------------------------------------------------- #

def inject_service_account_abuse(
    service_accounts_df: pd.DataFrame,
    auth_events_df: pd.DataFrame,
    persons_df: pd.DataFrame,
    rng: np.random.Generator,
    labels: LabelCollector,
) -> Tuple[pd.DataFrame, pd.DataFrame]:
    sa = service_accounts_df.copy()
    candidates = sa[sa["interactive_login_allowed"] == False]  # noqa: E712
    if len(candidates) == 0:
        candidates = sa

    n_target = max(1, int(round(SERVICE_ACCOUNT_ABUSE_RATE * len(sa))))
    targets = candidates.sample(
        n=min(n_target, len(candidates)), random_state=int(rng.integers(0, 1_000_000))
    )

    terminated_person_ids = set(persons_df[persons_df["status"] == "Terminated"]["person_id"])
    new_events: List[Dict] = []
    next_event_id = int(auth_events_df["auth_event_id"].max()) + 1
    identity_label_id_offset = 9_000_000  # service accounts are labeled using a namespaced pseudo-identity id

    for _, row in targets.iterrows():
        n_events = int(rng.integers(1, 4))
        for _ in range(n_events):
            event_date = REFERENCE_DATE - timedelta(days=int(rng.integers(0, 14)))
            event_dt = datetime.combine(event_date, datetime.min.time()) + timedelta(
                hours=int(rng.integers(0, 24)), minutes=int(rng.integers(0, 60))
            )
            new_events.append(
                {
                    "auth_event_id": next_event_id,
                    "platform_id": int(row["platform_id"]),
                    "platform_account_id": row["account_name"],
                    "event_timestamp": event_dt,
                    "source_country": None,
                    "source_ip": f"192.168.{int(rng.integers(0, 255))}.{int(rng.integers(0, 255))}",  # non-infra IP
                    "mfa_used": False,
                    "auth_result": "Success",
                    "session_type": "Interactive",  # the anomaly: interactive use of a non-interactive account
                }
            )
            next_event_id += 1

        owner_terminated = pd.notna(row["owner_person_id"]) and int(row["owner_person_id"]) in terminated_person_ids
        severity = "Critical" if row["privilege_level"] in ("Admin", "Super Admin") else "High"
        reason = (
            "its registered owner has left the company" if owner_terminated
            else "it is configured as automation-only (interactive login should never occur)"
        )
        explanation = f"Service account '{row['account_name']}' showed interactive login activity even though {reason}."
        labels.add(identity_label_id_offset + int(row["service_account_id"]), "SERVICE_ACCOUNT_ABUSE", severity, explanation)

    if new_events:
        auth_events_df = pd.concat([auth_events_df, pd.DataFrame.from_records(new_events)], ignore_index=True)

    LOGGER.info("Service Account Abuse: injected into %d service accounts", len(targets))
    return sa, auth_events_df


# --------------------------------------------------------------------------- #
# Anomaly 3 — Token Abuse (injected)
# --------------------------------------------------------------------------- #

def inject_token_abuse(
    api_tokens_df: pd.DataFrame, rng: np.random.Generator, labels: LabelCollector
) -> pd.DataFrame:
    tokens = api_tokens_df.copy()
    active_tokens = tokens[tokens["status"] == "Active"]
    n_target = max(1, int(round(TOKEN_ABUSE_RATE * len(active_tokens))))
    targets = active_tokens.sample(n=min(n_target, len(active_tokens)), random_state=int(rng.integers(0, 1_000_000)))
    identity_label_id_offset = 8_000_000  # tokens are labeled using a namespaced pseudo-identity id

    for idx, row in targets.iterrows():
        baseline_usage = row["usage_count_30d"]
        baseline_ip_diversity = row["source_ip_diversity_30d"]
        spike_multiplier = rng.uniform(5, 10)
        new_usage = int(baseline_usage * spike_multiplier)
        new_ip_diversity = int(baseline_ip_diversity + rng.integers(4, 9))
        recent_used = REFERENCE_DATE - timedelta(days=int(rng.integers(0, 2)))

        tokens.loc[idx, "usage_count_30d"] = new_usage
        tokens.loc[idx, "source_ip_diversity_30d"] = new_ip_diversity
        tokens.loc[idx, "last_used_date"] = pd.Timestamp(recent_used)

        owner_label = (
            f"service account #{int(row['owner_service_account_id'])}"
            if pd.notna(row["owner_service_account_id"])
            else f"person #{int(row['owner_person_id'])}"
        )
        explanation = (
            f"Token '{row['token_label']}' usage spiked to {new_usage} calls/30d from {new_ip_diversity} "
            f"distinct source IPs — far above its own baseline of {baseline_usage} calls from "
            f"{baseline_ip_diversity} IP(s). Owned by {owner_label}."
        )
        severity = "Critical" if row["scope"].startswith("read-write") else "High"
        labels.add(identity_label_id_offset + int(row["token_id"]), "TOKEN_ABUSE", severity, explanation)

    LOGGER.info("Token Abuse: injected into %d tokens", len(targets))
    return tokens


# --------------------------------------------------------------------------- #
# Main execution block
# --------------------------------------------------------------------------- #

def main() -> None:
    configure_logging()
    set_seeds()
    LOGGER.info("Starting anomaly injection (final pipeline stage)")

    rng = np.random.default_rng(RANDOM_SEED)
    labels = LabelCollector()

    persons_df = load_csv("persons.csv", date_cols=["hire_date", "termination_date"])
    identities_df = load_csv("identities.csv")
    role_assignments_df = load_csv("role_assignments.csv", date_cols=["granted_date", "expiration_date"])
    platform_roles_df = load_csv("platform_roles.csv")
    service_accounts_df = load_csv("service_accounts.csv", date_cols=["created_date", "last_credential_rotation_date"])
    api_tokens_df = load_csv("api_tokens.csv", date_cols=["issued_date", "expiration_date", "last_used_date", "last_rotation_date"])
    offboarding_df = load_csv("offboarding_events.csv", date_cols=["termination_date", "actual_revocation_at"])
    auth_events_df = load_csv("authentication_events.csv", date_cols=["event_timestamp"])

    account_tables: Dict[int, pd.DataFrame] = {}
    for platform_id, filename in PLATFORM_ACCOUNT_FILES.items():
        account_tables[platform_id] = load_csv(filename, date_cols=["created_date", "disabled_date", "last_login_date"])

    # --- Anomalies already naturally present — identify and label ---
    label_offboarding_gaps(offboarding_df, labels)
    label_orphaned_accounts(identities_df, account_tables, labels)

    # --- Anomalies actively injected ---
    role_assignments_df = inject_dormant_admin(
        role_assignments_df, platform_roles_df, account_tables, auth_events_df, rng, labels
    )
    role_assignments_df = inject_cross_platform_admin(
        role_assignments_df, platform_roles_df, identities_df, account_tables, rng, labels
    )
    role_assignments_df = inject_privilege_creep(
        role_assignments_df, platform_roles_df, identities_df, rng, labels
    )
    service_accounts_df, auth_events_df = inject_service_account_abuse(
        service_accounts_df, auth_events_df, persons_df, rng, labels
    )
    api_tokens_df = inject_token_abuse(api_tokens_df, rng, labels)

    # --- persist all mutated datasets ---
    save_csv(role_assignments_df, "role_assignments.csv")
    save_csv(service_accounts_df, "service_accounts.csv")
    save_csv(api_tokens_df, "api_tokens.csv")
    save_csv(auth_events_df, "authentication_events.csv")
    for platform_id, filename in PLATFORM_ACCOUNT_FILES.items():
        save_csv(account_tables[platform_id], filename)

    labels_df = labels.to_frame()
    save_csv(labels_df, "identity_risk_labels.csv")

    LOGGER.info("Anomaly type distribution in identity_risk_labels.csv:\n%s", labels_df["anomaly_type"].value_counts())
    LOGGER.info("Severity distribution:\n%s", labels_df["severity"].value_counts())
    LOGGER.info("Summary -> total label rows: %d | unique flagged entities: %d",
                len(labels_df), labels_df["identity_id"].nunique())
    LOGGER.info("Anomaly injection complete")


if __name__ == "__main__":
    main()
