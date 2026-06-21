"""
src/data_generation/generate_events.py

Generates offboarding_events.csv and authentication_events.csv for the Hybrid
Identity Governance synthetic dataset (Phase 5 MVP scope).

Offboarding outcomes are reconciled back into the 5 platform account CSVs so
account_status/disabled_date stay consistent with the canonical offboarding
timeline this module owns.
"""

from __future__ import annotations

import logging
import random
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import numpy as np
import pandas as pd

# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #

RANDOM_SEED: int = 42
DATA_DIR: Path = Path("data/synthetic_data")
REFERENCE_DATE: date = date(2026, 6, 20)

SLA_HOURS: int = 24
HR_NOTIFICATION_DELAY_RATE: float = 0.13  # matches the delayed-HR-sync rate used elsewhere

PLATFORM_IDS: Dict[str, int] = {
    "Active Directory": 1,
    "Azure AD": 2,
    "AWS IAM": 3,
    "Okta": 4,
    "Salesforce": 5,
}
PLATFORM_ACCOUNT_FILES: Dict[str, str] = {
    "Active Directory": "ad_accounts.csv",
    "Azure AD": "azure_accounts.csv",
    "AWS IAM": "aws_accounts.csv",
    "Okta": "okta_accounts.csv",
    "Salesforce": "salesforce_accounts.csv",
}

# Per-platform offboarding outcome distribution (Normal / Delayed / Failed),
# reflecting that centrally-governed directory platforms revoke access far
# more reliably than less-centrally-governed SaaS/IaaS platforms.
OUTCOME_DISTRIBUTION: Dict[str, Dict[str, float]] = {
    "Active Directory": {"Normal": 0.97, "Delayed": 0.02, "Failed": 0.01},
    "Azure AD": {"Normal": 0.97, "Delayed": 0.02, "Failed": 0.01},
    "Okta": {"Normal": 0.92, "Delayed": 0.06, "Failed": 0.02},
    "AWS IAM": {"Normal": 0.82, "Delayed": 0.12, "Failed": 0.06},
    "Salesforce": {"Normal": 0.78, "Delayed": 0.14, "Failed": 0.08},
}

ADMIN_LIKE_SENIORITY = {"Manager", "Director", "VP/Executive"}
WEEKEND_RATE_BY_TYPE: Dict[str, float] = {
    "employee": 0.06,
    "contractor": 0.07,
    "admin": 0.13,
}
EVENT_COUNT_RANGE_BY_TYPE: Dict[str, Tuple[int, int]] = {
    "employee": (4, 10),
    "contractor": (3, 8),
    "admin": (7, 15),
}
LOOKBACK_DAYS: int = 60
SERVICE_ACCOUNT_LOOKBACK_DAYS: int = 30
SERVICE_ACCOUNT_EVENT_RANGE: Tuple[int, int] = (10, 20)

MFA_USE_RATE_STANDARD: float = 0.85
MFA_USE_RATE_ADMIN: float = 0.96
AUTH_FAILURE_RATE: float = 0.03

LOGGER = logging.getLogger("generate_events")


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


def load_persons() -> pd.DataFrame:
    df = pd.read_csv(DATA_DIR / "persons.csv", parse_dates=["hire_date", "termination_date"])
    LOGGER.info("Loaded %d persons", len(df))
    return df


def load_identities() -> pd.DataFrame:
    df = pd.read_csv(DATA_DIR / "identities.csv")
    LOGGER.info("Loaded %d identities", len(df))
    return df


def load_service_accounts() -> pd.DataFrame:
    df = pd.read_csv(DATA_DIR / "service_accounts.csv", parse_dates=["created_date"])
    LOGGER.info("Loaded %d service accounts", len(df))
    return df


def load_account_tables() -> Dict[str, pd.DataFrame]:
    tables = {}
    for platform_name, filename in PLATFORM_ACCOUNT_FILES.items():
        df = pd.read_csv(DATA_DIR / filename, parse_dates=["created_date", "disabled_date", "last_login_date"])
        tables[platform_name] = df
        LOGGER.info("Loaded %d %s accounts", len(df), platform_name)
    return tables


def save_csv(df: pd.DataFrame, filename: str) -> Path:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    path = DATA_DIR / filename
    df.to_csv(path, index=False)
    LOGGER.info("Saved %s (%d rows, %d columns)", path, len(df), len(df.columns))
    return path


def weighted_outcome(rng: np.random.Generator, dist: Dict[str, float]) -> str:
    options = list(dist.keys())
    weights = np.array(list(dist.values()))
    return options[rng.choice(len(options), p=weights / weights.sum())]


# --------------------------------------------------------------------------- #
# Offboarding events (and reconciliation back into account tables)
# --------------------------------------------------------------------------- #

def generate_offboarding_events(
    persons_df: pd.DataFrame,
    identities_df: pd.DataFrame,
    account_tables: Dict[str, pd.DataFrame],
    rng: np.random.Generator,
) -> Tuple[pd.DataFrame, Dict[str, pd.DataFrame]]:
    LOGGER.info("Generating offboarding events and reconciling account status")

    person_to_identity = dict(zip(identities_df["person_id"], identities_df["identity_id"]))
    terminated = persons_df[persons_df["status"] == "Terminated"]

    # index accounts per platform by identity_id for fast lookup/patching
    account_index: Dict[str, pd.DataFrame] = {
        name: df.set_index("identity_id", drop=False) for name, df in account_tables.items()
    }

    records: List[Dict] = []
    offboarding_id = 1
    outcome_counts = {"Normal": 0, "Delayed": 0, "Failed": 0}

    for _, person in terminated.iterrows():
        identity_id = person_to_identity.get(person["person_id"])
        if identity_id is None or pd.isna(identity_id):
            continue
        term_date = person["termination_date"].date()

        hr_lag_days = int(rng.integers(1, 6)) if rng.random() < HR_NOTIFICATION_DELAY_RATE else 0
        hr_notification_sent_at = datetime.combine(term_date, datetime.min.time()) + timedelta(
            days=hr_lag_days, hours=int(rng.integers(0, 8))
        )
        expected_deadline = hr_notification_sent_at + timedelta(hours=SLA_HOURS)

        for platform_name, idx_df in account_index.items():
            if identity_id not in idx_df.index:
                continue  # person never had an account on this platform

            outcome = weighted_outcome(rng, OUTCOME_DISTRIBUTION[platform_name])
            outcome_counts[outcome] += 1

            if outcome == "Normal":
                actual_revocation = hr_notification_sent_at + timedelta(hours=int(rng.integers(1, SLA_HOURS - 1)))
                sla_breached = False
                revoked_by = "svc-offboarding-bot"
            elif outcome == "Delayed":
                actual_revocation = hr_notification_sent_at + timedelta(days=int(rng.integers(1, 10)))
                sla_breached = True
                revoked_by = "manual-helpdesk"
            else:  # Failed
                actual_revocation = None
                sla_breached = True
                revoked_by = None

            records.append(
                {
                    "offboarding_id": offboarding_id,
                    "person_id": person["person_id"],
                    "identity_id": identity_id,
                    "termination_date": term_date,
                    "termination_reason": person["termination_reason"],
                    "hr_notification_sent_at": hr_notification_sent_at,
                    "expected_revocation_sla_hours": SLA_HOURS,
                    "platform_id": PLATFORM_IDS[platform_name],
                    "expected_revocation_deadline": expected_deadline,
                    "actual_revocation_at": actual_revocation,
                    "sla_breached": sla_breached,
                    "revoked_by": revoked_by,
                }
            )
            offboarding_id += 1

            # reconcile the account table so account_status reflects this outcome
            if outcome == "Normal":
                pass  # generate_accounts.py's clean baseline already matches Normal
            elif outcome == "Delayed":
                idx_df.loc[identity_id, "account_status"] = "Disabled"
                idx_df.loc[identity_id, "disabled_date"] = pd.Timestamp(actual_revocation.date())
            else:  # Failed — access was never revoked
                idx_df.loc[identity_id, "account_status"] = "Active"
                idx_df.loc[identity_id, "disabled_date"] = pd.NaT

    df = pd.DataFrame.from_records(records)
    LOGGER.info("Offboarding events generated: %d rows across %d terminations", len(df), len(terminated))
    LOGGER.info("Outcome distribution: %s", outcome_counts)

    reconciled_tables = {name: idx_df.reset_index(drop=True) for name, idx_df in account_index.items()}
    return df, reconciled_tables


# --------------------------------------------------------------------------- #
# Authentication events (sparse baseline)
# --------------------------------------------------------------------------- #

def _sample_event_datetime(rng: np.random.Generator, is_admin_like: bool, lookback_days: int) -> datetime:
    for _ in range(20):
        day_offset = int(rng.integers(0, lookback_days))
        candidate_date = REFERENCE_DATE - timedelta(days=day_offset)
        is_weekend = candidate_date.weekday() >= 5
        weekend_rate = WEEKEND_RATE_BY_TYPE["admin" if is_admin_like else "employee"]
        if is_weekend and rng.random() > weekend_rate:
            continue
        break

    if is_admin_like and rng.random() < 0.15:
        hour = int(np.clip(rng.normal(21, 1.5), 18, 23))
    else:
        hour = int(np.clip(rng.normal(9.5, 2.0), 6, 19))
    minute = int(rng.integers(0, 60))
    return datetime.combine(candidate_date, datetime.min.time()) + timedelta(hours=hour, minutes=minute)


def _behavior_type(seniority: str, employment_type: str) -> str:
    if employment_type == "Contractor":
        return "contractor"
    if seniority in ADMIN_LIKE_SENIORITY:
        return "admin"
    return "employee"


def generate_human_authentication_events(
    account_tables: Dict[str, pd.DataFrame],
    persons_df: pd.DataFrame,
    identities_df: pd.DataFrame,
    rng: np.random.Generator,
) -> pd.DataFrame:
    LOGGER.info("Generating sparse authentication events for human accounts")

    identity_to_person: Dict[int, float] = dict(zip(identities_df["identity_id"], identities_df["person_id"]))
    persons_idx = persons_df.set_index("person_id")

    records: List[Dict] = []
    event_id = 1

    for platform_name, accounts_df in account_tables.items():
        platform_id = PLATFORM_IDS[platform_name]
        active_accounts = accounts_df[accounts_df["account_status"] == "Active"]

        for _, account in active_accounts.iterrows():
            person_id = identity_to_person.get(account["identity_id"])
            if person_id is None or pd.isna(person_id):
                continue  # orphan account — no behavioral profile to model
            person_id = int(person_id)
            if person_id not in persons_idx.index:
                continue
            person = persons_idx.loc[person_id]

            behavior = _behavior_type(person["seniority_level"], person["employment_type"])
            is_admin_like = behavior == "admin"
            n_min, n_max = EVENT_COUNT_RANGE_BY_TYPE[behavior]
            n_events = int(rng.integers(n_min, n_max + 1))

            mfa_rate = MFA_USE_RATE_ADMIN if is_admin_like else MFA_USE_RATE_STANDARD
            home_country = person["location_country"]

            for _ in range(n_events):
                event_dt = _sample_event_datetime(rng, is_admin_like, LOOKBACK_DAYS)
                travel_event = rng.random() < 0.03
                source_country = home_country if not travel_event else "United States"
                auth_result = "Success" if rng.random() > AUTH_FAILURE_RATE else "Failed"
                session_type = "SSO Federated" if platform_name in ("Okta", "Salesforce") and rng.random() < 0.4 else "Interactive"

                records.append(
                    {
                        "auth_event_id": event_id,
                        "platform_id": platform_id,
                        "platform_account_id": account["platform_account_id"],
                        "event_timestamp": event_dt,
                        "source_country": source_country,
                        "source_ip": f"10.{platform_id}.{int(rng.integers(0, 255))}.{int(rng.integers(0, 255))}",
                        "mfa_used": bool(rng.random() < mfa_rate),
                        "auth_result": auth_result,
                        "session_type": session_type,
                    }
                )
                event_id += 1

    df = pd.DataFrame.from_records(records)
    LOGGER.info("Human authentication events generated: %d rows", len(df))
    return df, event_id


def generate_service_account_authentication_events(
    service_accounts_df: pd.DataFrame, rng: np.random.Generator, start_event_id: int
) -> pd.DataFrame:
    LOGGER.info("Generating sparse authentication events for service accounts")

    records: List[Dict] = []
    event_id = start_event_id

    active_accounts = service_accounts_df[service_accounts_df["status"] == "Active"]
    for _, sa in active_accounts.iterrows():
        n_events = int(rng.integers(*SERVICE_ACCOUNT_EVENT_RANGE))
        fixed_ip = f"172.16.{int(sa['platform_id'])}.{int(rng.integers(0, 255))}"

        # near-regular cadence over the lookback window
        interval_days = SERVICE_ACCOUNT_LOOKBACK_DAYS / max(n_events, 1)
        for i in range(n_events):
            day_offset = min(int(i * interval_days + rng.integers(0, 2)), SERVICE_ACCOUNT_LOOKBACK_DAYS - 1)
            event_date = REFERENCE_DATE - timedelta(days=day_offset)
            event_dt = datetime.combine(event_date, datetime.min.time()) + timedelta(
                hours=int(rng.integers(0, 24)), minutes=int(rng.integers(0, 60))
            )
            records.append(
                {
                    "auth_event_id": event_id,
                    "platform_id": int(sa["platform_id"]),
                    "platform_account_id": sa["account_name"],
                    "event_timestamp": event_dt,
                    "source_country": None,
                    "source_ip": fixed_ip,
                    "mfa_used": False,
                    "auth_result": "Success" if rng.random() > 0.01 else "Failed",
                    "session_type": "API",
                }
            )
            event_id += 1

    df = pd.DataFrame.from_records(records)
    LOGGER.info("Service account authentication events generated: %d rows", len(df))
    return df


# --------------------------------------------------------------------------- #
# Main execution block
# --------------------------------------------------------------------------- #

def main() -> None:
    configure_logging()
    set_seeds()
    LOGGER.info("Starting event generation")

    rng = np.random.default_rng(RANDOM_SEED)
    persons_df = load_persons()
    identities_df = load_identities()
    service_accounts_df = load_service_accounts()
    account_tables = load_account_tables()

    offboarding_df, reconciled_tables = generate_offboarding_events(
        persons_df, identities_df, account_tables, rng
    )
    save_csv(offboarding_df, "offboarding_events.csv")

    for platform_name, filename in PLATFORM_ACCOUNT_FILES.items():
        save_csv(reconciled_tables[platform_name], filename)  # overwrite with reconciled status

    human_auth_df, next_event_id = generate_human_authentication_events(
        reconciled_tables, persons_df, identities_df, rng
    )
    service_auth_df = generate_service_account_authentication_events(service_accounts_df, rng, next_event_id)

    auth_df = pd.concat([human_auth_df, service_auth_df], ignore_index=True)
    save_csv(auth_df, "authentication_events.csv")

    LOGGER.info(
        "Summary -> offboarding_events: %d | authentication_events: %d (human: %d, service: %d)",
        len(offboarding_df), len(auth_df), len(human_auth_df), len(service_auth_df),
    )
    LOGGER.info("Event generation complete")


if __name__ == "__main__":
    main()
