"""
src/data_generation/generate_nonhuman.py

Generates service_accounts.csv and api_tokens.csv for the Hybrid Identity
Governance synthetic dataset (Phase 5 MVP scope).
"""

from __future__ import annotations

import logging
import random
from datetime import date, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import numpy as np
import pandas as pd
from faker import Faker

# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #

RANDOM_SEED: int = 42
DATA_DIR: Path = Path("data/synthetic_data")
REFERENCE_DATE: date = date(2026, 6, 20)

N_SERVICE_ACCOUNTS: int = 210
N_API_TOKENS: int = 600

PLATFORM_IDS: Dict[str, int] = {
    "Active Directory": 1,
    "Azure AD": 2,
    "AWS IAM": 3,
    "Okta": 4,
    "Salesforce": 5,
}
SERVICE_ACCOUNTS_PER_PLATFORM: Dict[str, int] = {
    "Active Directory": 50,
    "Azure AD": 55,
    "AWS IAM": 60,
    "Okta": 25,
    "Salesforce": 20,
}

CRITICALITY_LEVELS: Tuple[str, ...] = ("Mission-Critical", "High", "Medium", "Low")
CRITICALITY_WEIGHTS: Tuple[float, ...] = (0.08, 0.22, 0.40, 0.30)

PRIVILEGE_LEVELS: Tuple[str, ...] = ("Standard", "Elevated", "Admin", "Super Admin")
PRIVILEGE_WEIGHTS: Tuple[float, ...] = (0.45, 0.32, 0.19, 0.04)

OWNERSHIP_CURRENT_RATE: float = 0.88
OWNERSHIP_TERMINATED_OWNER_RATE: float = 0.09
OWNERSHIP_NEVER_ASSIGNED_RATE: float = 0.03
BACKUP_OWNER_RATE: float = 0.35

ROTATION_ON_POLICY_RATE: float = 0.65
ROTATION_OVERDUE_RATE: float = 0.25
ROTATION_NEVER_RATE: float = 0.10
ROTATION_POLICY_DAYS_CHOICES: Tuple[int, ...] = (30, 60, 90, 180)

INTERACTIVE_LOGIN_ALLOWED_RATE: float = 0.08
BREAKGLASS_RATE: float = 0.02

TOKEN_HUMAN_OWNED_RATE: float = 0.25
TOKEN_NO_EXPIRY_RATE: float = 0.15
TOKEN_EXPIRED_NOT_ROTATED_RATE: float = 0.25
# remaining ~60% have a defined, policy-conformant expiration

PURPOSE_VERBS = ["Synchronize", "Streamline", "Automate", "Aggregate", "Orchestrate", "Reconcile"]
PURPOSE_NOUNS = [
    "billing data export", "customer record sync", "deployment pipeline",
    "nightly reporting feed", "backup archival job", "data warehouse ingestion",
    "monitoring telemetry relay", "CI/CD release automation",
]

LOGGER = logging.getLogger("generate_nonhuman")


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
    Faker.seed(seed)


def build_faker() -> Faker:
    fkr = Faker("en_US")
    fkr.seed_instance(RANDOM_SEED + 900)
    return fkr


def load_persons() -> pd.DataFrame:
    df = pd.read_csv(DATA_DIR / "persons.csv", parse_dates=["hire_date", "termination_date"])
    LOGGER.info("Loaded %d persons", len(df))
    return df


def save_csv(df: pd.DataFrame, filename: str) -> Path:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    path = DATA_DIR / filename
    df.to_csv(path, index=False)
    LOGGER.info("Saved %s (%d rows, %d columns)", path, len(df), len(df.columns))
    return path


def weighted_choice(rng: np.random.Generator, options: Tuple, weights: Tuple[float, ...]):
    return options[rng.choice(len(options), p=np.array(weights) / sum(weights))]


# --------------------------------------------------------------------------- #
# Service accounts
# --------------------------------------------------------------------------- #

def _pick_owner(
    persons_df: pd.DataFrame, eligible_owner_pool: pd.DataFrame, rng: np.random.Generator
) -> Tuple[Optional[int], str]:
    draw = rng.random()
    if draw < OWNERSHIP_NEVER_ASSIGNED_RATE:
        return None, "never_assigned"
    if draw < OWNERSHIP_NEVER_ASSIGNED_RATE + OWNERSHIP_TERMINATED_OWNER_RATE:
        terminated_pool = persons_df[persons_df["status"] == "Terminated"]
        if len(terminated_pool) == 0:
            owner_id = eligible_owner_pool.sample(n=1, random_state=int(rng.integers(0, 1_000_000)))["person_id"].iloc[0]
            return int(owner_id), "current"
        owner_id = terminated_pool.sample(n=1, random_state=int(rng.integers(0, 1_000_000)))["person_id"].iloc[0]
        return int(owner_id), "terminated_owner"
    owner_id = eligible_owner_pool.sample(n=1, random_state=int(rng.integers(0, 1_000_000)))["person_id"].iloc[0]
    return int(owner_id), "current"


def generate_service_accounts(persons_df: pd.DataFrame, fkr: Faker, rng: np.random.Generator) -> pd.DataFrame:
    LOGGER.info("Generating %d service accounts", N_SERVICE_ACCOUNTS)

    eligible_owner_pool = persons_df[
        (persons_df["status"] == "Active")
        & (persons_df["seniority_level"].isin(["Senior IC", "Manager", "Director", "VP/Executive"]))
    ]

    records: List[Dict] = []
    service_account_id = 1

    for platform_name, count in SERVICE_ACCOUNTS_PER_PLATFORM.items():
        platform_id = PLATFORM_IDS[platform_name]
        for _ in range(count):
            purpose = f"{rng.choice(PURPOSE_VERBS)} {rng.choice(PURPOSE_NOUNS)}"
            verb_word = fkr.word()
            account_name = f"svc-{verb_word}-{service_account_id:04d}"

            owner_id, ownership_state = _pick_owner(persons_df, eligible_owner_pool, rng)
            backup_owner_id = None
            if ownership_state == "current" and rng.random() < BACKUP_OWNER_RATE:
                backup_candidate = eligible_owner_pool[eligible_owner_pool["person_id"] != owner_id]
                if len(backup_candidate) > 0:
                    backup_owner_id = int(
                        backup_candidate.sample(n=1, random_state=int(rng.integers(0, 1_000_000)))["person_id"].iloc[0]
                    )

            criticality = weighted_choice(rng, CRITICALITY_LEVELS, CRITICALITY_WEIGHTS)
            privilege_level = weighted_choice(rng, PRIVILEGE_LEVELS, PRIVILEGE_WEIGHTS)
            is_breakglass = bool(rng.random() < BREAKGLASS_RATE)
            interactive_allowed = bool(rng.random() < INTERACTIVE_LOGIN_ALLOWED_RATE) and not is_breakglass

            created_date = REFERENCE_DATE - timedelta(days=int(rng.integers(90, 1800)))
            rotation_policy_days = int(rng.choice(ROTATION_POLICY_DAYS_CHOICES))

            rotation_draw = rng.random()
            if rotation_draw < ROTATION_NEVER_RATE:
                last_rotation = None
                rotation_status = "Never Rotated"
            elif rotation_draw < ROTATION_NEVER_RATE + ROTATION_OVERDUE_RATE:
                days_since = rotation_policy_days * int(rng.integers(2, 6))
                last_rotation = REFERENCE_DATE - timedelta(days=days_since)
                rotation_status = "Overdue"
            else:
                days_since = int(rng.integers(0, rotation_policy_days))
                last_rotation = REFERENCE_DATE - timedelta(days=days_since)
                rotation_status = "Current"

            status = "Active" if ownership_state != "never_assigned" or rng.random() < 0.5 else "Orphaned"

            records.append(
                {
                    "service_account_id": service_account_id,
                    "account_name": account_name,
                    "platform_id": platform_id,
                    "owner_person_id": owner_id,
                    "backup_owner_person_id": backup_owner_id,
                    "purpose_description": purpose,
                    "criticality": criticality,
                    "privilege_level": privilege_level,
                    "interactive_login_allowed": interactive_allowed,
                    "last_credential_rotation_date": last_rotation,
                    "rotation_policy_days": rotation_policy_days,
                    "rotation_status": rotation_status,
                    "created_date": created_date,
                    "is_breakglass": is_breakglass,
                    "status": status,
                    "_ownership_state": ownership_state,
                }
            )
            service_account_id += 1

    df = pd.DataFrame.from_records(records)
    LOGGER.info("Service accounts generated: %d rows", len(df))
    LOGGER.info("Ownership distribution:\n%s", df["_ownership_state"].value_counts(normalize=True).round(3))
    LOGGER.info("Privilege level distribution:\n%s", df["privilege_level"].value_counts(normalize=True).round(3))
    LOGGER.info("Rotation status distribution:\n%s", df["rotation_status"].value_counts(normalize=True).round(3))
    df = df.drop(columns=["_ownership_state"])
    return df


# --------------------------------------------------------------------------- #
# API tokens
# --------------------------------------------------------------------------- #

def generate_api_tokens(
    service_accounts_df: pd.DataFrame, persons_df: pd.DataFrame, rng: np.random.Generator
) -> pd.DataFrame:
    LOGGER.info("Generating %d API tokens", N_API_TOKENS)

    n_human = int(round(N_API_TOKENS * TOKEN_HUMAN_OWNED_RATE))
    n_service = N_API_TOKENS - n_human

    human_owner_pool = persons_df[
        (persons_df["status"] == "Active")
        & (persons_df["department_name"].isin(
            {"Engineering", "Cloud Infrastructure & IT", "Data & Analytics", "Quality Assurance"}
        ))
    ]
    if len(human_owner_pool) == 0:
        human_owner_pool = persons_df[persons_df["status"] == "Active"]

    active_service_accounts = service_accounts_df[service_accounts_df["status"] == "Active"]

    records: List[Dict] = []
    token_id = 1

    def _build_token(owner_person_id: Optional[int], owner_service_account_id: Optional[int], platform_id: int,
                      owner_rotation_status: Optional[str], owner_created: Optional[date]) -> Dict:
        nonlocal token_id
        label_base = "dev-token" if owner_person_id is not None else "svc-token"
        label = f"{label_base}-{token_id:04d}"

        issued_floor = owner_created if owner_created is not None else (REFERENCE_DATE - timedelta(days=730))
        issued_window_days = max((REFERENCE_DATE - issued_floor).days, 30)
        issued_date = REFERENCE_DATE - timedelta(days=int(rng.integers(0, issued_window_days)))

        expiry_draw = rng.random()
        if expiry_draw < TOKEN_NO_EXPIRY_RATE:
            expiration_date = None
        elif expiry_draw < TOKEN_NO_EXPIRY_RATE + TOKEN_EXPIRED_NOT_ROTATED_RATE:
            expiration_date = issued_date + timedelta(days=int(rng.integers(30, 180)))
            if expiration_date > REFERENCE_DATE:
                expiration_date = REFERENCE_DATE - timedelta(days=int(rng.integers(1, 20)))
        else:
            expiration_date = REFERENCE_DATE + timedelta(days=int(rng.integers(15, 365)))

        # rotation pattern correlates with the owning entity's own hygiene where known
        if owner_rotation_status == "Never Rotated":
            rotation_status = "Never Rotated" if rng.random() < 0.70 else "Overdue"
        elif owner_rotation_status == "Overdue":
            rotation_status = "Overdue" if rng.random() < 0.55 else "Current"
        else:
            rotation_status = "Current" if rng.random() < 0.85 else "Overdue"
        last_rotation_date = issued_date if rotation_status != "Never Rotated" else None

        usage_count_30d = int(rng.integers(50, 2000)) if owner_service_account_id is not None else int(rng.integers(5, 300))
        source_ip_diversity_30d = int(rng.integers(1, 3)) if owner_service_account_id is not None else int(rng.integers(1, 5))

        last_used_date = REFERENCE_DATE - timedelta(days=int(rng.integers(0, 14)))

        scope = "read-write:assigned-resources" if owner_service_account_id is not None else "read-only:developer-sandbox"

        return {
            "token_id": token_id,
            "token_label": label,
            "platform_id": platform_id,
            "owner_person_id": owner_person_id,
            "owner_service_account_id": owner_service_account_id,
            "scope": scope,
            "issued_date": issued_date,
            "expiration_date": expiration_date,
            "last_used_date": last_used_date,
            "last_rotation_date": last_rotation_date,
            "rotation_status": rotation_status,
            "usage_count_30d": usage_count_30d,
            "source_ip_diversity_30d": source_ip_diversity_30d,
            "status": "Active",
        }

    for _ in range(n_human):
        owner = human_owner_pool.sample(n=1, random_state=int(rng.integers(0, 1_000_000))).iloc[0]
        platform_id = int(rng.choice(list(PLATFORM_IDS.values())))
        record = _build_token(int(owner["person_id"]), None, platform_id, None, owner["hire_date"].date())
        records.append(record)
        token_id += 1

    if len(active_service_accounts) > 0:
        service_choices = active_service_accounts.sample(
            n=n_service, replace=True, random_state=int(rng.integers(0, 1_000_000))
        )
        for _, sa in service_choices.iterrows():
            created = sa["created_date"]
            created_date = pd.to_datetime(created).date() if pd.notna(created) else None
            record = _build_token(
                None, int(sa["service_account_id"]), int(sa["platform_id"]),
                sa["rotation_status"], created_date,
            )
            records.append(record)
            token_id += 1

    df = pd.DataFrame.from_records(records)
    LOGGER.info("API tokens generated: %d rows (human: %d, service: %d)", len(df), n_human, n_service)
    LOGGER.info("No-expiration tokens: %d (%.1f%%)", df["expiration_date"].isna().sum(),
                100 * df["expiration_date"].isna().mean())
    return df


# --------------------------------------------------------------------------- #
# Main execution block
# --------------------------------------------------------------------------- #

def main() -> None:
    configure_logging()
    set_seeds()
    LOGGER.info("Starting non-human identity generation")

    rng = np.random.default_rng(RANDOM_SEED)
    fkr = build_faker()
    persons_df = load_persons()

    service_accounts_df = generate_service_accounts(persons_df, fkr, rng)
    save_csv(service_accounts_df, "service_accounts.csv")

    api_tokens_df = generate_api_tokens(service_accounts_df, persons_df, rng)
    save_csv(api_tokens_df, "api_tokens.csv")

    LOGGER.info(
        "Summary -> service_accounts: %d | api_tokens: %d",
        len(service_accounts_df), len(api_tokens_df),
    )
    LOGGER.info("Non-human identity generation complete")


if __name__ == "__main__":
    main()
