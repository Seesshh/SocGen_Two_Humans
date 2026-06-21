"""
src/data_generation/generate_access.py

Generates platform_roles.csv and role_assignments.csv for the Hybrid Identity
Governance synthetic dataset (Phase 5 MVP scope).

Privilege tier is derived deterministically from (department, seniority, platform) —
never assigned at random — matching Phase 3's "access derived, not randomized"
generation philosophy.
"""

from __future__ import annotations

import logging
import random
from datetime import date, timedelta
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

PRIVILEGE_TIERS: Tuple[str, ...] = ("Standard", "Power User", "Admin", "Super Admin")

TECH_DEPARTMENTS = {
    "Engineering", "Cloud Infrastructure & IT", "Data & Analytics",
    "Security", "Quality Assurance", "Product Management",
}
REVENUE_DEPARTMENTS = {"Sales", "Marketing", "Customer Success", "Customer Support"}

# Department eligibility curation per platform — drives WHICH department gets
# Power User / Admin native roles, never random.
POWER_USER_DEPTS: Dict[str, Set[str]] = {
    "Active Directory": TECH_DEPARTMENTS | {"Finance", "Legal", "Internal Audit", "Human Resources"},
    "Azure AD": TECH_DEPARTMENTS | REVENUE_DEPARTMENTS,
    "Okta": set(TECH_DEPARTMENTS),
    "AWS IAM": set(TECH_DEPARTMENTS),
    "Salesforce": set(REVENUE_DEPARTMENTS),
}
ADMIN_DEPTS: Dict[str, Set[str]] = {
    "Active Directory": {"Cloud Infrastructure & IT", "Security"},
    "Azure AD": {"Cloud Infrastructure & IT", "Security"},
    "Okta": {"Cloud Infrastructure & IT", "Security"},
    "AWS IAM": {"Cloud Infrastructure & IT", "Security", "Engineering"},
    "Salesforce": {"Sales", "Customer Success"},
}
SUPER_ADMIN_ELIGIBLE_DEPTS = {
    "Cloud Infrastructure & IT", "Security", "Executive Office",
    "Engineering", "Data & Analytics",
}
N_SUPER_ADMINS: int = 22

TIME_BOUND_GRANT_RATE: float = 0.10  # share of Power User/Admin grants that are time-bound

LOGGER = logging.getLogger("generate_access")


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


def load_departments() -> pd.DataFrame:
    df = pd.read_csv(DATA_DIR / "departments.csv")
    LOGGER.info("Loaded %d departments", len(df))
    return df


def load_account_tables() -> Dict[str, pd.DataFrame]:
    tables = {}
    for platform_name, filename in PLATFORM_ACCOUNT_FILES.items():
        df = pd.read_csv(DATA_DIR / filename, parse_dates=["created_date"])
        tables[platform_name] = df
        LOGGER.info("Loaded %d %s accounts", len(df), platform_name)
    return tables


def save_csv(df: pd.DataFrame, filename: str) -> Path:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    path = DATA_DIR / filename
    df.to_csv(path, index=False)
    LOGGER.info("Saved %s (%d rows, %d columns)", path, len(df), len(df.columns))
    return path


def _short_dept_name(department_name: str) -> str:
    words = department_name.replace("&", "").split()[:2]
    return "".join(w[:4].capitalize() for w in words)


# --------------------------------------------------------------------------- #
# Platform roles catalog
# --------------------------------------------------------------------------- #

def generate_platform_roles(departments_df: pd.DataFrame) -> pd.DataFrame:
    LOGGER.info("Generating platform role catalog")
    records: List[Dict] = []
    role_id = 1
    dept_names = departments_df["department_name"].tolist()

    for platform_name in PLATFORM_IDS:
        platform_id = PLATFORM_IDS[platform_name]

        # Super Admin — single platform-wide role
        records.append(
            {
                "platform_role_id": role_id,
                "platform_id": platform_id,
                "native_role_name": f"{platform_name} — Super Administrator",
                "privilege_tier": "Super Admin",
                "can_assume_other_roles": platform_name == "AWS IAM",
                "department_name": None,
            }
        )
        role_id += 1

        # Admin — curated department clusters
        for dept in sorted(ADMIN_DEPTS[platform_name]):
            records.append(
                {
                    "platform_role_id": role_id,
                    "platform_id": platform_id,
                    "native_role_name": f"{_short_dept_name(dept)} Administrator ({platform_name})",
                    "privilege_tier": "Admin",
                    "can_assume_other_roles": platform_name == "AWS IAM",
                    "department_name": dept,
                }
            )
            role_id += 1

        # Admin — generic fallback for Directors/VPs outside the curated admin departments
        # (models "admin over my own team's resources" rather than "owns this platform")
        records.append(
            {
                "platform_role_id": role_id,
                "platform_id": platform_id,
                "native_role_name": f"{platform_name} — Departmental Admin (Generic)",
                "privilege_tier": "Admin",
                "can_assume_other_roles": False,
                "department_name": None,
            }
        )
        role_id += 1

        # Power User — curated department clusters
        for dept in sorted(POWER_USER_DEPTS[platform_name]):
            records.append(
                {
                    "platform_role_id": role_id,
                    "platform_id": platform_id,
                    "native_role_name": f"{_short_dept_name(dept)} Power User ({platform_name})",
                    "privilege_tier": "Power User",
                    "can_assume_other_roles": False,
                    "department_name": dept,
                }
            )
            role_id += 1

        # Standard — one per department
        for dept in dept_names:
            records.append(
                {
                    "platform_role_id": role_id,
                    "platform_id": platform_id,
                    "native_role_name": f"{_short_dept_name(dept)} Standard Access ({platform_name})",
                    "privilege_tier": "Standard",
                    "can_assume_other_roles": False,
                    "department_name": dept,
                }
            )
            role_id += 1

    df = pd.DataFrame.from_records(records)
    LOGGER.info("Platform roles generated: %d rows", len(df))
    return df


# --------------------------------------------------------------------------- #
# Deterministic privilege tier derivation
# --------------------------------------------------------------------------- #

def determine_privilege_tier(
    seniority: str, department: str, platform_name: str, is_super_admin: bool
) -> str:
    if is_super_admin:
        return "Super Admin"
    if seniority == "Individual Contributor":
        return "Standard"
    if seniority == "Senior IC":
        return "Power User" if department in POWER_USER_DEPTS[platform_name] else "Standard"
    if seniority == "Manager":
        if department in ADMIN_DEPTS[platform_name]:
            return "Admin"
        return "Power User" if department in POWER_USER_DEPTS[platform_name] else "Standard"
    if seniority == "Director":
        if department in ADMIN_DEPTS[platform_name] or department in POWER_USER_DEPTS[platform_name]:
            return "Admin"
        return "Power User"
    # VP/Executive — broadly elevated, consistent with typical executive access scope
    return "Admin"


def select_super_admins(persons_df: pd.DataFrame, rng: np.random.Generator) -> Set[int]:
    pool = persons_df[
        (persons_df["seniority_level"].isin(["VP/Executive", "Director"]))
        & (persons_df["department_name"].isin(SUPER_ADMIN_ELIGIBLE_DEPTS))
        & (persons_df["status"] == "Active")
    ]
    n = min(N_SUPER_ADMINS, len(pool))
    chosen = rng.choice(pool["person_id"].to_numpy(), size=n, replace=False)
    LOGGER.info("Selected %d designated cross-platform super admins", n)
    return set(chosen.tolist())


# --------------------------------------------------------------------------- #
# Role assignments
# --------------------------------------------------------------------------- #

def generate_role_assignments(
    account_tables: Dict[str, pd.DataFrame],
    persons_df: pd.DataFrame,
    identities_df: pd.DataFrame,
    platform_roles_df: pd.DataFrame,
    rng: np.random.Generator,
) -> pd.DataFrame:
    LOGGER.info("Generating role assignments")

    identity_to_person: Dict[int, float] = dict(zip(identities_df["identity_id"], identities_df["person_id"]))
    persons_idx = persons_df.set_index("person_id")
    super_admins = select_super_admins(persons_df, rng)

    # role lookup: (platform_id, privilege_tier, department_or_None) -> platform_role_id
    role_lookup: Dict[Tuple[int, str, Optional[str]], int] = {}
    for _, row in platform_roles_df.iterrows():
        dept = row["department_name"] if pd.notna(row["department_name"]) else None
        role_lookup[(row["platform_id"], row["privilege_tier"], dept)] = row["platform_role_id"]

    records: List[Dict] = []
    assignment_id = 1

    for platform_name, accounts_df in account_tables.items():
        platform_id = PLATFORM_IDS[platform_name]

        for _, account in accounts_df.iterrows():
            person_id = identity_to_person.get(account["identity_id"])
            if person_id is None or pd.isna(person_id):
                continue  # orphan account — no role-derivation context
            person_id = int(person_id)
            person = persons_idx.loc[person_id]

            tier = determine_privilege_tier(
                person["seniority_level"], person["department_name"], platform_name,
                is_super_admin=person_id in super_admins,
            )

            dept_key = person["department_name"] if tier in ("Power User", "Admin", "Standard") else None
            platform_role_id = role_lookup.get((platform_id, tier, dept_key))
            if platform_role_id is None and tier == "Super Admin":
                platform_role_id = role_lookup.get((platform_id, "Super Admin", None))
            if platform_role_id is None and tier == "Admin":
                # department isn't in the curated admin list — use the generic departmental admin role
                platform_role_id = role_lookup.get((platform_id, "Admin", None))
            if platform_role_id is None:
                # last-resort fallback to the department's Standard role
                platform_role_id = role_lookup.get((platform_id, "Standard", person["department_name"]))
            if platform_role_id is None:
                continue

            created = account["created_date"]
            if pd.isna(created):
                continue
            granted_date = created.date() + timedelta(days=int(rng.integers(0, 14)))
            if granted_date > REFERENCE_DATE:
                granted_date = REFERENCE_DATE

            is_birthright = tier == "Standard"
            assignment_type = "Birthright" if is_birthright else "Requested"

            expiration_date = None
            if not is_birthright and rng.random() < TIME_BOUND_GRANT_RATE:
                expiration_date = granted_date + timedelta(days=int(rng.integers(30, 180)))

            approved_by = None if is_birthright else person.get("manager_person_id")
            if approved_by is not None and pd.notna(approved_by):
                approved_by = int(approved_by)
            else:
                approved_by = None
            approval_ticket = None if is_birthright else f"CHG{100000 + assignment_id}"

            records.append(
                {
                    "assignment_id": assignment_id,
                    "identity_id": account["identity_id"],
                    "platform_id": platform_id,
                    "platform_role_id": platform_role_id,
                    "business_role_id": person.get("business_role_id"),
                    "assignment_type": assignment_type,
                    "granted_date": granted_date,
                    "expiration_date": expiration_date,
                    "approved_by_person_id": approved_by,
                    "approval_ticket_ref": approval_ticket,
                    "status": "Active",
                }
            )
            assignment_id += 1

    df = pd.DataFrame.from_records(records)
    LOGGER.info("Role assignments generated: %d rows", len(df))

    tier_lookup = dict(zip(platform_roles_df["platform_role_id"], platform_roles_df["privilege_tier"]))
    df["_tier_for_logging"] = df["platform_role_id"].map(tier_lookup)
    LOGGER.info("Privilege tier distribution achieved:\n%s", df["_tier_for_logging"].value_counts(normalize=True).round(3))
    df = df.drop(columns=["_tier_for_logging"])
    return df


# --------------------------------------------------------------------------- #
# Main execution block
# --------------------------------------------------------------------------- #

def main() -> None:
    configure_logging()
    set_seeds()
    LOGGER.info("Starting role and access generation")

    rng = np.random.default_rng(RANDOM_SEED)
    departments_df = load_departments()
    persons_df = load_persons()
    identities_df = load_identities()
    account_tables = load_account_tables()

    platform_roles_df = generate_platform_roles(departments_df)
    role_assignments_df = generate_role_assignments(
        account_tables, persons_df, identities_df, platform_roles_df, rng
    )

    platform_roles_out = platform_roles_df.drop(columns=["department_name"])
    save_csv(platform_roles_out, "platform_roles.csv")
    save_csv(role_assignments_df, "role_assignments.csv")

    LOGGER.info(
        "Summary -> platform_roles: %d | role_assignments: %d",
        len(platform_roles_out), len(role_assignments_df),
    )
    LOGGER.info("Role and access generation complete")


if __name__ == "__main__":
    main()
