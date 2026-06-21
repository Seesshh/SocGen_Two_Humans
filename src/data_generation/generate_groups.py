"""
src/data_generation/generate_groups.py

Generates groups.csv, nested_group_relationships.csv, and group_memberships.csv
for the Hybrid Identity Governance synthetic dataset (Phase 5 MVP scope).
"""

from __future__ import annotations

import logging
import random
from datetime import date, timedelta
from pathlib import Path
from typing import Dict, List, Tuple

import networkx as nx
import numpy as np
import pandas as pd

# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #

RANDOM_SEED: int = 42
DATA_DIR: Path = Path("data/synthetic_data")
REFERENCE_DATE: date = date(2026, 6, 20)
MAX_NESTING_DEPTH: int = 5  # configured ceiling; actual generated depth is 2 (Tier C -> Tier B -> Tier A)

PLATFORM_IDS: Dict[str, int] = {
    "Active Directory": 1,
    "Azure AD": 2,
    "AWS IAM": 3,
    "Okta": 4,
    "Salesforce": 5,
}
PLATFORM_SHORT: Dict[str, str] = {
    "Active Directory": "AD",
    "Azure AD": "AZ",
    "AWS IAM": "AWS",
    "Okta": "OKTA",
    "Salesforce": "SF",
}
PLATFORM_ACCOUNT_FILES: Dict[str, str] = {
    "Active Directory": "ad_accounts.csv",
    "Azure AD": "azure_accounts.csv",
    "AWS IAM": "aws_accounts.csv",
    "Okta": "okta_accounts.csv",
    "Salesforce": "salesforce_accounts.csv",
}

# Total groups per platform (sums to exactly 300)
GROUPS_PER_PLATFORM: Dict[str, int] = {
    "Active Directory": 90,
    "Azure AD": 90,
    "Okta": 60,
    "AWS IAM": 30,
    "Salesforce": 30,
}
N_TIER_A_PER_PLATFORM: int = 1
N_TIER_B_PER_PLATFORM: int = 20  # one per department

TECH_DEPARTMENTS = {
    "Engineering", "Cloud Infrastructure & IT", "Data & Analytics",
    "Security", "Quality Assurance", "Product Management",
}
REVENUE_DEPARTMENTS = {"Sales", "Marketing", "Customer Success", "Customer Support"}

GROUP_SUFFIXES: Tuple[str, ...] = ("Approvers", "Admins", "PowerUsers", "ProjectAccess")
PRIVILEGED_SUFFIXES = {"Approvers", "Admins"}

POWER_USER_TIER_C_RATE: float = 0.15  # share of IC/Senior IC who land in a PowerUsers sub-group

LOGGER = logging.getLogger("generate_groups")


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
    df = pd.read_csv(DATA_DIR / "persons.csv")
    LOGGER.info("Loaded %d persons", len(df))
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
# Groups (3-tier structure: Tier A baseline, Tier B department, Tier C privileged)
# --------------------------------------------------------------------------- #

def generate_groups(departments_df: pd.DataFrame) -> pd.DataFrame:
    LOGGER.info("Generating groups across %d platforms (target: 300 total)", len(PLATFORM_IDS))
    records: List[Dict] = []
    group_id = 1
    dept_names = departments_df["department_name"].tolist()

    for platform_name, total in GROUPS_PER_PLATFORM.items():
        short = PLATFORM_SHORT[platform_name]
        n_tier_c = total - N_TIER_A_PER_PLATFORM - N_TIER_B_PER_PLATFORM

        # Tier A — single platform-wide baseline group
        records.append(
            {
                "group_id": group_id,
                "platform_id": PLATFORM_IDS[platform_name],
                "group_name": f"GRP-{short}-AllUsers-Baseline",
                "group_type": "Security",
                "is_privileged_group": False,
                "tier": "A",
                "department_name": None,
            }
        )
        tier_a_id = group_id
        group_id += 1

        # Tier B — one department-standard group per department
        tier_b_ids: Dict[str, int] = {}
        for dept in dept_names:
            records.append(
                {
                    "group_id": group_id,
                    "platform_id": PLATFORM_IDS[platform_name],
                    "group_name": f"GRP-{short}-{_short_dept_name(dept)}-Standard",
                    "group_type": "Security",
                    "is_privileged_group": False,
                    "tier": "B",
                    "department_name": dept,
                }
            )
            tier_b_ids[dept] = group_id
            group_id += 1

        # Tier C — privileged/project sub-groups, allocated by platform relevance
        if platform_name == "AWS IAM":
            eligible_depts = [d for d in dept_names if d in TECH_DEPARTMENTS] or dept_names
        elif platform_name == "Salesforce":
            eligible_depts = [d for d in dept_names if d in REVENUE_DEPARTMENTS] or dept_names
        else:
            eligible_depts = dept_names

        per_dept_counts = _distribute_tier_c_slots(eligible_depts, n_tier_c)
        for dept, count in per_dept_counts.items():
            for suffix in GROUP_SUFFIXES[:count]:
                records.append(
                    {
                        "group_id": group_id,
                        "platform_id": PLATFORM_IDS[platform_name],
                        "group_name": f"GRP-{short}-{_short_dept_name(dept)}-{suffix}",
                        "group_type": "Security",
                        "is_privileged_group": suffix in PRIVILEGED_SUFFIXES,
                        "tier": "C",
                        "department_name": dept,
                    }
                )
                group_id += 1

    df = pd.DataFrame.from_records(records)
    LOGGER.info("Groups generated: %d rows (target 300)", len(df))
    return df


def _distribute_tier_c_slots(eligible_depts: List[str], n_slots: int) -> Dict[str, int]:
    """Distribute n_slots Tier-C groups across eligible departments, cycling through
    the suffix list (max 4 per department) until the budget is exhausted."""
    counts: Dict[str, int] = {d: 0 for d in eligible_depts}
    remaining = n_slots
    idx = 0
    while remaining > 0 and eligible_depts:
        dept = eligible_depts[idx % len(eligible_depts)]
        if counts[dept] < len(GROUP_SUFFIXES):
            counts[dept] += 1
            remaining -= 1
        idx += 1
        if idx > 10_000:  # safety valve
            break
    return {d: c for d, c in counts.items() if c > 0}


# --------------------------------------------------------------------------- #
# Nested group relationships
# --------------------------------------------------------------------------- #

def build_nested_relationships(groups_df: pd.DataFrame) -> pd.DataFrame:
    LOGGER.info("Building nested group hierarchy")
    records: List[Dict] = []
    nesting_id = 1

    for platform_id in groups_df["platform_id"].unique():
        platform_groups = groups_df[groups_df["platform_id"] == platform_id]
        tier_a_row = platform_groups[platform_groups["tier"] == "A"].iloc[0]
        tier_b_by_dept = {
            row["department_name"]: row["group_id"]
            for _, row in platform_groups[platform_groups["tier"] == "B"].iterrows()
        }
        tier_c_rows = platform_groups[platform_groups["tier"] == "C"]

        # Tier B nests under Tier A (depth 1)
        for dept, tier_b_id in tier_b_by_dept.items():
            records.append(
                {
                    "nesting_id": nesting_id,
                    "parent_group_id": tier_a_row["group_id"],
                    "child_group_id": tier_b_id,
                    "nesting_depth": 1,
                }
            )
            nesting_id += 1

        # Tier C nests under the matching department's Tier B (depth 2)
        for _, row in tier_c_rows.iterrows():
            parent_id = tier_b_by_dept.get(row["department_name"])
            if parent_id is None:
                continue
            records.append(
                {
                    "nesting_id": nesting_id,
                    "parent_group_id": parent_id,
                    "child_group_id": row["group_id"],
                    "nesting_depth": 2,
                }
            )
            nesting_id += 1

    df = pd.DataFrame.from_records(records)
    LOGGER.info("Nested group relationships generated: %d rows", len(df))
    _validate_hierarchy_with_networkx(df)
    return df


def _validate_hierarchy_with_networkx(nesting_df: pd.DataFrame) -> None:
    """Build the nesting graph in networkx and confirm it is acyclic and within
    the configured maximum nesting depth — a sanity check on the generated structure."""
    graph = nx.DiGraph()
    for _, row in nesting_df.iterrows():
        # edge direction: parent -> child, mirroring "parent contains child"
        graph.add_edge(row["parent_group_id"], row["child_group_id"])

    is_dag = nx.is_directed_acyclic_graph(graph)
    if not is_dag:
        raise ValueError("Generated group nesting contains a cycle — invalid hierarchy")

    longest_path = nx.dag_longest_path_length(graph) if graph.number_of_edges() > 0 else 0
    LOGGER.info(
        "Hierarchy validation (networkx) -> DAG: %s | nodes: %d | edges: %d | max depth: %d (cap: %d)",
        is_dag, graph.number_of_nodes(), graph.number_of_edges(), longest_path, MAX_NESTING_DEPTH,
    )
    if longest_path > MAX_NESTING_DEPTH:
        raise ValueError(f"Nesting depth {longest_path} exceeds configured cap {MAX_NESTING_DEPTH}")


# --------------------------------------------------------------------------- #
# Group memberships (direct membership only — Tier A is reached via inheritance)
# --------------------------------------------------------------------------- #

def load_identities() -> pd.DataFrame:
    df = pd.read_csv(DATA_DIR / "identities.csv")
    LOGGER.info("Loaded %d identities", len(df))
    return df


def generate_group_memberships(
    account_tables: Dict[str, pd.DataFrame],
    persons_df: pd.DataFrame,
    identities_df: pd.DataFrame,
    groups_df: pd.DataFrame,
    rng: np.random.Generator,
) -> pd.DataFrame:
    LOGGER.info("Generating direct group memberships")

    identity_to_person: Dict[int, float] = dict(zip(identities_df["identity_id"], identities_df["person_id"]))
    dept_lookup = dict(zip(persons_df["person_id"], persons_df["department_name"]))
    seniority_lookup = dict(zip(persons_df["person_id"], persons_df["seniority_level"]))

    records: List[Dict] = []
    membership_id = 1

    for platform_name, accounts_df in account_tables.items():
        platform_id = PLATFORM_IDS[platform_name]
        platform_groups = groups_df[groups_df["platform_id"] == platform_id]
        tier_b_by_dept = {
            row["department_name"]: row["group_id"]
            for _, row in platform_groups[platform_groups["tier"] == "B"].iterrows()
        }
        tier_c_by_dept: Dict[str, Dict[str, int]] = {}
        for _, row in platform_groups[platform_groups["tier"] == "C"].iterrows():
            tier_c_by_dept.setdefault(row["department_name"], {})
            suffix = row["group_name"].split("-")[-1]
            tier_c_by_dept[row["department_name"]][suffix] = row["group_id"]

        for _, account in accounts_df.iterrows():
            # Resolve identity_id -> person_id explicitly via identities.csv; orphan
            # accounts (person_id is NaN) are deliberately excluded from
            # department-driven group placement, since they have no HR context.
            person_id = identity_to_person.get(account["identity_id"])
            if person_id is None or pd.isna(person_id):
                continue
            dept = dept_lookup.get(person_id)
            seniority = seniority_lookup.get(person_id)
            if dept is None:
                continue

            target_group_id = None
            dept_tier_c = tier_c_by_dept.get(dept, {})

            if seniority in ("Manager", "Director", "VP/Executive") and dept_tier_c:
                for suffix in ("Admins", "Approvers"):
                    if suffix in dept_tier_c:
                        target_group_id = dept_tier_c[suffix]
                        break

            if target_group_id is None and "PowerUsers" in dept_tier_c and rng.random() < POWER_USER_TIER_C_RATE:
                target_group_id = dept_tier_c["PowerUsers"]

            if target_group_id is None:
                target_group_id = tier_b_by_dept.get(dept)

            if target_group_id is None:
                continue

            created = account["created_date"]
            if pd.isna(created):
                continue
            added_date = created.date() + timedelta(days=int(rng.integers(0, 30)))
            if added_date > REFERENCE_DATE:
                added_date = REFERENCE_DATE

            records.append(
                {
                    "membership_id": membership_id,
                    "group_id": target_group_id,
                    "platform_id": platform_id,
                    "platform_account_id": account["platform_account_id"],
                    "added_date": added_date,
                    "added_by": "svc-provisioning-bot" if rng.random() < 0.85 else "manual-admin-team",
                }
            )
            membership_id += 1

    df = pd.DataFrame.from_records(records)
    LOGGER.info("Group memberships generated: %d rows", len(df))
    return df


# --------------------------------------------------------------------------- #
# Main execution block
# --------------------------------------------------------------------------- #

def main() -> None:
    configure_logging()
    set_seeds()
    LOGGER.info("Starting group structure generation")

    rng = np.random.default_rng(RANDOM_SEED)
    departments_df = load_departments()
    persons_df = load_persons()
    identities_df = load_identities()
    account_tables = load_account_tables()

    groups_df = generate_groups(departments_df)
    nesting_df = build_nested_relationships(groups_df)
    memberships_df = generate_group_memberships(account_tables, persons_df, identities_df, groups_df, rng)

    # drop generator-internal helper columns before saving groups.csv
    groups_out = groups_df.drop(columns=["tier", "department_name"])
    save_csv(groups_out, "groups.csv")
    save_csv(nesting_df, "nested_group_relationships.csv")
    save_csv(memberships_df, "group_memberships.csv")

    LOGGER.info(
        "Summary -> groups: %d | nested relationships: %d | memberships: %d",
        len(groups_out), len(nesting_df), len(memberships_df),
    )
    LOGGER.info("Group structure generation complete")


if __name__ == "__main__":
    main()
