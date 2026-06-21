"""
src/data_generation/generate_org.py

Generates departments.csv, roles.csv, and persons.csv for the
Hybrid Identity Governance synthetic dataset (Phase 5 MVP scope).
"""

from __future__ import annotations

import logging
import random
from dataclasses import dataclass
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import Dict, List, Tuple

import numpy as np
import pandas as pd
from faker import Faker

# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #

RANDOM_SEED: int = 42
OUTPUT_DIR: Path = Path("data/synthetic_data")
REFERENCE_DATE: date = date(2026, 6, 20)

N_DEPARTMENTS: int = 20
N_PERSONS: int = 1500
N_EMPLOYEES: int = 1200
N_CONTRACTORS: int = 300

TERMINATION_RATE: float = 0.15
DELAYED_HR_SYNC_RATE: float = 0.13

COMPANY_DOMAIN: str = "corp.example.com"

LOGGER = logging.getLogger("generate_org")


# --------------------------------------------------------------------------- #
# Reference data
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class DepartmentSpec:
    name: str
    division: str
    weight: float


DEPARTMENT_SPECS: Tuple[DepartmentSpec, ...] = (
    DepartmentSpec("Engineering", "Technology", 18.0),
    DepartmentSpec("Sales", "Revenue", 14.0),
    DepartmentSpec("Customer Support", "Operations", 9.0),
    DepartmentSpec("Operations", "Operations", 8.0),
    DepartmentSpec("Cloud Infrastructure & IT", "Technology", 9.0),
    DepartmentSpec("Finance", "Finance & Risk", 6.0),
    DepartmentSpec("Marketing", "Revenue", 6.0),
    DepartmentSpec("Human Resources", "People", 4.0),
    DepartmentSpec("Procurement", "Finance & Risk", 3.0),
    DepartmentSpec("Legal", "Finance & Risk", 2.0),
    DepartmentSpec("Product Management", "Technology", 5.0),
    DepartmentSpec("Data & Analytics", "Technology", 4.0),
    DepartmentSpec("Quality Assurance", "Technology", 3.0),
    DepartmentSpec("Customer Success", "Revenue", 3.0),
    DepartmentSpec("Security", "Technology", 2.0),
    DepartmentSpec("Facilities", "Operations", 1.5),
    DepartmentSpec("Corporate Communications", "People", 1.0),
    DepartmentSpec("Internal Audit", "Finance & Risk", 1.0),
    DepartmentSpec("Training & Development", "People", 1.0),
    DepartmentSpec("Executive Office", "Corporate", 1.5),
)

SENIORITY_LEVELS: Tuple[str, ...] = (
    "Individual Contributor",
    "Senior IC",
    "Manager",
    "Director",
    "VP/Executive",
)
SENIORITY_WEIGHTS: Tuple[float, ...] = (0.68, 0.17, 0.10, 0.035, 0.015)

ROLE_TIERS: Tuple[str, ...] = ("Individual Contributor", "Manager", "Director")
ROLE_TIER_CATEGORY: Dict[str, str] = {
    "Individual Contributor": "Birthright",
    "Manager": "Functional",
    "Director": "Privileged",
}
SENIORITY_TO_ROLE_TIER: Dict[str, str] = {
    "Individual Contributor": "Individual Contributor",
    "Senior IC": "Individual Contributor",
    "Manager": "Manager",
    "Director": "Director",
    "VP/Executive": "Director",
}
SENSITIVE_ROLE_DEPARTMENTS = {"Finance", "Legal", "Security", "Internal Audit"}

COUNTRY_WEIGHTS: Dict[str, float] = {
    "India": 55.0,
    "United States": 20.0,
    "United Kingdom": 5.0,
    "Germany": 5.0,
    "Singapore": 5.0,
    "Australia": 2.5,
    "Canada": 2.5,
    "Ireland": 2.5,
    "Philippines": 2.5,
}

COUNTRY_LOCALE_MAP: Dict[str, str] = {
    "India": "en_IN",
    "United States": "en_US",
    "United Kingdom": "en_GB",
    "Germany": "de_DE",
    "Singapore": "en_US",
    "Australia": "en_AU",
    "Canada": "en_CA",
    "Ireland": "en_GB",
    "Philippines": "en_US",
}

HIRE_DATE_RANGE_YEARS: Dict[str, Tuple[float, float]] = {
    "VP/Executive": (3.0, 8.0),
    "Director": (1.0, 6.0),
    "Manager": (0.5, 5.0),
    "Senior IC": (0.3, 4.0),
    "Individual Contributor": (0.05, 3.0),
}


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


def build_faker_pool() -> Dict[str, Faker]:
    pool: Dict[str, Faker] = {}
    for offset, (country, locale) in enumerate(COUNTRY_LOCALE_MAP.items()):
        try:
            fkr = Faker(locale)
        except AttributeError:
            LOGGER.warning("Locale '%s' unavailable for %s; falling back to en_US", locale, country)
            fkr = Faker("en_US")
        fkr.seed_instance(RANDOM_SEED + offset)
        pool[country] = fkr
    return pool


def normalized_weights(weights: List[float]) -> np.ndarray:
    arr = np.array(weights, dtype=float)
    return arr / arr.sum()


def exact_counts(weights: Tuple[float, ...], total: int) -> List[int]:
    raw = [w * total for w in weights]
    counts = [int(np.floor(x)) for x in raw]
    remainder = total - sum(counts)
    fractional_order = sorted(
        range(len(weights)), key=lambda i: raw[i] - counts[i], reverse=True
    )
    for i in range(remainder):
        counts[fractional_order[i]] += 1
    return counts


def save_csv(df: pd.DataFrame, filename: str) -> Path:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    path = OUTPUT_DIR / filename
    df.to_csv(path, index=False)
    LOGGER.info("Saved %s (%d rows, %d columns)", path, len(df), len(df.columns))
    return path


# --------------------------------------------------------------------------- #
# Departments
# --------------------------------------------------------------------------- #

def generate_departments() -> pd.DataFrame:
    LOGGER.info("Generating %d departments", N_DEPARTMENTS)
    records = []
    for idx, spec in enumerate(DEPARTMENT_SPECS, start=1):
        records.append(
            {
                "department_id": idx,
                "department_name": spec.name,
                "division": spec.division,
                "cost_center": f"CC-{1000 + idx * 10}",
            }
        )
    df = pd.DataFrame.from_records(records)
    LOGGER.info("Departments generated: %d rows", len(df))
    return df


# --------------------------------------------------------------------------- #
# Roles
# --------------------------------------------------------------------------- #

def _role_name_for_tier(department_name: str, tier: str) -> str:
    if tier == "Individual Contributor":
        return f"{department_name} Associate"
    if tier == "Manager":
        return f"{department_name} Manager"
    return f"Director of {department_name}"


def generate_roles(departments_df: pd.DataFrame) -> pd.DataFrame:
    LOGGER.info("Generating roles (%d tiers per department)", len(ROLE_TIERS))
    records = []
    role_id = 1
    for _, dept in departments_df.iterrows():
        for tier in ROLE_TIERS:
            records.append(
                {
                    "role_id": role_id,
                    "role_name": _role_name_for_tier(dept["department_name"], tier),
                    "role_tier": tier,
                    "role_category": ROLE_TIER_CATEGORY[tier],
                    "owning_department_id": dept["department_id"],
                    "requires_background_check": (
                        tier == "Director" or dept["department_name"] in SENSITIVE_ROLE_DEPARTMENTS
                    ),
                    "is_privileged": tier in ("Manager", "Director"),
                }
            )
            role_id += 1
    df = pd.DataFrame.from_records(records)
    LOGGER.info("Roles generated: %d rows", len(df))
    return df


def _build_role_lookup(roles_df: pd.DataFrame) -> Dict[Tuple[int, str], Tuple[int, str]]:
    lookup: Dict[Tuple[int, str], Tuple[int, str]] = {}
    for _, row in roles_df.iterrows():
        lookup[(row["owning_department_id"], row["role_tier"])] = (
            row["role_id"],
            row["role_name"],
        )
    return lookup


# --------------------------------------------------------------------------- #
# Persons
# --------------------------------------------------------------------------- #

def _make_unique_email(full_name: str, used_emails: set) -> str:
    parts = full_name.lower().replace(",", "").split()
    if len(parts) >= 2:
        first, last = parts[0], parts[-1]
    else:
        first, last = parts[0], "user"
    base = "".join(ch for ch in f"{first}.{last}" if ch.isalnum() or ch == ".")
    candidate = f"{base}@{COMPANY_DOMAIN}"
    suffix = 1
    while candidate in used_emails:
        suffix += 1
        candidate = f"{base}{suffix}@{COMPANY_DOMAIN}"
    used_emails.add(candidate)
    return candidate


def _sample_hire_date(seniority: str, rng: np.random.Generator) -> date:
    min_years, max_years = HIRE_DATE_RANGE_YEARS[seniority]
    years_ago = rng.uniform(min_years, max_years)
    days_ago = int(years_ago * 365.25)
    return REFERENCE_DATE - timedelta(days=days_ago)


def _build_hierarchy(persons_df: pd.DataFrame, rng: np.random.Generator) -> pd.Series:
    """Assign manager_person_id for every person using a seniority-based hierarchy."""
    manager_ids = pd.Series(index=persons_df.index, dtype="float64")

    exec_dept_rows = persons_df.index[
        (persons_df["department_name"] == "Executive Office")
        & (persons_df["seniority_level"] == "VP/Executive")
    ]
    all_vp_idxs = persons_df.index[persons_df["seniority_level"] == "VP/Executive"].tolist()
    ceo_idx = exec_dept_rows[0] if len(exec_dept_rows) > 0 else all_vp_idxs[0]
    manager_ids.loc[ceo_idx] = np.nan

    all_director_idxs = persons_df.index[persons_df["seniority_level"] == "Director"].tolist()
    all_manager_idxs = persons_df.index[persons_df["seniority_level"] == "Manager"].tolist()

    dept_vp_map: Dict[int, List[int]] = {}
    for idx in all_vp_idxs:
        dept_vp_map.setdefault(persons_df.loc[idx, "department_id"], []).append(idx)

    for idx in all_vp_idxs:
        if idx != ceo_idx:
            manager_ids.loc[idx] = persons_df.loc[ceo_idx, "person_id"]

    dept_director_map: Dict[int, List[int]] = {}
    for idx in all_director_idxs:
        dept_director_map.setdefault(persons_df.loc[idx, "department_id"], []).append(idx)

    for idx in all_director_idxs:
        dept_id = persons_df.loc[idx, "department_id"]
        candidates = dept_vp_map.get(dept_id) or all_vp_idxs
        chosen = candidates[rng.integers(0, len(candidates))]
        manager_ids.loc[idx] = persons_df.loc[chosen, "person_id"]

    dept_manager_map: Dict[int, List[int]] = {}
    for idx in all_manager_idxs:
        dept_manager_map.setdefault(persons_df.loc[idx, "department_id"], []).append(idx)

    for idx in all_manager_idxs:
        dept_id = persons_df.loc[idx, "department_id"]
        candidates = dept_director_map.get(dept_id) or dept_vp_map.get(dept_id) or all_director_idxs
        chosen = candidates[rng.integers(0, len(candidates))]
        manager_ids.loc[idx] = persons_df.loc[chosen, "person_id"]

    ic_idxs = persons_df.index[
        persons_df["seniority_level"].isin(["Individual Contributor", "Senior IC"])
    ].tolist()
    for idx in ic_idxs:
        dept_id = persons_df.loc[idx, "department_id"]
        candidates = dept_manager_map.get(dept_id) or dept_director_map.get(dept_id) or all_manager_idxs
        chosen = candidates[rng.integers(0, len(candidates))]
        manager_ids.loc[idx] = persons_df.loc[chosen, "person_id"]

    return manager_ids


def _apply_termination(persons_df: pd.DataFrame, rng: np.random.Generator) -> pd.DataFrame:
    df = persons_df.copy()
    df["status"] = "Active"
    df["termination_date"] = pd.Series([None] * len(df), index=df.index, dtype="object")
    df["termination_reason"] = pd.Series([None] * len(df), index=df.index, dtype="object")

    eligible = df.index[df["manager_person_id"].notna()].to_numpy()  # excludes the CEO
    n_terminated = int(round(TERMINATION_RATE * len(df)))
    terminated_idx = rng.choice(eligible, size=n_terminated, replace=False)

    for idx in terminated_idx:
        hire = df.loc[idx, "hire_date"]
        window_start = max(hire + timedelta(days=30), REFERENCE_DATE - timedelta(days=365))
        if window_start >= REFERENCE_DATE:
            window_start = REFERENCE_DATE - timedelta(days=1)
        days_span = max((REFERENCE_DATE - window_start).days, 1)
        term_date = window_start + timedelta(days=int(rng.integers(0, days_span)))

        employment_type = df.loc[idx, "employment_type"]
        if employment_type == "Contractor":
            reason = rng.choice(["End of Contract", "Involuntary"], p=[0.8, 0.2])
        else:
            reason = rng.choice(["Voluntary", "Involuntary"], p=[0.75, 0.25])

        df.loc[idx, "status"] = "Terminated"
        df.loc[idx, "termination_date"] = term_date
        df.loc[idx, "termination_reason"] = reason

    LOGGER.info(
        "Terminated persons: %d (%.1f%% of population)",
        n_terminated,
        100 * n_terminated / len(df),
    )
    return df


def _apply_background_check_level(persons_df: pd.DataFrame, rng: np.random.Generator) -> pd.DataFrame:
    df = persons_df.copy()

    def _level(row: pd.Series) -> str:
        if row["department_name"] in SENSITIVE_ROLE_DEPARTMENTS:
            return "Enhanced"
        if row["seniority_level"] in ("Director", "VP/Executive"):
            return "Enhanced"
        return "Enhanced" if rng.random() < 0.05 else "Standard"

    df["background_check_level"] = df.apply(_level, axis=1)
    return df


def _apply_audit_timestamps(persons_df: pd.DataFrame, rng: np.random.Generator) -> pd.DataFrame:
    df = persons_df.copy()
    created_at: List[datetime] = []
    updated_at: List[datetime] = []

    for _, row in df.iterrows():
        created = datetime.combine(row["hire_date"], datetime.min.time()) + timedelta(
            hours=int(rng.integers(8, 18))
        )
        created_at.append(created)

        lag_days = int(rng.integers(1, 10)) if rng.random() < DELAYED_HR_SYNC_RATE else 0
        if row["status"] == "Terminated":
            base = datetime.combine(row["termination_date"], datetime.min.time())
        else:
            base = datetime.combine(REFERENCE_DATE, datetime.min.time()) - timedelta(
                days=int(rng.integers(0, 5))
            )
        updated = base + timedelta(days=lag_days, hours=int(rng.integers(1, 23)))
        updated_at.append(updated)

    df["created_at"] = created_at
    df["updated_at"] = updated_at
    return df


def generate_persons(departments_df: pd.DataFrame, roles_df: pd.DataFrame) -> pd.DataFrame:
    LOGGER.info("Generating %d persons", N_PERSONS)
    rng = np.random.default_rng(RANDOM_SEED)

    dept_weights = normalized_weights([s.weight for s in DEPARTMENT_SPECS])
    department_ids = rng.choice(
        departments_df["department_id"].to_numpy(), size=N_PERSONS, p=dept_weights
    )

    seniority_counts = exact_counts(SENIORITY_WEIGHTS, N_PERSONS)
    seniority_pool: List[str] = []
    for level, count in zip(SENIORITY_LEVELS, seniority_counts):
        seniority_pool.extend([level] * count)
    rng.shuffle(seniority_pool)

    employment_pool = ["Employee"] * N_EMPLOYEES + ["Contractor"] * N_CONTRACTORS
    rng.shuffle(employment_pool)

    country_names = list(COUNTRY_WEIGHTS.keys())
    country_weights = normalized_weights(list(COUNTRY_WEIGHTS.values()))
    countries = rng.choice(country_names, size=N_PERSONS, p=country_weights)

    faker_pool = build_faker_pool()
    dept_lookup = departments_df.set_index("department_id")["department_name"].to_dict()
    role_lookup = _build_role_lookup(roles_df)

    used_emails: set = set()
    records = []
    for i in range(N_PERSONS):
        person_id = i + 1
        department_id = int(department_ids[i])
        department_name = dept_lookup[department_id]
        seniority = seniority_pool[i]
        employment_type = employment_pool[i]
        country = countries[i]

        fkr = faker_pool[country]
        full_name = fkr.name()
        email = _make_unique_email(full_name, used_emails)

        role_tier = SENIORITY_TO_ROLE_TIER[seniority]
        role_id, job_title = role_lookup[(department_id, role_tier)]
        hire_date = _sample_hire_date(seniority, rng)

        records.append(
            {
                "person_id": person_id,
                "employee_number": f"E{person_id:07d}",
                "full_name": full_name,
                "email": email,
                "department_id": department_id,
                "department_name": department_name,
                "job_title": job_title,
                "business_role_id": role_id,
                "seniority_level": seniority,
                "employment_type": employment_type,
                "hire_date": hire_date,
                "location_country": country,
            }
        )

    persons_df = pd.DataFrame.from_records(records)

    persons_df["manager_person_id"] = _build_hierarchy(persons_df, rng).to_numpy()
    persons_df["manager_person_id"] = persons_df["manager_person_id"].astype("Int64")

    persons_df = _apply_termination(persons_df, rng)
    persons_df = _apply_background_check_level(persons_df, rng)
    persons_df = _apply_audit_timestamps(persons_df, rng)

    column_order = [
        "person_id",
        "employee_number",
        "full_name",
        "email",
        "department_id",
        "department_name",
        "job_title",
        "business_role_id",
        "seniority_level",
        "manager_person_id",
        "employment_type",
        "hire_date",
        "termination_date",
        "termination_reason",
        "status",
        "background_check_level",
        "location_country",
        "created_at",
        "updated_at",
    ]
    persons_df = persons_df[column_order]
    LOGGER.info("Persons generated: %d rows", len(persons_df))
    return persons_df


# --------------------------------------------------------------------------- #
# Main execution block
# --------------------------------------------------------------------------- #

def main() -> None:
    configure_logging()
    set_seeds()
    LOGGER.info("Starting organizational data generation")

    departments_df = generate_departments()
    save_csv(departments_df, "departments.csv")

    roles_df = generate_roles(departments_df)
    save_csv(roles_df, "roles.csv")

    persons_df = generate_persons(departments_df, roles_df)
    save_csv(persons_df, "persons.csv")

    LOGGER.info(
        "Summary -> departments: %d | roles: %d | persons: %d (active: %d, terminated: %d)",
        len(departments_df),
        len(roles_df),
        len(persons_df),
        int((persons_df["status"] == "Active").sum()),
        int((persons_df["status"] == "Terminated").sum()),
    )
    LOGGER.info("Organizational data generation complete")


if __name__ == "__main__":
    main()
