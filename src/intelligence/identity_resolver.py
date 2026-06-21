"""
src/intelligence/identity_resolver.py

Cross-platform Identity Resolution Engine for the Hybrid Identity Governance
platform (Phase 5 MVP scope, Phase 4 Identity Resolver component).

Resolves human accounts across Active Directory, Azure AD, AWS IAM, Okta, and
Salesforce back to a single canonical identity per employee/contractor, using a
tiered matching strategy (employee ID -> exact email -> exact derived username
-> fuzzy name similarity) with an explicit 0-100 confidence score and a full
evidence trail for every linkage decision.

Inputs:
    employees.csv (falls back to persons.csv if employees.csv is absent)
    ad_accounts.csv, azure_accounts.csv, aws_accounts.csv,
    okta_accounts.csv, salesforce_accounts.csv

Outputs:
    resolved_identities.csv          — one row per resolved/orphaned identity
    identity_resolution_evidence.csv — one row per platform account, full evidence
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import numpy as np
import pandas as pd
from rapidfuzz import fuzz, process

# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #

DATA_DIR: Path = Path("data/synthetic_data")
OUTPUT_DIR: Path = Path("data/synthetic_data")

PLATFORM_FILES: Dict[str, str] = {
    "Active Directory": "ad_accounts.csv",
    "Azure AD": "azure_accounts.csv",
    "AWS IAM": "aws_accounts.csv",
    "Okta": "okta_accounts.csv",
    "Salesforce": "salesforce_accounts.csv",
}

# Confidence scores, 0-100
CONFIDENCE_EMPLOYEE_ID: float = 100.0
CONFIDENCE_EXACT_EMAIL: float = 95.0
CONFIDENCE_EXACT_USERNAME: float = 90.0
CONFIDENCE_FUZZY_HIGH: float = 75.0     # similarity >= FUZZY_HIGH_THRESHOLD
CONFIDENCE_FUZZY_MEDIUM: float = 55.0   # similarity >= FUZZY_MEDIUM_THRESHOLD
CONFIDENCE_FUZZY_LOW: float = 35.0      # similarity >= FUZZY_LOW_THRESHOLD

FUZZY_HIGH_THRESHOLD: float = 92.0
FUZZY_MEDIUM_THRESHOLD: float = 85.0
FUZZY_LOW_THRESHOLD: float = 75.0

AUTO_LINK_THRESHOLD: float = 85.0       # >= this: confidently linked
MANUAL_REVIEW_THRESHOLD: float = 35.0   # [this, AUTO_LINK_THRESHOLD): plausible but uncertain
AMBIGUITY_MARGIN: float = 4.0           # top-2 fuzzy candidates within this many points -> ambiguous

EMPLOYEE_ID_PATTERN = re.compile(r"\b[A-Za-z]{1,3}\d{5,9}\b")
EMPLOYEE_ID_CANDIDATE_COLUMNS: Tuple[str, ...] = ("employee_id", "employee_number", "emp_id", "hr_id")
EMPLOYEE_ID_TEXT_COLUMNS: Tuple[str, ...] = ("login_name", "sam_account_name", "distinguished_name", "upn", "email")

NAME_FIELD_CANDIDATES: Tuple[str, ...] = ("display_name", "full_name", "login_name", "upn", "email")

LOGGER = logging.getLogger("identity_resolver")


# --------------------------------------------------------------------------- #
# Data structures
# --------------------------------------------------------------------------- #

@dataclass
class MatchCandidate:
    employee_key: Optional[str]          # canonical employee identifier (employee_number/person_id), None if unresolved
    confidence_score: float
    resolution_method: str
    matched_on: str
    notes: str = ""


@dataclass
class EmployeeIndex:
    """Precomputed lookup structures built once from the employee roster,
    reused across every account match for performance."""
    employees_df: pd.DataFrame
    key_column: str
    email_lookup: Dict[str, str] = field(default_factory=dict)
    employee_id_lookup: Dict[str, str] = field(default_factory=dict)
    name_choices: Dict[str, str] = field(default_factory=dict)        # key -> normalized full name
    username_choices: Dict[str, str] = field(default_factory=dict)    # key -> normalized expected username


# --------------------------------------------------------------------------- #
# Setup / IO helpers
# --------------------------------------------------------------------------- #

def configure_logging() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def load_employees() -> pd.DataFrame:
    candidates = ["employees.csv", "persons.csv"]
    for filename in candidates:
        path = DATA_DIR / filename
        if path.exists():
            df = pd.read_csv(path)
            LOGGER.info("Loaded %d employee records from %s", len(df), filename)
            return _standardize_employee_columns(df)
    raise FileNotFoundError(
        f"Could not find an employee roster — looked for {candidates} in {DATA_DIR}"
    )


def _standardize_employee_columns(df: pd.DataFrame) -> pd.DataFrame:
    """Normalize column-naming differences between an 'employees.csv' export
    and our internal 'persons.csv' schema so the rest of the resolver can
    operate on a single consistent shape."""
    out = df.copy()
    rename_map = {
        "person_id": "employee_key",
        "employee_number": "employee_number",
        "name": "full_name",
    }
    for src, dst in rename_map.items():
        if src in out.columns and dst not in out.columns:
            out[dst] = out[src]

    if "employee_key" not in out.columns:
        if "employee_number" in out.columns:
            out["employee_key"] = out["employee_number"]
        elif "employee_id" in out.columns:
            out["employee_key"] = out["employee_id"]
        else:
            out["employee_key"] = out.index.astype(str)

    out["employee_key"] = out["employee_key"].astype(str)
    if "full_name" not in out.columns:
        raise ValueError("Employee roster is missing a name column (expected 'full_name' or 'name')")
    if "email" not in out.columns:
        out["email"] = None
    if "employee_number" not in out.columns:
        out["employee_number"] = out["employee_key"]
    if "employment_type" not in out.columns:
        out["employment_type"] = "Unknown"
    return out


def load_platform_accounts() -> Dict[str, pd.DataFrame]:
    accounts: Dict[str, pd.DataFrame] = {}
    for platform_name, filename in PLATFORM_FILES.items():
        path = DATA_DIR / filename
        if not path.exists():
            LOGGER.warning("Account file not found, skipping: %s", path)
            continue
        df = pd.read_csv(path)
        accounts[platform_name] = df
        LOGGER.info("Loaded %d %s accounts", len(df), platform_name)
    return accounts


def save_csv(df: pd.DataFrame, filename: str) -> Path:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    path = OUTPUT_DIR / filename
    df.to_csv(path, index=False)
    LOGGER.info("Saved %s (%d rows, %d columns)", path, len(df), len(df.columns))
    return path


# --------------------------------------------------------------------------- #
# Normalization helpers
# --------------------------------------------------------------------------- #

def normalize_text(value: Optional[str]) -> str:
    if value is None or (isinstance(value, float) and np.isnan(value)):
        return ""
    text = str(value).strip().lower()
    text = re.sub(r"[^a-z0-9@._ ]", "", text)
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def normalize_email(value: Optional[str]) -> str:
    text = normalize_text(value)
    return text


def derive_expected_username(full_name: str) -> str:
    """Mirrors the common 'first-initial + last-name' username convention
    used across most of the directory/SSO platforms in scope."""
    parts = [p for p in re.split(r"\s+", full_name.strip()) if p.isalpha()]
    if len(parts) >= 2:
        return f"{parts[0][0]}{parts[-1]}".lower()
    return parts[0].lower() if parts else ""


def extract_embedded_employee_id(text_fields: List[str]) -> Optional[str]:
    for value in text_fields:
        if not value or (isinstance(value, float) and np.isnan(value)):
            continue
        match = EMPLOYEE_ID_PATTERN.search(str(value))
        if match:
            return match.group(0).upper()
    return None


# --------------------------------------------------------------------------- #
# Employee index construction
# --------------------------------------------------------------------------- #

def build_employee_index(employees_df: pd.DataFrame) -> EmployeeIndex:
    LOGGER.info("Building employee lookup index (%d employees)", len(employees_df))
    idx = EmployeeIndex(employees_df=employees_df, key_column="employee_key")

    for _, row in employees_df.iterrows():
        key = row["employee_key"]

        email = normalize_email(row.get("email"))
        if email:
            # if duplicate email maps to two employees, the first wins for exact
            # lookup but the conflict is still discoverable via name matching
            idx.email_lookup.setdefault(email, key)

        emp_number = str(row.get("employee_number") or "").strip().upper()
        if emp_number:
            idx.employee_id_lookup.setdefault(emp_number, key)

        full_name = normalize_text(row.get("full_name"))
        if full_name:
            idx.name_choices[key] = full_name

        expected_username = derive_expected_username(row.get("full_name", ""))
        if expected_username:
            idx.username_choices[key] = expected_username

    LOGGER.info(
        "Index built -> emails: %d | employee_ids: %d | names: %d",
        len(idx.email_lookup), len(idx.employee_id_lookup), len(idx.name_choices),
    )
    return idx


# --------------------------------------------------------------------------- #
# Matching tiers
# --------------------------------------------------------------------------- #

def match_by_employee_id(account: pd.Series, idx: EmployeeIndex) -> Optional[MatchCandidate]:
    for col in EMPLOYEE_ID_CANDIDATE_COLUMNS:
        if col in account.index and pd.notna(account.get(col)):
            candidate_id = str(account[col]).strip().upper()
            if candidate_id in idx.employee_id_lookup:
                return MatchCandidate(
                    employee_key=idx.employee_id_lookup[candidate_id],
                    confidence_score=CONFIDENCE_EMPLOYEE_ID,
                    resolution_method="Exact Employee ID",
                    matched_on=col,
                )

    embedded_id = extract_embedded_employee_id(
        [account.get(c) for c in EMPLOYEE_ID_TEXT_COLUMNS if c in account.index]
    )
    if embedded_id and embedded_id in idx.employee_id_lookup:
        return MatchCandidate(
            employee_key=idx.employee_id_lookup[embedded_id],
            confidence_score=CONFIDENCE_EMPLOYEE_ID,
            resolution_method="Exact Employee ID",
            matched_on="embedded_id_pattern",
        )
    return None


def match_by_email(account: pd.Series, idx: EmployeeIndex) -> Optional[MatchCandidate]:
    account_email = normalize_email(account.get("email"))
    if not account_email:
        return None  # missing email — handled gracefully by falling through to later tiers
    employee_key = idx.email_lookup.get(account_email)
    if employee_key:
        return MatchCandidate(
            employee_key=employee_key,
            confidence_score=CONFIDENCE_EXACT_EMAIL,
            resolution_method="Exact Email",
            matched_on="email",
        )
    return None


def match_by_username_exact(account: pd.Series, idx: EmployeeIndex) -> Optional[MatchCandidate]:
    for col in ("login_name", "sam_account_name", "upn"):
        if col not in account.index or pd.isna(account.get(col)):
            continue
        local_part = normalize_text(account[col]).split("@")[0]
        for employee_key, expected_username in idx.username_choices.items():
            if local_part and local_part == expected_username:
                return MatchCandidate(
                    employee_key=employee_key,
                    confidence_score=CONFIDENCE_EXACT_USERNAME,
                    resolution_method="Exact Username",
                    matched_on=col,
                )
    return None


def match_by_fuzzy_name(account: pd.Series, idx: EmployeeIndex) -> Optional[MatchCandidate]:
    query = ""
    matched_field = None
    for field_name in NAME_FIELD_CANDIDATES:
        if field_name in account.index and pd.notna(account.get(field_name)):
            query = normalize_text(account[field_name]).split("@")[0]
            matched_field = field_name
            if query:
                break
    if not query or not idx.name_choices:
        return None

    top_matches = process.extract(
        query, idx.name_choices, scorer=fuzz.token_sort_ratio, limit=2
    )
    if not top_matches:
        return None

    best_name, best_score, best_key = top_matches[0]

    if len(top_matches) > 1:
        _, second_score, _ = top_matches[1]
        if best_score >= FUZZY_LOW_THRESHOLD and (best_score - second_score) <= AMBIGUITY_MARGIN:
            # two (or more) employees with near-identical names — don't silently
            # auto-attribute; surface the ambiguity with a capped confidence
            return MatchCandidate(
                employee_key=best_key,
                confidence_score=min(CONFIDENCE_FUZZY_LOW, best_score),
                resolution_method="Fuzzy Name (Ambiguous — Duplicate Name)",
                matched_on=matched_field or "name",
                notes=f"Competing candidate also scored {second_score:.1f} — manual review recommended",
            )

    if best_score >= FUZZY_HIGH_THRESHOLD:
        return MatchCandidate(
            employee_key=best_key, confidence_score=CONFIDENCE_FUZZY_HIGH,
            resolution_method="Fuzzy Name (High)", matched_on=matched_field or "name",
        )
    if best_score >= FUZZY_MEDIUM_THRESHOLD:
        return MatchCandidate(
            employee_key=best_key, confidence_score=CONFIDENCE_FUZZY_MEDIUM,
            resolution_method="Fuzzy Name (Medium)", matched_on=matched_field or "name",
        )
    if best_score >= FUZZY_LOW_THRESHOLD:
        return MatchCandidate(
            employee_key=best_key, confidence_score=CONFIDENCE_FUZZY_LOW,
            resolution_method="Fuzzy Name (Low)", matched_on=matched_field or "name",
        )
    return None


def resolve_account(account: pd.Series, idx: EmployeeIndex) -> MatchCandidate:
    """Runs the tiered matching strategy in priority order, returning the
    first (highest-confidence) match found. Falls through gracefully when
    a tier's required field is missing (e.g., no email on the account)."""
    for matcher in (match_by_employee_id, match_by_email, match_by_username_exact, match_by_fuzzy_name):
        result = matcher(account, idx)
        if result is not None:
            return result
    return MatchCandidate(
        employee_key=None, confidence_score=0.0,
        resolution_method="Unresolved", matched_on="none",
        notes="No employee ID, email, username, or name match found — possible orphaned account",
    )


# --------------------------------------------------------------------------- #
# Orchestration: build evidence, then aggregate into resolved identities
# --------------------------------------------------------------------------- #

def build_resolution_evidence(
    platform_accounts: Dict[str, pd.DataFrame], idx: EmployeeIndex
) -> pd.DataFrame:
    LOGGER.info("Resolving accounts across %d platforms", len(platform_accounts))
    records: List[Dict] = []
    evidence_id = 1

    for platform_name, accounts_df in platform_accounts.items():
        for _, account in accounts_df.iterrows():
            result = resolve_account(account, idx)
            account_id = account.get("platform_account_id", account.get("login_name", f"row-{evidence_id}"))
            records.append(
                {
                    "evidence_id": evidence_id,
                    "platform": platform_name,
                    "platform_account_id": account_id,
                    "account_email": account.get("email"),
                    "account_login_name": account.get("login_name"),
                    "matched_employee_key": result.employee_key,
                    "confidence_score": round(result.confidence_score, 1),
                    "resolution_method": result.resolution_method,
                    "matched_on": result.matched_on,
                    "resolution_band": _confidence_band(result.confidence_score),
                    "notes": result.notes,
                }
            )
            evidence_id += 1

    df = pd.DataFrame.from_records(records)
    LOGGER.info("Resolution evidence generated: %d rows", len(df))
    LOGGER.info("Resolution method distribution:\n%s", df["resolution_method"].value_counts())
    LOGGER.info("Resolution band distribution:\n%s", df["resolution_band"].value_counts())
    return df


def _confidence_band(score: float) -> str:
    if score >= AUTO_LINK_THRESHOLD:
        return "Linked"
    if score >= MANUAL_REVIEW_THRESHOLD:
        return "Under Review"
    return "Unresolved"


def build_resolved_identities(evidence_df: pd.DataFrame, employees_df: pd.DataFrame) -> pd.DataFrame:
    LOGGER.info("Aggregating evidence into resolved identities")
    employee_lookup = employees_df.set_index("employee_key")

    records: List[Dict] = []
    identity_id = 1

    linked_or_review = evidence_df[evidence_df["resolution_band"] != "Unresolved"]
    for employee_key, group in linked_or_review.groupby("matched_employee_key"):
        matched_accounts = ";".join(
            f"{row['platform']}:{row['platform_account_id']}" for _, row in group.iterrows()
        )
        methods = ";".join(sorted(set(group["resolution_method"])))
        overall_confidence = round(group["confidence_score"].min(), 1)  # weakest link sets overall trust
        emp_row = employee_lookup.loc[employee_key] if employee_key in employee_lookup.index else None

        records.append(
            {
                "identity_id": identity_id,
                "employee_key": employee_key,
                "full_name": emp_row["full_name"] if emp_row is not None else None,
                "email": emp_row["email"] if emp_row is not None else None,
                "employment_type": emp_row["employment_type"] if emp_row is not None else None,
                "matched_accounts": matched_accounts,
                "platform_count": group["platform"].nunique(),
                "confidence_score": overall_confidence,
                "resolution_method": methods,
                "identity_status": "Linked" if overall_confidence >= AUTO_LINK_THRESHOLD else "Under Review",
            }
        )
        identity_id += 1

    # employees with zero matched accounts at all still exist as identities (no platform footprint yet)
    matched_keys = set(linked_or_review["matched_employee_key"].dropna())
    for employee_key, emp_row in employee_lookup.iterrows():
        if employee_key in matched_keys:
            continue
        records.append(
            {
                "identity_id": identity_id,
                "employee_key": employee_key,
                "full_name": emp_row["full_name"],
                "email": emp_row["email"],
                "employment_type": emp_row["employment_type"],
                "matched_accounts": "",
                "platform_count": 0,
                "confidence_score": 0.0,
                "resolution_method": "No Accounts Found",
                "identity_status": "No Footprint",
            }
        )
        identity_id += 1

    # unresolved accounts become orphaned identities — grouped by shared email
    # where available, otherwise one orphaned identity per account
    orphan_evidence = evidence_df[evidence_df["resolution_band"] == "Unresolved"]
    orphan_groups: Dict[str, List[pd.Series]] = {}
    ungrouped_orphans: List[pd.Series] = []
    for _, row in orphan_evidence.iterrows():
        email = normalize_email(row.get("account_email"))
        if email:
            orphan_groups.setdefault(email, []).append(row)
        else:
            ungrouped_orphans.append(row)

    for email, rows in orphan_groups.items():
        matched_accounts = ";".join(f"{r['platform']}:{r['platform_account_id']}" for r in rows)
        records.append(
            {
                "identity_id": identity_id,
                "employee_key": None,
                "full_name": None,
                "email": email,
                "employment_type": None,
                "matched_accounts": matched_accounts,
                "platform_count": len({r["platform"] for r in rows}),
                "confidence_score": 0.0,
                "resolution_method": "Unresolved",
                "identity_status": "Orphaned",
            }
        )
        identity_id += 1

    for row in ungrouped_orphans:
        records.append(
            {
                "identity_id": identity_id,
                "employee_key": None,
                "full_name": None,
                "email": row.get("account_email"),
                "employment_type": None,
                "matched_accounts": f"{row['platform']}:{row['platform_account_id']}",
                "platform_count": 1,
                "confidence_score": 0.0,
                "resolution_method": "Unresolved",
                "identity_status": "Orphaned",
            }
        )
        identity_id += 1

    df = pd.DataFrame.from_records(records)
    LOGGER.info("Resolved identities generated: %d rows", len(df))
    LOGGER.info("Identity status distribution:\n%s", df["identity_status"].value_counts())
    return df


# --------------------------------------------------------------------------- #
# Main execution block
# --------------------------------------------------------------------------- #

def main() -> None:
    configure_logging()
    LOGGER.info("Starting identity resolution")

    employees_df = load_employees()
    platform_accounts = load_platform_accounts()
    if not platform_accounts:
        raise RuntimeError("No platform account files were found — nothing to resolve")

    idx = build_employee_index(employees_df)
    evidence_df = build_resolution_evidence(platform_accounts, idx)
    resolved_df = build_resolved_identities(evidence_df, employees_df)

    save_csv(resolved_df, "resolved_identities.csv")
    save_csv(evidence_df, "identity_resolution_evidence.csv")

    n_linked = (resolved_df["identity_status"] == "Linked").sum()
    n_review = (resolved_df["identity_status"] == "Under Review").sum()
    n_orphaned = (resolved_df["identity_status"] == "Orphaned").sum()
    n_no_footprint = (resolved_df["identity_status"] == "No Footprint").sum()
    LOGGER.info(
        "Summary -> total identities: %d | Linked: %d | Under Review: %d | Orphaned: %d | No Footprint: %d",
        len(resolved_df), n_linked, n_review, n_orphaned, n_no_footprint,
    )
    LOGGER.info("Identity resolution complete")


if __name__ == "__main__":
    main()
