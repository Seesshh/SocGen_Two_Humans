"""
src/data_generation/generate_accounts.py

Generates identities.csv, the 5 platform account CSVs (ad/azure/aws/okta/salesforce),
and identity_correlation_mapping.csv for the Hybrid Identity Governance synthetic
dataset (Phase 5 MVP scope).
"""

from __future__ import annotations

import logging
import random
from datetime import date, timedelta
from difflib import SequenceMatcher
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
COMPANY_DOMAIN: str = "corp.example.com"

N_ORPHAN_IDENTITIES: int = 40

# platform_id mapping kept consistent across the whole generation pipeline
PLATFORM_IDS: Dict[str, int] = {
    "Active Directory": 1,
    "Azure AD": 2,
    "AWS IAM": 3,
    "Okta": 4,
    "Salesforce": 5,
}

# Coverage-pattern proportions, solved to hit exact blueprint marginal coverage:
# AD=88%, Azure AD=96%, Okta=93%
ACCOUNT_PATTERN_WEIGHTS: Dict[str, float] = {
    "CORE_TRIAD": 0.84,   # AD + Azure AD + Okta
    "CLOUD_ONLY": 0.09,   # Azure AD + Okta, no AD
    "AD_ONLY": 0.04,      # AD only
    "AZURE_ONLY": 0.03,   # Azure AD only
}

TECH_DEPARTMENTS = {
    "Engineering", "Cloud Infrastructure & IT", "Data & Analytics",
    "Security", "Quality Assurance", "Product Management",
}
REVENUE_DEPARTMENTS = {"Sales", "Marketing", "Customer Success", "Customer Support"}

AWS_PROB_TECH: float = 0.50
AWS_PROB_OTHER: float = 0.04
SF_PROB_REVENUE: float = 0.50
SF_PROB_OTHER: float = 0.03

NOISY_EMAIL_RATE: float = 0.05      # accounts whose email won't exact-match persons.csv
NOISY_NAME_RATE: float = 0.02       # accounts whose display name is also altered

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

LOGGER = logging.getLogger("generate_accounts")


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
            fkr = Faker("en_US")
        fkr.seed_instance(RANDOM_SEED + 500 + offset)
        pool[country] = fkr
    return pool


def load_persons() -> pd.DataFrame:
    path = DATA_DIR / "persons.csv"
    df = pd.read_csv(path, parse_dates=["hire_date", "termination_date"])
    LOGGER.info("Loaded %d persons from %s", len(df), path)
    return df


def save_csv(df: pd.DataFrame, filename: str) -> Path:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    path = DATA_DIR / filename
    df.to_csv(path, index=False)
    LOGGER.info("Saved %s (%d rows, %d columns)", path, len(df), len(df.columns))
    return path


def make_pseudo_guid(rng: np.random.Generator) -> str:
    raw = rng.integers(0, 256, size=16, dtype=np.uint8).tobytes()
    h = raw.hex()
    return f"{h[0:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"


# --------------------------------------------------------------------------- #
# Coverage / overlap pattern assignment
# --------------------------------------------------------------------------- #

def assign_account_patterns(persons_df: pd.DataFrame, rng: np.random.Generator) -> pd.DataFrame:
    df = persons_df.copy()
    patterns = list(ACCOUNT_PATTERN_WEIGHTS.keys())
    weights = np.array(list(ACCOUNT_PATTERN_WEIGHTS.values()))
    chosen = rng.choice(patterns, size=len(df), p=weights / weights.sum())

    df["has_ad"] = np.isin(chosen, ["CORE_TRIAD", "AD_ONLY"])
    df["has_azure"] = np.isin(chosen, ["CORE_TRIAD", "CLOUD_ONLY", "AZURE_ONLY"])
    df["has_okta"] = np.isin(chosen, ["CORE_TRIAD", "CLOUD_ONLY"])
    df["account_pattern"] = chosen

    def _aws_prob(dept: str) -> float:
        return AWS_PROB_TECH if dept in TECH_DEPARTMENTS else AWS_PROB_OTHER

    def _sf_prob(dept: str) -> float:
        return SF_PROB_REVENUE if dept in REVENUE_DEPARTMENTS else SF_PROB_OTHER

    aws_draws = rng.random(len(df))
    sf_draws = rng.random(len(df))
    aws_probs = df["department_name"].map(_aws_prob).to_numpy()
    sf_probs = df["department_name"].map(_sf_prob).to_numpy()
    df["has_aws"] = aws_draws < aws_probs
    df["has_salesforce"] = sf_draws < sf_probs

    for col in ("has_ad", "has_azure", "has_okta", "has_aws", "has_salesforce"):
        pct = 100 * df[col].mean()
        LOGGER.info("Coverage achieved -> %s: %.1f%%", col, pct)

    return df


# --------------------------------------------------------------------------- #
# Identities
# --------------------------------------------------------------------------- #

def generate_identities(persons_df: pd.DataFrame, rng: np.random.Generator) -> pd.DataFrame:
    LOGGER.info("Generating identities (%d persons + %d orphans)", len(persons_df), N_ORPHAN_IDENTITIES)
    records = []
    identity_id = 1
    for _, p in persons_df.iterrows():
        records.append(
            {
                "identity_id": identity_id,
                "person_id": p["person_id"],
                "canonical_email": p["email"],
                "identity_status": "Linked",
                "first_seen_date": p["hire_date"].date(),
                "last_reconciled_at": REFERENCE_DATE - timedelta(days=int(rng.integers(0, 10))),
            }
        )
        identity_id += 1

    for _ in range(N_ORPHAN_IDENTITIES):
        first_seen = REFERENCE_DATE - timedelta(days=int(rng.integers(60, 1500)))
        records.append(
            {
                "identity_id": identity_id,
                "person_id": pd.NA,
                "canonical_email": None,
                "identity_status": "Orphaned",
                "first_seen_date": first_seen,
                "last_reconciled_at": REFERENCE_DATE - timedelta(days=int(rng.integers(0, 30))),
            }
        )
        identity_id += 1

    df = pd.DataFrame.from_records(records)
    LOGGER.info("Identities generated: %d rows (%d orphaned)", len(df), N_ORPHAN_IDENTITIES)
    return df


# --------------------------------------------------------------------------- #
# Shared account field construction
# --------------------------------------------------------------------------- #

def _username_from_name(full_name: str) -> str:
    parts = [p.lower() for p in full_name.split() if p.isalpha()]
    if len(parts) >= 2:
        return f"{parts[0][0]}{parts[-1]}"
    return parts[0] if parts else "user"


def _maybe_noisy_name(full_name: str, rng: np.random.Generator) -> str:
    if rng.random() < NOISY_NAME_RATE:
        parts = full_name.split()
        if len(parts) >= 2:
            return f"{parts[0][0]}. {parts[-1]}"  # e.g. "P. Sharma" instead of "Priya Sharma"
    return full_name


def _maybe_noisy_email(canonical_email: str, full_name: str, rng: np.random.Generator) -> str:
    if rng.random() < NOISY_EMAIL_RATE:
        local = _username_from_name(full_name)
        suffix = int(rng.integers(100, 999))
        return f"{local}{suffix}@{COMPANY_DOMAIN}"
    return canonical_email


def _account_status_and_dates(
    person_row: pd.Series, rng: np.random.Generator
) -> Tuple[str, date, Optional[date], date]:
    """Clean baseline lifecycle state (anomaly injection happens in a later stage)."""
    created_date = (person_row["hire_date"].date()) + timedelta(days=int(rng.integers(0, 5)))
    if person_row["status"] == "Terminated":
        term_date = person_row["termination_date"].date()
        disabled_date = term_date + timedelta(days=int(rng.integers(0, 2)))
        last_login = term_date - timedelta(days=int(rng.integers(0, 10)))
        return "Disabled", created_date, disabled_date, last_login
    last_login = REFERENCE_DATE - timedelta(days=int(rng.integers(0, 21)))
    return "Active", created_date, None, last_login


def _build_common_fields(
    platform_account_id: str,
    identity_id: int,
    login_name: str,
    email: str,
    display_name: str,
    person_row: pd.Series,
    rng: np.random.Generator,
) -> Dict:
    status, created_date, disabled_date, last_login = _account_status_and_dates(person_row, rng)
    return {
        "platform_account_id": platform_account_id,
        "identity_id": identity_id,
        "login_name": login_name,
        "email": email,
        "display_name": display_name,
        "account_status": status,
        "created_date": created_date,
        "disabled_date": disabled_date,
        "last_login_date": last_login,
    }


# --------------------------------------------------------------------------- #
# Platform-specific account generators
# --------------------------------------------------------------------------- #

def generate_ad_accounts(
    persons_df: pd.DataFrame, identities_df: pd.DataFrame, faker_pool: Dict[str, Faker], rng: np.random.Generator
) -> pd.DataFrame:
    id_lookup = dict(zip(identities_df["person_id"], identities_df["identity_id"]))
    records = []
    subset = persons_df[persons_df["has_ad"]]
    for _, p in subset.iterrows():
        identity_id = id_lookup[p["person_id"]]
        display_name = _maybe_noisy_name(p["full_name"], rng)
        email = _maybe_noisy_email(p["email"], p["full_name"], rng)
        sam = _username_from_name(p["full_name"])
        account_id = f"AD-{identity_id:06d}"
        common = _build_common_fields(account_id, identity_id, sam, email, display_name, p, rng)
        common.update(
            {
                "sam_account_name": sam,
                "distinguished_name": f"CN={display_name},OU={p['department_name']},DC=corp,DC=example,DC=com",
                "ou_path": f"{p['department_name']}/{p['location_country']}",
            }
        )
        records.append(common)
    df = pd.DataFrame.from_records(records)
    LOGGER.info("AD accounts generated: %d rows", len(df))
    return df


def generate_azure_accounts(
    persons_df: pd.DataFrame, identities_df: pd.DataFrame, faker_pool: Dict[str, Faker], rng: np.random.Generator
) -> pd.DataFrame:
    id_lookup = dict(zip(identities_df["person_id"], identities_df["identity_id"]))
    records = []
    subset = persons_df[persons_df["has_azure"]]
    for _, p in subset.iterrows():
        identity_id = id_lookup[p["person_id"]]
        display_name = _maybe_noisy_name(p["full_name"], rng)
        email = _maybe_noisy_email(p["email"], p["full_name"], rng)
        upn = email
        account_id = f"AZ-{identity_id:06d}"
        common = _build_common_fields(account_id, identity_id, upn, email, display_name, p, rng)

        if p["has_ad"]:
            sync_source = "AD Synced"
        elif p["employment_type"] == "Contractor" and rng.random() < 0.5:
            sync_source = "B2B Guest"
        else:
            sync_source = "Cloud-Only"

        common.update(
            {
                "upn": upn,
                "object_id": make_pseudo_guid(rng),
                "sync_source": sync_source,
                "conditional_access_compliant": bool(rng.random() < 0.90),
            }
        )
        records.append(common)
    df = pd.DataFrame.from_records(records)
    LOGGER.info("Azure AD accounts generated: %d rows", len(df))
    return df


def generate_aws_accounts(
    persons_df: pd.DataFrame, identities_df: pd.DataFrame, faker_pool: Dict[str, Faker], rng: np.random.Generator
) -> pd.DataFrame:
    id_lookup = dict(zip(identities_df["person_id"], identities_df["identity_id"]))
    aws_sub_accounts = ["778812455123", "881023456789", "552310987654"]
    records = []
    subset = persons_df[persons_df["has_aws"]]
    for _, p in subset.iterrows():
        identity_id = id_lookup[p["person_id"]]
        display_name = _maybe_noisy_name(p["full_name"], rng)
        email = _maybe_noisy_email(p["email"], p["full_name"], rng)
        username = _username_from_name(p["full_name"])
        account_id = f"AWS-{identity_id:06d}"
        common = _build_common_fields(account_id, identity_id, username, email, display_name, p, rng)

        iam_type = "IAM User" if rng.random() < 0.75 else "Federated Role"
        sub_account = aws_sub_accounts[int(rng.integers(0, len(aws_sub_accounts)))]
        if iam_type == "IAM User":
            arn = f"arn:aws:iam::{sub_account}:user/{username}"
            access_key_active = bool(rng.random() < 0.35)
            federation_source = None
        else:
            arn = f"arn:aws:iam::{sub_account}:role/{username}-federated"
            access_key_active = False
            federation_source = "Okta SSO"

        common.update(
            {
                "aws_account_number": sub_account,
                "iam_user_or_role": iam_type,
                "arn": arn,
                "access_key_active": access_key_active,
                "federation_source": federation_source,
            }
        )
        records.append(common)
    df = pd.DataFrame.from_records(records)
    LOGGER.info("AWS accounts generated: %d rows", len(df))
    return df


def generate_okta_accounts(
    persons_df: pd.DataFrame, identities_df: pd.DataFrame, faker_pool: Dict[str, Faker], rng: np.random.Generator
) -> pd.DataFrame:
    id_lookup = dict(zip(identities_df["person_id"], identities_df["identity_id"]))
    records = []
    subset = persons_df[persons_df["has_okta"]]
    for _, p in subset.iterrows():
        identity_id = id_lookup[p["person_id"]]
        display_name = _maybe_noisy_name(p["full_name"], rng)
        email = _maybe_noisy_email(p["email"], p["full_name"], rng)
        account_id = f"OKTA-{identity_id:06d}"
        common = _build_common_fields(account_id, identity_id, email, email, display_name, p, rng)
        common.update(
            {
                "okta_user_id": f"00u{make_pseudo_guid(rng)[:14].replace('-', '')}",
                "federated_apps_count": int(rng.integers(2, 11)),
                "is_sso_broker_admin": bool(rng.random() < 0.01),
            }
        )
        records.append(common)
    df = pd.DataFrame.from_records(records)
    LOGGER.info("Okta accounts generated: %d rows", len(df))
    return df


def generate_salesforce_accounts(
    persons_df: pd.DataFrame, identities_df: pd.DataFrame, faker_pool: Dict[str, Faker], rng: np.random.Generator
) -> pd.DataFrame:
    id_lookup = dict(zip(identities_df["person_id"], identities_df["identity_id"]))
    profile_choices = ["Standard User", "Sales Manager", "Marketing User", "System Administrator"]
    profile_weights = [0.80, 0.12, 0.05, 0.03]
    perm_set_options = [
        "PS_BulkDataAccess", "PS_FinanceExport", "PS_CampaignManager",
        "PS_ReportBuilder", "PS_APIAccess",
    ]
    records = []
    subset = persons_df[persons_df["has_salesforce"]]
    for _, p in subset.iterrows():
        identity_id = id_lookup[p["person_id"]]
        display_name = _maybe_noisy_name(p["full_name"], rng)
        email = _maybe_noisy_email(p["email"], p["full_name"], rng)
        username = _username_from_name(p["full_name"])
        account_id = f"SF-{identity_id:06d}"
        common = _build_common_fields(account_id, identity_id, username, email, display_name, p, rng)

        n_sets = int(rng.integers(0, 3))
        chosen_sets = (
            list(rng.choice(perm_set_options, size=n_sets, replace=False)) if n_sets > 0 else []
        )
        common.update(
            {
                "salesforce_user_id": f"005{make_pseudo_guid(rng)[:15].replace('-', '')}",
                "profile_name": rng.choice(profile_choices, p=profile_weights),
                "permission_sets": ";".join(chosen_sets),
                "provisioned_by": "Central IT" if rng.random() < 0.70 else "Business Admin (Self-Service)",
            }
        )
        records.append(common)
    df = pd.DataFrame.from_records(records)
    LOGGER.info("Salesforce accounts generated: %d rows", len(df))
    return df


# --------------------------------------------------------------------------- #
# Orphan accounts (no linked person)
# --------------------------------------------------------------------------- #

def generate_orphan_accounts(
    identities_df: pd.DataFrame, faker_pool: Dict[str, Faker], rng: np.random.Generator
) -> Dict[str, pd.DataFrame]:
    orphan_identities = identities_df[identities_df["identity_status"] == "Orphaned"]
    platform_choices = ["Active Directory", "Azure AD", "Okta"]  # legacy-cruft-prone platforms
    platform_weights = [0.45, 0.30, 0.25]

    extra: Dict[str, List[Dict]] = {p: [] for p in PLATFORM_IDS}
    default_fkr = faker_pool["United States"]

    for _, ident in orphan_identities.iterrows():
        platform = rng.choice(platform_choices, p=platform_weights)
        synthetic_name = default_fkr.name()
        synthetic_user = _username_from_name(synthetic_name) + str(int(rng.integers(10, 99)))
        synthetic_email = f"{synthetic_user}@corp-legacy.example.com"
        created_date = REFERENCE_DATE - timedelta(days=int(rng.integers(180, 1800)))
        last_login = REFERENCE_DATE - timedelta(days=int(rng.integers(120, 900)))
        identity_id = ident["identity_id"]

        base = {
            "platform_account_id": f"{platform[:2].upper()}-ORPH-{identity_id:06d}",
            "identity_id": identity_id,
            "login_name": synthetic_user,
            "email": synthetic_email,
            "display_name": synthetic_name,
            "account_status": "Active" if rng.random() < 0.7 else "Disabled",
            "created_date": created_date,
            "disabled_date": None,
            "last_login_date": last_login,
        }

        if platform == "Active Directory":
            base.update(
                {
                    "sam_account_name": synthetic_user,
                    "distinguished_name": f"CN={synthetic_name},OU=Unmanaged,DC=corp,DC=example,DC=com",
                    "ou_path": "Unmanaged/Legacy",
                }
            )
        elif platform == "Azure AD":
            base.update(
                {
                    "upn": synthetic_email,
                    "object_id": make_pseudo_guid(rng),
                    "sync_source": "Cloud-Only",
                    "conditional_access_compliant": False,
                }
            )
        else:  # Okta
            base.update(
                {
                    "okta_user_id": f"00u{make_pseudo_guid(rng)[:14].replace('-', '')}",
                    "federated_apps_count": int(rng.integers(0, 3)),
                    "is_sso_broker_admin": False,
                }
            )
        extra[platform].append(base)

    return {
        "Active Directory": pd.DataFrame.from_records(extra["Active Directory"]),
        "Azure AD": pd.DataFrame.from_records(extra["Azure AD"]),
        "Okta": pd.DataFrame.from_records(extra["Okta"]),
    }


# --------------------------------------------------------------------------- #
# Identity resolution / correlation mapping
# --------------------------------------------------------------------------- #

def _normalize_name(name: str) -> str:
    return "".join(ch for ch in name.lower() if ch.isalpha())


def _name_similarity(a: str, b: str) -> float:
    return SequenceMatcher(None, _normalize_name(a), _normalize_name(b)).ratio()


def _resolve_account(
    account_email: Optional[str],
    account_display_name: str,
    email_lookup: Dict[str, int],
    normalized_names: List[Tuple[int, str]],
) -> Tuple[Optional[int], float, str]:
    if account_email and account_email.lower() in email_lookup:
        return email_lookup[account_email.lower()], 0.95, "Exact Email"

    normalized_account_name = _normalize_name(account_display_name)
    best_person_id: Optional[int] = None
    best_score = 0.0
    for person_id, norm_name in normalized_names:
        sim = SequenceMatcher(None, normalized_account_name, norm_name).ratio()
        if sim >= 0.92 and sim > best_score:
            best_person_id, best_score = person_id, 0.65
        elif sim >= 0.85 and best_score < 0.40:
            best_person_id, best_score = person_id, 0.40

    if best_person_id is not None:
        method = "Fuzzy Name (High)" if best_score >= 0.65 else "Fuzzy Name (Low)"
        return best_person_id, best_score, method
    return None, 0.0, "Unresolved"


def generate_identity_correlation_mapping(
    account_dfs: Dict[str, pd.DataFrame],
    persons_df: pd.DataFrame,
    identities_df: pd.DataFrame,
    rng: np.random.Generator,
) -> pd.DataFrame:
    LOGGER.info("Running identity resolution across all platform accounts")
    email_lookup = dict(zip(persons_df["email"].str.lower(), persons_df["person_id"]))
    person_to_identity = dict(zip(identities_df["person_id"], identities_df["identity_id"]))
    normalized_names = [
        (pid, _normalize_name(name))
        for pid, name in zip(persons_df["person_id"], persons_df["full_name"])
    ]

    records = []
    mapping_id = 1
    unresolved_count = 0
    low_confidence_count = 0

    for platform_name, df in account_dfs.items():
        platform_id = PLATFORM_IDS[platform_name]
        for _, account in df.iterrows():
            resolved_person_id, confidence, method = _resolve_account(
                account.get("email"), account["display_name"], email_lookup, normalized_names
            )
            if resolved_person_id is not None:
                resolved_identity_id = person_to_identity.get(resolved_person_id, account["identity_id"])
            else:
                resolved_identity_id = account["identity_id"]  # falls back to ground-truth orphan identity
                unresolved_count += 1

            if 0 < confidence < 0.85:
                low_confidence_count += 1

            records.append(
                {
                    "mapping_id": mapping_id,
                    "identity_id": resolved_identity_id,
                    "platform_id": platform_id,
                    "platform_account_id": account["platform_account_id"],
                    "match_method": method,
                    "match_confidence": round(confidence, 3),
                    "linked_at": account["created_date"],
                }
            )
            mapping_id += 1

    df_out = pd.DataFrame.from_records(records)
    LOGGER.info(
        "Correlation mapping generated: %d rows (%d unresolved, %d low-confidence/under-review)",
        len(df_out), unresolved_count, low_confidence_count,
    )
    return df_out


# --------------------------------------------------------------------------- #
# Main execution block
# --------------------------------------------------------------------------- #

def main() -> None:
    configure_logging()
    set_seeds()
    LOGGER.info("Starting account generation")

    rng = np.random.default_rng(RANDOM_SEED)
    persons_df = load_persons()
    faker_pool = build_faker_pool()

    persons_df = assign_account_patterns(persons_df, rng)
    identities_df = generate_identities(persons_df, rng)
    save_csv(identities_df, "identities.csv")

    ad_df = generate_ad_accounts(persons_df, identities_df, faker_pool, rng)
    azure_df = generate_azure_accounts(persons_df, identities_df, faker_pool, rng)
    aws_df = generate_aws_accounts(persons_df, identities_df, faker_pool, rng)
    okta_df = generate_okta_accounts(persons_df, identities_df, faker_pool, rng)
    salesforce_df = generate_salesforce_accounts(persons_df, identities_df, faker_pool, rng)

    orphan_extras = generate_orphan_accounts(identities_df, faker_pool, rng)
    ad_df = pd.concat([ad_df, orphan_extras["Active Directory"]], ignore_index=True)
    azure_df = pd.concat([azure_df, orphan_extras["Azure AD"]], ignore_index=True)
    okta_df = pd.concat([okta_df, orphan_extras["Okta"]], ignore_index=True)

    save_csv(ad_df, "ad_accounts.csv")
    save_csv(azure_df, "azure_accounts.csv")
    save_csv(aws_df, "aws_accounts.csv")
    save_csv(okta_df, "okta_accounts.csv")
    save_csv(salesforce_df, "salesforce_accounts.csv")

    account_dfs = {
        "Active Directory": ad_df,
        "Azure AD": azure_df,
        "AWS IAM": aws_df,
        "Okta": okta_df,
        "Salesforce": salesforce_df,
    }
    mapping_df = generate_identity_correlation_mapping(account_dfs, persons_df, identities_df, rng)
    save_csv(mapping_df, "identity_correlation_mapping.csv")

    LOGGER.info(
        "Summary -> identities: %d | total platform accounts: %d | correlation rows: %d",
        len(identities_df),
        sum(len(df) for df in account_dfs.values()),
        len(mapping_df),
    )
    LOGGER.info("Account generation complete")


if __name__ == "__main__":
    main()
