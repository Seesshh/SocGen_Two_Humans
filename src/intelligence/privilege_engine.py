"""
src/intelligence/privilege_engine.py

Effective Privilege Calculator for the Hybrid Identity Governance platform
(Phase 4 Effective Privilege Calculator component, Phase 5 MVP scope).

Computes, per resolved identity, the *effective* privilege reachable through:
  - Direct platform role assignments
  - Inherited privilege via direct group membership
  - Inherited privilege via nested (multi-level) group membership
  - Aggregated cross-platform exposure

Two bridging notes, since the required inputs do not include every table a
fully-joined computation would ideally have:

  * role_assignments.csv references identity_id values minted by the original
    data-generation pipeline, not the identity_id values resolved_identities.csv
    assigns (the resolver renumbers identities from scratch). The true
    invariant across both is the underlying employee/person key, so role
    assignments are bridged to a resolved identity via
    role_assignments.identity_id == resolved_identities.employee_key. Rows
    that cannot be bridged are still preserved under a synthetic
    "UNBRIDGED:<original_id>" identity rather than silently dropped.
  * group_memberships.csv carries no tier/permission information of its own —
    it only states which groups an account belongs to. Inferring what a group
    *grants* requires group_name/is_privileged_group context, so groups.csv is
    loaded as an *optional* enrichment input. Its absence does not fail the
    run; nested-group privilege is then tracked structurally (membership,
    depth, blast radius) without a tier label, and this is logged clearly.

Output: effective_privileges.csv
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

import numpy as np
import pandas as pd

# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #

DATA_DIR: Path = Path("data/synthetic_data")
OUTPUT_DIR: Path = Path("data/synthetic_data")

PLATFORM_ID_TO_NAME: Dict[int, str] = {1: "Active Directory", 2: "Azure AD", 3: "AWS IAM", 4: "Okta", 5: "Salesforce"}

REQUIRED_INPUTS: Dict[str, str] = {
    "role_assignments": "role_assignments.csv",
    "group_memberships": "group_memberships.csv",
    "nested_group_relationships": "nested_group_relationships.csv",
    "platform_roles": "platform_roles.csv",
    "resolved_identities": "resolved_identities.csv",
}
OPTIONAL_INPUTS: Dict[str, str] = {"groups": "groups.csv"}

TIER_ORDER: List[str] = ["Standard", "Power User", "Admin", "Super Admin"]
TIER_RANK: Dict[str, int] = {t: i for i, t in enumerate(TIER_ORDER)}
UNKNOWN_TIER: str = "Unknown (no group-tier source)"

MAX_NESTING_DEPTH: int = 5
BLAST_RADIUS_MIN_TIER: str = "Power User"  # platforms count toward blast radius at or above this tier

GROUP_SUFFIX_TIER_MAP: Dict[str, str] = {
    "Standard": "Standard",
    "Baseline": "Standard",
    "PowerUsers": "Power User",
    "Approvers": "Admin",
    "Admins": "Admin",
}

LOGGER = logging.getLogger("privilege_engine")


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
        LOGGER.warning(
            "Optional enrichment input '%s' not found — group-derived privilege tiers "
            "will be tracked structurally (membership/depth) without a tier label",
            filename,
        )
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
    """Normalizes an ID value that may have been silently upcast to float64 by
    pandas (any column containing a NaN gets upcast), so '5' and '5.0' are
    always treated as the same identifier."""
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


# --------------------------------------------------------------------------- #
# Identity bridging
# --------------------------------------------------------------------------- #

def build_identity_bridges(
    resolved_identities_df: pd.DataFrame,
) -> Tuple[Dict[str, int], Dict[Tuple[str, str], int], Dict[int, pd.Series]]:
    """Builds two lookups: original-identity-key -> resolved identity_id (via
    employee_key), and (platform, platform_account_id) -> resolved identity_id
    (via the matched_accounts field)."""
    employee_key_to_resolved: Dict[str, int] = {}
    account_to_resolved: Dict[Tuple[str, str], int] = {}
    resolved_context: Dict[int, pd.Series] = {}

    for _, row in resolved_identities_df.iterrows():
        resolved_id = row["identity_id"]
        resolved_context[resolved_id] = row

        emp_key = clean_id(row.get("employee_key"))
        if emp_key is not None:
            employee_key_to_resolved[emp_key] = resolved_id

        matched_accounts = row.get("matched_accounts")
        if isinstance(matched_accounts, str) and matched_accounts.strip():
            for chunk in matched_accounts.split(";"):
                if ":" not in chunk:
                    continue
                platform_name, account_id = chunk.split(":", 1)
                account_to_resolved[(platform_name.strip(), account_id.strip())] = resolved_id

    LOGGER.info(
        "Identity bridges built -> employee_key lookups: %d | account lookups: %d",
        len(employee_key_to_resolved), len(account_to_resolved),
    )
    return employee_key_to_resolved, account_to_resolved, resolved_context


# --------------------------------------------------------------------------- #
# Group nesting closure
# --------------------------------------------------------------------------- #

def build_group_ancestor_closure(nested_groups_df: pd.DataFrame) -> Dict[str, Dict[str, int]]:
    """For every group, computes every ancestor group reachable by walking
    child -> parent edges (parent_group_id contains child_group_id, so a
    member of the child also inherits everything the parent grants),
    bounded by MAX_NESTING_DEPTH."""
    child_to_parent: Dict[str, List[str]] = {}
    for _, row in nested_groups_df.iterrows():
        child = clean_id(row["child_group_id"])
        parent = clean_id(row["parent_group_id"])
        if child is None or parent is None:
            continue
        child_to_parent.setdefault(child, []).append(parent)

    closure: Dict[str, Dict[str, int]] = {}

    def _ancestors(group_id: str) -> Dict[str, int]:
        if group_id in closure:
            return closure[group_id]
        result: Dict[str, int] = {}
        frontier = [(group_id, 0)]
        visited = {group_id}
        while frontier:
            current, depth = frontier.pop(0)
            if depth >= MAX_NESTING_DEPTH:
                continue
            for parent in child_to_parent.get(current, []):
                if parent in visited:
                    continue
                visited.add(parent)
                result[parent] = depth + 1
                frontier.append((parent, depth + 1))
        closure[group_id] = result
        return result

    all_groups = set(child_to_parent.keys()) | {p for parents in child_to_parent.values() for p in parents}
    for group_id in all_groups:
        _ancestors(group_id)

    LOGGER.info("Group ancestor closure built for %d groups", len(closure))
    return closure


def build_group_tier_map(groups_df: Optional[pd.DataFrame]) -> Dict[str, str]:
    """Infers the privilege tier a group confers from its name suffix
    (matching the naming convention used by the generation pipeline) or its
    is_privileged_group flag as a fallback."""
    tier_map: Dict[str, str] = {}
    if groups_df is None:
        return tier_map

    for _, row in groups_df.iterrows():
        group_id = clean_id(row["group_id"])
        if group_id is None:
            continue
        name = str(row.get("group_name", ""))
        suffix = name.split("-")[-1] if "-" in name else ""
        tier = GROUP_SUFFIX_TIER_MAP.get(suffix)
        if tier is None:
            tier = "Admin" if bool(row.get("is_privileged_group")) else "Standard"
        tier_map[group_id] = tier

    LOGGER.info("Group tier map built for %d groups (inferred from naming convention)", len(tier_map))
    return tier_map


# --------------------------------------------------------------------------- #
# Direct privileges (role_assignments.csv x platform_roles.csv)
# --------------------------------------------------------------------------- #

def compute_direct_privileges(
    role_assignments_df: pd.DataFrame,
    platform_roles_df: pd.DataFrame,
    employee_key_to_resolved: Dict[str, int],
) -> Dict[int, List[Dict]]:
    LOGGER.info("Computing direct privileges from role_assignments.csv")
    role_tier_lookup: Dict[str, Tuple[str, int, str]] = {}
    for _, row in platform_roles_df.iterrows():
        key = clean_id(row["platform_role_id"])
        if key is not None:
            role_tier_lookup[key] = (row["privilege_tier"], row["platform_id"], row.get("native_role_name", ""))

    by_identity: Dict[int, List[Dict]] = {}
    n_bridged, n_unbridged, n_inactive = 0, 0, 0

    for _, row in role_assignments_df.iterrows():
        if row.get("status") != "Active":
            n_inactive += 1
            continue

        platform_role_key = clean_id(row["platform_role_id"])
        role_info = role_tier_lookup.get(platform_role_key)
        if role_info is None:
            continue
        tier, platform_id, native_role_name = role_info

        original_identity_key = clean_id(row["identity_id"])
        resolved_id = employee_key_to_resolved.get(original_identity_key)
        if resolved_id is None:
            resolved_id = f"UNBRIDGED:{original_identity_key}"
            n_unbridged += 1
        else:
            n_bridged += 1

        by_identity.setdefault(resolved_id, []).append(
            {
                "source": "Direct",
                "platform_id": platform_id,
                "platform_name": PLATFORM_ID_TO_NAME.get(platform_id, f"Platform-{platform_id}"),
                "tier": tier,
                "depth": 0,
                "detail": f"Direct {tier} via role '{native_role_name}'",
                "assignment_type": row.get("assignment_type"),
            }
        )

    LOGGER.info(
        "Direct privileges computed -> bridged rows: %d | unbridged rows: %d | inactive/skipped rows: %d",
        n_bridged, n_unbridged, n_inactive,
    )
    return by_identity


# --------------------------------------------------------------------------- #
# Inherited / nested-group privileges (group_memberships.csv x nesting closure)
# --------------------------------------------------------------------------- #

def compute_inherited_privileges(
    group_memberships_df: pd.DataFrame,
    account_to_resolved: Dict[Tuple[str, str], int],
    ancestor_closure: Dict[str, Dict[str, int]],
    group_tier_map: Dict[str, str],
) -> Dict[int, List[Dict]]:
    LOGGER.info("Computing inherited privileges from group_memberships.csv + nested group closure")
    by_identity: Dict[int, List[Dict]] = {}
    n_matched_account, n_unmatched_account = 0, 0

    for _, row in group_memberships_df.iterrows():
        platform_id = row["platform_id"]
        platform_name = PLATFORM_ID_TO_NAME.get(platform_id, f"Platform-{platform_id}")
        account_key = (platform_name, str(row["platform_account_id"]))
        resolved_id = account_to_resolved.get(account_key)
        if resolved_id is None:
            n_unmatched_account += 1
            continue
        n_matched_account += 1

        direct_group_id = clean_id(row["group_id"])
        if direct_group_id is None:
            continue

        # the directly-joined group itself (depth 0) plus every ancestor it inherits from
        chain: List[Tuple[str, int]] = [(direct_group_id, 0)]
        chain.extend(ancestor_closure.get(direct_group_id, {}).items())

        for group_id, depth in chain:
            tier = group_tier_map.get(group_id, UNKNOWN_TIER)
            by_identity.setdefault(resolved_id, []).append(
                {
                    "source": "Inherited" if depth > 0 else "Direct Group Membership",
                    "platform_id": platform_id,
                    "platform_name": platform_name,
                    "tier": tier,
                    "depth": depth,
                    "detail": (
                        f"{'Inherited' if depth > 0 else 'Direct group membership'} {tier} "
                        f"via group GROUP:{group_id}" + (f" (nesting depth {depth})" if depth > 0 else "")
                    ),
                    "group_id": group_id,
                }
            )

    LOGGER.info(
        "Inherited privileges computed -> memberships matched to a resolved identity: %d | unmatched: %d",
        n_matched_account, n_unmatched_account,
    )
    return by_identity


# --------------------------------------------------------------------------- #
# Aggregation into effective_privileges.csv
# --------------------------------------------------------------------------- #

def _merge_sources(direct: Dict[int, List[Dict]], inherited: Dict[int, List[Dict]]) -> Dict[int, List[Dict]]:
    merged: Dict[int, List[Dict]] = {}
    for d in (direct, inherited):
        for identity_id, entries in d.items():
            merged.setdefault(identity_id, []).extend(entries)
    return merged


def _highest_tier(entries: List[Dict]) -> str:
    ranked = [e["tier"] for e in entries if e["tier"] in TIER_RANK]
    if not ranked:
        return "None"
    return max(ranked, key=lambda t: TIER_RANK[t])


def _build_explanation(identity_label: str, entries: List[Dict]) -> str:
    if not entries:
        return f"{identity_label} has no active role assignments or group-derived access in scope."

    direct_entries = [e for e in entries if e["source"] == "Direct"]
    inherited_entries = [e for e in entries if e["source"] in ("Inherited", "Direct Group Membership")]

    parts = []
    if direct_entries:
        direct_summary = "; ".join(sorted({f"{e['tier']} on {e['platform_name']}" for e in direct_entries}))
        parts.append(f"Direct grants: {direct_summary}.")
    nested_only = [e for e in inherited_entries if e["source"] == "Inherited"]
    if nested_only:
        deepest = max(nested_only, key=lambda e: e["depth"])
        parts.append(
            f"Deepest inherited grant: {deepest['tier']} on {deepest['platform_name']} "
            f"via nested group chain reaching {deepest['depth']} level(s) of inheritance "
            f"(GROUP:{deepest.get('group_id')})."
        )
    platforms = sorted({e["platform_name"] for e in entries})
    parts.append(f"Effective reach spans {len(platforms)} platform(s): {', '.join(platforms)}.")
    return " ".join(parts)


def build_effective_privileges(
    merged: Dict[int, List[Dict]], resolved_context: Dict[int, pd.Series]
) -> pd.DataFrame:
    LOGGER.info("Aggregating effective privileges for %d identities", len(merged))
    records = []

    for identity_id, entries in merged.items():
        # deduplicate (platform, tier, source-depth) so the same grant observed via
        # multiple paths isn't double counted in effective_permission_count
        unique_grants = {(e["platform_id"], e["tier"], e["depth"]) for e in entries}
        direct_grants = {(e["platform_id"], e["tier"]) for e in entries if e["source"] == "Direct"}
        inherited_grants = {(e["platform_id"], e["tier"]) for e in entries if e["source"] != "Direct"}

        admin_platforms = {pid for pid, tier, _ in unique_grants if tier in ("Admin", "Super Admin")}
        super_admin_flag = any(tier == "Super Admin" for _, tier, _ in unique_grants)
        privilege_depth = max((e["depth"] for e in entries), default=0)

        blast_radius_min_rank = TIER_RANK.get(BLAST_RADIUS_MIN_TIER, 1)
        blast_platforms = {
            pid for pid, tier, _ in unique_grants
            if tier in TIER_RANK and TIER_RANK[tier] >= blast_radius_min_rank
        }

        context = resolved_context.get(identity_id)
        identity_label = (
            f"Identity {identity_id} ({context['full_name']})"
            if context is not None and pd.notna(context.get("full_name"))
            else f"Identity {identity_id}"
        )

        records.append(
            {
                "identity_id": identity_id,
                "full_name": context["full_name"] if context is not None else None,
                "employee_key": context["employee_key"] if context is not None else None,
                "identity_status": context["identity_status"] if context is not None else "Unbridged",
                "direct_permission_count": len(direct_grants),
                "inherited_permission_count": len(inherited_grants),
                "effective_permission_count": len(unique_grants),
                "admin_permission_count": len(admin_platforms),
                "super_admin_flag": super_admin_flag,
                "privilege_depth": privilege_depth,
                "privilege_blast_radius": len(blast_platforms),
                "highest_privilege_tier": _highest_tier(entries),
                "platforms_with_access": ";".join(sorted({e["platform_name"] for e in entries})),
                "explanation": _build_explanation(identity_label, entries),
            }
        )

    # include resolved identities that have zero privilege entries at all —
    # absence of access is itself a meaningful, reportable result
    covered_ids = set(merged.keys())
    for identity_id, context in resolved_context.items():
        if identity_id in covered_ids:
            continue
        records.append(
            {
                "identity_id": identity_id,
                "full_name": context.get("full_name"),
                "employee_key": context.get("employee_key"),
                "identity_status": context.get("identity_status"),
                "direct_permission_count": 0,
                "inherited_permission_count": 0,
                "effective_permission_count": 0,
                "admin_permission_count": 0,
                "super_admin_flag": False,
                "privilege_depth": 0,
                "privilege_blast_radius": 0,
                "highest_privilege_tier": "None",
                "platforms_with_access": "",
                "explanation": f"Identity {identity_id} has no active role assignments or group-derived access in scope.",
            }
        )

    df = pd.DataFrame.from_records(records).sort_values(
        ["super_admin_flag", "admin_permission_count", "privilege_blast_radius"], ascending=False
    ).reset_index(drop=True)
    LOGGER.info("Effective privileges generated: %d rows", len(df))
    return df


# --------------------------------------------------------------------------- #
# Main execution block
# --------------------------------------------------------------------------- #

def main() -> None:
    configure_logging()
    LOGGER.info("Starting effective privilege calculation")

    role_assignments_df = load_required("role_assignments")
    group_memberships_df = load_required("group_memberships")
    nested_groups_df = load_required("nested_group_relationships")
    platform_roles_df = load_required("platform_roles")
    resolved_identities_df = load_required("resolved_identities")
    groups_df = load_optional("groups")

    employee_key_to_resolved, account_to_resolved, resolved_context = build_identity_bridges(resolved_identities_df)
    ancestor_closure = build_group_ancestor_closure(nested_groups_df)
    group_tier_map = build_group_tier_map(groups_df)

    direct = compute_direct_privileges(role_assignments_df, platform_roles_df, employee_key_to_resolved)
    inherited = compute_inherited_privileges(
        group_memberships_df, account_to_resolved, ancestor_closure, group_tier_map
    )
    merged = _merge_sources(direct, inherited)

    effective_df = build_effective_privileges(merged, resolved_context)
    save_csv(effective_df, "effective_privileges.csv")

    LOGGER.info(
        "Summary -> identities scored: %d | Super Admins: %d | avg effective_permission_count: %.2f | "
        "avg privilege_blast_radius: %.2f",
        len(effective_df),
        int(effective_df["super_admin_flag"].sum()),
        effective_df["effective_permission_count"].mean(),
        effective_df["privilege_blast_radius"].mean(),
    )
    LOGGER.info("Effective privilege calculation complete")


if __name__ == "__main__":
    main()
