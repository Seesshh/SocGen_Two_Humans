"""
src/intelligence/graph_builder.py

Identity Graph Engine for the Hybrid Identity Governance platform
(Phase 4 Identity Graph Engine component, Phase 5 MVP scope).

Builds a single NetworkX MultiDiGraph spanning Employees, Identities, platform
Accounts, Groups, (business) Roles, Permissions, Service Accounts, Tokens, and
Departments, then computes degree centrality, betweenness centrality, and a
custom "privilege reach" metric per node.

Required inputs (per the Phase 5 blueprint contract):
    resolved_identities.csv, group_memberships.csv, roles.csv,
    role_assignments.csv, service_accounts.csv, api_tokens.csv

Two design notes, since this module's required-input contract does not include
every table referenced by every requested node/edge type:

  * No `permissions.csv`/`platform_roles.csv` is in scope. Each distinct
    `platform_role_id` observed in role_assignments.csv is therefore modeled
    directly as a Permission node (the platform-specific grant itself is the
    finest-grained access unit available from the required inputs).
  * `departments.csv`, `persons.csv`/`employees.csv` (for REPORTS_TO), and
    `nested_group_relationships.csv` (for INHERITS) are *optionally* loaded
    from the same data directory if present, to enrich Department nodes,
    manager-reporting edges, and group-nesting edges. Their absence does not
    fail the build — those node/edge types are simply left empty, and a clear
    log message explains why.

Outputs:
    identity_graph.pkl  — the built networkx.MultiDiGraph, pickled
    graph_metrics.csv   — per-node degree centrality, betweenness centrality,
                           and privilege reach
"""

from __future__ import annotations

import logging
import pickle
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import networkx as nx
import numpy as np
import pandas as pd

# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #

DATA_DIR: Path = Path("data/synthetic_data")
OUTPUT_DIR: Path = Path("data/synthetic_data")

PLATFORM_ID_TO_NAME: Dict[int, str] = {1: "Active Directory", 2: "Azure AD", 3: "AWS IAM", 4: "Okta", 5: "Salesforce"}

REQUIRED_INPUTS: Dict[str, str] = {
    "resolved_identities": "resolved_identities.csv",
    "group_memberships": "group_memberships.csv",
    "roles": "roles.csv",
    "role_assignments": "role_assignments.csv",
    "service_accounts": "service_accounts.csv",
    "api_tokens": "api_tokens.csv",
}
OPTIONAL_INPUTS: Dict[str, str] = {
    "departments": "departments.csv",
    "employees": "employees.csv",          # falls back to persons.csv if absent
    "persons": "persons.csv",
    "groups": "groups.csv",
    "nested_group_relationships": "nested_group_relationships.csv",
}

PRIVILEGE_REACH_CUTOFF: int = 5             # hop limit, mirrors the graph-traversal depth cap used elsewhere
BETWEENNESS_EXACT_NODE_LIMIT: int = 500     # below this, compute exact betweenness
BETWEENNESS_SAMPLE_SIZE: int = 200          # above the limit, approximate with k sampled sources
BETWEENNESS_SEED: int = 42

LOGGER = logging.getLogger("graph_builder")


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
        LOGGER.warning("Optional enrichment input '%s' not found — related node/edge types will be skipped", filename)
        return None
    df = pd.read_csv(path)
    LOGGER.info("Loaded optional input %s (%d rows)", filename, len(df))
    return df


def save_pickle(graph: nx.MultiDiGraph, filename: str) -> Path:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    path = OUTPUT_DIR / filename
    with open(path, "wb") as f:
        pickle.dump(graph, f, protocol=pickle.HIGHEST_PROTOCOL)
    LOGGER.info("Saved %s (%.2f MB)", path, path.stat().st_size / (1024 * 1024))
    return path


def save_csv(df: pd.DataFrame, filename: str) -> Path:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    path = OUTPUT_DIR / filename
    df.to_csv(path, index=False)
    LOGGER.info("Saved %s (%d rows, %d columns)", path, len(df), len(df.columns))
    return path


# --------------------------------------------------------------------------- #
# Node key builders — string-prefixed composite keys avoid cross-type ID collisions.
#
# Every builder routes through _clean_id() because pandas silently upcasts an
# otherwise-integer ID column to float64 the moment it contains even one NaN
# (e.g. business_role_id on ungoverned injected grants, employee_key on
# orphaned identities) — without normalization, "565" and "565.0" would
# produce two different node keys for what should be the same node.
# --------------------------------------------------------------------------- #

def _clean_id(value) -> Optional[str]:
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


def k_employee(employee_key) -> Optional[str]:
    clean = _clean_id(employee_key)
    return f"EMPLOYEE:{clean}" if clean is not None else None


def k_identity(identity_id) -> Optional[str]:
    clean = _clean_id(identity_id)
    return f"IDENTITY:{clean}" if clean is not None else None


def k_account(platform_name: str, account_id: str) -> str:
    return f"ACCOUNT:{platform_name}:{account_id}"


def k_group(group_id) -> Optional[str]:
    clean = _clean_id(group_id)
    return f"GROUP:{clean}" if clean is not None else None


def k_role(role_id) -> Optional[str]:
    clean = _clean_id(role_id)
    return f"ROLE:{clean}" if clean is not None else None


def k_permission(platform_role_id) -> Optional[str]:
    clean = _clean_id(platform_role_id)
    return f"PERMISSION:{clean}" if clean is not None else None


def k_service_account(service_account_id) -> Optional[str]:
    clean = _clean_id(service_account_id)
    return f"SERVICEACCOUNT:{clean}" if clean is not None else None


def k_token(token_id) -> Optional[str]:
    clean = _clean_id(token_id)
    return f"TOKEN:{clean}" if clean is not None else None


def k_department(department_id) -> Optional[str]:
    clean = _clean_id(department_id)
    return f"DEPARTMENT:{clean}" if clean is not None else None


def _parse_matched_accounts(matched_accounts: str) -> List[Tuple[str, str]]:
    """Parses 'Platform:account_id;Platform:account_id;...' into [(platform, account_id), ...]."""
    if not isinstance(matched_accounts, str) or not matched_accounts.strip():
        return []
    pairs = []
    for chunk in matched_accounts.split(";"):
        chunk = chunk.strip()
        if not chunk or ":" not in chunk:
            continue
        platform_name, account_id = chunk.split(":", 1)
        pairs.append((platform_name.strip(), account_id.strip()))
    return pairs


# --------------------------------------------------------------------------- #
# Node construction
# --------------------------------------------------------------------------- #

def add_employee_and_identity_and_account_nodes(
    graph: nx.MultiDiGraph, resolved_identities_df: pd.DataFrame
) -> None:
    n_employee, n_identity, n_account = 0, 0, 0
    for _, row in resolved_identities_df.iterrows():
        identity_node = k_identity(row["identity_id"])
        graph.add_node(
            identity_node,
            node_type="Identity",
            identity_id=row["identity_id"],
            identity_status=row.get("identity_status"),
            confidence_score=row.get("confidence_score"),
        )
        n_identity += 1

        employee_key = row.get("employee_key")
        employee_node = k_employee(employee_key)
        if employee_node:
            if employee_node not in graph:
                graph.add_node(
                    employee_node,
                    node_type="Employee",
                    employee_key=employee_key,
                    full_name=row.get("full_name"),
                    email=row.get("email"),
                    employment_type=row.get("employment_type"),
                )
                n_employee += 1
            graph.add_edge(employee_node, identity_node, edge_type="OWNS")

        for platform_name, account_id in _parse_matched_accounts(row.get("matched_accounts", "")):
            account_node = k_account(platform_name, account_id)
            if account_node not in graph:
                graph.add_node(account_node, node_type="Account", platform=platform_name, platform_account_id=account_id)
                n_account += 1
            graph.add_edge(identity_node, account_node, edge_type="OWNS")

    LOGGER.info("Nodes added -> Employee: %d | Identity: %d | Account: %d", n_employee, n_identity, n_account)


def add_group_nodes(
    graph: nx.MultiDiGraph, group_memberships_df: pd.DataFrame, groups_df: Optional[pd.DataFrame]
) -> Dict[int, str]:
    group_attrs: Dict[int, Dict] = {}
    if groups_df is not None:
        for _, row in groups_df.iterrows():
            group_attrs[row["group_id"]] = {
                "group_name": row.get("group_name"),
                "group_type": row.get("group_type"),
                "is_privileged_group": row.get("is_privileged_group"),
            }

    n_group = 0
    for group_id in group_memberships_df["group_id"].unique():
        node = k_group(group_id)
        attrs = group_attrs.get(group_id, {})
        graph.add_node(node, node_type="Group", group_id=group_id, **attrs)
        n_group += 1
    LOGGER.info("Nodes added -> Group: %d", n_group)
    return {gid: k_group(gid) for gid in group_memberships_df["group_id"].unique()}


def add_role_and_department_nodes(graph: nx.MultiDiGraph, roles_df: pd.DataFrame) -> None:
    n_role, n_dept = 0, 0
    seen_depts = set()
    for _, row in roles_df.iterrows():
        role_node = k_role(row["role_id"])
        graph.add_node(
            role_node,
            node_type="Role",
            role_id=row["role_id"],
            role_name=row.get("role_name"),
            role_category=row.get("role_category"),
            is_privileged=row.get("is_privileged"),
        )
        n_role += 1

        dept_id = row.get("owning_department_id")
        if pd.notna(dept_id):
            dept_node = k_department(dept_id)
            if dept_id not in seen_depts:
                graph.add_node(dept_node, node_type="Department", department_id=dept_id)
                seen_depts.add(dept_id)
                n_dept += 1
            graph.add_edge(role_node, dept_node, edge_type="MEMBER_OF")

    LOGGER.info("Nodes added -> Role: %d | Department: %d (proxy, ID-only unless enriched)", n_role, n_dept)


def enrich_department_names(graph: nx.MultiDiGraph, departments_df: Optional[pd.DataFrame]) -> None:
    if departments_df is None:
        return
    name_lookup = dict(zip(departments_df["department_id"], departments_df["department_name"]))
    updated = 0
    for node, attrs in graph.nodes(data=True):
        if attrs.get("node_type") == "Department":
            dept_id = attrs.get("department_id")
            if dept_id in name_lookup:
                graph.nodes[node]["department_name"] = name_lookup[dept_id]
                updated += 1
    LOGGER.info("Enriched %d Department nodes with names from departments.csv", updated)


def add_permission_nodes(graph: nx.MultiDiGraph, role_assignments_df: pd.DataFrame) -> None:
    n_permission = 0
    for platform_role_id in role_assignments_df["platform_role_id"].dropna().unique():
        node = k_permission(platform_role_id)
        graph.add_node(node, node_type="Permission", platform_role_id=platform_role_id)
        n_permission += 1
    LOGGER.info(
        "Nodes added -> Permission: %d (proxy: one per distinct platform_role_id — "
        "no permissions.csv/platform_roles.csv in this module's input contract)",
        n_permission,
    )


def add_service_account_and_token_nodes(
    graph: nx.MultiDiGraph, service_accounts_df: pd.DataFrame, api_tokens_df: pd.DataFrame
) -> None:
    n_sa = 0
    for _, row in service_accounts_df.iterrows():
        node = k_service_account(row["service_account_id"])
        graph.add_node(
            node,
            node_type="ServiceAccount",
            service_account_id=row["service_account_id"],
            account_name=row.get("account_name"),
            criticality=row.get("criticality"),
            privilege_level=row.get("privilege_level"),
            status=row.get("status"),
            is_breakglass=row.get("is_breakglass"),
        )
        n_sa += 1

    n_token = 0
    for _, row in api_tokens_df.iterrows():
        node = k_token(row["token_id"])
        graph.add_node(
            node,
            node_type="Token",
            token_id=row["token_id"],
            scope=row.get("scope"),
            status=row.get("status"),
            rotation_status=row.get("rotation_status"),
        )
        n_token += 1

    LOGGER.info("Nodes added -> ServiceAccount: %d | Token: %d", n_sa, n_token)


# --------------------------------------------------------------------------- #
# Edge construction
# --------------------------------------------------------------------------- #

def add_member_of_edges(graph: nx.MultiDiGraph, group_memberships_df: pd.DataFrame) -> None:
    n_edges = 0
    n_missing_account = 0
    for _, row in group_memberships_df.iterrows():
        platform_name = PLATFORM_ID_TO_NAME.get(row["platform_id"])
        if platform_name is None:
            continue
        account_node = k_account(platform_name, row["platform_account_id"])
        if account_node not in graph:
            n_missing_account += 1
            continue
        graph.add_edge(
            account_node, k_group(row["group_id"]), edge_type="MEMBER_OF",
            added_date=row.get("added_date"), added_by=row.get("added_by"),
        )
        n_edges += 1
    LOGGER.info("Edges added -> MEMBER_OF (Account->Group): %d (skipped %d — account not in resolved identities)",
                n_edges, n_missing_account)


def add_has_role_and_has_permission_edges(
    graph: nx.MultiDiGraph, role_assignments_df: pd.DataFrame, resolved_identities_df: pd.DataFrame
) -> None:
    identity_ids = set(resolved_identities_df["identity_id"])
    n_has_role, n_has_permission, n_role_to_permission = 0, 0, 0
    seen_role_permission_pairs = set()

    for _, row in role_assignments_df.iterrows():
        identity_id = row["identity_id"]
        if identity_id not in identity_ids:
            continue
        identity_node = k_identity(identity_id)
        permission_node = k_permission(row["platform_role_id"])

        if permission_node in graph:
            graph.add_edge(
                identity_node, permission_node, edge_type="HAS_PERMISSION",
                assignment_type=row.get("assignment_type"), status=row.get("status"),
                granted_date=row.get("granted_date"), expiration_date=row.get("expiration_date"),
            )
            n_has_permission += 1

        business_role_id = row.get("business_role_id")
        role_node = k_role(business_role_id)
        if role_node and role_node in graph:
            graph.add_edge(identity_node, role_node, edge_type="HAS_ROLE", status=row.get("status"))
            n_has_role += 1

            pair = (role_node, permission_node)
            if pair not in seen_role_permission_pairs and permission_node in graph:
                graph.add_edge(role_node, permission_node, edge_type="HAS_PERMISSION")
                seen_role_permission_pairs.add(pair)
                n_role_to_permission += 1

    LOGGER.info(
        "Edges added -> HAS_ROLE (Identity->Role): %d | HAS_PERMISSION (Identity->Permission): %d | "
        "HAS_PERMISSION (Role->Permission, deduplicated): %d",
        n_has_role, n_has_permission, n_role_to_permission,
    )


def add_owns_and_uses_edges(
    graph: nx.MultiDiGraph, service_accounts_df: pd.DataFrame, api_tokens_df: pd.DataFrame
) -> None:
    n_owns_sa, n_owns_token, n_uses = 0, 0, 0

    for _, row in service_accounts_df.iterrows():
        employee_node = k_employee(row.get("owner_person_id"))
        if employee_node and employee_node in graph:
            graph.add_edge(employee_node, k_service_account(row["service_account_id"]), edge_type="OWNS")
            n_owns_sa += 1

    for _, row in api_tokens_df.iterrows():
        token_node = k_token(row["token_id"])
        employee_node = k_employee(row.get("owner_person_id"))
        sa_node = k_service_account(row.get("owner_service_account_id"))

        if employee_node and employee_node in graph:
            graph.add_edge(employee_node, token_node, edge_type="OWNS")
            n_owns_token += 1
        elif sa_node and sa_node in graph:
            graph.add_edge(sa_node, token_node, edge_type="USES")
            n_uses += 1

    LOGGER.info(
        "Edges added -> OWNS (Employee->ServiceAccount): %d | OWNS (Employee->Token): %d | "
        "USES (ServiceAccount->Token): %d",
        n_owns_sa, n_owns_token, n_uses,
    )


def add_reports_to_edges(graph: nx.MultiDiGraph, persons_df: Optional[pd.DataFrame]) -> None:
    if persons_df is None:
        LOGGER.warning("Skipping REPORTS_TO edges — no persons.csv/employees.csv available with manager data")
        return
    if "manager_person_id" not in persons_df.columns or "person_id" not in persons_df.columns:
        LOGGER.warning("Skipping REPORTS_TO edges — manager_person_id/person_id columns not present")
        return

    n_edges = 0
    for _, row in persons_df.iterrows():
        employee_node = k_employee(row.get("person_id"))
        manager_node = k_employee(row.get("manager_person_id"))
        if employee_node and manager_node and employee_node in graph and manager_node in graph:
            graph.add_edge(employee_node, manager_node, edge_type="REPORTS_TO")
            n_edges += 1
    LOGGER.info("Edges added -> REPORTS_TO (Employee->Employee): %d", n_edges)


def add_inherits_edges(graph: nx.MultiDiGraph, nested_groups_df: Optional[pd.DataFrame]) -> None:
    if nested_groups_df is None:
        LOGGER.warning("Skipping INHERITS edges — no nested_group_relationships.csv available")
        return

    n_edges = 0
    for _, row in nested_groups_df.iterrows():
        child_node = k_group(row["child_group_id"])
        parent_node = k_group(row["parent_group_id"])
        if child_node in graph and parent_node in graph:
            graph.add_edge(child_node, parent_node, edge_type="INHERITS", nesting_depth=row.get("nesting_depth"))
            n_edges += 1
    LOGGER.info("Edges added -> INHERITS (Group->Group): %d", n_edges)


# --------------------------------------------------------------------------- #
# Metrics
# --------------------------------------------------------------------------- #

def compute_degree_centrality(graph: nx.MultiDiGraph) -> Dict[str, float]:
    LOGGER.info("Computing degree centrality")
    return nx.degree_centrality(graph)


def compute_betweenness_centrality(graph: nx.MultiDiGraph) -> Dict[str, float]:
    n = graph.number_of_nodes()
    simple_graph = nx.DiGraph(graph)  # betweenness centrality requires a simple graph, not a multigraph
    if n <= BETWEENNESS_EXACT_NODE_LIMIT:
        LOGGER.info("Computing exact betweenness centrality (%d nodes)", n)
        return nx.betweenness_centrality(simple_graph)
    LOGGER.info(
        "Graph has %d nodes (> %d) — approximating betweenness centrality with k=%d sampled sources",
        n, BETWEENNESS_EXACT_NODE_LIMIT, BETWEENNESS_SAMPLE_SIZE,
    )
    return nx.betweenness_centrality(simple_graph, k=min(BETWEENNESS_SAMPLE_SIZE, n), seed=BETWEENNESS_SEED)


def compute_privilege_reach(graph: nx.MultiDiGraph) -> Dict[str, int]:
    """For every node, counts how many distinct Permission nodes are reachable
    via outgoing directed paths within PRIVILEGE_REACH_CUTOFF hops — a proxy
    for 'how much access does compromising this node ultimately expose'."""
    LOGGER.info("Computing privilege reach (cutoff=%d hops)", PRIVILEGE_REACH_CUTOFF)
    reach: Dict[str, int] = {}
    for node in graph.nodes:
        reachable = nx.single_source_shortest_path_length(graph, node, cutoff=PRIVILEGE_REACH_CUTOFF)
        permission_count = sum(
            1 for n in reachable if n != node and graph.nodes[n].get("node_type") == "Permission"
        )
        reach[node] = permission_count
    return reach


def build_graph_metrics(graph: nx.MultiDiGraph) -> pd.DataFrame:
    degree = compute_degree_centrality(graph)
    betweenness = compute_betweenness_centrality(graph)
    privilege_reach = compute_privilege_reach(graph)

    records = []
    for node, attrs in graph.nodes(data=True):
        records.append(
            {
                "node_id": node,
                "node_type": attrs.get("node_type"),
                "degree_centrality": round(degree.get(node, 0.0), 6),
                "betweenness_centrality": round(betweenness.get(node, 0.0), 6),
                "privilege_reach": privilege_reach.get(node, 0),
            }
        )
    df = pd.DataFrame.from_records(records).sort_values("privilege_reach", ascending=False).reset_index(drop=True)
    return df


def log_node_and_edge_counts(graph: nx.MultiDiGraph) -> None:
    node_type_counts = pd.Series([attrs.get("node_type") for _, attrs in graph.nodes(data=True)]).value_counts()
    edge_type_counts = pd.Series([attrs.get("edge_type") for _, _, attrs in graph.edges(data=True)]).value_counts()
    LOGGER.info("Node counts by type:\n%s", node_type_counts.to_string())
    LOGGER.info("Edge counts by type:\n%s", edge_type_counts.to_string())
    LOGGER.info("Total nodes: %d | Total edges: %d", graph.number_of_nodes(), graph.number_of_edges())


# --------------------------------------------------------------------------- #
# Main execution block
# --------------------------------------------------------------------------- #

def main() -> None:
    configure_logging()
    LOGGER.info("Starting identity graph construction")

    resolved_identities_df = load_required("resolved_identities")
    group_memberships_df = load_required("group_memberships")
    roles_df = load_required("roles")
    role_assignments_df = load_required("role_assignments")
    service_accounts_df = load_required("service_accounts")
    api_tokens_df = load_required("api_tokens")

    departments_df = load_optional("departments")
    groups_df = load_optional("groups")
    nested_groups_df = load_optional("nested_group_relationships")
    persons_df = load_optional("employees") or load_optional("persons")

    graph = nx.MultiDiGraph()

    # --- nodes ---
    add_employee_and_identity_and_account_nodes(graph, resolved_identities_df)
    add_group_nodes(graph, group_memberships_df, groups_df)
    add_role_and_department_nodes(graph, roles_df)
    enrich_department_names(graph, departments_df)
    add_permission_nodes(graph, role_assignments_df)
    add_service_account_and_token_nodes(graph, service_accounts_df, api_tokens_df)

    # --- edges ---
    add_member_of_edges(graph, group_memberships_df)
    add_has_role_and_has_permission_edges(graph, role_assignments_df, resolved_identities_df)
    add_owns_and_uses_edges(graph, service_accounts_df, api_tokens_df)
    add_reports_to_edges(graph, persons_df)
    add_inherits_edges(graph, nested_groups_df)

    log_node_and_edge_counts(graph)

    metrics_df = build_graph_metrics(graph)

    save_pickle(graph, "identity_graph.pkl")
    save_csv(metrics_df, "graph_metrics.csv")

    LOGGER.info(
        "Top 5 nodes by privilege reach:\n%s",
        metrics_df.head(5)[["node_id", "node_type", "privilege_reach"]].to_string(index=False),
    )
    LOGGER.info("Identity graph construction complete")


if __name__ == "__main__":
    main()
