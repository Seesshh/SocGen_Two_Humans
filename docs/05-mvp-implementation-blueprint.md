# Hybrid Identity Governance — Hackathon MVP Implementation Blueprint (Phase 5)
### Source of truth: Phase 1 (Business Analysis) + Phase 2 (33-table Data Model) + Phase 3 (Generation Strategy) + Phase 4 (Detection Engine Design)

*Scope note: This document does not redesign entities, anomalies, or architecture from Phases 1–4. It scopes that design down to what one engineer can build in 48 hours, and specifies exact implementation logic, function signatures, and schemas for that scope. Function signatures and pseudocode are provided for clarity; this is a blueprint, not a finished codebase.*

---

## STEP 1 — MVP SCOPE REDUCTION

| Layer (from Phase 4) | MUST (MVP) | SHOULD (V2) | OPTIONAL (Future Roadmap) |
|---|---|---|---|
| **Identity Resolution** | Exact email/employee-ID match + fuzzy-name fallback, confidence scoring, manual-review flag | Conflict-handling disambiguation queue, periodic re-validation | Full negative-constraint rule set, ML-based matching |
| **Identity Graph** | NetworkX graph with core node/edge types (Person, Identity, PlatformAccount, Group, PlatformRole, ServiceAccount, Token); nightly-equivalent single batch build | Point-in-time snapshotting, incremental updates | Graph database (Neo4j) backend, real-time delta updates |
| **Effective Privilege Calculator** | Direct + group + **nested-group** resolution (the core differentiator); privilege-tier-level output (not full atomic-permission algebra) | Role-chaining (`CAN_ASSUME`) closure, full permission-catalog resolution | Control-plane exposure / programmatic-privilege split, asset-reachability scoring |
| **Rule Engine** | 7 core rules: Offboarding Gap, Dormant Admin, Cross-Platform Admin, Privilege Creep, Service Account Abuse, Token Abuse, Orphaned Account | Remaining 6 of the 13 Phase-4 rules (MFA Disabled Admin, Impossible Travel, Contractor Access After Expiry, Break-Glass Abuse, Persistent SoD Violation, ungoverned Privilege Escalation) | Full 15 advanced anomalies from Phase 3 |
| **Behavior Analytics** | None — dormancy handled as a simple Rule Engine threshold check (last-login vs. now) | Per-identity baselining for login timing/geography | Full statistical/ML behavioral baselining, impossible-travel velocity calc |
| **Risk Scoring** | Simplified weighted sum across 3 components: Privilege, Governance, Cross-Platform (drop Behavior and Exposure sub-scores — no Behavior Analytics or Graph Analytics yet to feed them) | Reintroduce Behavior Risk once behavioral baselining exists | Full 5-component formula, time-decay modeling |
| **Incident Correlation** | Group by same `identity_id` + fixed 72-hour window; severity = max(component severities) + count-based bonus | Escalation-pattern recognition (specific ordered sequences) | Cross-identity graph-proximity correlation |
| **Graph Analytics** | None for MVP — Graph Explorer page shows direct visualization only (no centrality/path-finding compute) | Shortest-path-to-asset, lateral movement path-finding | Centrality, blast radius, toxic-combination matrix |
| **Dashboard** | 5 pages: Executive Overview, Identity Risk Registry, Identity Graph Explorer, Incident Investigation, Offboarding Monitor | Privilege Analytics, Service Account Monitor, Token Governance pages | Full 8-page Phase 4 dashboard, RBAC, drilldown depth |
| **Incident Narratives** | Template-based (string formatting, no LLM call) using the exact 4 example formats from Phase 4 Step 11 | LLM-generated narratives (API call) | Fully dynamic, context-aware generation |

**Aggressive reduction principle:** every cut above removes *breadth*, never the *structural insight* that makes this project distinctive — nested-group inheritance, cross-platform correlation, and an explainable risk score survive every cut; granular permission algebra, full behavioral ML, and 9 of the 22 anomaly types do not.

---

## STEP 2 — FINAL DATASETS

*Scale reduction: 1,500 total persons (1,200 employees + 300 contractors) instead of Phase 2's 6,000 — proportionally scaled (~4x down) to keep generation and in-memory processing fast within a 48-hour window, while preserving every distribution and anomaly-rate percentage exactly as designed in Phase 3.*

| Dataset | Why Required (MVP) | Can Be Removed? | Expected Row Count |
|---|---|---|---|
| `departments` | Drives role derivation and dashboard grouping | No | 20 |
| `persons` | Core identity backbone | No | 1,500 |
| `vendors` | Only needed for Contractor-Access-After-Expiry rule (not in MVP's 7) | **Yes** | 0 (V2) |
| `contracts` | Same as above | **Yes** | 0 (V2) |
| `identities` | Canonical cross-platform hub | No | ~1,540 (incl. ~40 orphans) |
| `identity_correlation_mapping` | Core deliverable — identity resolution demo | No | ~5,400 |
| `platforms` | Static reference, trivial cost | No | 5 |
| `ad_accounts` | Required for Cross-Platform Admin, Offboarding Gap | No | ~1,320 |
| `azure_accounts` | Same | No | ~1,440 |
| `okta_accounts` | Same | No | ~1,395 |
| `aws_accounts` | Same | No | ~345 |
| `salesforce_accounts` | Same | No | ~270 |
| `roles` (business) | Drives deterministic role-based generation | No | 60 |
| `platform_roles` | Required for privilege-tier detection (all 7 rules use this) | No | 160 |
| `permissions` (atomic catalog) | MVP uses `platform_roles.privilege_tier` directly instead of atomic permission resolution | **Yes** | 0 (V2) |
| `groups` | Required for nested-inheritance demo (key differentiator) | No | 300 |
| `nested_group_relationships` | Same | No | 110 |
| `group_memberships` | Same | No | ~29,000 |
| `role_assignments` | Required for Privilege Creep, Cross-Platform Admin | No | ~6,200 |
| `permission_assignments` | Direct-exception layer; not required by any of the 7 MVP rules | **Yes** | 0 (V2) |
| `service_accounts` | Required for Service Account Abuse | No | 210 |
| `api_tokens` | Required for Token Abuse | No | 600 |
| `access_reviews` | No MVP dashboard page consumes review data | **Yes** | 0 (V2) |
| `review_decisions` | Same | **Yes** | 0 (V2) |
| `offboarding_events` | Required for Offboarding Gap + Offboarding Monitor page | No | ~1,300 |
| `privilege_escalation_events` | Only needed for ungoverned-escalation rule (not in MVP's 7) | **Yes** | 0 (V2) |
| `authentication_events` | Required for Dormant Admin + Service Account Abuse, but generated **sparse** (see note) | No (reduced) | ~30,000 |
| `audit_log_events` | No MVP rule consumes this | **Yes** | 0 (V2) |
| `sod_rules` / `sod_violations` | Persistent SoD Violation is not in MVP's 7 rules | **Yes** | 0 (V2) |
| `mfa_enrollment` | MFA Disabled Admin is not in MVP's 7 rules | **Yes** | 0 (V2) |
| `breakglass_usage_log` | Break-Glass Abuse is not in MVP's 7 rules | **Yes** | 0 (V2) |
| `identity_risk_scores` | Computed live by the Risk Scoring Engine at runtime — not pre-generated as a static synthetic table | N/A (engine output) | n/a |
| `identity_risk_labels` | **Ground-truth file** — critical demo asset: lets the dashboard show live precision/recall against known injected anomalies | No | ~1,540 |

**Sparse `authentication_events` technique:** rather than generating a full year of per-session events for the entire population (Phase 3's ~2.1M-row design), generate **90 days of full event-level history only for the ~20% of identities/service accounts carrying an injected anomaly** (~310 identities + relevant service accounts). For everyone else, populate `last_login_date` directly as a field on the platform-account row — sufficient for the Dormant Admin rule, which only needs a single timestamp comparison, without paying the storage/compute cost of full per-session logs for a population that doesn't need them for any MVP rule.

**Net result: 21 of 33 original datasets retained, 12 deferred to V2 — roughly 100,000–150,000 total rows across all kept tables, comfortably fast to generate in-memory and to query from Streamlit.**

---

## STEP 3 — FINAL PROJECT STRUCTURE

```
identity-risk-platform/
├── README.md
├── requirements.txt
├── config.py                          # central constants: row counts, thresholds, file paths
│
├── data/
│   └── synthetic_data/                # all generated CSVs land here
│       ├── departments.csv
│       ├── persons.csv
│       ├── identities.csv
│       ├── identity_correlation_mapping.csv
│       ├── platforms.csv
│       ├── ad_accounts.csv
│       ├── azure_accounts.csv
│       ├── aws_accounts.csv
│       ├── okta_accounts.csv
│       ├── salesforce_accounts.csv
│       ├── roles.csv
│       ├── platform_roles.csv
│       ├── groups.csv
│       ├── nested_group_relationships.csv
│       ├── group_memberships.csv
│       ├── role_assignments.csv
│       ├── service_accounts.csv
│       ├── api_tokens.csv
│       ├── offboarding_events.csv
│       ├── authentication_events.csv
│       └── identity_risk_labels.csv
│
├── src/
│   ├── data_generation/
│   │   ├── __init__.py
│   │   ├── generate_org.py            # departments, persons, roles, platform_roles
│   │   ├── generate_accounts.py       # identities, correlation mapping, 5 platform account tables
│   │   ├── generate_groups.py         # groups, nested_group_relationships, group_memberships
│   │   ├── generate_access.py         # role_assignments
│   │   ├── generate_nonhuman.py       # service_accounts, api_tokens
│   │   ├── generate_events.py         # offboarding_events, authentication_events (sparse)
│   │   ├── inject_anomalies.py        # applies the 7 anomaly injection methods + writes labels
│   │   └── run_all.py                 # orchestrates full generation in dependency order
│   │
│   ├── identity_resolution/
│   │   ├── __init__.py
│   │   └── identity_resolver.py
│   │
│   ├── graph_engine/
│   │   ├── __init__.py
│   │   ├── graph_builder.py
│   │   └── privilege_engine.py        # Effective Privilege Calculator
│   │
│   ├── rule_engine/
│   │   ├── __init__.py
│   │   ├── rules.py                   # the 7 rule functions
│   │   └── anomaly_events.py          # standardizes rule output into anomaly_events schema
│   │
│   ├── incident_engine/
│   │   ├── __init__.py
│   │   └── incident_correlator.py
│   │
│   ├── risk_engine/
│   │   ├── __init__.py
│   │   └── risk_scoring.py
│   │
│   ├── narratives/
│   │   ├── __init__.py
│   │   └── narrative_templates.py     # template-based incident narrative generator
│   │
│   ├── dashboard/
│   │   ├── app.py                     # Streamlit entry point
│   │   └── pages/
│   │       ├── 1_executive_overview.py
│   │       ├── 2_identity_risk_registry.py
│   │       ├── 3_identity_graph_explorer.py
│   │       ├── 4_incident_investigation.py
│   │       └── 5_offboarding_monitor.py
│   │
│   └── utils/
│       ├── __init__.py
│       ├── io_helpers.py              # CSV load/save wrappers
│       └── id_generators.py           # surrogate-key sequence helpers
│
├── models/                            # (empty for MVP — reserved for V2 ML baselining)
│
├── outputs/
│   ├── evaluation_report.md           # precision/recall vs. identity_risk_labels.csv
│   └── demo_screenshots/
│
├── docs/
│   ├── phase1_business_analysis.md
│   ├── phase2_data_model.md
│   ├── phase3_generation_strategy.md
│   ├── phase4_detection_design.md
│   └── phase5_implementation_blueprint.md   # this document
│
└── assets/
    └── logo.png
```

---

## STEP 4 — IMPLEMENTATION MODULES

| Module | Purpose | Inputs | Outputs | Key Functions | Dependencies |
|---|---|---|---|---|---|
| `identity_resolver.py` | Correlate platform accounts to canonical identities | `persons.csv`, all 5 platform account CSVs | `identity_correlation_mapping.csv` | `compute_match_confidence()`, `resolve_all_accounts()`, `flag_for_manual_review()` | pandas, `rapidfuzz` (or `difflib`) for fuzzy matching |
| `graph_builder.py` | Build the NetworkX identity graph | All MVP CSVs | In-memory `networkx.MultiDiGraph`, optionally pickled to disk for dashboard reuse | `build_graph()`, `add_person_nodes()`, `add_account_edges()`, `add_group_edges()` | networkx, identity_resolver output |
| `privilege_engine.py` | Compute effective privilege tier per identity | Graph object | Per-identity effective privilege table (identity_id, platform_id, effective_tier, source_breakdown) | `expand_nested_groups()`, `compute_effective_privilege()`, `aggregate_cross_platform()` | graph_builder output |
| `rules.py` | Run the 7 deterministic rules | All relevant CSVs + privilege_engine output | Standardized `anomaly_events` DataFrame | `rule_offboarding_gap()`, `rule_dormant_admin()`, `rule_cross_platform_admin()`, `rule_privilege_creep()`, `rule_service_account_abuse()`, `rule_token_abuse()`, `rule_orphaned_account()`, `run_all_rules()` | privilege_engine output, data CSVs |
| `incident_correlator.py` | Group anomaly events into incidents | `anomaly_events` DataFrame | `incidents` DataFrame (incident_id, identity_id, severity, contributing_events, evidence) | `group_by_identity_and_window()`, `compute_severity()`, `build_incident_records()` | rules.py output |
| `risk_scoring.py` | Compute 0–100 risk score per identity | `anomaly_events`, privilege_engine output | `identity_risk_scores` DataFrame (computed live) | `compute_privilege_risk()`, `compute_governance_risk()`, `compute_cross_platform_risk()`, `compute_total_risk()` | privilege_engine, rules.py output |
| `narrative_templates.py` | Generate human-readable incident explanations | An `incidents` row | Formatted narrative string (Exec/Technical/Evidence/Impact/Actions) | `generate_narrative(incident_row)` | incident_correlator output |
| `inject_anomalies.py` | Inject the 7 anomaly patterns into generated data and write ground-truth labels | In-progress generated tables | Modified tables + `identity_risk_labels.csv` | `inject_offboarding_gap()`, `inject_dormant_admin()`, ... (one per anomaly), `write_labels()` | All `generate_*.py` modules |
| `app.py` + `pages/*.py` | Streamlit dashboard | All CSVs + live engine outputs | Rendered UI | Page-specific render functions | All engine modules |

---

## STEP 5 — DATA GENERATOR IMPLEMENTATION PLAN

Exact sequence (adapted from Phase 2/3's dependency tiers to the MVP's reduced table set):

```
1.  departments.csv
2.  roles.csv                      (depends on departments)
3.  platforms.csv                  (static)
4.  platform_roles.csv             (depends on platforms)
5.  groups.csv                     (depends on platforms)
6.  nested_group_relationships.csv (depends on groups)
7.  persons.csv                    (depends on departments)
8.  identities.csv                 (depends on persons — ~2.6% left unlinked for orphan injection)
9.  ad_accounts.csv, azure_accounts.csv, aws_accounts.csv,
    okta_accounts.csv, salesforce_accounts.csv
                                    (depend on identities + platforms; generated together
                                     per the coverage % distributions from Phase 3 Step 2)
10. identity_correlation_mapping.csv
                                    (generated immediately after account creation, using the
                                     SAME matching logic the identity_resolver module implements
                                     — see note below)
11. service_accounts.csv           (depends on persons as owners, platforms)
12. api_tokens.csv                 (depends on service_accounts, persons, platforms)
13. group_memberships.csv          (depends on platform accounts + groups)
14. role_assignments.csv           (depends on platform accounts/identities + platform_roles + roles)
15. offboarding_events.csv         (depends on persons with status='Terminated', platforms)
16. authentication_events.csv      (sparse — depends on knowing which ~20% will carry anomalies,
                                     so generated AFTER anomaly targets are selected in step 17)
17. inject_anomalies.py runs LAST, across all already-generated tables:
       - selects the target population for each of the 7 anomalies per Phase 3's injection rates
       - mutates the relevant rows (e.g., nulling `actual_revocation_at`, stale `last_login_date`)
       - generates the sparse authentication_events rows for the selected anomaly population
       - writes identity_risk_labels.csv as the final ground-truth output
```

**Important note on step 10:** generating `identity_correlation_mapping` via the *same* matching logic as the production `identity_resolver` module (rather than a separate "answer key" generator) is a deliberate design choice — it means the demo can show the resolver actually re-deriving correct links from the raw account data live, rather than reading a pre-baked answer. The synthetic generator only needs to inject the deliberate **name inconsistencies and low-confidence cases** (Phase 3 Step 12 data-quality noise) that make this a meaningful demonstration rather than a trivial exact-match exercise.

---

## STEP 6 — IDENTITY RESOLUTION IMPLEMENTATION

**Inputs:** `persons.csv`, the 5 platform account CSVs (each contributing `login_name`, `email`, `created_date`).

**Matching fields (in priority order):**
1. `email` (platform account) vs. `persons.email` — normalized to lowercase, trimmed.
2. `full_name` (platform account, where available) vs. `persons.full_name` — normalized (lowercase, diacritics stripped, whitespace collapsed).
3. `department`/`manager` corroboration where the platform account exposes it (e.g., AD's OU path implies department).

**Confidence score formula:**
```
def compute_match_confidence(account_row, person_row) -> float:
    score = 0.0
    if exact_match(account_row.email, person_row.email):
        score = 0.95
    elif normalized_name_similarity(account_row.full_name, person_row.full_name) >= 0.92:
        score = 0.65
    elif normalized_name_similarity(account_row.full_name, person_row.full_name) >= 0.85:
        score = 0.40
    else:
        return 0.0   # no candidate

    # corroboration adjustments
    if department_matches(account_row, person_row):
        score += 0.05
    if account_row.created_date >= person_row.hire_date:
        pass  # expected, no penalty
    else:
        score -= 0.20   # logically suspicious — account predates hire

    return min(score, 1.00)
```
`normalized_name_similarity` uses a standard string-similarity ratio (e.g., `rapidfuzz.fuzz.token_sort_ratio` divided by 100) — token-sort handling means "John Smith" and "Smith, John" score identically.

**Identity correlation logic:**
```
def resolve_all_accounts(persons_df, account_dfs: dict) -> pd.DataFrame:
    mappings = []
    for platform_id, accounts_df in account_dfs.items():
        for _, account in accounts_df.iterrows():
            candidates = [(p, compute_match_confidence(account, p)) for _, p in persons_df.iterrows()]
            candidates = [c for c in candidates if c[1] > 0]
            candidates.sort(key=lambda c: c[1], reverse=True)
            if not candidates:
                mappings.append(make_orphan_mapping(account, platform_id))
            elif len(candidates) >= 2 and candidates[0][1] - candidates[1][1] < 0.05:
                mappings.append(make_ambiguous_mapping(account, platform_id, candidates[:2]))  # manual review
            else:
                best_person, confidence = candidates[0]
                status = "Linked" if confidence >= 0.85 else "Under Review"
                mappings.append(make_mapping(account, platform_id, best_person, confidence, status))
    return pd.DataFrame(mappings)
```
*(For the MVP's ~1,500-person scale, a brute-force candidate comparison is fast enough — no need for blocking/indexing optimizations that would matter at the full 6,000-person scale.)*

**Output schema:** matches Phase 2's `identity_correlation_mapping` table exactly — `mapping_id`, `identity_id`, `platform_id`, `platform_account_id`, `match_method`, `match_confidence`, `linked_at`.

**Edge cases handled:**
- No candidate above 0 confidence → orphan mapping (feeds the Orphaned Account rule).
- Two candidates within 0.05 confidence of each other → flagged `'Under Review'`, never auto-linked (false-match prevention).
- Account `created_date` before person's `hire_date` → confidence penalty regardless of name match strength.

---

## STEP 7 — EFFECTIVE PRIVILEGE ENGINE IMPLEMENTATION

**Inputs:** the built NetworkX graph (from `graph_builder.py`).

**Outputs:** a flat table — one row per `(identity_id, platform_id)` — with `direct_tier`, `inherited_tier` (highest tier reached via group nesting), `effective_tier` (max of the two), and a `source_breakdown` string explaining which path produced the result (for narrative generation).

**Calculation flow:**
```
1. For each identity, find all PlatformAccount nodes connected via RESOLVES_TO.
2. For each PlatformAccount, find direct HAS_ROLE edges → direct_tier = max(privilege_tier of those roles).
3. For each PlatformAccount, find direct MEMBER_OF edges → starting group set.
4. Recursively traverse INHERITS edges from the starting group set (max depth 5) →
   full reachable group set.
5. For each group in the reachable set, check its associated HAS_PERMISSION/role linkage →
   inherited_tier = max privilege tier reachable through any group in the closure.
6. effective_tier(identity, platform) = max(direct_tier, inherited_tier).
7. Aggregate across platforms per identity → cross_platform_admin_flag = True if
   effective_tier == 'Admin' or 'Super Admin' on 2+ distinct platform_id values.
```

**NetworkX usage:**
- `nx.MultiDiGraph` as the graph type, supporting parallel edges (e.g., one person owning multiple tokens).
- `nx.descendants()` or a manual breadth-first traversal bounded by `cutoff=5` for the nested-group closure (step 4) — `nx.bfs_tree(graph, source=group_node, depth_limit=5)` restricted to `INHERITS` edges via an edge-type filter.
- Per-identity subgraph extraction (`nx.ego_graph(graph, identity_node, radius=5)`) is used by the Graph Explorer dashboard page to render only the relevant neighborhood rather than the full graph.

**Required functions:**
```
def expand_nested_groups(graph, starting_groups: set, max_depth: int = 5) -> set: ...
def compute_effective_privilege(graph, identity_id) -> dict: ...
def aggregate_cross_platform(effective_privilege_table: pd.DataFrame) -> pd.DataFrame: ...
def build_privilege_table(graph) -> pd.DataFrame: ...   # orchestrates the above for all identities
```

---

## STEP 8 — RULE ENGINE IMPLEMENTATION (7 Core Rules)

Each function returns rows conforming to a standardized `anomaly_events` schema: `(identity_id, anomaly_type, severity, evidence: dict, detected_at)`.

| Function | Inputs | Outputs | Logic |
|---|---|---|---|
| `rule_offboarding_gap(offboarding_df, accounts_dict)` | `offboarding_events.csv`, all 5 platform account DataFrames | Rows tagged `OFFBOARDING_GAP` | For each `offboarding_events` row, check whether `actual_revocation_at` is null past `expected_revocation_deadline`, **or** the matching platform account row still shows `account_status == 'Active'`. Severity = `'High'`, escalating to `'Critical'` if elapsed days since deadline > 30. |
| `rule_dormant_admin(accounts_dict, threshold_days=90)` | All 5 platform account DataFrames | Rows tagged `DORMANT_ADMIN` | Filter accounts where `privilege_tier in ('Admin','Super Admin')` and `(today - last_login_date).days > threshold_days` and `account_status == 'Active'`. Severity = `'Medium'` at threshold, `'High'` beyond 180 days. |
| `rule_cross_platform_admin(privilege_table)` | Output of `build_privilege_table()` (Step 7) | Rows tagged `CROSS_PLATFORM_ADMIN` | Group `privilege_table` by `identity_id`, count distinct `platform_id` where `effective_tier in ('Admin','Super Admin')`. Flag where count ≥ 2. Severity = `'High'` at 2, `'Critical'` at 3+. |
| `rule_privilege_creep(role_assignments_df, persons_df)` | `role_assignments.csv`, `persons.csv` (for inferred role-change timing) | Rows tagged `PRIVILEGE_CREEP` | For identities with a detected role change (earliest and latest distinct `business_role_id` per identity differ), check whether any `role_assignments` row tied to the *prior* role remains `status == 'Active'` more than 30 days after the newest role's `granted_date`. Severity = `'Medium'`, `'High'` if the stale grant's tier ≥ Admin. |
| `rule_service_account_abuse(service_accounts_df, auth_events_df, persons_df)` | `service_accounts.csv`, `authentication_events.csv`, `persons.csv` | Rows tagged `SERVICE_ACCOUNT_ABUSE` | Flag where `interactive_login_allowed == False` and a matching `authentication_events` row has `session_type == 'Interactive'`; **or** activity exists after `owner_person_id`'s `persons.status == 'Terminated'`. Severity = `'High'`, `'Critical'` if `privilege_level >= 'Admin'`. |
| `rule_token_abuse(api_tokens_df, auth_events_df)` | `api_tokens.csv`, `authentication_events.csv` | Rows tagged `TOKEN_ABUSE` | Compute each token's own trailing-baseline `usage_count_30d`; flag if current usage exceeds baseline by >3σ, **or** `last_used_date` falls after the owning entity's disablement date. Severity = `'High'`. |
| `rule_orphaned_account(identities_df, persons_df)` | `identities.csv`, `persons.csv` | Rows tagged `ORPHANED_CROSS_PLATFORM` | Flag where `identities.person_id` is null, **or** the linked `persons.status == 'Terminated'` while `identity_status` still shows `'Linked'`. Severity = `'Medium-High'`, `'Critical'` if any linked account shows Admin-tier `effective_tier`. |
| `run_all_rules(...)` | All of the above | Single concatenated `anomaly_events` DataFrame | Calls each rule function and concatenates results, then hands off to `incident_correlator.py` |

---

## STEP 9 — INCIDENT CORRELATION IMPLEMENTATION

**Alert grouping:** events from `anomaly_events` are grouped where they share the same `identity_id` **and** fall within a rolling 72-hour window of each other (using `detected_at`). MVP implementation does this via a simple sort-and-window-scan over events grouped by `identity_id` (no need for the full graph-proximity correlation from Phase 4 — same-identity grouping alone captures the highest-value cases for a demo).

**Time windows:** fixed at 72 hours, configurable via `config.py` (`INCIDENT_CORRELATION_WINDOW_HOURS = 72`).

**Severity calculation:**
```
def compute_severity(event_group: list) -> str:
    base = max(event['severity'] for event in event_group)
    distinct_types = len(set(event['anomaly_type'] for event in event_group))
    bonus = 0
    if distinct_types >= 3:
        bonus = 2   # escalate two severity levels
    elif distinct_types == 2:
        bonus = 1
    return escalate(base, bonus)   # escalate() maps Medium->High->Critical, capping at Critical
```

**Evidence collection:** each resulting `incidents` row stores: `incident_id`, `identity_id`, `severity`, `anomaly_types` (list), `contributing_event_ids`, `first_detected_at`, `last_detected_at`, and a concatenated `evidence` field pulling the `evidence` dict from every contributing event — this becomes the direct input to `narrative_templates.generate_narrative()`.

---

## STEP 10 — RISK SCORING IMPLEMENTATION

**Exact formula (MVP — 3 components, per Step 1's reduction):**
```
RiskScore(identity) = 0.45 × PrivilegeRisk + 0.35 × GovernanceRisk + 0.20 × CrossPlatformRisk
```
*(Weights rebalanced from Phase 4's 5-component 30/20/20/20/10 split, since Behavior Risk and Exposure Risk have no source engine in the MVP — their relative importance is folded into Privilege and Governance Risk rather than dropped silently.)*

| Component | Computation |
|---|---|
| `PrivilegeRisk` | `{'Standard': 5, 'Power User': 25, 'Admin': 60, 'Super Admin': 90}[effective_tier]`, taking the identity's highest effective tier across all platforms |
| `GovernanceRisk` | Sum of anomaly severity weights for every `anomaly_events` row tied to this identity (`{'Low': 10, 'Medium': 25, 'High': 50, 'Critical': 80}`), capped at 100 |
| `CrossPlatformRisk` | `100` if flagged by `rule_cross_platform_admin`, else `0` |

**Python data structures (schema, not implementation):**
```
RiskScoreRecord = {
    "identity_id": int,
    "score_date": "YYYY-MM-DD",
    "privilege_risk": float,       # 0-100
    "governance_risk": float,      # 0-100
    "cross_platform_risk": float,  # 0-100
    "total_risk_score": float,     # 0-100, weighted sum
    "risk_cluster": str,           # 'Low' | 'Medium' | 'High' | 'Critical'
    "contributing_anomaly_types": list[str],
}
```
A list of these (as `dict`s) is converted directly to a pandas DataFrame for the dashboard layer — no separate ORM/database needed for a 48-hour build.

**Feature inputs:** `build_privilege_table()` output (Step 7), `anomaly_events` (Step 8/9 output).

**Output schema:** matches the `RiskScoreRecord` structure above; written/read as `identity_risk_scores` in-memory (not persisted to CSV, computed fresh each dashboard load given the MVP's small data volume).

---

## STEP 11 — STREAMLIT DASHBOARD IMPLEMENTATION (5 Pages)

### Page 1 — Executive Overview
- **Widgets:** 4 metric cards — org-wide avg risk score, # Critical-cluster identities, offboarding SLA compliance %, # open incidents.
- **Charts:** risk cluster distribution (Plotly donut), anomaly type frequency (Plotly horizontal bar), top 10 riskiest identities (Plotly table or styled DataFrame).
- **Filters:** department dropdown, platform multiselect.
- **Tables:** top 10 open Critical/High incidents.
- **Actions:** "View Identity" button per top-riskiest row → deep-links to Page 2 with that identity pre-selected (via `st.session_state`).

### Page 2 — Identity Risk Registry
- **Widgets:** total identities count, % flagged count.
- **Charts:** risk score histogram (Plotly).
- **Filters:** department, employment type, risk cluster, anomaly type (all via `st.sidebar` multiselect/selectbox).
- **Tables:** full sortable `st.dataframe` of identities with `risk_score`, `risk_cluster`, `anomaly_types`, color-coded by cluster (via pandas Styler).
- **Actions:** row-click (via `st.dataframe` selection or a fallback `st.selectbox` of identity IDs) → expands an inline detail panel showing the 3 risk sub-scores and contributing evidence.

### Page 3 — Identity Graph Explorer
- **Widgets:** identity selector (`st.selectbox`), radius slider (1–3 hops).
- **Charts:** interactive graph rendering via `pyvis` (NetworkX → HTML, embedded with `st.components.v1.html`) showing the `nx.ego_graph()` subgraph around the selected identity.
- **Filters:** node-type checkboxes (show/hide Groups, Service Accounts, Tokens).
- **Tables:** edge list for the displayed subgraph (source, target, edge type, key properties).
- **Actions:** clicking a node in the pyvis graph (via its built-in click handling, surfaced back through a query param or selectbox sync) re-centers the view on that node.

### Page 4 — Incident Investigation
- **Widgets:** severity filter chips (Critical/High/Medium/Low).
- **Charts:** incident volume by anomaly-type combination (Plotly bar).
- **Filters:** date range, status, anomaly type.
- **Tables:** incident case list (`incident_id`, `identity_id`, `severity`, `anomaly_types`, `first_detected_at`).
- **Actions:** "Investigate" button per row → renders the full generated narrative (Step 9's evidence + `narrative_templates.generate_narrative()`) in an `st.expander`.

### Page 5 — Offboarding Monitor
- **Widgets:** SLA compliance % metric card, # open gaps metric card.
- **Charts:** time-to-revocation by platform (Plotly box plot).
- **Filters:** termination reason, platform, employment type.
- **Tables:** terminated persons with per-platform revocation status, color-coded (green = on-time, red = gap).
- **Actions:** click a person → full per-platform offboarding timeline (small Plotly timeline/Gantt-style chart).

---

## STEP 12 — DEMO FLOW (5 Minutes)

**Beginning (0:00–1:00) — The Problem**
Open on the Executive Overview page already loaded. State the problem in one sentence: *"This company has 1,500 people spread across 5 identity systems, and nobody can answer 'who has access to what' with confidence."* Point at the risk cluster donut — *"Our engine just told us 18% of identities carry at least one governance risk most teams would never find."*

**Middle, Part 1 (1:00–2:30) — Identity Resolution & the Hard Data Problem**
Switch to Identity Risk Registry. Click into one specific identity (pre-chosen, e.g., a Cross-Platform Admin case). Show its 5 platform accounts with **slightly different names/emails** — then show the `identity_correlation_mapping` confidence scores that correctly linked them anyway. *Wow moment #1: "We didn't assume clean joins — we solved the actual correlation problem."*

**Middle, Part 2 (2:30–3:30) — Effective Privilege & the Graph**
Switch to Identity Graph Explorer, centered on the same identity. Visually trace a path: direct group membership → nested parent group → privileged role — *"Here's access this person has that no flat spreadsheet would ever show you."* Show the Cross-Platform Admin flag firing because this identity is Admin on two separate platforms simultaneously. *Wow moment #2: the graph visualization itself.*

**Middle, Part 3 (3:30–4:15) — Incident Correlation & Narrative**
Switch to Incident Investigation. Open the correlated incident for this same identity — show that 3 separate raw signals (Cross-Platform Admin + Dormant Admin + a stale token) were automatically grouped into **one** Critical incident with a plain-English narrative. *Wow moment #3: "This isn't a wall of alerts — it's one investigation-ready case file."*

**End (4:15–5:00) — Trust & Validation**
Switch to a quick terminal/notebook output (prepared in advance) showing `evaluation_report.md`: precision/recall computed against `identity_risk_labels.csv`, including the orphaned-account detection rate specifically called out. *Closing line: "Every score this system produces traces back to evidence we can show you — that's what makes it auditable, not just a demo."*

**What judges learn:** this team understood the *actual* hard problems (identity correlation, nested inheritance, alert fatigue) rather than building a generic anomaly-flagging toy — and validated their own detector against ground truth instead of just asserting it works.

---

## STEP 13 — BUILD ORDER (48 Hours, One Engineer)

| Hours | Task |
|---|---|
| **1–4** | Project scaffolding (folder structure, `requirements.txt`, `config.py`); write `generate_org.py` (departments, roles, persons, platform_roles) |
| **5–8** | `generate_accounts.py` — identities + 5 platform account tables with coverage-% distributions from Phase 3 |
| **9–12** | `generate_groups.py` (groups, nesting, memberships) + `generate_access.py` (role_assignments) — get the deterministic role-derivation logic working end to end |
| **13–16** | `generate_nonhuman.py` (service accounts, tokens) + `generate_events.py` (offboarding events, sparse auth events skeleton) |
| **17–20** | `inject_anomalies.py` — implement all 7 injection methods + write `identity_risk_labels.csv`; **run full generation pipeline end-to-end and sanity-check row counts/distributions** |
| **21–24** | `identity_resolver.py` — implement matching + confidence scoring against the now-generated data; validate it correctly re-derives the known-correct links |
| **25–28** | `graph_builder.py` — build the NetworkX graph from all generated tables |
| **29–32** | `privilege_engine.py` — nested-group expansion, effective tier calculation, cross-platform aggregation |
| **33–35** | `rules.py` — implement and test all 7 rule functions against the privilege engine output |
| **36–37** | `incident_correlator.py` — grouping + severity logic |
| **38–39** | `risk_scoring.py` — 3-component formula |
| **40** | `narrative_templates.py` — 4 template formats from Phase 4 Step 11 |
| **41–45** | Streamlit dashboard — build all 5 pages, wire to engine outputs (this is the largest single remaining block; build Executive Overview and Identity Risk Registry first since the demo opens there) |
| **46** | Generate `evaluation_report.md` (precision/recall vs. `identity_risk_labels.csv`) for the demo's closing moment |
| **47** | End-to-end demo rehearsal; fix any broken cross-page navigation or slow queries |
| **48** | Buffer — bug fixes, polish, prepare the pre-chosen "hero" identity used throughout the demo script |

---

## FINAL OUTPUT

### 1. Final MVP Architecture
Data Generator → Identity Resolver → Graph Builder → Effective Privilege Engine → Rule Engine (7 rules) → Incident Correlator → Risk Scoring Engine (3-component) → Narrative Templates → Streamlit Dashboard (5 pages). Behavior Analytics and full Graph Analytics are explicitly deferred to V2.

### 2. Final Folder Structure
As specified in Step 3 — 6 `src/` subpackages, flat CSV data layer, no database required.

### 3. Final Module List
9 core modules (Step 4): `identity_resolver.py`, `graph_builder.py`, `privilege_engine.py`, `rules.py`, `incident_correlator.py`, `risk_scoring.py`, `narrative_templates.py`, `inject_anomalies.py`, plus the Streamlit app and its 5 pages.

### 4. Final Build Order
48-hour, hour-by-hour sequence (Step 13) — data generation first (hours 1–20), detection pipeline second (hours 21–40), dashboard and polish last (hours 41–48).

### 5. Final Dashboard Design
5 Streamlit pages (Step 11), each with defined widgets, charts, filters, tables, and actions, all backed by pandas DataFrames with no external database dependency.

### 6. Final Demo Script
5-minute narrative arc (Step 12): Problem → Identity Resolution wow moment → Graph/Effective Privilege wow moment → Incident Correlation wow moment → Validated-accuracy closing moment.

---

*End of Phase 5 implementation blueprint. Function signatures and pseudocode above specify exact logic and structure; full implementation (writing and testing the actual module bodies) is the next step beyond this document.*
