# Hybrid Identity Governance — Detection & Risk Intelligence Engine (Phase 4)
### Source of truth: Phase 1 (Business Analysis) + Phase 2 (33-table Data Model) + Phase 3 (Generation Strategy, 22-category anomaly taxonomy, risk weighting model)

*Scope note: This document designs the detection intelligence layer only — architecture, algorithms, formulas, and rule logic, described in plain language. No code. No datasets/entities/anomalies are redesigned; all references map directly to Phase 2 table/column names and Phase 3's anomaly taxonomy.*

---

## STEP 1 — DETECTION ENGINE ARCHITECTURE

### Overall data flow
```
33 Source Tables (Phase 2)
        │
        ▼
 IDENTITY RESOLVER ──────► identities + identity_correlation_mapping (confidence-scored)
        │
        ▼
 IDENTITY GRAPH ENGINE ──► in-memory graph (nodes/edges from all relationship tables)
        │
        ▼
 EFFECTIVE PRIVILEGE CALCULATOR ──► per-identity effective permission sets (direct/inherited/chained)
        │
        ├──────────────────────────────┐
        ▼                              ▼
   RULE ENGINE                BEHAVIOR ANALYTICS ENGINE
 (deterministic, 13+ rules)   (per-identity statistical baselining)
        │                              │
        └──────────────┬───────────────┘
                        ▼
              ANOMALY DETECTION ENGINE
           (unifies both into standardized anomaly_events,
                  tagged with Phase 3's 22-category taxonomy)
                        │
          ┌─────────────┴─────────────┐
          ▼                           ▼
  RISK SCORING ENGINE        INCIDENT CORRELATION ENGINE
  (identity_risk_scores)     (groups related events into incidents)
          │                           │
          └─────────────┬─────────────┘
                         ▼
              DASHBOARD / REPORTING LAYER
```

### Component specifications

| Component | Purpose | Inputs | Outputs | Dependencies | Business Value |
|---|---|---|---|---|---|
| **Identity Resolver** | Correlate fragmented platform accounts into one canonical identity per human/non-human entity | `persons`, all 5 platform account tables, `service_accounts` | `identities`, `identity_correlation_mapping` (confidence-scored) | None (first stage) | Without this, no cross-platform risk (blast radius, cross-platform admin) is even measurable — it's the foundation everything else stands on |
| **Identity Graph Engine** | Maintain a traversable graph of every identity relationship | Resolver output + `role_assignments`, `group_memberships`, `nested_group_relationships`, `permission_assignments`, `service_accounts` (ownership), `api_tokens` (ownership), `persons.manager_person_id` | In-memory graph object + periodic snapshots | Identity Resolver | Enables path-based, structural risk analysis (blast radius, lateral movement, concentration) that flat tables cannot express |
| **Effective Privilege Calculator** | Compute true effective access per identity, resolving inheritance and chaining | Identity Graph | Per-identity effective permission sets (direct, inherited, chained, programmatic, control-plane) | Identity Graph Engine | Surfaces hidden over-privilege invisible in raw assignment tables (Phase 1, BR-I-19) |
| **Rule Engine** | Deterministic, explainable detection of known anomaly patterns | All source tables + Effective Privilege Calculator output | Raw rule-hit events with evidence references | Effective Privilege Calculator (for privilege rules), raw tables (for others) | Auditor-defensible, reproducible, zero-ambiguity baseline detection layer |
| **Behavior Analytics Engine** | Statistical baselining to catch deviations rules can't define deterministically | `authentication_events`, `audit_log_events`, grouped by canonical identity | Per-identity behavioral baseline + deviation flags | Identity Resolver (to group events across platforms) | Catches novel/behavioral anomalies (impossible travel, shared accounts) static rules miss |
| **Anomaly Detection Engine** | Unify Rule Engine + Behavior Analytics output into one standardized event stream | Rule Engine + Behavior Analytics output | Standardized `anomaly_events`, tagged to Phase 3's 22-category taxonomy | Rule Engine, Behavior Analytics Engine | Single consistent interface for scoring/correlation regardless of detection method |
| **Risk Scoring Engine** | Compute composite 0–100 identity risk score | Anomaly Detection Engine + Effective Privilege Calculator + governance metadata | `identity_risk_scores` (time series) | Anomaly Detection Engine, Effective Privilege Calculator | Finite remediation capacity needs prioritization; this is the CISO/board reporting metric |
| **Incident Correlation Engine** | Group related raw anomaly events into one investigation-ready incident | Anomaly Detection Engine + Identity Graph | `incidents` (grouped evidence, computed severity) | Anomaly Detection Engine, Identity Graph Engine | Directly addresses the SecOps "alert fatigue" pain point identified in Phase 1 Step 2 |

---

## STEP 2 — IDENTITY RESOLUTION ENGINE

### The problem
One person can exist as an `ad_accounts` row, an `azure_accounts` row, an `aws_accounts` row, an `okta_accounts` row, and a `salesforce_accounts` row — five independently-provisioned records with no guaranteed shared key.

### Matching strategy — tiered, deterministic-first with probabilistic fallback

| Tier | Method | Base Confidence | Notes |
|---|---|---|---|
| 1 | Exact natural-key match (e.g., HR employee number embedded in platform attributes, where present) | 1.00 | Strongest possible signal; auto-link |
| 2 | Exact email match (`persons.email` = platform account email) | 0.95 | Primary working key in practice — most platforms expose email |
| 3 | Normalized name + corroborating attribute (department, manager, hire-date window) agreement | 0.60–0.80 | Name normalization handles casing, diacritics, "Last, First" vs. "First Last" ordering |
| 4 | Fuzzy name similarity only (similarity score above a minimum threshold), no corroboration | 0.30–0.50 | Routed to manual review, never auto-linked |
| 5 | No candidate found | n/a | Treated as an unresolved/orphan candidate |

### Confidence scoring
Base tier score is adjusted by corroboration/conflict modifiers, capped at 1.00:
- **+0.05** same department as `persons` record
- **+0.03** same manager hierarchy
- **+0.02** account creation date falls within a plausible window of `hire_date`
- **−0.10** department mismatch
- **−0.20** account creation date predates `hire_date` (logically suspicious — flag regardless of score)
- **−0.15** employment_type mismatch signals (e.g., account metadata suggests a service identity, not human)

### Identity correlation logic
For every new or changed platform account: run tiers in order, stop at first match. **Auto-link** at confidence ≥ 0.85. **Queue for manual review** at 0.50–0.84. **Leave unresolved/flag as orphan candidate** below 0.50. Every linkage decision — automatic or manual — is written to `identity_correlation_mapping` with `match_method` and `match_confidence` populated, preserving a full audit trail of *how* each link was established (directly supporting Phase 1's Auditor Question #19).

### Conflict handling
If a platform account scores a high-confidence match against **two or more distinct `persons` records** (e.g., common-name collision), the engine does **not** auto-assign. It holds both candidates in an internal disambiguation queue with their respective scores and routes to manual tie-break. Auto-resolution is never permitted when multiple candidates clear the auto-link threshold simultaneously — ambiguity itself is the signal to stop, not to guess.

### False match prevention
- Hard negative constraints (logical impossibilities) override any positive score: account predating hire date, conflicting country/employment-type metadata.
- Auto-link threshold (0.85) is intentionally conservative — false negatives (an account sitting in the orphan queue a bit longer) are preferred over false positives (linking the wrong person, which corrupts every downstream privilege and risk calculation for two identities at once).
- **Periodic re-validation:** matching logic re-runs quarterly against the latest `persons` data, since departmental moves, name changes, or newly-populated attributes can change a previously low-confidence match into a high-confidence one (or reveal a previously "confident" match was wrong).
- Every correlation decision — including who approved a manual match — is retained, giving auditors a reconstructable trail rather than a black-box join.

---

## STEP 3 — IDENTITY GRAPH DESIGN

### Node types
| Node Type | Key Properties |
|---|---|
| `Person` | person_id, full_name, department_id, employment_type, status |
| `Identity` | identity_id, identity_status |
| `PlatformAccount` | platform_account_id, platform_id, account_status, privilege_tier |
| `BusinessRole` | role_id, role_name, is_privileged |
| `PlatformRole` | platform_role_id, native_role_name, privilege_tier, can_assume_other_roles |
| `Group` | group_id, group_name, is_privileged_group |
| `Permission` | permission_id, sensitivity_level, data_classification_scope |
| `ServiceAccount` | service_account_id, criticality, privilege_level, status |
| `Token` (API Token) | token_id, scope, expiration_date, rotation_status |
| `Department` | department_id, department_name |
| `Asset` *(new for graph purposes — represents a critical system/data resource reachable via a permission, e.g., "Production AWS Account," "Customer PII Store," "Financial Reporting System")* | asset_id, asset_name, criticality, data_classification |

### Edge types
| Edge | Direction | Properties | Meaning |
|---|---|---|---|
| `REPORTS_TO` | Person → Person | — | Manager hierarchy |
| `BELONGS_TO_DEPT` | Person → Department | — | Org placement |
| `RESOLVES_TO` | PlatformAccount → Identity | confidence, match_method | Output of the Identity Resolver |
| `MEMBER_OF` | PlatformAccount → Group | added_date, added_by | Direct group membership |
| `INHERITS` | Group(child) → Group(parent) | nesting_depth | Nested group inheritance |
| `HAS_ROLE` | PlatformAccount/Identity → PlatformRole | granted_date, expiration_date, approval_ticket_ref | Role assignment |
| `MAPS_TO` | PlatformRole → BusinessRole | — | Links platform-native role to business role template |
| `HAS_PERMISSION` | PlatformRole/Group → Permission | — | What a role or group actually grants |
| `GRANTED_DIRECT` | Identity → Permission | grant_reason, expiration_date | Direct exception grant (`permission_assignments`) |
| `OWNS` | Person → ServiceAccount, Person → Token | since_date | Accountability/control-plane relationship |
| `USES` | ServiceAccount → Token | — | A service account's own credentials |
| `CAN_ASSUME` | PlatformRole → PlatformRole | — | Role-chaining (notably AWS) |
| `ACCESSES` | Permission/PlatformRole → Asset | — | What critical resource a permission ultimately reaches |

### Graph construction strategy
- **Full batch rebuild** nightly from all 33 source tables — the authoritative ground-truth refresh.
- **Incremental intraday updates** for high-value changes (new `role_assignments`, new `service_accounts`, `offboarding_events` firing) feeding a near-real-time delta layer on top of the nightly base.
- **Point-in-time snapshotting**, aligned with `identity_risk_scores`' monthly cadence, so the engine can answer "what access did this identity actually have on date X" — essential for audit reconstruction and for Persistent SoD Violation / Privilege Creep detection, which are inherently temporal.
- Implemented as a **multi-edge directed graph** (NetworkX `MultiDiGraph`, as specified) to allow parallel relationships between the same node pair (e.g., a person owning multiple tokens). At true enterprise production scale this pattern maps directly onto a graph database (e.g., Neo4j); NetworkX is appropriate at this dataset's scale for in-memory analysis.

---

## STEP 4 — EFFECTIVE PRIVILEGE CALCULATOR

| Privilege Source | Contribution to Effective Access |
|---|---|
| **Direct Permissions** (`permission_assignments`) | Added to the set with no traversal required — these are deliberate, explicit exceptions, and the most important population for least-privilege testing |
| **Group Memberships** (`group_memberships`) | Contributes whatever permissions the directly-joined group grants via its `HAS_PERMISSION` edges |
| **Nested Groups** (`nested_group_relationships` / `INHERITS` edges) | Recursively expands: membership in a child group also confers everything every ancestor group grants, traversed up the full inheritance chain (capped at depth 5 to bound runaway recursion while comfortably exceeding the generation-time depth of 3) |
| **Inherited (Business) Roles** | A business role assignment implies specific platform role assignment(s) per the role-derivation logic established in Phase 3; permissions follow from the platform role's own `HAS_PERMISSION` edges |
| **Cross-Platform Roles** | Per-platform effective sets are aggregated per identity across all platforms; this aggregation is also where Cross-Platform Admin concentration is **directly observed**, not separately re-derived |
| **Service Accounts (ownership)** | Owning a service account is a *secondary, control-plane* privilege source — the owner can rotate its credentials and effectively direct its use. This is tracked as **Control-Plane Exposure**, kept distinct from primary held permissions so it isn't silently blended into (and doesn't overstate) day-to-day interactive access |
| **Tokens (ownership)** | A token inherits its owning identity's/service account's scope; tracked as **Programmatic Privilege**, kept distinct from interactive effective privilege so a mismatch between the two (token scope broader than the owner's interactive access) is itself a detectable signal, feeding Token Scope Creep |

### Effective Privilege Calculation Formula (descriptive, set-based)

```
For identity I on platform P:

EffectivePrivilege(I, P) =
      DirectPermissions(I, P)
    ∪ ⋃ [PermissionsOf(role) for role in RoleAssignments(I, P)]
    ∪ ⋃ [PermissionsOf(g) for g in closure(DirectGroups(I, P), INHERITS)]
    ∪ ⋃ [PermissionsOf(role) for role in closure(RoleAssignments(I, P), CAN_ASSUME)]

ProgrammaticPrivilege(I, P) = ⋃ [ScopeOf(t) for t in TokensOwned(I) where platform(t) = P]

ControlPlaneExposure(I) = ⋃ [EffectivePrivilege(sa, platform(sa)) for sa in ServiceAccountsOwned(I)]

TotalRiskRelevantSurface(I) =
      EffectivePrivilege(I, all platforms)
    ∪ ProgrammaticPrivilege(I, all platforms)
    ∪ ControlPlaneExposure(I)

closure(X, EDGE_TYPE) = transitive closure of set X under the given edge type,
                        bounded by max traversal depth = 5
```

`TotalRiskRelevantSurface(I)` is the single most important output of this component — it is the input every downstream rule, behavioral check, and risk score component ultimately consumes when reasoning about "what can this identity actually do."

---

## STEP 5 — RULE ENGINE DESIGN

Each rule operates directly on Phase 2 tables and produces a standardized evidence-bearing event tagged with its Phase 3 `anomaly_type` label.

| Rule | Logic | Thresholds | Severity | Evidence Produced | Recommended Remediation |
|---|---|---|---|---|---|
| **Offboarding Gap** | For `persons.status = 'Terminated'`, check each platform's `offboarding_events` row: flag if `actual_revocation_at IS NULL` past `expected_revocation_deadline`, or the corresponding platform account still shows `account_status = 'Active'` | Zero tolerance (binary); severity scales with elapsed time | High, escalating to Critical beyond 30 days | Termination date/reason, affected platform(s), elapsed time past SLA | Immediate revocation on the gapped platform(s); root-cause the automation gap |
| **Dormant Admin** | `privilege_tier IN ('Admin','Super Admin')` AND no `authentication_events` within the dormancy window AND `account_status = 'Active'` | 90 days (Admin), 60 days (Super Admin) | Medium at threshold, High beyond 180 days | Privilege tier, days dormant, last login timestamp | Disable/downgrade pending owner re-justification |
| **Cross-Platform Admin** | Identity holds `privilege_tier IN ('Admin','Super Admin')` on 2+ distinct `platform_id` values concurrently | ≥2 platforms | High at 2, Critical at 3+ | Per-platform roles held, effective privilege summary | Justify or split into platform-scoped roles; convert standing access to just-in-time |
| **Service Account Abuse** | `interactive_login_allowed = FALSE` with matching `session_type = 'Interactive'` events; OR activity continues after owner's `persons.status = 'Terminated'` | Any occurrence | High; Critical if privilege_level ≥ Admin | Session logs, owner status, criticality | Disable interactive capability or account; investigate actor; reassign ownership |
| **Token Abuse** | `usage_count_30d`/`source_ip_diversity_30d` exceeds the token's **own** rolling baseline by >3 standard deviations; OR activity after owner disablement | >3σ from own baseline; any post-disablement activity | High; Critical if `data_classification_scope` is Confidential/Regulated | Usage time series vs. baseline, scope, owner status | Immediate revoke/rotate; review actions taken during anomalous window |
| **Privilege Escalation (ungoverned)** | `privilege_escalation_events` with `approval_ticket_ref IS NULL` or `approved_by_person_id IS NULL` | Any null approval | High; Critical if non-breakglass and no `expiration_at` set | Escalation detail, requester, granted timestamp | Retroactive review; revoke if unjustified; tighten gating |
| **Privilege Creep** | After a detected role/department change, prior-role `group_memberships`/`role_assignments` remain `Active` beyond a grace window | >30 days post role-change | Medium, High if lingering access includes Admin-tier or sensitive permissions | Role-change timeline vs. access timeline, list of stale grants | Targeted revocation of prior-role access; automate mover-triggered review |
| **Orphaned Account** | `identities.person_id IS NULL`, or linked `persons.status = 'Terminated'` while `identity_status` still shows active correlated accounts | Any occurrence | Medium-High, Critical if Admin-tier access exists | Identity record, correlation history, active accounts | Investigate origin; reconcile against HR; disable pending resolution |
| **MFA Disabled Admin** | `mfa_enrollment.mfa_enrolled = FALSE` for any account with `privilege_tier IN ('Admin','Super Admin')` | Any occurrence | Critical | Privilege tier, enrollment status/history | Enforce MFA immediately or suspend access until compliant |
| **Impossible Travel** | Consecutive `authentication_events` on one account imply a travel velocity exceeding plausible limits | >900 km/h implied speed between events | Critical | Both events, geolocations, computed velocity, account's normal geographic baseline | Immediate session termination, forced credential reset, MFA re-verification |
| **Contractor Access After Expiry** | `role_assignments.status = 'Active'` for a contractor past `contracts.contract_end_date` with no active renewal | Any occurrence; severity scales with days past expiry | High, Critical beyond 14 days | Contract record, active access list, renewal status | Immediate suspension pending renewal confirmation; align automation to contract dates |
| **Break-Glass Abuse** | `breakglass_usage_log` with `incident_ref IS NULL`, or `post_use_reviewed = FALSE` more than 7 days after `released_at` | Any null incident_ref; >7-day review lag | Critical (no incident ref), Medium (review lag only) | Usage window, invoker, account criticality | Mandatory retroactive documentation; review for misuse; tighten checkout gating |
| **Persistent SoD Violation** | `sod_violations.remediation_status = 'Open'` for more than 90 days since `detected_at` | >90 days open | High, Critical beyond 180 days or if `regulatory_basis = 'SOX'` | Violation detail, both conflicting permissions, time open | Escalate to compliance/audit committee; force a remediation or formally documented risk-acceptance decision |

---

## STEP 6 — BEHAVIOR ANALYTICS ENGINE

**Core principle (carried forward from Phase 3):** every baseline is computed **per identity, against its own history** — never against a population-wide average — because legitimately diverse roles make population averages a poor and false-positive-prone yardstick.

| Identity Type | Normal Behavior | Abnormal Behavior | Features Required | Detection Signals |
|---|---|---|---|---|
| **Employee** | Single-peak working-hours login curve, consistent source IP range, near-zero weekend activity, expected vacation gaps | Multi-modal login-time distribution, new/unrecognized source IP outside known range, weekend spikes without historical precedent | Hourly/daily login histogram, source IP/geo set, failed-login rate, MFA usage rate | Z-score deviation per feature against own 60–90 day rolling window |
| **Contractor** | Similar to employee but with broader allowance for non-standard hours (distributed vendor teams); shorter/more sporadic gaps | Activity continuing past `contract_end_date`; sudden platform-coverage expansion inconsistent with role | As above + `contracts.contract_end_date` join | Same baseline deviation methodology + contract-date cross-check |
| **Admin** | Primary working-hours peak plus a smaller legitimate after-hours peak (maintenance/on-call); occasional justified mid-vacation access | Dormancy beyond threshold; sudden new-geography login; privileged-action volume spike outside known maintenance windows | Login histogram (dual-peak baseline), `audit_log_events` privileged-action count per day, MFA usage rate | Deviation from dual-peak baseline; correlation with `privilege_escalation_events` |
| **Service Account** | Flat, machine-clock-regular cadence, fixed source IP, 24/7 or fixed batch windows, no weekend/vacation concept | Interactive-session events; cadence drift outside a tight tolerance band; new source IP; complete activity gap (no concept of "vacation" for a machine) | Inter-event interval distribution, `session_type` field, source IP set | Tight-tolerance deviation (much narrower bands than human baselines, since regularity itself is the expected signature) |
| **Token** | Usage volume and source-IP-diversity consistent with the owning entity's own historical pattern | Sharp spike in `usage_count_30d`/`source_ip_diversity_30d`; activity after owner disablement; scope expansion beyond original justification | `usage_count_30d`, `source_ip_diversity_30d`, `scope` history across reissues | Own-baseline statistical deviation (Token Abuse rule) + scope-diff comparison (Token Scope Creep) |

**How deviations are identified:** each feature is converted into a deviation score (e.g., z-score or percentile rank against the identity's own trailing window); per-feature scores combine into an aggregate behavioral anomaly score per identity per day/week. New accounts with insufficient history fall back to a population-level baseline for their role/tier ("cold start") until enough individual history accumulates (recommended minimum: 30 days). This aggregate score both triggers specific rules (Impossible Travel, Excessive Failed Logins, Shared Admin Account) and feeds the Risk Scoring Engine's Behavior Risk component directly.

---

## STEP 7 — GRAPH ANALYTICS

| Analysis | Detection Logic | Risk Impact | Visualization Strategy |
|---|---|---|---|
| **Shortest Path Risks** | Compute shortest-path existence/length from Standard-tier identity/account nodes to designated critical `Asset` nodes; flag paths at or below a hop threshold (≤2) that weren't expected given nominal privilege tier | Reveals *actual* reachability versus nominal role labels — a "Standard" user might be 2 hops from a critical asset through an overlooked group nesting | Path-highlight overlay in the Graph Explorer showing the exact edge chain |
| **Privilege Inheritance Chains** | Depth-first traversal of `INHERITS`/`CAN_ASSUME` edges from an identity's direct grants, enumerating the full ancestry | Surfaces "invisible" access depth (Phase 1, BR-I-19) that flat review tables hide entirely | Tree or Sankey diagram: direct grants → each inherited layer |
| **Privilege Concentration** | Graph centrality measures (in-degree, betweenness) computed on `PlatformRole`/`Group`/`Permission` nodes | High-centrality nodes are single points of failure — compromise or misconfiguration of one such node cascades across hundreds of identities at once | Node size/color scaled by centrality score in the Graph Explorer |
| **Toxic Access Combinations** | Set-intersection check between an identity's `TotalRiskRelevantSurface` (Step 4) and predefined dangerous pairings (extends `sod_rules` plus a broader toxic-combination rule set) | Direct fraud/sabotage potential, distinct from simple over-privilege | Identity × toxic-pair matrix with heatmap shading |
| **Lateral Movement Opportunities** | Path-finding from "weak" entry nodes (flagged by Behavior/MFA signals) to Admin/Super Admin nodes via `OWNS`/`USES`/`CAN_ASSUME` edges, scored by path length and number of privilege upgrades crossed | Directly models real attacker tradecraft from Phase 1's attack-path analysis | Highlighted attack-path overlay; ranked "shortest path to admin" list per low-trust account |
| **Cross-Platform Blast Radius** | Graph traversal unioning `TotalRiskRelevantSurface` across all platforms and critical assets for a given identity or service account | Directly quantifies "single compromise, multi-system impact" — Phase 1's core cross-platform risk insight | Radial/blast-radius diagram centered on the identity, with rings representing platforms/assets reached |

---

## STEP 8 — INCIDENT CORRELATION ENGINE

### Why correlation matters
Raw `anomaly_events` are numerous and frequently represent *one* underlying situation viewed from several angles — e.g., a single account-takeover-to-privilege-expansion chain can simultaneously trigger Cross-Platform Admin, Token Abuse, and Impossible Travel rule hits. Surfacing these as three unrelated alerts is exactly the alert-fatigue problem Phase 1's SecOps stakeholder analysis flagged.

### How alerts become incidents
Events are grouped into a single incident when they share:
1. **The same identity_id** (or a closely graph-connected identity — e.g., a person and a service account they `OWN`).
2. **A correlation time window** (default 72 hours, configurable).
3. **A recognizable escalation pattern** — e.g., `Privilege Escalation` → new `Admin` role on Platform A → new `Admin` role on Platform B → new `api_tokens` row created → `Impossible Travel` flag, in chronological sequence.

### How severity is calculated
```
IncidentSeverity = max(individual contributing event severities)
                  + escalation_bonus

escalation_bonus considers:
  - number of distinct anomaly_types correlated together
    (more distinct types = more likely a coordinated event, not one isolated glitch)
  - whether the chain spans multiple platforms
    (cross-platform correlation is inherently more severe — Phase 1's risk-propagation insight)
  - presence of any Critical-severity component event
    (sets a hard floor on overall incident severity regardless of other factors)
```

### How evidence is grouped
Each incident packages: a chronological timeline of every contributing raw event (full evidence fields per Step 5's rule definitions), the connecting graph subpath between implicated nodes (Step 7), and the resulting risk-score delta — producing one complete, ordered case file for an investigator instead of several disconnected alerts.

---

## STEP 9 — RISK SCORING ENGINE

### Composite formula
```
RiskScore(I) = 0.30 × PrivilegeRisk(I)
             + 0.20 × BehaviorRisk(I)
             + 0.20 × ExposureRisk(I)
             + 0.20 × GovernanceRisk(I)
             + 0.10 × CrossPlatformRisk(I)

(each sub-component normalized to a 0–100 scale before weighting; total capped at 100)
```

| Component | Weight | Derived From |
|---|---|---|
| **Privilege Risk** | 30% | Effective Privilege Calculator output — privilege tier, control-plane exposure, programmatic privilege breadth |
| **Behavior Risk** | 20% | Behavior Analytics Engine's aggregate deviation score |
| **Exposure Risk** | 20% | Graph Analytics — blast radius size, shortest-path-to-asset proximity, role/group centrality |
| **Governance Risk** | 20% | Rule Engine hits tied to process failures — offboarding gaps, MFA gaps, unapproved escalations, persistent SoD violations, stale reviews |
| **Cross-Platform Risk** | 10% | Cross-Platform Admin rule + blast-radius platform count — kept separate despite overlap with Privilege/Exposure, because Phase 1 named cross-platform concentration as a distinct, named risk category the CISO and board specifically track |

This **extends, rather than replaces**, the additive anomaly-weight model defined in Phase 3 Step 14: that weight table becomes the primary input feeding the Governance Risk and Behavior Risk sub-components, while Privilege/Exposure/Cross-Platform Risk add the graph-derived structural dimensions Phase 3's generation-side model didn't need (since it was building the data, not analyzing it).

### Why auditors would trust this score
1. **Every sub-component traces to specific, inspectable evidence** — a rule hit, a graph metric, a behavioral deviation — nothing is a black box.
2. **The weighting is fixed, published, and version-controlled** — identical inputs always produce identical scores, satisfying the reproducibility auditors specifically test for.
3. **The score decomposes on demand** — an auditor asking "why is this identity at 87?" gets a structured five-component breakdown, not just a number.
4. **It's built entirely from the same source-of-truth tables an auditor can independently query** — there is no separate, opaque scoring pipeline disconnected from the data of record.

---

## STEP 10 — RISK CLUSTERS

| Cluster | Score Range | Characteristics | Examples | Recommended Actions |
|---|---|---|---|---|
| **Low** | 0–29 | Standard privilege, no rule hits, behavior within baseline | Typical employee with birthright access only | Standard review cadence; no special action |
| **Medium** | 30–54 | Power-user privilege, or a single low/medium-severity hit | Lingering access 60 days after a role change | Address in next standard review cycle with explicit attestation required on the flagged item |
| **High** | 55–79 | Admin-tier privilege combined with ≥1 High-severity hit, multiple compounding Medium hits, or meaningful behavioral deviation | Dormant admin account; contractor access past expiry | Expedited review within 5 business days; consider temporary suspension; notify manager and platform owner |
| **Critical** | 80–100 | Any Critical-severity hit, and/or multiple co-occurring High hits forming a correlated incident | Cross-platform admin + dormant + orphaned combination; Impossible Travel on a Super Admin account | Immediate access suspension; SecOps incident response engagement; CISO notification; mandatory post-incident review |

---

## STEP 11 — INCIDENT NARRATIVES

### Template structure
**Executive Summary** (plain business language, what happened and why it matters) → **Technical Summary** (specific systems/accounts/timestamps) → **Evidence** (bulleted, specific, traceable to source rows) → **Business Impact** → **Compliance Impact** (named framework/control) → **Recommended Actions** (prioritized, specific).

### Example 1 — Offboarding Gap
> **Executive Summary:** A former employee's access to AWS was not revoked after departure and remained active for several days beyond policy, creating a window of unauthorized cloud access.
> **Technical Summary:** Identity 500091 (terminated, voluntary departure). AD, Azure AD, and Okta access were correctly revoked within SLA. The corresponding AWS IAM account remained `Active` for 3 additional days before manual disablement.
> **Evidence:** `offboarding_events` row showing `actual_revocation_at` null past `expected_revocation_deadline` for the AWS platform row; `persons.termination_date`; `aws_accounts.account_status = 'Active'` as of the audit date.
> **Business Impact:** The former employee retained the ability to access cloud infrastructure resources they were authorized for during employment for 3 days post-departure.
> **Compliance Impact:** Violates the offboarding SLA control (BR-E-05/BR-E-18); a control auditors specifically sample for under SOX and ISO 27001 access-termination testing.
> **Recommended Actions:** (1) Disable the AWS account immediately. (2) Confirm no activity occurred during the gap via `audit_log_events`. (3) Root-cause why AWS wasn't included in the automated offboarding trigger. (4) Remediate the integration gap.

### Example 2 — Cross-Platform Admin
> **Executive Summary:** This identity holds full administrative privileges on both AWS and Salesforce simultaneously, creating a single point of compromise with multi-system impact.
> **Technical Summary:** Standing `Admin`-tier role assignments on both AWS (AdministratorAccess-equivalent) and Salesforce (System Administrator profile), both currently active with no time-bound expiration set.
> **Evidence:** Corresponding `role_assignments` rows for both platforms; Effective Privilege Calculator output confirming standing, non-expiring admin access on both.
> **Business Impact:** A single compromised credential or insider-misuse event for this identity could result in unauthorized changes to cloud infrastructure *and* full access to customer relationship data simultaneously.
> **Compliance Impact:** Relevant to least-privilege testing (BR-E-23) and segregation-of-duties principles even absent a named SoD rule for this exact pairing; auditors typically flag broad cross-system admin concentration on sight.
> **Recommended Actions:** (1) Require documented business justification for dual-platform admin. (2) Evaluate splitting into platform-scoped roles. (3) Convert to time-bound/just-in-time elevation if justified. (4) Add to the next Privileged Access Review with mandatory manager and platform-owner sign-off.

### Example 3 — Token Abuse
> **Executive Summary:** An API token tied to a billing automation service showed a sharp, unexplained spike in usage volume and originating locations, consistent with potential credential theft or unauthorized reuse.
> **Technical Summary:** Token owned by service account `svc-billing-etl`. Baseline: ~14,000 calls/30 days from 1–2 known infrastructure IPs. Observed: 60,000+ calls from 5 previously-unseen source IPs within a 48-hour window.
> **Evidence:** `api_tokens.usage_count_30d`/`source_ip_diversity_30d` trend versus the token's own 90-day rolling baseline; corresponding `authentication_events` showing the anomalous IP set.
> **Business Impact:** This token's scope grants read/write access to billing data; activity at this volume could indicate large-scale data exfiltration or fraudulent automated activity.
> **Compliance Impact:** Relevant to token hygiene control (BR-E-07) and any regulated-data-handling requirement if billing data includes payment information (PCI-DSS).
> **Recommended Actions:** (1) Revoke and rotate the token immediately. (2) Review all actions taken during the anomalous window via `audit_log_events`. (3) Determine the exposure source (code repository scan, log review). (4) Implement IP allowlisting for this token going forward.

### Example 4 — Dormant Admin
> **Executive Summary:** An administrative account has not been used in over 120 days but remains fully active and privileged — unnecessary standing risk with no offsetting business activity.
> **Technical Summary:** `Admin`-tier account, 124 days since last login, `account_status` still `Active`. The owning identity remains employed and active in other systems — this is not an offboarding gap; the person simply isn't using this particular access.
> **Evidence:** 124-day absence in `authentication_events`; account privilege tier; confirmation of the identity's continued activity elsewhere (ruling out the simpler offboarding explanation).
> **Business Impact:** An unused but live privileged credential is an attractive, low-noise target — malicious use wouldn't stand out against any recent legitimate baseline, since none exists.
> **Compliance Impact:** Relevant to dormant-account hygiene (BR-E-10) and least-privilege testing; a direct "why does this person still have this if they haven't used it in four months?" audit question.
> **Recommended Actions:** (1) Confirm continued business need with the identity/manager. (2) Revoke if not needed. (3) Convert to just-in-time elevation if needed only occasionally. (4) Add to the dormant-privileged-account watchlist for the next quarterly review.

---

## STEP 12 — DASHBOARD REQUIREMENTS

| Page | KPIs | Charts | Tables | Filters | Drilldowns |
|---|---|---|---|---|---|
| **Executive Overview** | Org-wide avg risk score & trend; # open Critical incidents; # identities in High/Critical cluster; offboarding SLA compliance %; privileged-account MFA coverage % | 12-month risk score trend (line); risk cluster distribution (donut); incidents by category (bar); top 10 riskiest identities (leaderboard) | Top 10 open Critical incidents | Date range, department/division, platform | Click a cluster slice → Identity Risk Registry filtered to that cluster |
| **Identity Risk Registry** | Total identities; % flagged; avg risk score; cluster distribution | Risk score histogram; anomaly-type frequency bar chart | Full sortable/filterable identity list (score, cluster, anomaly tags, last review date) | Department, employment type, platform, cluster, anomaly type, date range | Click identity → full Identity Profile (graph subview, evidence, history) |
| **Privilege Analytics** | % identities with cross-platform admin; avg effective permissions per tier; # toxic combinations; privilege concentration index | Privilege tier distribution by platform; direct-vs-effective permission scatter (visualizing the inheritance gap); toxic-combination heatmap | Identities flagged for SoD/toxic combinations | Platform, role, privilege tier | Click identity → effective privilege breakdown by layer (direct/inherited/chained) |
| **Identity Graph Explorer** | Graph size (nodes/edges); # high-centrality nodes; # sub-threshold paths to critical assets | Interactive force-directed graph; centrality ranking bar chart | High-centrality node list; detected lateral-movement paths | Node type, platform, relationship type, max path depth | Click node → expand neighbors; click edge → evidence (grant date, approver) |
| **Offboarding Monitor** | SLA compliance % (overall and per platform); # open gaps; avg time-to-revocation | Time-to-revocation distribution by platform (box plot); SLA breach trend | Terminated persons with per-platform revocation status | Termination reason, platform, date range, employment type | Click person → full cross-platform offboarding timeline |
| **Service Account Monitor** | Total accounts; % with current owner; % overdue rotation; % flagged for abuse | Ownership status breakdown; rotation status breakdown; criticality distribution | Full service account list (owner, last rotation, last activity, flags) | Platform, criticality, ownership status, privilege level | Click account → activity timeline, owned tokens, related audit entries |
| **Token Governance** | Total active tokens; % without expiration; % overdue rotation; # flagged | Expiration status breakdown; usage trend for flagged tokens; scope-breadth distribution | Full token list (owner, scope, expiry, rotation, flags) | Owner type, platform, expiration status | Click token → usage time series vs. baseline, owning entity profile |
| **Incident Investigation** | Open incidents by severity; avg time-to-resolution; # requiring CISO notification | Incident volume trend; incidents by correlated anomaly-type combination | Incident case list (severity, status, involved identities, event count) | Severity, status, date range, anomaly type, platform | Click incident → full case file (timeline, evidence, graph subpath, generated narrative) |

---

## STEP 13 — HACKATHON WINNING FEATURES

| # | Feature | Impact | Complexity | Judge Appeal |
|---|---|---|---|---|
| 1 | Incident Correlation Engine (noisy alerts → investigation-ready incidents) | High | Medium | High — most teams stop at raw alerts |
| 2 | Effective Privilege Calculator with direct-vs-effective comparison view | High | Medium | High — directly demonstrates grasp of the hardest real IAM problem |
| 3 | Identity Graph Explorer with lateral-movement/blast-radius path-finding | High | High | Very High — visually compelling, demonstrates attacker-mindset thinking |
| 4 | Confidence-scored cross-platform identity resolution (shown explicitly, not assumed) | Medium-High | Medium | High — most teams assume clean joins; surfacing the hard data problem stands out |
| 5 | AI-generated incident narratives (Exec/Technical/Compliance framing) | Medium-High | Low-Medium | High — cheap relative to payoff, makes the tool usable by a non-technical auditor/CISO |
| 6 | Point-in-time graph snapshotting ("what access did X have on date Y") | Medium | Medium | Medium-High — directly answers a real auditor question from Phase 1 |
| 7 | Decomposable, auditor-defensible risk score (5 components shown on demand) | High | Low | High — cheap to build, but most teams ship a single opaque number |
| 8 | Toxic combination / SoD detection via effective-privilege set intersection | Medium-High | Medium | Medium-High |
| 9 | Per-identity behavioral baselining (vs. population-average thresholds) | Medium | Medium-High | Medium — methodologically sound, rewarded by judges who probe the approach |
| 10 | Risk score time-series with realistic post-remediation decay modeling | Medium | Medium | Medium-High — demonstrates temporal sophistication most teams skip |

---

## STEP 14 — FINAL DETECTION BLUEPRINT

### 1. Complete Detection Architecture
Eight-component pipeline (Step 1): Identity Resolver → Identity Graph Engine → Effective Privilege Calculator → {Rule Engine, Behavior Analytics Engine} → Anomaly Detection Engine → {Risk Scoring Engine, Incident Correlation Engine} → Dashboard.

### 2. Graph Architecture
11 node types, 13 edge types (Step 3), built as a multi-edge directed graph with nightly full rebuild, intraday incremental updates, and monthly point-in-time snapshots.

### 3. Risk Scoring Design
Five-component weighted formula (30/20/20/20/10 — Privilege/Behavior/Exposure/Governance/Cross-Platform), extending Phase 3's additive anomaly-weight table rather than replacing it (Step 9).

### 4. Rule Engine Design
13 deterministic rules (Step 5), each with explicit logic, thresholds, severity, evidence, and remediation, directly mapped to Phase 3's anomaly taxonomy and Phase 2's table/column structure.

### 5. Behavior Analytics Design
Per-identity (never population-wide) statistical baselining across 5 identity types, with a defined cold-start fallback (Step 6).

### 6. Incident Correlation Design
Identity-proximity + time-window + escalation-pattern grouping, with a severity formula that rewards multi-type, multi-platform, Critical-anchored chains (Step 8).

### 7. Dashboard Requirements
8 pages fully specified with KPIs, charts, tables, filters, and drilldowns (Step 12).

### 8. Top 10 Features to Build First (priority build order, optimizing for impact-per-effort under hackathon time constraints)
1. Decomposable risk score with visible sub-components (#7 — cheapest high-impact win)
2. AI-generated incident narratives (#5 — cheap, high judge appeal)
3. Confidence-scored identity resolution, surfaced explicitly in the UI (#4)
4. Effective Privilege Calculator with direct-vs-effective visualization (#2)
5. Incident Correlation Engine (#1)
6. Toxic combination / SoD detection (#8)
7. Identity Graph Explorer with path-finding (#3 — highest visual payoff, save for once the core pipeline works)
8. Point-in-time snapshotting (#6)
9. Per-identity behavioral baselining (#9)
10. Risk score decay/time-series modeling (#10)

---

*End of Phase 4 detection and risk intelligence engine design. This document intentionally stops at architecture and logic design — no code, no implementation.*
