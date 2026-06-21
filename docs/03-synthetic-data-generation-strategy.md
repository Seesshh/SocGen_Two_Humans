# Hybrid Identity Governance — Synthetic Data Generation Strategy (Phase 3)
### Source of truth: Phase 1 Business Problem Analysis + Phase 2 Data Model Design (33 tables, entity counts as previously specified)

*Scope note: This document designs generation logic, distributions, anomaly injection plans, and label/risk-scoring design only. No code. Entities and schemas are reused exactly as defined in Phase 2 — none are redesigned here.*

---

## STEP 1 — GENERATION ORDER (DEPENDENCY FLOW)

Datasets must be generated in strict dependency order so that every foreign key reference points to an already-existing row. Tables generated in the same tier have no dependency on each other and can be generated in any order within that tier.

```
TIER 0 — Static reference data (no dependencies)
  platforms
  sod_rules            (depends only on a permissions catalog stub; see Tier 3 note)

TIER 1 — Organizational backbone
  departments
  vendors

TIER 2 — People
  employees (persons)            ← departments, vendors
  contracts                      ← employees (contractors only), vendors

TIER 3 — Canonical identity + access catalog
  identities                     ← employees (nullable link, enabling orphan injection)
  roles (business roles)         ← departments
  platform_roles                 ← platforms
  permissions                    ← platforms
  groups                         ← platforms

TIER 4 — Structural relationships among catalog objects
  nested_group_relationships     ← groups
  sod_rules (finalized)          ← permissions   [moved here once permissions exist]

TIER 5 — Platform accounts (the fragmented identities)
  ad_accounts, azure_accounts, aws_accounts,
  okta_accounts, salesforce_accounts            ← identities, platforms
  identity_correlation_mapping                  ← identities, platform accounts (generated together)

TIER 6 — Non-human identities
  service_accounts               ← employees (owner), platforms
  api_tokens                     ← service_accounts, employees, platforms

TIER 7 — Access grants
  group_memberships              ← platform accounts, groups
  role_assignments               ← platform accounts/identities, platform_roles, roles
  permission_assignments         ← identities, permissions

TIER 8 — Derived/detected relationships
  sod_violations                 ← role_assignments + permission_assignments + sod_rules

TIER 9 — Security posture snapshots
  mfa_enrollment                 ← platform accounts

TIER 10 — Time-series behavioral data (spans the full 1-year window)
  authentication_events          ← platform accounts, service_accounts (via tokens)
  privilege_escalation_events    ← identities, role_assignments, employees (approvers)
  breakglass_usage_log           ← service_accounts (breakglass subtype), employees
  audit_log_events               ← platform accounts, role_assignments/permission changes

TIER 11 — Governance process data
  access_reviews                 ← platforms, calendar periods
  review_decisions               ← access_reviews, role_assignments, identities, employees (reviewers)
  offboarding_events             ← employees (terminated), platforms

TIER 12 — Computed/longitudinal outputs (generated last, after all anomalies are injected)
  identity_risk_scores           ← all prior tiers (monthly snapshots)
  identity_risk_labels           ← all prior tiers + the anomaly injection plan itself (ground truth)
```

**Why this order matters:** anomalies are not a separate "bolt-on" step — they are injected *as* each tier is generated (e.g., an orphaned account is created by deliberately leaving a `identities` row unlinked in Tier 3/5, not by editing a finished dataset afterward). Generating `identity_risk_labels` last ensures every injected anomaly across all tiers has already happened and can be faithfully recorded as ground truth.

---

## STEP 2 — REALISTIC ENTERPRISE DISTRIBUTIONS

### Employees (6,000 total persons)

**Department distribution** (35 departments; shown as representative top-weighted set, remainder spread across smaller departments):
| Department | % of Population |
|---|---|
| Engineering | 18% |
| Sales | 14% |
| Customer Support / Operations | 12% |
| Cloud Infrastructure / IT | 9% |
| Finance | 6% |
| Marketing | 6% |
| HR | 4% |
| Procurement | 3% |
| Legal | 2% |
| Remaining 26 smaller departments | 26% (combined, long-tail distributed) |

**Seniority distribution:**
| Level | % |
|---|---|
| Individual Contributor | 68% |
| Senior IC | 17% |
| Manager | 10% |
| Director | 3.5% |
| VP / Executive | 1.5% |

**Employment type:** Employee 83.3% (5,000) / Contractor 16.7% (1,000) — per given scope.

**Country distribution:**
| Region | % |
|---|---|
| Primary HQ country | 55% |
| Secondary hub country | 20% |
| Tertiary regional offices (3–4 countries) | 15% |
| Other/distributed remote | 10% |

### Accounts

**Platform coverage (% of the ~6,150 identities holding an account on that platform):**
| Platform | Coverage |
|---|---|
| Azure AD | 96% |
| Okta | 93% |
| Active Directory | 88% |
| AWS IAM (human) | 23% |
| Salesforce | 18% |

**Account overlap / identity composition:**
| Pattern | % of Identities |
|---|---|
| Full core triad (AD + Azure AD + Okta) | 84% |
| Core triad + AWS | 19% (subset of above) |
| Core triad + Salesforce | 15% (subset of above) |
| Cloud-only (Azure AD/Okta, no AD) — B2B guests, newer contractors | 5% |
| AD-only (legacy/on-prem-only, no cloud presence yet) | 2.5% |

### Privilege tier distribution (applied across all platform accounts, ~19,500 human accounts)
| Tier | % | Approx. Count |
|---|---|---|
| Standard | 80% | ~15,600 |
| Power User (elevated, team/project scope) | 12% | ~2,340 |
| Admin | 6.5% | ~1,270 |
| Super Admin (cross-platform / org-wide) | 1.5% | ~290 |

This pyramid should hold **per platform**, not just in aggregate — i.e., AWS and Salesforce (the less centrally governed platforms) should skew slightly higher toward Admin/Super Admin than AD/Azure AD, reflecting realistic decentralized self-administration (Phase 1, BR-I-06).

---

## STEP 3 — ROLE GENERATION STRATEGY

Access must be **derived, not randomized**. The generation logic should follow a deterministic chain with controlled, bounded variance:

1. **Business role assignment** is determined by `department × seniority × job_title`, not by chance. Each department has a small set of canonical business roles (e.g., Finance → "Financial Analyst," "AP/AR Specialist," "Finance Manager," "Controller"). Every employee is assigned exactly one primary business role from their department's role set, weighted by the seniority distribution from Step 2.
2. **Platform role assignment** follows from the business role via a **role-to-platform-role mapping table** (a lookup, not randomness): each business role defines which platforms it touches and at what privilege tier (e.g., "Financial Analyst" → Azure AD Standard, Okta Standard, Salesforce none, AWS none; "Cloud Platform Engineer" → AWS Admin, Azure AD Standard, AD Standard, Okta Standard). This is what makes platform coverage in Step 2 *emerge* from role logic rather than being assigned independently per account.
3. **Permission assignment** is **90% role-derived** (i.e., comes along automatically with the assigned `platform_role`) and only **10% direct exceptions** (`permission_assignments` rows) — modeling the realistic minority of "one-off" access grants that don't fit cleanly into a role template. Direct exceptions should be biased toward Finance, Legal, and Cloud Infrastructure departments, where ad hoc data/system access requests are most common in real organizations.
4. **Controlled randomness** should only be applied to: (a) exact `granted_date` within a plausible window around the employee's `hire_date` or role-change date, (b) which specific approver (manager or designated alternate) signed off, and (c) whether a given identity holds 1 vs. 2 platform roles on a given platform (some employees legitimately need two distinct roles, e.g., "Standard User" + "Project-Specific Reader"). Randomness should **never** decide *which* platforms or privilege tiers an identity gets — that must always trace back to role logic.

This approach guarantees that any anomaly later injected (e.g., Cross-Platform Admin) is recognizable specifically *because* it breaks the deterministic role-to-access chain — which is what makes it detectable rather than indistinguishable noise.

---

## STEP 4 — GROUP INHERITANCE GENERATION

Groups should be generated as a **three-tier nested structure** that mirrors how real AD/Azure AD/Okta environments are organized:

**Tier A — Baseline/organization-wide groups** (top of the nesting chain, broadest membership)
- Example: `GRP-AllEmployees-BaselineAccess`, `GRP-AllContractors-RestrictedAccess`

**Tier B — Department/function groups** (nested inside Tier A groups)
- Example: `GRP-Finance-Standard` (nested inside `GRP-AllEmployees-BaselineAccess`), `GRP-Engineering-Standard`

**Tier C — Privileged/project-specific groups** (nested inside Tier B groups)
- Example: `GRP-Finance-Approvers` (nested inside `GRP-Finance-Standard`), `GRP-AWS-CloudOps-Admins` (nested inside `GRP-Engineering-Standard`)

**Generation logic:**
- Every identity is added as a *direct* member of exactly one Tier C (or Tier B, if no privileged group applies) group based on their assigned business role from Step 3 — never directly to a Tier A group.
- Nesting (`nested_group_relationships`) is pre-built as a fixed organizational hierarchy template (roughly 35 Tier B groups — one per department — each containing 2–4 Tier C sub-groups), generated once, not per-employee.
- Effective access for any identity therefore "emerges naturally" through recursive resolution: direct membership in `GRP-Finance-Approvers` → inherits `GRP-Finance-Standard` → inherits `GRP-AllEmployees-BaselineAccess`. A reviewer looking only at direct membership sees one group; computing effective access reveals three layers of grants — exactly the gap Phase 1 flagged as a recurring blind spot (BR-I-19).

**Worked example:**
| Identity | Direct Membership | Inherited (via nesting) | Effective Group-Derived Access |
|---|---|---|---|
| Priya S. (Senior Financial Analyst) | `GRP-Finance-Approvers` | `GRP-Finance-Standard`, `GRP-AllEmployees-BaselineAccess` | 3 groups' worth of permissions, though only 1 is visible without recursive resolution |

Roughly **35–40% of all groups** should participate in at least one nesting relationship (consistent with Phase 2's 480-nesting-relationship target against 1,250 total groups), with nesting depth capped at 3 levels to remain realistic (real environments rarely exceed 3–4 levels before becoming unmanageable, which is itself a known governance failure mode worth preserving as background noise rather than the primary anomaly signal).

---

## STEP 5 — LOGIN BEHAVIOR SIMULATION

| Identity Type | Frequency | Working Hours Pattern | Geographic Pattern | Weekend Behavior | Vacation Behavior |
|---|---|---|---|---|---|
| **Standard Employee** | ~1 login session/workday, clustered into 3–6 discrete `authentication_events` (app-by-app) | Gaussian distribution centered on local 9am start, session activity tapering off by ~6–7pm local time | Single consistent source IP range (home/office) per employee; rare travel-related secondary IP (~3% of days) | 4–6% chance of an isolated weekend login (catching up on work) | ~15–20 business days/year modeled as contiguous login gaps; no login activity at all during the gap window |
| **Contractor** | Similar frequency to standard employees but slightly lower (~0.85x), reflecting part-time/project-based engagement patterns | Same working-hours model, but a higher share (10–15%) work non-standard local hours if working with an offshore/distributed vendor team | Often a narrower, vendor-network-consistent IP range | 5–8% weekend login chance, slightly higher than employees (deadline-driven work) | Shorter, more sporadic gaps (contract-based, less standardized PTO) |
| **Admin (Elevated/Admin tier)** | Higher daily session count than standard users (more systems touched), plus periodic after-hours activity tied to maintenance windows | Same baseline working-hours curve **plus** a secondary smaller peak in late evening/early morning (change windows, incident response) | Consistent primary IP, but more likely to show secondary IPs (remote incident response, VPN) | 10–15% weekend login chance (on-call rotations) | Vacation gaps still occur, but should sometimes show a *single* anomalous login mid-vacation (legitimate emergency access) — useful as a "normal but unusual" pattern distinct from injected anomalies |
| **Service Account** | Extremely regular, machine-clock-driven intervals (e.g., every 15 minutes, or a single nightly batch run at a fixed time ±2 minutes) | No human-shaped curve at all — flat, scheduled cadence 24/7 or fixed batch windows | Single, fixed source IP (the hosting infrastructure) — near-zero variance | Identical behavior 7 days/week (no concept of "weekend") | No vacation concept — any gap in an otherwise perfectly regular service account's activity is itself a notable signal (potential outage or compromise indicator), not normal behavior |

**Generation approach:** build each account's 1-year login history as a baseline pattern (per the table above) with small natural jitter (±10–15 minutes on timing, occasional missed days for humans), and treat any *injected anomaly* as a deliberate, larger deviation from that account's **own established baseline** — not from a population-wide average. This is what makes anomalies like "Excessive Failed Logins" or "Impossible Travel" (Step 11) realistically detectable via per-identity behavioral baselining rather than naive thresholding.

---

## STEP 6 — ACCESS REVIEW GENERATION

| Review Type | Cadence | Population Reviewed | Approval Rate | Revocation Rate | Flagged/Escalation Rate |
|---|---|---|---|---|---|
| **Standard (Quarterly)** | 4x/year, broad population | All active employee identities, rotating ~50% of population per quarter (full coverage twice/year) | 87% | 10% | 3% |
| **Privileged Access Review** | Quarterly, dedicated campaign | All Admin/Super Admin tier identities (100% coverage every quarter) | 78% | 17% | 5% |
| **Contractor Review** | Monthly (per BR-E-25's elevated cadence) | All active contractor identities | 75% | 20% | 5% |
| **SoD-Focused Review** | Semi-annual | Identities holding any permission flagged in `sod_rules` | 70% | 22% | 8% |

**Realism logic:**
- Approval rates should **not be uniform across reviewers** — generate a per-reviewer "rigor score" (e.g., drawn from a distribution skewed toward moderate diligence, with a long tail of low-rigor reviewers). Low-rigor reviewers should show unusually fast `decision_date` clustering and near-100% approval rates — this becomes the basis for the "Review Rubber-Stamping" advanced anomaly (Step 11).
- For every `outcome = 'Revoked'` decision, only **~80%** should receive a matching `revocation_executed_date` and a corresponding status change in `role_assignments`/`group_memberships`. The remaining ~20% should be left as **decided-but-not-executed** — this is intentional and directly supports Phase 2's auditor-evidence design (decision vs. execution gap).
- Privileged and contractor reviews should show measurably higher revocation rates than standard reviews, reflecting genuinely tighter scrutiny — this differentiation is itself a realism signal a hackathon judge would expect to see.

---

## STEP 7 — OFFBOARDING SIMULATION

| Offboarding Outcome | % of ~900 Annual Terminations | Cause |
|---|---|---|
| **Normal (on-time, all platforms)** | 78% | Automated HR-to-IT trigger fires correctly; centrally-governed platforms (AD, Azure AD, Okta) revoke within SLA |
| **Delayed (breaches SLA, eventually completed)** | 14% | Manual processing backlog; termination occurring near a weekend/holiday; revocation completed in less-centrally-governed platforms (AWS, Salesforce) days later than the core triad |
| **Failed (never completed within the 1-year observation window)** | 8% | No automated integration exists for that specific platform/app; owning team failed to act on a manual ticket; orphaned service-account-style access tied to the departed employee that no offboarding workflow even targets |

**Per-platform skew (within the delayed/failed buckets):** AD and Azure AD should show the **lowest** delayed/failed rates (these are typically the most centrally automated), Okta slightly higher, and AWS/Salesforce the **highest** — directly reflecting Phase 1's insight that newer/less-centrally-governed platforms are the weakest link (BR-I-10). Roughly: AD/Azure AD ~3% combined delayed+failed, Okta ~8%, AWS ~18%, Salesforce ~22%.

**Causal realism:** involuntary terminations should show a *smaller* delayed/failed rate than voluntary ones for the core triad (heightened urgency triggers faster action) but should **not** show a correspondingly lower rate on AWS/Salesforce — modeling the real-world finding that urgency awareness rarely extends past the primary directory.

---

## STEP 8 — SERVICE ACCOUNT GENERATION

| Attribute | Distribution |
|---|---|
| **Ownership** | 88% have an active, current owner; 9% have an owner whose `persons.status = 'Terminated'` (orphaned-by-departure, feeding Service Account Abuse anomaly); 3% have `owner_person_id = NULL` from creation (never properly assigned) |
| **Backup owner present** | Only 35% have a populated `backup_owner_person_id` — realistically, backup ownership is the exception, not the norm |
| **Rotation adherence** | 65% rotate on/near their defined `rotation_policy_days`; 25% are overdue (rotation lapsed past policy but has occurred at least once); 10% show `rotation_status = 'Never Rotated'` since creation |
| **Privilege level** | Standard 45% / Elevated 32% / Admin 19% / Super Admin or breakglass 4% — skewed higher than human accounts, reflecting realistic over-provisioning of automation identities |
| **Interactive login allowed flag** | 92% correctly set to `FALSE` (pure automation); 8% set to `TRUE` (legitimately need occasional human interactive use, e.g., a deployment account a developer sometimes logs into directly) — this 8% population is the pool from which Service Account Abuse anomalies are injected when interactive use occurs *beyond* what this flag would justify |
| **Criticality** | Mission-Critical 8% / High 22% / Medium 40% / Low 30% |

---

## STEP 9 — API TOKEN GENERATION

| Attribute | Distribution |
|---|---|
| **Owner type** | 25% human-owned (individual developer tokens); 75% service-account-owned |
| **Expiry presence** | 60% have a defined, policy-conformant `expiration_date`; 25% have an `expiration_date` that has already lapsed without rotation (expired-but-still-flagged-active in source system, a realistic hygiene failure); 15% have **no expiration set at all** (`NULL`) — direct BR-E-07 violation population |
| **Rotation pattern** | Mirrors owning service account/developer's general hygiene — tokens owned by "Never Rotated" service accounts should themselves show `rotation_status = 'Never Rotated'` at a much higher rate (~70%) than tokens owned by well-rotated accounts (~8%), preserving realistic correlation between entities rather than independent randomness |
| **Usage pattern (baseline)** | Service-owned tokens: regular, automation-consistent `usage_count_30d` matching the owning service account's login cadence (Step 5). Human-owned tokens: bursty, lower-volume usage clustered around active development periods |
| **Source IP diversity (baseline)** | Service-owned: 1–2 source IPs (fixed infrastructure). Human-owned: 2–4 (laptop, CI runner, home/office) |

---

## STEP 10 — REQUIRED ANOMALY DESIGN (7 Core Anomalies)

| # | Anomaly | Injection Rate | Injection Method | Severity | Business Impact |
|---|---|---|---|---|---|
| 1 | **Offboarding Gap** | 8% of terminations (the "Failed" bucket from Step 7) | For the affected `persons`, leave `actual_revocation_at = NULL` (or set it well past `expected_revocation_deadline`) on 1–2 specific `offboarding_events` platform rows, while other platforms correctly show timely revocation — mirrors the "AD disabled, AWS still active" edge case | High | Direct unauthorized access window for a former employee |
| 2 | **Dormant Admin** | 3% of Admin/Super Admin tier accounts | Set `last_login_date` (and corresponding `authentication_events` history) to stop 90+ days before the observation end date while `account_status` remains `'Active'` | Medium-High | Unmonitored standing privilege with no offsetting business activity |
| 3 | **Privilege Creep** | 8% of identities who experienced a department/role change during the year | After a role-change event, retain the *previous* role's `group_memberships`/`role_assignments` as still `Active` instead of revoking them, while also granting the new role's access normally | Medium | Unbounded access accumulation over a career |
| 4 | **Service Account Abuse** | 2% of service accounts | For accounts with `interactive_login_allowed = FALSE`, inject a small cluster of `authentication_events` with `session_type = 'Interactive'`; alternatively, continue generating activity after the owning `persons.status` becomes `'Terminated'` | High | Potential credential misuse or undisclosed manual use of automation identity |
| 5 | **Token Abuse** | 2.5% of active tokens | Inject a sharp spike in `usage_count_30d` and `source_ip_diversity_30d` relative to that token's own established baseline, concentrated in a short window; or continue `last_used_date` activity after the owning identity/service account is disabled | High | Potential token theft, replay, or unauthorized automation reuse |
| 6 | **Cross-Platform Admin** | 4% of identities | Assign `platform_role.privilege_tier IN ('Admin','Super Admin')` on 2 or more distinct platforms simultaneously for the same `identity_id`, deliberately bypassing the Step 3 role-derivation chain (this is an intentional *exception* to normal generation logic, not a product of it) | High | Single-point-of-compromise risk spanning multiple systems |
| 7 | **Orphaned Account** | 2.5% of identities | Either leave `identities.person_id = NULL` from creation, or set the linked `persons.status = 'Terminated'` while `identities.identity_status` remains `'Linked'` (i.e., reconciliation never caught up) — labeled in the ground-truth file as `ORPHANED_CROSS_PLATFORM` to match downstream evaluation tooling | Medium-High | Untraceable, potentially unauthorized standing access |

---

## STEP 11 — ADVANCED ANOMALIES (15 Additional)

| # | Anomaly | Definition | Detection Logic (descriptive) | Severity |
|---|---|---|---|---|
| 8 | **Excessive Privilege Accumulation** | An identity holds materially more *distinct* role/group grants than is typical for its current role, accumulated gradually over multiple role changes (a more extreme, multi-event version of #3) | Compare total active grant count per identity against the department/role-level median; flag identities in, e.g., the top 2% of grant-count distribution with grants spanning 3+ distinct historical roles | High |
| 9 | **MFA Disabled Admin** | An Admin/Super Admin-tier account with `mfa_enrollment.mfa_enrolled = FALSE` | Direct join between privilege tier and MFA status | Critical |
| 10 | **Shared Admin Account** | A single privileged account shows authentication patterns inconsistent with one human user | Detect concurrent or near-concurrent sessions from geographically inconsistent source IPs, or a login-time distribution that doesn't fit any single coherent working-hours pattern (multi-modal rather than the single-peak baseline from Step 5) | High |
| 11 | **Zombie Service Account** | A service account with `account_status = 'Active'` but zero `authentication_events`/`audit_log_events` activity for 12+ consecutive months | Join service account status against full-year activity tables; flag complete absence, not just reduced activity | Medium |
| 12 | **Excessive Failed Logins** | A sustained or spiking pattern of `auth_result = 'Failed'` events, suggestive of brute-force or credential-stuffing activity | Compare failed-login rate in a rolling window against the account's own baseline failure rate (which should normally be near zero) | High |
| 13 | **Contractor Access After Contract Expiry** | `role_assignments` remain `'Active'` for a contractor identity past their `contracts.contract_end_date` | Join `role_assignments.status = 'Active'` against `contracts.contract_end_date < current observation date` for contractor-type persons | High |
| 14 | **Privilege Escalation Without Approval** | A `privilege_escalation_events` row with `approval_ticket_ref IS NULL` | Direct null-check on the approval reference field | High |
| 15 | **Break-Glass Without Incident Reference** | A `breakglass_usage_log` entry with `incident_ref IS NULL` | Direct null-check; especially severe if also `post_use_reviewed = FALSE` | Critical |
| 16 | **Token Scope Creep** | A token's `scope` expands across successive reissues beyond what its original `token_label`/purpose would justify | Compare scope breadth (e.g., number of distinct actions/resources) at issuance vs. most recent reissue for the same logical token lineage | Medium |
| 17 | **Unrotated Long-Lived Credential** | A service account or token with `rotation_status = 'Never Rotated'` and an age exceeding 365 days | Age calculation from `created_date`/`issued_date` combined with rotation status | Medium-High |
| 18 | **Review Rubber-Stamping Pattern** | A reviewer approves ~100% of assigned items with implausibly fast `decision_date`-to-`decision_date` spacing across a large batch | Per-reviewer aggregation: approval rate combined with decision-timing density within a campaign | Medium |
| 19 | **Orphaned Group Ownership** | A privileged group's provisioning/membership-granting activity (`group_memberships.added_by`) traces back to a `persons` record that is now `'Terminated'`, with no successor managing the group | Join `added_by` (where it maps to a person) against current `persons.status` | Medium |
| 20 | **Impossible Travel** | Two `authentication_events` for the same account from source IPs implying physically impossible travel time between them | Compare consecutive event timestamps and geolocated source IPs for implied velocity exceeding plausible travel speed | Critical |
| 21 | **Persistent SoD Violation** | An `sod_violations` row remains `remediation_status = 'Open'` for an extended period (90+ days) despite detection | Age calculation on `detected_at` for still-open violations | High |
| 22 | **Duplicate Identity Drift** | Two distinct `identities` (and their `persons` records) represent the same actual human — typically an M&A or re-hire artifact — each independently accumulating separate access over time | Near-duplicate detection on name/email similarity combined with overlapping department/hire patterns across two distinct `person_id`/`identity_id` pairs that never resolve to one record | Medium |

---

## STEP 12 — DATA QUALITY IMPERFECTIONS

Realistic enterprise data is never clean. The following imperfections should be deliberately introduced **as generation noise, separate from the anomaly injection plan** in Steps 10–11 — they represent normal data-quality friction, not security findings:

| Imperfection | Target Rate | Where Applied |
|---|---|---|
| Missing/null optional values (e.g., `manager_person_id` for top-level execs, `backup_owner_person_id`, non-critical address/location fields) | 3–5% of applicable fields | Across `persons`, `service_accounts` |
| Naming inconsistencies across platforms (nicknames, middle initials, transliteration/diacritic differences, casing differences) | 6–10% of cross-platform account pairs for the same identity | Between `ad_accounts`/`azure_accounts`/`okta_accounts`/`aws_accounts`/`salesforce_accounts` login/display name fields |
| Duplicate identity records (distinct from the deliberate Duplicate Identity Drift anomaly — this is lower-grade noise, e.g., simple double data-entry) | 1–2% of `persons` (~60–120 records) | `persons` table, concentrated around known "M&A integration window" date ranges if simulated |
| Identity correlation failures (low-confidence or absent matches, broader than the deliberate Orphaned Account anomaly) | 3–4% of platform accounts | `identity_correlation_mapping.match_confidence < 0.6`, or rows entirely absent for a small population of legitimate but never-correlated accounts |
| Delayed HR updates | 12–15% of role-change/termination events | `hr_notification_sent_at` lagging the true event date by 1–10 days in `offboarding_events` and implied role-change timing in `role_assignments` |
| Inconsistent timestamp granularity/timezone artifacts | Background noise, ~2% of timestamp fields | Minor generation realism (e.g., a small subset of events logged in UTC vs. local time inconsistently) |

**Important distinction:** Step 12 noise should be statistically separable from Step 10/11 anomalies during evaluation — i.e., a well-built detector should learn to tolerate ordinary data messiness (Step 12) without flagging it as risk, while still catching genuine anomalies (Steps 10–11). Blending these two categories indistinguishably would make the dataset impossible to evaluate meaningfully; keeping them generated through separate logic paths preserves a clean ground truth.

---

## STEP 13 — LABEL DESIGN: `identity_risk_labels.csv`

*Note on naming: aligning to `identity_risk_labels.csv` (rather than the more generic `identity_labels.csv`) since this is the exact filename and column convention an evaluation script would read from, based on the shared evaluation snippet (`pd.read_csv('identity_risk_labels.csv')`, columns `is_risky` and `anomaly_type`, with the exact category string `'ORPHANED_CROSS_PLATFORM'`). The schema below is designed to satisfy that evaluation pattern directly.*

**Primary Key:** `label_id`
**Foreign Key:** `identity_id` → `identities.identity_id`

| Column | Data Type | Example | Purpose |
|---|---|---|---|
| label_id | BIGINT | 1 | Surrogate key |
| identity_id | BIGINT | 500091 | The identity this ground-truth label describes |
| is_risky | BOOLEAN | TRUE | Primary binary target for anomaly/risk classification tasks |
| anomaly_type | ENUM (22 values + `'NONE'`) | `'ORPHANED_CROSS_PLATFORM'` | Primary multi-class target; exact category labels listed below |
| contributing_anomaly_types | VARCHAR(255) (nullable) | `'DORMANT_ADMIN;ORPHANED_CROSS_PLATFORM'` | Semicolon-delimited list when an identity has **multiple co-occurring** injected anomalies — supports multi-label evaluation, not just single-class |
| severity | ENUM | `'High'` | Supports severity-weighted evaluation, not just flat precision/recall |
| risk_score_ground_truth | DECIMAL(5,2) | 81.50 | Continuous target for risk-prediction (regression) tasks — computed per Step 14's weighting model |
| detection_difficulty | ENUM | `'Medium'` | `'Easy'` (single, obvious signal e.g. null expiration), `'Medium'` (requires joining 2+ tables), `'Hard'` (requires baseline/temporal comparison, e.g. Impossible Travel, Privilege Creep) — lets a hackathon judge weight scoring by difficulty tier |
| primary_platform_id | INT (nullable) | 3 | Which platform the anomaly is most evident on, where applicable (null for identity-level anomalies like Privilege Creep) |
| injected_at | DATE | 2026-03-12 | When, during the 1-year simulation, the anomaly condition began — supports temporal/early-detection evaluation |
| label_source | ENUM | `'Injected'` / `'Background Noise'` | Distinguishes deliberately injected anomalies (Steps 10–11) from naturally-emerging edge cases the generator produced incidentally — useful for debugging the generator itself |

**Exact `anomaly_type` category values (for consistency with downstream evaluation tooling):**
```
OFFBOARDING_GAP, DORMANT_ADMIN, PRIVILEGE_CREEP, SERVICE_ACCOUNT_ABUSE,
TOKEN_ABUSE, CROSS_PLATFORM_ADMIN, ORPHANED_CROSS_PLATFORM,
EXCESSIVE_PRIVILEGE_ACCUMULATION, MFA_DISABLED_ADMIN, SHARED_ADMIN_ACCOUNT,
ZOMBIE_SERVICE_ACCOUNT, EXCESSIVE_FAILED_LOGINS, CONTRACTOR_ACCESS_AFTER_EXPIRY,
ESCALATION_WITHOUT_APPROVAL, BREAKGLASS_WITHOUT_INCIDENT, TOKEN_SCOPE_CREEP,
UNROTATED_LONG_LIVED_CREDENTIAL, REVIEW_RUBBER_STAMPING, ORPHANED_GROUP_OWNERSHIP,
IMPOSSIBLE_TRAVEL, PERSISTENT_SOD_VIOLATION, DUPLICATE_IDENTITY_DRIFT, NONE
```

**Task support:**
- **Anomaly Detection (classification):** `is_risky` (binary) and/or `anomaly_type` (multi-class) as targets.
- **Risk Prediction (regression):** `risk_score_ground_truth` as a continuous target, with `identity_risk_scores` providing the monthly time-series version for trend-prediction tasks.
- **Privilege Abuse Detection (focused subset):** filter `anomaly_type` to the privilege-specific subset (`PRIVILEGE_CREEP`, `EXCESSIVE_PRIVILEGE_ACCUMULATION`, `CROSS_PLATFORM_ADMIN`, `SHARED_ADMIN_ACCOUNT`, `ESCALATION_WITHOUT_APPROVAL`) as a dedicated evaluation slice.

**On the evaluation targets implied by the shared script** (Precision > 75%, Recall > 70%, Orphaned detection > 90%): hitting a 90%+ recall specifically on `ORPHANED_CROSS_PLATFORM` requires that anomaly to be injected via **unambiguous, structurally clean signals** (a genuinely null `person_id` or a genuinely stale `identity_status`) rather than subtle statistical noise — Step 10's injection method for this anomaly is deliberately binary/structural for exactly this reason, while harder anomalies (Impossible Travel, Privilege Creep) are intentionally noisier and should be expected to pull down blended precision/recall if averaged across *all* categories rather than evaluated per-category.

---

## STEP 14 — RISK SCORE DESIGN

**Identity Risk Score: 0–100, recalculated monthly per identity (feeding `identity_risk_scores`).**

### Base score (privilege-tier exposure, before any anomaly)
| Privilege Tier | Base Score |
|---|---|
| Standard | 5 |
| Power User | 15 |
| Admin | 35 |
| Super Admin | 55 |

### Anomaly weight additions (applied per co-occurring anomaly, additive, capped at 100 total)
| Anomaly | Weight |
|---|---|
| Offboarding Gap | +40 |
| Service Account Abuse | +35 |
| Impossible Travel | +35 |
| MFA Disabled Admin | +30 |
| Token Abuse | +30 |
| Cross-Platform Admin | +25 |
| Orphaned Account (Cross-Platform) | +25 |
| Shared Admin Account | +25 |
| Excessive Privilege Accumulation | +22 |
| Persistent SoD Violation | +20 |
| Dormant Admin | +20 |
| Excessive Failed Logins | +18 |
| Contractor Access After Expiry | +18 |
| Escalation Without Approval | +17 |
| Break-Glass Without Incident Reference | +17 |
| Privilege Creep | +15 |
| Unrotated Long-Lived Credential | +12 |
| Zombie Service Account | +10 |
| Orphaned Group Ownership | +10 |
| Token Scope Creep | +10 |
| Review Rubber-Stamping (affects the *reviewer's process risk*, not the reviewed identity directly — modeled separately) | n/a — process-level metric |
| Duplicate Identity Drift | +8 (applied to both linked identities) |

### Combination logic
- Score = `base_score + sum(applicable anomaly weights)`, capped at 100.
- **Compounding is intentional:** an identity that is both a Dormant Admin *and* an Orphaned Account should score very high (55 base + 20 + 25 = 100, capped) — this realistic compounding is exactly the pattern a hackathon judge would expect a good detector to surface as a top-priority case, not an edge case to be averaged away.

### Time dynamics
- **Growth while unresolved:** for anomalies tied to a detectable "open" state (e.g., `sod_violations.remediation_status = 'Open'`, an unrevoked offboarding gap), add **+2 points per additional 30 days** the condition remains unresolved, up to a +20 cap per anomaly — modeling the realistic principle that risk compounds the longer something goes unaddressed, not just whether it exists.
- **Decay after remediation:** upon remediation (e.g., access revoked, rotation performed, ownership reassigned), the associated anomaly weight should **not disappear instantly**. Apply an immediate partial reduction (–60% of the anomaly's weight) at the remediation month, followed by linear decay of the remainder over the following 2–3 monthly snapshots back to the base score — reflecting that trust/posture recovery is gradual, which also gives a risk-prediction model a meaningful temporal pattern to learn rather than a step function.
- **Monthly snapshot cadence** (matching Phase 2's `identity_risk_scores` design) means the *trend* — not just the point-in-time value — becomes a learnable feature: a steadily climbing score over several months is itself a distinct, realistic risk signal (e.g., for slowly-developing Privilege Creep) versus a sudden spike (e.g., Token Abuse).

---

## STEP 15 — FINAL GENERATION BLUEPRINT

### 1. Dataset Generation Sequence
Exactly as specified in Step 1's 12-tier dependency flow, terminating in `identity_risk_scores` and `identity_risk_labels` as the final two outputs.

### 2. Entity Counts (consistent with Phase 2 Step 12, restated for direct use)
| Entity | Count |
|---|---|
| Persons (employees + contractors) | 6,000 |
| Identities | ~6,150 |
| Platform accounts (human, all 5 platforms combined) | ~19,500 |
| Service accounts | 850 |
| API tokens | 2,400 |
| Business roles | 220 |
| Platform roles | 650 |
| Permissions | 4,500 |
| Groups | 1,250 |
| Group memberships | 138,000 |
| Role assignments | 26,000 |
| Permission assignments | 7,500 |
| Access review campaigns | 22 |
| Review decisions | 42,000 |
| Offboarding event rows | ~5,400 |
| Privilege escalation events | 4,800 |
| Authentication events | ~2.1 million |
| Audit log events | ~310,000 |
| SoD rules / violations | 40 / 180 |
| MFA enrollment records | 19,500 |
| Break-glass usage events | 65 |
| Identity risk score snapshots | 73,800 |
| **Identity risk labels** | **~6,150 (one per identity, multi-label via `contributing_anomaly_types`)** |

### 3. Distribution Tables
All distributions specified in Steps 2 (employees/accounts/privilege), 5 (login behavior), 6 (review outcomes), 7 (offboarding outcomes), 8 (service accounts), 9 (API tokens), and 12 (data quality noise) apply directly as generation parameters.

### 4. Anomaly Injection Plan
22 total anomaly categories (7 core, Step 10 + 15 advanced, Step 11), each with a defined injection rate, structural injection method, and severity — summarized across both step tables. Total anomalous identity population (allowing overlap/co-occurrence) should land around **18–22% of the ~6,150 identities** carrying at least one flagged condition — realistic for a deliberately rich detection dataset without being so dense it stops resembling a real environment (where the vast majority of access is, in fact, legitimate).

### 5. Label Generation Plan
`identity_risk_labels.csv` generated last (Step 13), populated directly from the injection plan's bookkeeping (every injection method in Steps 10–11 should log which identity/table/field it touched, feeding the label file automatically rather than being independently re-derived after the fact — avoiding label leakage/inconsistency risk).

### 6. Data Quality Simulation Plan
Step 12's noise categories applied as a **separate, parallel generation pass** across `persons`, the platform account tables, and `identity_correlation_mapping`, statistically independent from the anomaly injection plan so that ground-truth labels remain clean and noise doesn't contaminate the evaluation signal.

---

*End of Phase 3 synthetic data generation strategy. This document intentionally stops at generation logic and label/risk-score design — no code, no implementation.*
