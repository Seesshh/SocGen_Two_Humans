# Hybrid Identity Governance Platform — Pre-Demo Technical Validation Report
### Prepared as final engineering review, 24 hours before judging

**Epistemic basis — read this before anything else.** I personally wrote, executed, and debugged 13 of the 15 files in this project, against a fresh end-to-end run performed for this exact report (timings, row counts, and distributions below are from that run, completed minutes ago — not memory from earlier in this conversation). **`rules.py` and `app.py` have never been shared with me in any form.** No code, no output, no screenshots. Every section touching those two files is explicitly marked `[UNVERIFIED]` and is a checklist for you to run yourself, not a finding about your actual code. I will not fabricate confidence about files I haven't read — that would be a worse failure than an incomplete report, especially with judging in 24 hours.

If you paste or upload `rules.py` and `app.py` now, I will run the identical hands-on validation on them that the rest of this report is based on, and can update the Go/No-Go call within minutes.

---

## STEP 1 — Codebase Inventory

| File | Purpose | Status | Issues |
|---|---|---|---|
| `generate_org.py` | Departments, business roles, employee/contractor roster with hierarchy | **Working** | None outstanding |
| `generate_accounts.py` | Identities + 5 platform accounts + cross-platform correlation | **Working** | Originally had a name-matching bug (fixed — see Step 10) |
| `generate_groups.py` | Groups, nested hierarchy, memberships | **Working** | None outstanding |
| `generate_access.py` | Platform roles + role assignments, privilege-tier derivation | **Working** | Originally had a role-lookup fallback bug that silently downgraded Admin→Standard (fixed — see Step 10) |
| `generate_nonhuman.py` | Service accounts + API tokens | **Working** | None outstanding |
| `generate_events.py` | Offboarding events + sparse authentication events, reconciles account status | **Working** | None outstanding |
| `inject_anomalies.py` | Injects/labels all 7 anomalies, produces ground truth | **Working** | Dormant Admin sample size is thin (3 cases) — see Step 4 |
| `identity_resolver.py` | Cross-platform identity resolution from raw accounts | **Working** | None outstanding |
| `graph_builder.py` | NetworkX identity graph + metrics | **Working, with a design gap** | Service accounts have no direct privilege edges of their own — see Step 6 |
| `privilege_engine.py` | Effective privilege calculation (direct + inherited) | **Working** | None outstanding |
| `rules.py` | Rule-based anomaly detection → alerts | **UNVERIFIED** | Never seen. Downstream modules currently run on a documented fallback (see Step 2) |
| `risk_scoring.py` | 5-factor 0-100 identity risk score | **Working, with a tuning weakness** | Only 20.2% of true positives reach High/Critical band — see Step 7 |
| `incident_correlator.py` | Groups alerts into incidents | **Working** | Correctly tested against fallback alerts only — temporal correlation logic untested against real timestamp variance |
| `generate_llm_narratives.py` | Template-based incident narratives | **Working** | None outstanding |
| `app.py` | Streamlit dashboard | **UNVERIFIED** | Never seen |

**13 Working, 0 Risky, 0 Incomplete, 0 Broken, 2 Unverified.** The "0 Broken" is not a guess — every one of those 13 files just ran clean, exit code 0, in the fresh run this report is based on.

---

## STEP 2 — Execution Order Validation

### Verified dependency graph (real run, just performed)
```
generate_org.py            [0.89s]  → departments.csv, roles.csv, persons.csv
   ↓
generate_accounts.py       [8.33s]  → identities.csv, {ad,azure,aws,okta,salesforce}_accounts.csv,
   ↓                                  identity_correlation_mapping.csv
   ├→ generate_groups.py   [0.98s]  → groups.csv, nested_group_relationships.csv, group_memberships.csv
   └→ generate_access.py   [1.54s]  → platform_roles.csv, role_assignments.csv
         ↓
generate_nonhuman.py       [1.15s]  → service_accounts.csv, api_tokens.csv
   ↓
generate_events.py         [2.88s]  → offboarding_events.csv, authentication_events.csv
                                       (also REWRITES the 5 account CSVs to reconcile offboarding status)
   ↓
inject_anomalies.py        [1.70s]  → identity_risk_labels.csv
                                       (also REWRITES role_assignments.csv, service_accounts.csv,
                                        api_tokens.csv, authentication_events.csv, 5 account CSVs)
   ↓
identity_resolver.py       [8.38s]  → resolved_identities.csv, identity_resolution_evidence.csv
   ├→ graph_builder.py     [2.94s]  → identity_graph.pkl, graph_metrics.csv
   └→ privilege_engine.py  [1.27s]  → effective_privileges.csv
         ↓
   [rules.py]               ⚠ UNVERIFIED → expected: alerts.csv
         ↓
risk_scoring.py             [1.27s]  → identity_risk_scores.csv
   (falls back to identity_risk_labels.csv if alerts.csv is absent — confirmed firing in this run)
   ↓
incident_correlator.py      [1.09s]  → incidents.csv
   ↓
generate_llm_narratives.py  [0.47s]  → incident_narratives.csv
   ↓
   [app.py]                 ⚠ UNVERIFIED
```
**Total verified runtime: 32.89 seconds, end-to-end, 13 stages.** That's your real headroom for a live "watch it run" demo moment if you want one.

### Missing files
- **`alerts.csv` does not exist anywhere in the pipeline right now.** `risk_scoring.py` and `incident_correlator.py` both detected its absence and used their documented fallback (confirmed via log: `"alerts.csv not found — deriving a fallback alerts table from identity_risk_labels.csv"`). This means **everything downstream of this point — risk scores, incidents, narratives — is currently running on ground-truth labels, not on actual rule-engine detections.** If `rules.py` exists and produces `alerts.csv`, the *moment* you run it, the whole back half of the pipeline silently switches behavior. That switch needs to be tested before judging, not discovered during it.

### Circular dependencies
None found. The 13-stage chain is a strict DAG.

### Broken references
None within the 13 verified files. The only broken/unconfirmed reference in the whole project is `alerts.csv`, described above.

---

## STEP 3 — Schema Validation (every CSV, from the fresh run)

| File | Rows | Primary Key | Key Foreign Keys |
|---|---|---|---|
| `departments.csv` | 20 | `department_id` | — |
| `persons.csv` | 1,500 | `person_id` | `department_id`, `manager_person_id` (self) |
| `roles.csv` | 60 | `role_id` | `owning_department_id` |
| `identities.csv` | 1,540 | `identity_id` | `person_id` (nullable — orphans) |
| `ad_accounts.csv` | 1,330 | `platform_account_id` | `identity_id` |
| `azure_accounts.csv` | 1,455 | `platform_account_id` | `identity_id` |
| `aws_accounts.csv` | 353 | `platform_account_id` | `identity_id` |
| `okta_accounts.csv` | 1,397 | `platform_account_id` | `identity_id` |
| `salesforce_accounts.csv` | 273 | `platform_account_id` | `identity_id` |
| `identity_correlation_mapping.csv` | 4,808 | `mapping_id` | `identity_id`, `platform_id` |
| `groups.csv` | 300 | `group_id` | `platform_id` |
| `nested_group_relationships.csv` | 295 | `nesting_id` | `parent_group_id`, `child_group_id` → `groups.group_id` |
| `group_memberships.csv` | 4,768 | `membership_id` | `group_id`, `platform_account_id` |
| `platform_roles.csv` | 157 | `platform_role_id` | `platform_id` |
| `role_assignments.csv` | 4,891 | `assignment_id` | `identity_id` *(original numbering — see warning below)*, `platform_role_id`, `business_role_id` |
| `service_accounts.csv` | 210 | `service_account_id` | `owner_person_id`, `backup_owner_person_id` |
| `api_tokens.csv` | 600 | `token_id` | `owner_person_id` OR `owner_service_account_id` |
| `offboarding_events.csv` | 715 | `offboarding_id` | `person_id`, `identity_id`, `platform_id` |
| `authentication_events.csv` | 32,218 | `auth_event_id` | `platform_account_id`, `platform_id` |
| `identity_risk_labels.csv` | 269 | — (one row per identity-anomaly pair) | `identity_id` *(mixed namespace — see warning below)* |
| `resolved_identities.csv` | 1,501 | `identity_id` *(resolver's own numbering)* | `employee_key` → `persons.person_id` |
| `identity_resolution_evidence.csv` | 4,808 | `evidence_id` | `platform_account_id` |
| `effective_privileges.csv` | 1,501 | `identity_id` *(matches resolved_identities)* | `employee_key` |
| `graph_metrics.csv` | 9,007 | `node_id` (composite string key) | — |
| `identity_graph.pkl` | 9,007 nodes / 23,437 edges | — | binary, not a CSV |
| `identity_risk_scores.csv` | 1,560 | `identity_id` | — |
| `incidents.csv` | 257 | `incident_id` | `identity_id` |
| `incident_narratives.csv` | 257 | `incident_id` | `identity_id` |

### The one schema fact that matters most for your demo prep
**There are two different `identity_id` columns in this project that are not the same numbering scheme**, and they're both just called `identity_id`:
1. **Original numbering** (from `generate_accounts.py`'s `identities.csv`, used by `role_assignments.csv`, `offboarding_events.csv`, `identity_risk_labels.csv`) — here `identity_id == person_id` for every linked identity.
2. **Resolver numbering** (from `identity_resolver.py`'s `resolved_identities.csv`, used by `effective_privileges.csv`, `identity_risk_scores.csv`, `incidents.csv`, `incident_narratives.csv`, `graph_metrics.csv` node keys) — a fresh sequence assigned by re-deriving identities from raw account data.

Every module I built bridges between these two correctly via `employee_key`/`person_id`, verified with **zero unbridged rows** in every join I tested. But if anyone — including a freshly-written `rules.py` — joins `role_assignments.csv` directly against `identity_risk_scores.csv` on `identity_id` without going through that bridge, **it will silently join the wrong rows together for most of the dataset**, not error out. This is the single most dangerous landmine in the schema. Say it out loud to your team before tonight.

### Mismatches found and fixed during development (now resolved, listed for your awareness)
- `business_role_id` / `platform_role_id` / `employee_key` columns get silently upcast from int to float64 by pandas the moment a NaN appears (orphans, ungoverned grants). Three separate instances of this caused silent zero-result joins; all three are fixed in the delivered code via a `clean_id()`/`_clean_id()` normalization helper. **If `rules.py` does its own joins on these columns without the same normalization, it is at risk of the identical silent failure.**

---

## STEP 4 — Data Generation Validation

### Realistic distributions (verified, fresh run)
- 1,500 persons (1,200 employee / 300 contractor — exact 80/20 split), 225 terminated (exactly 15.0%)
- Platform coverage: AD 87.4%, Azure AD 96.1%, Okta 92.7%, AWS 23.5%, Salesforce 18.2% — within 1pp of every blueprint target
- Privilege pyramid (role_assignments): Standard ~80%, Power User ~15%, Admin ~4%, Super Admin 1.5% (exact target)
- Org hierarchy: 1 CEO, manager-tier validation showed 0 genuine violations across 1,499 reporting relationships (one earlier false-positive in my own test harness, not the data — already resolved)

### Anomaly injection — actual numbers, this run

| Anomaly | Count | Target | Verdict |
|---|---|---|---|
| Privilege Creep | 123 | 123.2 (8%) | **Generated, detectable, meaningful** — exact match |
| Cross Platform Admin | 69 | ~62 (4%) | **Generated, detectable, partially meaningful** — see caveat below |
| Orphaned Account | 40 | 38.5 (2.5%) | **Generated, detectable, meaningful** — near-exact |
| Offboarding Gap | 15 | ~18 (8% of terminations) | **Generated, detectable, meaningful** — slightly under target |
| Token Abuse | 15 | 15 (2.5%) | **Generated, detectable, meaningful** — exact match |
| Service Account Abuse | 4 | ~4.2 (2%) | **Generated, detectable, meaningful** — close match |
| Dormant Admin | 3 | ~4 (3%) | **Generated, technically detectable, weak for demo** — too few cases to showcase confidently live |

**The Cross Platform Admin caveat, stated plainly:** all 69 cases are "legitimately senior people who get broad access by design," not "someone who shouldn't have this access but does." The rule will fire on them — but if a judge asks "show me the difference between a legitimate senior admin and an anomalous one," the current dataset can't answer that question, because it never generated the anomalous case on purpose. This was flagged when the file was built and is still true.

**7 of 7 required anomalies are present in the data and carry ground-truth labels.** 5 of 7 are well-represented; Dormant Admin is thin; Cross Platform Admin's *intended* failure mode (ungoverned exception, not legitimate seniority) was never actually generated.

---

## STEP 5 — Detection Engine Validation

### Trace: Generated Data → Detection Rule → Alert → Incident → Risk Score

| Stage | Status | Evidence |
|---|---|---|
| Generated Data | Verified | 269 labeled anomalies across 7 types, real CSVs, real injection logic |
| Detection Rule (`rules.py`) | **UNVERIFIED** | Never seen. This is the actual missing link in the chain. |
| Alert (`alerts.csv`) | **Does not exist** — fallback active | `risk_scoring.py`/`incident_correlator.py` derive a stand-in directly from ground-truth labels |
| Incident (`incidents.csv`) | Verified, but only against the fallback | 269 alerts → 257 incidents, 12 genuine multi-anomaly correlations, severity escalation logic confirmed working |
| Risk Score (`identity_risk_scores.csv`) | Verified, but only against the fallback | Flagged identities average 31.6 vs 14.0 unflagged; full trace below |

**What this means concretely:** the pipeline's *shape* — that an anomaly in the data eventually produces a scored, narrated incident — is proven correct. What is **not** proven is whether your actual `rules.py` *correctly identifies* those 269 anomalies from first principles (joining raw tables, applying thresholds, computing severity) the way the fallback currently assumes they're already known. **The fallback is graded on an open-book test; `rules.py` has to pass the closed-book version.**

### Logic/implementation correctness (for the 5 verified intelligence modules)
- `identity_resolver.py`: tiered matching (employee ID → email → username → fuzzy name) verified correct, including a stress test where a name-collision bug surfaced in my own offline test data and the ambiguity-detection logic correctly caught it rather than mis-linking.
- `graph_builder.py`: edge construction verified correct after fixing the ID-upcast bug (before the fix: `HAS_ROLE`=0, `OWNS`=0 edges, silently; after: thousands of correct edges, matching expected counts exactly, e.g. `REPORTS_TO`=1,499 = 1,500 persons − 1 CEO).
- `privilege_engine.py`: bridging verified with **zero unbridged role assignments and zero unmatched group memberships** on real data. Nested-group depth tracing confirmed correct (spot-checked an identity with `privilege_depth=2` reaching a baseline group through two nesting levels).
- `risk_scoring.py`: 5-component formula confirmed mathematically consistent with logged sub-scores on every spot-checked row.
- `incident_correlator.py`: correlation grouping and Critical-floor escalation logic confirmed correct on a real multi-anomaly case (Cross Platform Admin + Privilege Creep → correctly escalated to Critical, combined remediation correctly merged).

### Edge cases handled
- Missing email → falls through to username/name matching (`identity_resolver.py`)
- Orphaned accounts (no person link) → resolved as Orphaned identities, not silently dropped
- Ungoverned grants (`business_role_id IS NULL`) → no `HAS_ROLE` edge created, but `HAS_PERMISSION` edge still created (correctly distinguishes "no role justification" from "no access")
- Service accounts with no owner → preserved as isolated graph nodes rather than dropped (see Step 6 for why this is also a problem)

### Scalability
Confirmed fine at current scale (32.89s full pipeline). Known future bottlenecks: `iterrows()`-heavy loops in `graph_builder.py`/`privilege_engine.py`/`generate_groups.py`, and `nx.single_source_shortest_path_length()` per-node for `privilege_reach`. Neither is a problem at tonight's scale; both would need vectorization before a true enterprise-scale (Phase 2's ~19,500-account target) run.

---

## STEP 6 — Graph Validation

**Real numbers from this run:** 9,007 nodes, 23,437 edges, 6 connected components.

### Disconnected nodes — found, real, not hypothetical
- **4 fully isolated nodes (zero edges at all)**, all `ServiceAccount` type: `SERVICEACCOUNT:75`, `82`, `121`, `136`. Root cause: these are the deliberately-unowned service accounts (the "never assigned" ~3% population from `generate_nonhuman.py`) with no tokens referencing them either, so they have no `OWNS` edge (no owner) and no `USES` edge (no tokens). One of them (`SERVICEACCOUNT:75`) is flagged `is_breakglass=True` with `Admin` privilege — **an isolated, unowned, break-glass admin service account is exactly the kind of thing a real auditor would want surfaced, and right now the graph has no path to it from any identity at all.**
- **One small disconnected component**: `SERVICEACCOUNT:53` plus its two tokens (`TOKEN:332`, `TOKEN:513`) — connected to each other but cut off from the main graph (no human owner, so no path back to any Employee/Identity).

### Graph design flaw — service accounts have no direct privilege edges
Service accounts only get `OWNS` (from owner) and `USES` (to their tokens) edges. **They never get `HAS_ROLE`/`HAS_PERMISSION` edges of their own**, because `role_assignments.csv` only covers human-bridged identities in the current `graph_builder.py` design. This means `privilege_reach` for *any* ServiceAccount node is structurally always 0, even for ones that are otherwise well-connected — the graph currently cannot answer "if this specific service account is compromised, what can it directly do," only "who owns it and what tokens does it hold." This is a real, demonstrable design gap, not a hypothetical one.

### Node/edge design (carried forward, still accurate)
- Permission nodes are a documented proxy (one per `platform_role_id`, since no granular permission catalog was in scope) — coarser than true permission-level analysis.
- `OWNS` is overloaded across 4 distinct relationships (Employee→Identity, Identity→Account, Employee→ServiceAccount, Employee→Token) because the requested 7-edge vocabulary had no dedicated "belongs to" type.
- `REPORTS_TO` (1,499 edges) and `INHERITS` (89 edges) both depend on optional enrichment files being present — confirmed working this run, but silently empty if those files are absent.

### Risk propagation
`privilege_reach` correctly identifies the highest-exposure nodes (top results this run were Employee nodes with reach=31, consistent with the REPORTS_TO→HAS_ROLE→HAS_PERMISSION chain). Weakness carried forward: no distance-decay — a node 5 hops from 31 permissions scores identically to one 1 hop away.

---

## STEP 7 — Risk Scoring Validation

### Score ranges and weighting (verified mathematically consistent)
0-100 scale, 5 components (Privilege 30% / Behavior 20% / Exposure 20% / Governance 20% / Cross-Platform 10%), correctly clipped and rounded in every row spot-checked.

### Severity mapping
Risk bands: Low (0-29) / Medium (30-54) / High (55-79) / Critical (80+). This run: **0 identities reached Critical**, 52 High, 180 Medium, 1,328 Low.

### Do anomalous identities consistently score higher? — Yes, but not dramatically
- Ground-truth-flagged identities: avg risk_score **31.6**
- Unflagged identities: avg risk_score **14.0**
- **Only 20.2%** of flagged identities land in High/Critical band

**This is the single most important number in this whole report for your live demo.** The direction is correct and statistically real — but if your demo narrative is "watch the system catch the bad actors with a dramatic Critical score," the data as currently weighted won't deliver that for 4 out of 5 true positives. Two fixes, both fast: (1) increase Governance Risk's weight or add a compounding bonus for multiple co-occurring signals, or (2) reframe your demo narrative around percentile rank / relative ordering rather than absolute band membership — "this identity is in the top 3% of risk in the company" is true and compelling even at a score of 35.

### Explainability / auditor friendliness
Strong — every score decomposes into its 5 named components plus a human-readable `top_risk_reason`, verified to read naturally on real output (not generic placeholder text). Missing: a `risk_model_version` field, so a future weight change would make historical scores unexplainable.

---

## STEP 8 — Dashboard Validation `[UNVERIFIED — entirely]`

I cannot evaluate pages, charts, filters, KPIs, or drilldowns in code I have never seen. What I can tell you with certainty: **every CSV `app.py` would need to read has the schema documented in Step 3 above, generated by code that ran clean 30 seconds ago.** If `app.py` was built against those exact column names, it should work. If it was built against assumed/remembered column names, or against `alerts.csv` (which doesn't exist), it will fail live.

**What you should personally check in the next hour, in this order:**
1. Does `app.py` import and run with zero errors against the real `data/synthetic_data/` directory right now?
2. Does it read `alerts.csv`? If yes, it will crash — that file doesn't exist unless `rules.py` has been run and produces it.
3. Click through every page once, end to end, with no exceptions thrown.
4. Specifically check anything reading `identity_id` columns — confirm it's using the right namespace per the warning in Step 3.

---

## STEP 9 — Live Demo Simulation (Judge's Seat)

**What I can simulate honestly:** the backend/data story, since I've directly inspected it. **What I cannot simulate:** the actual screen a judge looks at, since that's `app.py`, which I haven't seen. The following is split accordingly.

### First impression (data/architecture, verified)
A judge digging into the CSVs or asking "show me your data model" would find a genuinely sophisticated, internally consistent system — cross-platform identity correlation with confidence scoring, nested-group privilege inheritance, a real graph with computed centrality and privilege-reach metrics, a 5-factor explainable risk score. This is well above the "basic rules + basic dashboard" baseline most hackathon teams ship.

### Strengths (verified)
- Reproducible end-to-end in under 35 seconds — a genuinely strong "let's just run it live" moment if you want one.
- Real bugs caught and fixed during development (the ID-upcast pattern, the matching bug) — if a judge asks "how do you know this works," you have a concrete, specific answer instead of "it looks right."
- The cross-platform identity resolution story (showing inconsistent names/emails across 5 platforms correctly re-linked with confidence scores) is a strong, underused differentiator most teams won't have built.

### Weaknesses (verified)
- Risk score separation (20.2% in top bands) is a real, demonstrable weak point if probed directly.
- Cross Platform Admin's "all legitimate, none anomalous" population undercuts the "look, we caught the bad case" story for that specific anomaly.
- Dormant Admin has only 3 examples — thin ground for a confident live walkthrough.

### Confusing parts (verified)
- The dual `identity_id` namespace (Step 3) would confuse a technical judge who starts cross-referencing CSVs by hand during Q&A, unless you can explain the bridge clearly and fast.

### Boring / Impressive parts `[UNVERIFIED — depends entirely on app.py]`
Cannot assess without seeing the dashboard. The backend substance is there to make this impressive *if* the dashboard surfaces it well; equally, a dashboard that doesn't show the graph, the multi-platform correlation, or the explainable risk breakdown would waste the most differentiated parts of the build.

---

## STEP 10 — Bug Hunt

### Critical Bugs
| File | Root Cause | Impact | Fix |
|---|---|---|---|
| `rules.py` (status) | Never verified to exist or produce correct `alerts.csv` | Entire detection-engine story is unproven; downstream silently runs on ground-truth labels instead | Run it against real upstream CSVs *today*, diff its output against `identity_risk_labels.csv` |
| `app.py` (status) | Never verified | Could fail live on first click | Run it against the real data directory *today*, click every page |
| Project-wide | pandas silently upcasts int ID columns to float64 on any NaN; `"5"` ≠ `"5.0"` as dict keys | Any new join on an ID column (in `rules.py`, `app.py`, or future code) can silently produce empty/wrong results with exit code 0 | Normalize every ID column to string at load time, everywhere, including any new code |

### High Priority
- **Cross Platform Admin has no "anomalous" examples**, only legitimate ones (file: `inject_anomalies.py` / `generate_access.py` interaction) — weakens the one anomaly story most likely to come up in Q&A about cross-platform risk.
- **Dormant Admin sample size = 3** (file: `inject_anomalies.py`) — too thin to demo confidently.
- **Only 20.2% of true positives reach High/Critical band** (file: `risk_scoring.py`) — real risk to the "the system flags bad actors" demo narrative.
- **4 isolated + 3 disconnected ServiceAccount nodes in the graph** (file: `graph_builder.py`) — currently invisible to any identity-rooted graph query; one of them is a break-glass admin account.

### Medium Priority
- `clean_id()` logic duplicated across 4 files instead of shared (maintenance risk, not a live-demo risk).
- No `risk_model_version` field on `identity_risk_scores.csv`.
- Optional-enrichment files (`departments.csv`, `groups.csv`, `nested_group_relationships.csv`, `resolved_identities.csv`) are silent dependencies for `graph_builder.py`/`privilege_engine.py` — works today because they're present, but undocumented as a hard requirement anywhere.
- ServiceAccount nodes have no direct `HAS_ROLE`/`HAS_PERMISSION` edges of their own (graph design gap, Step 6).

### Low Priority
- No automated test suite — every validation so far has been manual inspection (thorough, but not repeatable by someone else without doing the same work).
- `iterrows()`-heavy loops will need vectorization before true enterprise scale, irrelevant at tonight's data size.
- Betweenness centrality approximation (k=200 sampling) never validated against an exact computation.

---

## STEP 11 — Test Plan (exact commands, exact expected output)

Run each in order. All expected values below are from the fresh run performed for this report — if your output differs meaningfully, something has changed since this review.

```
1) python3 generate_org.py
   Expected files: departments.csv, roles.csv, persons.csv
   Expected rows: 20 / 60 / 1500
   Sanity check: persons.csv termination rate ≈ 15.0%

2) python3 generate_accounts.py
   Expected files: identities.csv, ad_accounts.csv, azure_accounts.csv,
                    aws_accounts.csv, okta_accounts.csv, salesforce_accounts.csv,
                    identity_correlation_mapping.csv
   Expected rows: 1540 / 1330 / 1455 / 353 / 1397 / 273 / 4808
   Sanity check: coverage % within 1pp of 88/96/93/23/18

3) python3 generate_groups.py
   Expected files: groups.csv, nested_group_relationships.csv, group_memberships.csv
   Expected rows: 300 / 295 / 4768
   Sanity check: groups.csv exactly 300 rows (hard requirement, not approximate)

4) python3 generate_access.py
   Expected files: platform_roles.csv, role_assignments.csv
   Expected rows: ~157 / ~4891 (will vary slightly run-to-run only if seed changes)
   Sanity check: privilege tier distribution approximately 80/15/4/1.5%

5) python3 generate_nonhuman.py
   Expected files: service_accounts.csv, api_tokens.csv
   Expected rows: 210 / 600
   Sanity check: ~15% of tokens have null expiration_date

6) python3 generate_events.py
   Expected files: offboarding_events.csv, authentication_events.csv
                    (also REWRITES the 5 account CSVs — re-check their row counts unchanged)
   Expected rows: ~715 / ~32,000-33,000
   Sanity check: at least one identity shows account_status='Active' despite
                 persons.status='Terminated' (the offboarding gap signal)

7) python3 inject_anomalies.py
   Expected files: identity_risk_labels.csv
                    (also REWRITES role_assignments.csv, service_accounts.csv,
                     api_tokens.csv, authentication_events.csv, 5 account CSVs)
   Expected rows: ~260-270
   Sanity check: labels.groupby('anomaly_type').size() shows all 7 anomaly types present

8) python3 identity_resolver.py
   Expected files: resolved_identities.csv, identity_resolution_evidence.csv
   Expected rows: ~1501 / 4808
   Sanity check: identity_status value_counts shows mostly 'Linked', some 'Under Review'

9) python3 graph_builder.py
   Expected files: identity_graph.pkl, graph_metrics.csv
   Expected: 9007 nodes, 23437 edges (or close, if upstream randomness shifted slightly)
   Sanity check: log line "Total nodes: ... | Total edges: ..." — if either is near 0,
                 something broke silently; this should NEVER happen but is exactly
                 the failure mode this project has hit before

10) python3 privilege_engine.py
    Expected files: effective_privileges.csv
    Expected rows: ~1501
    Sanity check: log line "bridged rows: X | unbridged rows: 0" — unbridged should be 0

11) [rules.py]  RUN THIS YOURSELF AND CONFIRM
    Expected file: alerts.csv
    Sanity check: does it match the schema documented in Step 3 of this report?
                  (alert_id, identity_id, anomaly_type, severity, platform_id,
                   detected_at, evidence, rule_name)

12) python3 risk_scoring.py
    Expected file: identity_risk_scores.csv
    Expected rows: ~1560
    Sanity check: log line shows "alerts.csv not found, deriving fallback" UNLESS
                  rules.py has already produced a real alerts.csv — if you ran step 11,
                  confirm this log line does NOT appear (i.e. it used the real file)

13) python3 incident_correlator.py
    Expected file: incidents.csv
    Expected rows: ~257 (will change once real alerts.csv with real timestamps feeds it)

14) python3 generate_llm_narratives.py
    Expected file: incident_narratives.csv
    Expected rows: matches incidents.csv row count exactly

15) [app.py]  RUN THIS YOURSELF
    Launch it. Click every page. Note any exception. Report back.
```

---

## STEP 12 — Go / No-Go Review

### Verdict: CONDITIONAL GO — pending 2 checks you can complete in under an hour

**The 13 modules I verified are demo-ready right now, with no qualification.** They ran clean, end-to-end, in 33 seconds, producing internally consistent, schema-correct, reproducible output with all 7 required anomalies present and labeled.

**Blockers to a confident GO:**
1. **`rules.py` has never been run against real upstream data in front of me or, as far as I know, anyone validating it the way the other 13 files were validated.** Run Step 11's test right now. If it produces a correctly-shaped `alerts.csv`, this blocker clears.
2. **`app.py` has never been launched against this real data.** Run Step 11's test #15 right now. If every page loads without an exception, this blocker clears.

**If both checks pass in the next hour: this is a full GO, and a competitive one.** If either fails, you have 24 hours, which is enough time to fix a schema mismatch (most likely failure mode, given this project's history) but not enough time to discover it live during judging.

**If you genuinely cannot test `rules.py`/`app.py` before judging:** demo the verified 13-stage pipeline directly — running it live, walking through the schema, the graph, the privilege calculation, and the risk scores — and be upfront that the rule engine and dashboard are "in final integration." That is a real, creditable position; pretending otherwise and having it fail live is the actual risk.

---

## FINAL OUTPUT

| Score | Value | Basis |
|---|---|---|
| **Project Health Score** | **68 / 100** | Strong, evidence-backed core (13/15 files) pulled down hard by 2 unverified, demo-critical unknowns and a real risk-scoring tuning weakness |
| **Architecture Score** | **7 / 10** | Consistent, well-documented patterns; held back by 3 duplicated-logic instances and the dual-identity-namespace design |
| **Engineering Score** | **7.5 / 10** | Genuine bugs found and fixed with evidence, not assumed away; reproducible; zero silent failures in 13 verified files |
| **Security Score** | **6 / 10** | Threat model (7 anomalies) is real and well-evidenced; capped because rule-engine correctness and dashboard access control are both unknown |
| **Innovation Score** | **7 / 10** | Cross-platform correlation, nested-group inheritance, 5-factor explainable scoring are genuinely above baseline; capped by undelivered Phase-4 differentiators (lateral movement, toxic combinations) |
| **Demo Readiness Score** | **5 / 10** | Deliberately conservative — cannot rate readiness higher while the literal screen judges will look at is unverified |

### Top 10 Fixes Before Submission
1. Run `rules.py` against real upstream data and confirm `alerts.csv` matches the documented schema
2. Run `app.py` against the real data directory and click every page
3. Address the 20.2% true-positive-to-High/Critical-band gap in `risk_scoring.py` (weight rebalance or compounding bonus)
4. Generate at least a few more Dormant Admin cases for a credible live walkthrough
5. Add at least one genuinely "ungoverned" Cross Platform Admin case, not just legitimate-seniority ones
6. Investigate and fix (or knowingly accept) the 4 isolated + 3 disconnected ServiceAccount nodes in the graph
7. Normalize ID columns to string at load time in any new/untested code (`rules.py`, `app.py`) to avoid the float-upcast failure class
8. Confirm `app.py` doesn't assume `alerts.csv` exists unconditionally
9. Prepare a clear, fast explanation of the dual-identity-namespace design for technical Q&A
10. Add a `risk_model_version` field if there's time — cheap, and a good "we thought about this" talking point

### Top 10 Strengths
1. Entire 13-stage verified pipeline runs end-to-end in 33 seconds, reproducibly
2. All 7 required anomalies present and labeled with ground truth
3. Cross-platform identity resolution with genuine confidence scoring (not assumed clean joins)
4. Nested-group privilege inheritance correctly modeled and traced (verified depth=2 cases)
5. 5-factor, fully decomposable, explainable risk score — real auditor-friendliness, not just a single black-box number
6. Real bugs were found and fixed during development with concrete evidence, not glossed over
7. Template-based narrative generation produces genuinely readable, professional output with zero LLM dependency
8. Graph correctly computes degree centrality, betweenness centrality, and a custom privilege-reach metric
9. Multi-anomaly incident correlation with correct severity escalation, verified on a real case
10. Clean separation of concerns across 13 well-scoped, independently-testable modules

### Probability of Top 3 Placement
**20-35%, and that range is driven almost entirely by the two unknowns.** The verified foundation alone — reproducible pipeline, real anomaly coverage, explainable scoring, a working graph — is genuinely above-median for a hackathon submission and would support the higher end of that range on its own. But placement is decided by what judges actually see and probe, which is `rules.py`'s real detection accuracy and `app.py`'s actual experience — both unverified. A clean pass on both pushes you toward the top of that range or higher; a failure discovered live pushes you toward the bottom regardless of how strong the other 13 files are.

### Single Biggest Risk
**`rules.py` and `app.py` failing silently or visibly during judging because they were never run against real upstream data the way the other 13 files were.** This project has a demonstrated, repeated history (three separate instances) of code that runs with exit code 0 and produces confidently wrong output. There is no reason to believe the two unverified files are immune to the same failure class — and they're the two files a judge will actually interact with.

### Single Biggest Advantage
**A genuinely tested, reproducible, bug-fixed foundation that most hackathon teams will not have.** Most submissions at this stage have never had their pandas joins checked for silent NaN-upcast failures, never had their identity bridging verified at zero-unmatched-rows, never had their graph checked for disconnected components. This project has all three, with real numbers to back it up. That's a substantive, defensible technical story — if the last two files hold up under the same scrutiny the first thirteen did.
