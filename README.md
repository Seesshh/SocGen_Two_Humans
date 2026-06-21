# Hybrid Identity Governance Platform

A cross-platform identity governance and risk detection system that correlates identities across Active Directory, Azure AD, AWS IAM, Okta, and Salesforce, computes effective privilege through direct and nested-group inheritance, detects 10 categories of access-governance anomalies, and surfaces everything through an explainable risk score and an interactive dashboard.

Built as a synthetic-data hackathon MVP: every dataset is generated, not real, but every detection, scoring, and correlation step runs against that data exactly as it would against a real enterprise identity system.

---

## Quick Start

```bash
pip install pandas numpy faker rapidfuzz networkx streamlit plotly reportlab pypdf

# Run the full pipeline, in order
python3 src/data_generation/generate_org.py
python3 src/data_generation/generate_accounts.py
python3 src/data_generation/generate_groups.py
python3 src/data_generation/generate_access.py
python3 src/data_generation/generate_nonhuman.py
python3 src/data_generation/generate_events.py
python3 src/data_generation/inject_anomalies.py
python3 src/intelligence/identity_resolver.py
python3 src/intelligence/graph_builder.py
python3 src/intelligence/privilege_engine.py
python3 src/intelligence/rules.py
python3 src/intelligence/risk_scoring.py
python3 src/intelligence/incident_correlator.py
python3 src/intelligence/generate_llm_narratives.py
python3 generate_executive_report.py

# Launch the dashboard
streamlit run app.py
```

Full pipeline runtime: ~35 seconds end to end on the reference dataset (1,500 employees/contractors, ~4,800 platform accounts, ~32,000 authentication events).

---

## Architecture

```
DATA GENERATION (7 stages)
  generate_org.py            -> departments, roles, persons
  generate_accounts.py       -> identities, 5 platform accounts, cross-platform correlation mapping
  generate_groups.py         -> groups, nested hierarchy, memberships
  generate_access.py         -> platform roles, role assignments (deterministic privilege-tier derivation)
  generate_nonhuman.py       -> service accounts, API tokens
  generate_events.py         -> offboarding events, sparse authentication events
  inject_anomalies.py        -> injects/labels 7 core anomalies, ground truth (identity_risk_labels.csv)

INTELLIGENCE LAYER (7 stages)
  identity_resolver.py       -> re-resolves identities from raw accounts (tiered matching + confidence scoring)
  graph_builder.py           -> builds the NetworkX identity graph (9 node types, 7 edge types) + metrics
  privilege_engine.py        -> computes effective privilege (direct + nested-group inherited)
  rules.py                   -> 10-rule detection engine -> alerts.csv
  risk_scoring.py            -> 5-factor weighted 0-100 risk score -> identity_risk_scores.csv
  incident_correlator.py     -> groups alerts into incidents by identity + time window
  generate_llm_narratives.py -> template-based Executive/Technical/Business/Compliance narratives

REPORTING
  generate_executive_report.py -> downloadable PDF executive report

DASHBOARD
  app.py                     -> 8-page Streamlit dashboard, dark theme, Demo Mode
```

### Why two passes through "identity resolution"?
`generate_accounts.py` builds the synthetic ground-truth identity linkage as part of generating the data. `identity_resolver.py` then re-derives identity linkage from scratch using only the raw account data — exactly what a real resolver would have to do, with no access to ground truth. This is intentional: it's what makes the detection layer a genuine test of the resolution logic, not just a replay of known answers.

### The identity-ID namespace, explained once
Two different `identity_id` numbering schemes exist in this project, by design:
- **Original** (from `generate_accounts.py` / `identities.csv`) — used by `role_assignments.csv`, `offboarding_events.csv`, `alerts.csv`, `identity_risk_labels.csv`. Equal to `persons.person_id` for every linked identity.
- **Resolved** (from `identity_resolver.py` / `resolved_identities.csv`) — used by `effective_privileges.csv`, `identity_risk_scores.csv`, `incidents.csv`.

Every module that needs both bridges them via `employee_key` (verified at zero unmatched rows in testing). `app.py`'s `get_identity_detail()` function is the clearest worked example of this bridge if you need a reference.

---

## Folder Structure

```
identity-risk-platform/
├── app.py                          # Streamlit dashboard (8 pages, Demo Mode)
├── generate_executive_report.py    # PDF executive report generator
├── README.md
├── src/
│   ├── data_generation/
│   │   ├── generate_org.py
│   │   ├── generate_accounts.py
│   │   ├── generate_groups.py
│   │   ├── generate_access.py
│   │   ├── generate_nonhuman.py
│   │   ├── generate_events.py
│   │   └── inject_anomalies.py
│   └── intelligence/
│       ├── identity_resolver.py
│       ├── graph_builder.py
│       ├── privilege_engine.py
│       ├── rules.py
│       ├── risk_scoring.py
│       ├── incident_correlator.py
│       └── generate_llm_narratives.py
└── data/
    └── synthetic_data/             # all generated CSVs + identity_graph.pkl + executive_report.pdf land here
```

---

## Detected Anomalies

| Anomaly | Detection Method | Validated Precision / Recall vs. Ground Truth |
|---|---|---|
| Offboarding Gap | `offboarding_events.csv` — no revocation recorded past SLA | 100% / 100% |
| Dormant Admin | Admin-tier account, no login in 90+ days | 75% / 100% |
| Cross Platform Admin | Admin-tier on 2+ platforms simultaneously | 99% / 100% |
| Privilege Creep | Stale grant alongside a more recent one, same platform | 100% / 100% |
| Service Account Abuse | Interactive session on an automation-only account | 100% / 100% |
| Token Abuse | Usage statistically outlying vs. the token's own owner-type population | 100% / 100% |
| Orphaned Account | Identity with no linked HR record | 100% / 100% |
| MFA Disabled Admin | Proxy: admin-tier account, zero MFA-protected logins recorded | n/a (no enrollment table in scope; documented proxy) |
| Shared Admin Account | Consecutive logins, same account, different network origins, short window | n/a (logically sound; current synthetic data's IP scheme doesn't vary per-account enough to exercise it — see code comments in `rules.py`) |
| Contractor Access After Expiry | Offboarding Gap, scoped to `termination_reason == 'End of Contract'` | Proxy (no contracts.csv in scope; documented in `rules.py`) |

Precision/recall computed by comparing `alerts.csv` (real rule-engine output) against `identity_risk_labels.csv` (ground truth injected by `inject_anomalies.py`) — the same identities, independently arrived at twice.

---

## Demo Mode

The dashboard sidebar includes a Demo Mode panel with five injection buttons (Offboarding Gap, Dormant Admin, Token Abuse, Privilege Creep, Cross Platform Admin). Each mutates the **in-memory session copy** of the relevant data and immediately refreshes the affected views — it never writes to the CSVs on disk, so it's safe to click repeatedly during a live demo without corrupting the underlying dataset.

---

## Known Limitations (stated plainly, not hidden)

- **Authentication events are intentionally sparse** (last ~60-90 days only, by design, to keep the dataset lightweight) — Behavior Risk and any rule relying on login history can only evaluate accounts that have recorded activity in that window.
- **Risk score separation is real but moderate**: ground-truth-flagged identities average ~31 vs. ~14 for unflagged, but only ~20% land in the High/Critical band. This is mathematically defensible (a single non-compounding anomaly shouldn't max out the score) but worth knowing before a live demo built around "watch it flag Critical."
- **The Shared Admin Account rule has no positive test case** in the current synthetic dataset — not because the logic is wrong, but because `generate_events.py`'s source-IP generation doesn't vary enough per account to produce the pattern it looks for. Documented directly in `rules.py`.
- **`MFA Disabled Admin` and `Contractor Access After Expiry`** are implemented as documented proxies against real data (no dedicated MFA-enrollment or contracts table exists in this dataset's scope) rather than against purpose-built tables. See the `rules.py` module docstring for the exact reasoning.

---

## Tech Stack

`pandas`, `numpy`, `Faker`, `rapidfuzz`, `networkx`, `streamlit`, `plotly`, `reportlab`

---

## Screenshots

*(placeholder — capture from a live `streamlit run app.py` session)*

- `screenshots/executive_overview.png`
- `screenshots/identity_risk_registry.png`
- `screenshots/identity_graph_explorer.png`
- `screenshots/incident_investigation.png`
- `screenshots/offboarding_monitor.png`
