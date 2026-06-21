# Hybrid Identity Governance — Enterprise Data Model Design (Phase 2)
### Source of truth: Phase 1 Business Problem Analysis (stakeholders, 52 business rules, lifecycle, risks, anomalies, attacker paths)

*Scope assumptions: 5,000 employees, 1,000 contractors, 5 platforms (AD, Azure AD, AWS IAM, Okta, Salesforce), service accounts, API tokens, 1 year of historical data. This document designs the data model only — no code, no dashboards, no architecture decisions beyond the data layer.*

---

## STEP 1 — ENTITY IDENTIFICATION

| Entity | Purpose | Why Required |
|---|---|---|
| **Person** | Canonical human record (employee or contractor) | Single source of truth required by BR-E-01, BR-I-01; root of the entire lifecycle |
| **Department** | Organizational grouping for persons | Needed for role/access templates, reporting, SoD scoping |
| **Contract** | Tracks vendor/contractor engagement terms | Required to support BR-E-14, BR-E-25 (contract-linked access expiry) |
| **Vendor** | Tracks the third-party organization a contractor belongs to | Needed for vendor-level risk aggregation and review cadence (BR-E-25) |
| **Identity** | Canonical cross-platform identity ("golden record") that links a Person to all their platform Accounts | Core to solving identity sprawl/correlation (Step 5 of Phase 1) |
| **Platform** | Reference list of the 5 systems plus service-account/token platforms | Needed to scope every account, role, and permission to a system |
| **Account** | A platform-specific login/identity object (per-platform table; see Step 4) | Represents the actual fragmented identities described in Phase 1 |
| **Role (Business Role)** | Job-function-based access template (e.g., "Financial Analyst") | Supports birthright provisioning (BR-E-17) and role-based access |
| **Platform Role/Profile** | Platform-native role object (AWS IAM Role, Salesforce Profile, etc.) | Required because platforms don't share a common role model |
| **Permission** | Atomic access right (e.g., `s3:GetObject`, "Edit Opportunity") | Needed to compute effective access and least-privilege violations |
| **Group** | Directory group object (AD/Azure AD/Okta group) | Required to model group-based access grants |
| **Group Membership** | Person/Account → Group assignment | Needed to compute direct group-derived access |
| **Nested Group Relationship** | Group → Group parent/child links | Required to resolve effective access (BR-I-19) |
| **Role Assignment** | Account/Identity → Role linkage | Core privilege-grant record |
| **Permission Assignment** | Direct (non-role) permission grants — exceptions | Captures "exception" access outside standard roles |
| **Service Account** | Non-human, automation-use identity | Required by BR-E-06, anomaly "Service Account Abuse" |
| **API Token** | Programmatic credential, often tied to a Service Account or Person | Required by BR-E-07, anomaly "Token Abuse" |
| **Access Review (Campaign)** | A recertification exercise (e.g., Q1 2026 AWS Admin Review) | Required by BR-E-04 |
| **Review Decision** | Line-item outcome of a review (approve/revoke per access item) | Evidence layer for auditors (Phase 1 Step 9) |
| **Offboarding Event** | Termination-triggered de-provisioning record | Required by BR-E-05, BR-E-18, anomaly "Offboarding Gap" |
| **Privilege Escalation Event** | Record of a temporary/permanent elevation grant | Required by BR-E-16, BR-E-21, anomaly "Privilege Escalation" |
| **Authentication/Login Event** | Per-login record per account | Needed for dormancy detection (BR-E-10), behavioral anomaly detection |
| **Audit Log Event** | Generic privileged-action log (config change, permission change, data access) | Required by BR-E-11, BR-E-22 |
| **SoD Rule** | Definition of a conflicting permission/role pair | Required by BR-E-09 |
| **SoD Violation** | Detected instance of a person holding both sides of an SoD rule | Direct fraud-risk evidence for auditors |
| **MFA Enrollment** | MFA status per account | Required by BR-E-12 |
| **Break-Glass Usage Log** | Record of emergency/break-glass account invocation | Required by BR-I-08 |
| **Identity Risk Score** | Periodic computed risk score per identity | Supports CISO/board reporting, prioritization |
| **Identity Correlation Mapping** | Confidence-scored linkage between accounts believed to belong to the same Identity | Solves the cross-platform correlation problem directly (BR-I-03) |

**Total core entities identified: 27**

---

## STEP 2 — MASTER DATA MODEL

*Convention: every table includes a synthetic surrogate key (`*_id`) as primary key even where a natural key exists, for referential stability. Data types are shown in generic SQL form (engineer can map to the target platform/file format).*

### 2.1 `persons`
**Purpose:** Canonical record for every employee and contractor (the HR/vendor system of record).
**Primary Key:** `person_id`
**Foreign Keys:** `manager_person_id` → `persons.person_id` (self-referencing); `department_id` → `departments.department_id`; `vendor_id` → `vendors.vendor_id` (nullable, contractors only)

| Column | Data Type | Example | Business Meaning |
|---|---|---|---|
| person_id | BIGINT | 100482 | Surrogate key |
| employee_number | VARCHAR(12) | "E0048291" | Natural HR identifier (BR-E-01) |
| full_name | VARCHAR(120) | "Priya Subramaniam" | Display name used for cross-platform correlation |
| email | VARCHAR(150) | priya.subramaniam@corp.com | Primary correlation key across platforms (BR-I-03) |
| department_id | INT | 14 | FK → departments |
| job_title | VARCHAR(100) | "Senior Financial Analyst" | Drives birthright role mapping (BR-E-17) |
| manager_person_id | BIGINT | 100120 | FK self-reference; drives approval routing (BR-E-02) |
| employment_type | ENUM | "Employee","Contractor" | Distinguishes review cadence (BR-E-25), offboarding SLA |
| vendor_id | INT (nullable) | 22 | FK → vendors, contractors only |
| hire_date | DATE | 2022-03-14 | Lifecycle start |
| termination_date | DATE (nullable) | 2026-05-01 | Lifecycle end; null = active |
| termination_reason | ENUM (nullable) | "Voluntary","Involuntary","End of Contract" | Drives offboarding urgency (BR-I-09) |
| status | ENUM | "Active","Terminated","On Leave" | Current lifecycle state |
| background_check_level | ENUM | "Standard","Enhanced" | Supports BR-E-24 for sensitive roles |
| location_country | VARCHAR(56) | "India" | Supports jurisdictional/regulatory scoping |
| created_at | DATETIME | 2022-03-10 09:00:00 | Record creation timestamp |
| updated_at | DATETIME | 2026-05-02 08:15:00 | Last HR sync timestamp (supports BR-I-01 freshness checks) |

### 2.2 `departments`
**Primary Key:** `department_id`

| Column | Data Type | Example | Business Meaning |
|---|---|---|---|
| department_id | INT | 14 | Surrogate key |
| department_name | VARCHAR(80) | "Corporate Finance" | Used for SoD scoping, role templates |
| division | VARCHAR(80) | "Finance & Risk" | Higher-level rollup for board/CISO reporting |
| cost_center | VARCHAR(20) | "CC-4410" | Finance/audit traceability |

### 2.3 `vendors`
**Primary Key:** `vendor_id`

| Column | Data Type | Example | Business Meaning |
|---|---|---|---|
| vendor_id | INT | 22 | Surrogate key |
| vendor_name | VARCHAR(120) | "Nexora Consulting Pvt Ltd" | Identifies the third-party org |
| risk_tier | ENUM | "Low","Medium","High" | Drives review frequency (BR-E-25) |
| msa_status | ENUM | "Active","Expired" | Master agreement status |

### 2.4 `contracts`
**Purpose:** Tracks individual contractor engagement terms, distinct from the master vendor agreement.
**Primary Key:** `contract_id`
**Foreign Keys:** `person_id` → `persons.person_id`; `vendor_id` → `vendors.vendor_id`

| Column | Data Type | Example | Business Meaning |
|---|---|---|---|
| contract_id | BIGINT | 88210 | Surrogate key |
| person_id | BIGINT | 100482 | The contractor this contract covers |
| vendor_id | INT | 22 | Supplying vendor organization |
| contract_start_date | DATE | 2025-06-01 | Access should not predate this (BR-E-14) |
| contract_end_date | DATE | 2026-06-01 | Access must expire at/before this date (BR-E-14) |
| renewal_status | ENUM | "Active","Renewed","Expired","Terminated Early" | Drives access-expiry automation logic |

### 2.5 `identities`
**Purpose:** The cross-platform "golden record" that all platform Accounts should correlate to.
**Primary Key:** `identity_id`
**Foreign Keys:** `person_id` → `persons.person_id`

| Column | Data Type | Example | Business Meaning |
|---|---|---|---|
| identity_id | BIGINT | 500091 | Surrogate key — the canonical cross-platform identity |
| person_id | BIGINT (nullable) | 100482 | FK → persons; **nullable** to allow orphaned identities with no HR match (BR-I-20, anomaly "Orphaned Account") |
| canonical_email | VARCHAR(150) | priya.subramaniam@corp.com | Primary matching key |
| identity_status | ENUM | "Linked","Orphaned","Under Review" | Reconciliation state (BR-E-19, BR-E-20) |
| first_seen_date | DATE | 2022-03-14 | Earliest account creation across platforms |
| last_reconciled_at | DATETIME | 2026-06-01 02:00:00 | Last time correlation logic ran against this identity |

### 2.6 `identity_correlation_mapping`
**Purpose:** Confidence-scored linkage between a platform Account and the canonical Identity it is believed to belong to — directly models BR-I-03 (imperfect cross-platform correlation).
**Primary Key:** `mapping_id`
**Foreign Keys:** `identity_id` → `identities.identity_id`; `account_id`, `platform_id` (composite reference into the relevant platform account table — see Step 4)

| Column | Data Type | Example | Business Meaning |
|---|---|---|---|
| mapping_id | BIGINT | 991234 | Surrogate key |
| identity_id | BIGINT | 500091 | The canonical identity |
| platform_id | INT | 3 | FK → platforms (which platform the account lives in) |
| platform_account_id | VARCHAR(64) | "AWSU-88213" | Natural key of the account in its source platform table |
| match_method | ENUM | "Exact Email","Employee ID","Fuzzy Name","Manual" | How the link was established |
| match_confidence | DECIMAL(4,3) | 0.972 | Confidence score; low scores flag for manual review |
| linked_at | DATETIME | 2024-01-15 03:00:00 | When the correlation was made |

### 2.7 `platforms`
**Primary Key:** `platform_id`

| Column | Data Type | Example | Business Meaning |
|---|---|---|---|
| platform_id | INT | 1–7 | Surrogate key |
| platform_name | VARCHAR(40) | "Active Directory","Azure AD","AWS IAM","Okta","Salesforce","Service Account Registry","API Token Registry" | Reference list of in-scope systems |
| platform_type | ENUM | "Directory","IaaS","SSO Broker","SaaS","Internal Registry" | Classifies governance maturity expectations |

### 2.8 Platform Account Tables
*(See full detail in Step 4 — `ad_accounts`, `azure_accounts`, `aws_accounts`, `okta_accounts`, `salesforce_accounts`. Each shares a common column set plus platform-specific extensions.)*

### 2.9 `roles` (Business Roles)
**Purpose:** Job-function access templates used for birthright provisioning.
**Primary Key:** `role_id`

| Column | Data Type | Example | Business Meaning |
|---|---|---|---|
| role_id | INT | 305 | Surrogate key |
| role_name | VARCHAR(100) | "Financial Analyst — Standard" | Maps to job titles for default access (BR-E-17) |
| role_category | ENUM | "Birthright","Functional","Privileged","Administrative" | Drives approval rigor (BR-E-03, BR-E-08) |
| owning_department_id | INT | 14 | FK → departments; who certifies this role's content |
| requires_background_check | BOOLEAN | TRUE | Supports BR-E-24 |
| is_privileged | BOOLEAN | FALSE | Drives review cadence and MFA requirement linkage |

### 2.10 `platform_roles`
**Purpose:** Platform-native role/profile objects (AWS IAM Role, Salesforce Profile/Permission Set, Azure AD Role, Okta App Role).
**Primary Key:** `platform_role_id`
**Foreign Keys:** `platform_id` → `platforms.platform_id`

| Column | Data Type | Example | Business Meaning |
|---|---|---|---|
| platform_role_id | BIGINT | 71029 | Surrogate key |
| platform_id | INT | 3 | Which platform this role lives in |
| native_role_name | VARCHAR(120) | "arn:aws:iam::aws:policy/AdministratorAccess" | The platform's own role identifier |
| privilege_tier | ENUM | "Standard","Elevated","Admin","Super Admin" | Drives cross-platform admin concentration detection (Phase 1 anomaly) |
| can_assume_other_roles | BOOLEAN | TRUE | Supports role-chaining/escalation-path detection (Phase 1 Step 11, attack path #5) |

### 2.11 `permissions`
**Purpose:** Atomic access rights catalog.
**Primary Key:** `permission_id`
**Foreign Keys:** `platform_id` → `platforms.platform_id`

| Column | Data Type | Example | Business Meaning |
|---|---|---|---|
| permission_id | BIGINT | 220981 | Surrogate key |
| platform_id | INT | 3 | Which platform defines this permission |
| permission_name | VARCHAR(150) | "s3:DeleteObject" / "Modify All Data" | The atomic right |
| sensitivity_level | ENUM | "Low","Medium","High","Critical" | Drives least-privilege and SoD evaluation |
| data_classification_scope | ENUM | "None","Internal","Confidential","Regulated" | Supports compliance scoping (HIPAA/PCI/GDPR relevance) |

### 2.12 `groups`
**Purpose:** Directory group objects (AD/Azure AD/Okta).
**Primary Key:** `group_id`
**Foreign Keys:** `platform_id` → `platforms.platform_id`

| Column | Data Type | Example | Business Meaning |
|---|---|---|---|
| group_id | BIGINT | 33012 | Surrogate key |
| platform_id | INT | 1 | Which directory platform owns this group |
| group_name | VARCHAR(120) | "GRP-FIN-Approvers" | Group object name |
| group_type | ENUM | "Security","Distribution","Role-Assignable" | Drives whether membership confers access |
| is_privileged_group | BOOLEAN | TRUE | Flags groups that grant elevated access — central to nested-inheritance risk (BR-I-19) |

### 2.13 `nested_group_relationships`
**Purpose:** Parent/child group links enabling recursive effective-access resolution.
**Primary Key:** `nesting_id`
**Foreign Keys:** `parent_group_id`, `child_group_id` → `groups.group_id`

| Column | Data Type | Example | Business Meaning |
|---|---|---|---|
| nesting_id | BIGINT | 5512 | Surrogate key |
| parent_group_id | BIGINT | 33012 | The group that *contains* the child |
| child_group_id | BIGINT | 33099 | The group whose members inherit parent's access |
| nesting_depth | INT | 2 | Position in the inheritance chain; supports recursive resolution |

### 2.14 `group_memberships`
**Purpose:** Direct Account → Group assignments.
**Primary Key:** `membership_id`
**Foreign Keys:** `group_id` → `groups.group_id`; `platform_account_id`/`platform_id` (composite reference into platform account tables)

| Column | Data Type | Example | Business Meaning |
|---|---|---|---|
| membership_id | BIGINT | 781234 | Surrogate key |
| group_id | BIGINT | 33012 | FK → groups |
| platform_id | INT | 1 | Which platform's account table to resolve against |
| platform_account_id | VARCHAR(64) | "AD-100482" | Natural key of the member account |
| added_date | DATE | 2023-02-01 | When membership began — needed for privilege-creep aging analysis |
| added_by | VARCHAR(64) | "svc-provisioning-bot" | Accountability/justification trail |

### 2.15 `role_assignments`
**Purpose:** Account/Identity → Role linkage (business role and/or platform role).
**Primary Key:** `assignment_id`

| Column | Data Type | Example | Business Meaning |
|---|---|---|---|
| assignment_id | BIGINT | 990123 | Surrogate key |
| identity_id | BIGINT | 500091 | FK → identities |
| platform_id | INT | 3 | Platform the role applies to |
| platform_role_id | BIGINT | 71029 | FK → platform_roles |
| business_role_id | INT (nullable) | 305 | FK → roles, if assignment originated from a business role template |
| assignment_type | ENUM | "Birthright","Requested","Temporary","Inherited" | Drives elevation/temporary-access tracking (BR-E-16) |
| granted_date | DATE | 2023-05-10 | Start of access |
| expiration_date | DATE (nullable) | 2023-05-17 | Required for temporary grants (BR-E-16); null = standing access |
| approved_by_person_id | BIGINT | 100120 | FK → persons; supports BR-E-02, BR-E-21 |
| approval_ticket_ref | VARCHAR(40) | "CHG0098213" | Links to change management record (BR-E-21) |
| status | ENUM | "Active","Expired","Revoked" | Current state |

### 2.16 `permission_assignments`
**Purpose:** Direct, non-role-based permission exceptions (the access that doesn't fit the "clean" role model — common in real environments).
**Primary Key:** `perm_assignment_id`

| Column | Data Type | Example | Business Meaning |
|---|---|---|---|
| perm_assignment_id | BIGINT | 660921 | Surrogate key |
| identity_id | BIGINT | 500091 | FK → identities |
| permission_id | BIGINT | 220981 | FK → permissions |
| grant_reason | VARCHAR(200) | "One-off vendor data export, approved by CISO" | Justification text — supports least-privilege audit testing |
| granted_date | DATE | 2025-11-03 | Start date |
| expiration_date | DATE (nullable) | 2025-11-10 | Supports time-bound exception tracking |
| status | ENUM | "Active","Expired","Revoked" | Current state |

### 2.17 `service_accounts`
*(Full detail in Step 6.)*

### 2.18 `api_tokens`
*(Full detail in Step 7.)*

### 2.19 `access_reviews` / `review_decisions`
*(Full detail in Step 8.)*

### 2.20 `offboarding_events`
*(Full detail in Step 9.)*

### 2.21 `privilege_escalation_events`
**Purpose:** Records every elevation grant, time-bound or not — central to detecting attack path #5/#7/#15 from Phase 1.
**Primary Key:** `escalation_id`

| Column | Data Type | Example | Business Meaning |
|---|---|---|---|
| escalation_id | BIGINT | 440021 | Surrogate key |
| identity_id | BIGINT | 500091 | Who was elevated |
| platform_id | INT | 3 | Where |
| from_privilege_tier | ENUM | "Standard" | Baseline before escalation |
| to_privilege_tier | ENUM | "Admin" | Privilege after escalation |
| requested_at | DATETIME | 2026-02-11 14:02:00 | Request time |
| approved_by_person_id | BIGINT (nullable) | 100120 | FK → persons; **nullable** to model attack path "escalation without approval" (BR-E-21 violation) |
| approval_ticket_ref | VARCHAR(40) (nullable) | "CHG0099812" | Null = unauthorized/undocumented escalation |
| granted_at | DATETIME | 2026-02-11 14:10:00 | Effective time |
| expiration_at | DATETIME (nullable) | 2026-02-11 18:10:00 | Intended auto-expiry (BR-E-16) |
| actual_revocation_at | DATETIME (nullable) | 2026-02-13 09:00:00 | When it was actually removed — gap vs. expiration_at exposes enforcement failure (BR-I-22) |
| is_breakglass | BOOLEAN | FALSE | Flags emergency-access usage (BR-I-08) |

### 2.22 `authentication_events`
**Purpose:** Per-login record per account — backbone of dormancy and behavioral-anomaly detection.
**Primary Key:** `auth_event_id`

| Column | Data Type | Example | Business Meaning |
|---|---|---|---|
| auth_event_id | BIGINT | (sequential) | Surrogate key |
| platform_id | INT | 4 | Which platform |
| platform_account_id | VARCHAR(64) | "OKTA-88213" | Account that authenticated |
| event_timestamp | DATETIME | 2026-06-18 08:31:02 | When login occurred |
| source_ip | VARCHAR(45) | "10.44.21.8" | Supports anomaly/geo-velocity detection |
| mfa_used | BOOLEAN | TRUE | Supports BR-E-12 evidence |
| auth_result | ENUM | "Success","Failed","Locked" | Supports brute-force/compromise detection |
| session_type | ENUM | "Interactive","API","SSO Federated" | Distinguishes human vs. automated use (relevant to service account abuse) |

### 2.23 `audit_log_events`
**Purpose:** Generic privileged-action log (permission changes, config changes, sensitive data access) — required by BR-E-11, BR-E-22.
**Primary Key:** `audit_event_id`

| Column | Data Type | Example | Business Meaning |
|---|---|---|---|
| audit_event_id | BIGINT | (sequential) | Surrogate key |
| platform_id | INT | 3 | Where the action occurred |
| actor_platform_account_id | VARCHAR(64) | "AWSU-88213" | Who performed the action |
| action_type | VARCHAR(80) | "IAM:AttachRolePolicy" | What was done |
| target_object | VARCHAR(150) | "role/finance-readonly" | What was acted upon |
| event_timestamp | DATETIME | 2026-04-02 11:15:43 | When |
| change_ticket_ref | VARCHAR(40) (nullable) | "CHG0100021" | Links to approved change record; null flags unauthorized change |

### 2.24 `sod_rules`
**Purpose:** Defines conflicting permission/role pairs (BR-E-09).
**Primary Key:** `sod_rule_id`

| Column | Data Type | Example | Business Meaning |
|---|---|---|---|
| sod_rule_id | INT | 12 | Surrogate key |
| rule_name | VARCHAR(120) | "Vendor Create vs. Payment Approve" | Human-readable conflict name |
| conflicting_permission_id_a | BIGINT | 220981 | First side of the conflict |
| conflicting_permission_id_b | BIGINT | 220982 | Second side of the conflict |
| regulatory_basis | VARCHAR(80) | "SOX" | Why the rule exists |

### 2.25 `sod_violations`
**Purpose:** Detected instances where one identity holds both sides of an SoD rule.
**Primary Key:** `violation_id`

| Column | Data Type | Example | Business Meaning |
|---|---|---|---|
| violation_id | BIGINT | 8821 | Surrogate key |
| sod_rule_id | INT | 12 | FK → sod_rules |
| identity_id | BIGINT | 500091 | Who has the conflicting access |
| detected_at | DATETIME | 2026-03-01 02:00:00 | When detection ran |
| remediation_status | ENUM | "Open","Remediated","Accepted Risk" | Tracks whether action was taken |
| remediated_at | DATETIME (nullable) | 2026-03-15 10:00:00 | Closure timestamp |

### 2.26 `mfa_enrollment`
**Purpose:** Tracks MFA status per account (BR-E-12).
**Primary Key:** `mfa_id`

| Column | Data Type | Example | Business Meaning |
|---|---|---|---|
| mfa_id | BIGINT | 33421 | Surrogate key |
| platform_id | INT | 4 | Which platform |
| platform_account_id | VARCHAR(64) | "OKTA-88213" | Account in question |
| mfa_enrolled | BOOLEAN | TRUE | Enrollment status |
| mfa_method | ENUM | "Push","TOTP","Hardware Key","None" | Method strength |
| enrolled_date | DATE (nullable) | 2023-06-01 | When enrolled |

### 2.27 `breakglass_usage_log`
**Purpose:** Records every invocation of an emergency/break-glass account (BR-I-08).
**Primary Key:** `usage_id`

| Column | Data Type | Example | Business Meaning |
|---|---|---|---|
| usage_id | BIGINT | 41 | Surrogate key |
| service_account_id | BIGINT | 7710 | FK → service_accounts (break-glass accounts are modeled as a service_account subtype) |
| invoked_by_person_id | BIGINT | 100533 | Who checked it out |
| invoked_at | DATETIME | 2026-01-09 02:14:00 | Start of use |
| released_at | DATETIME (nullable) | 2026-01-09 04:40:00 | End of use |
| incident_ref | VARCHAR(40) (nullable) | "INC0040221" | Null = no declared incident, a red flag (attack path #11) |
| post_use_reviewed | BOOLEAN | TRUE | Evidence of compensating control |

### 2.28 `identity_risk_scores`
**Purpose:** Periodic computed risk score per identity, feeding CISO/board-level reporting.
**Primary Key:** `score_id`

| Column | Data Type | Example | Business Meaning |
|---|---|---|---|
| score_id | BIGINT | 990012 | Surrogate key |
| identity_id | BIGINT | 500091 | FK → identities |
| score_date | DATE | 2026-06-01 | Snapshot date (supports trend reporting) |
| risk_score | DECIMAL(5,2) | 78.40 | Composite score (0–100) |
| contributing_factors | VARCHAR(255) | "Cross-platform admin; dormant 45 days" | Human-readable driver summary |

---

## STEP 3 — EMPLOYEE DATASET: `employees.csv`

*Note: this is the flat, exportable view of the `persons` table (Step 2.1), covering both employees and contractors, since both share the same lifecycle skeleton.*

| Column | Why It Exists | Business Rule Supported |
|---|---|---|
| employee_id | Unique identifier required to anchor every downstream access record | BR-E-01 |
| full_name | Required for cross-platform identity correlation (fuzzy matching fallback) | BR-I-03 |
| email | Primary, most reliable correlation key across platforms | BR-I-03 |
| department | Scopes SoD rules, role templates, and review ownership | BR-E-09, BR-E-23 |
| job_title / role | Drives birthright access provisioning | BR-E-17 |
| manager | Defines the approval chain for access requests | BR-E-02, BR-I-05 |
| employment_type | Distinguishes employee vs. contractor handling (review cadence, offboarding speed) | BR-E-25, BR-I-09 |
| hire_date | Anchors lifecycle start; supports tenure-based privilege-creep analysis | Lifecycle Stage 1 |
| termination_date | Anchors lifecycle end; triggers offboarding workflow | BR-E-05, BR-E-18 |
| termination_reason | Distinguishes voluntary vs. involuntary handling speed | BR-I-09 |
| status | Drives whether the identity should currently have any active access at all | BR-E-19, BR-E-20 (reconciliation) |
| background_check_level | Supports access eligibility for sensitive roles | BR-E-24 |
| vendor_id (contractors only) | Links contractor access to contract lifecycle | BR-E-14, BR-E-25 |
| location_country | Supports jurisdiction-specific access/regulatory scoping | Compliance requirement (Phase 1 Step 1.6) |
| last_hr_sync_at | Surfaces HR-to-IT data freshness gaps | BR-I-01 |

---

## STEP 4 — PLATFORM ACCOUNT DATASETS

All five platform account tables share a **common core** (for correlation and reconciliation) plus **platform-specific extensions** (to realistically reflect how each system actually models identity).

### Common columns (present in all 5 tables)
| Column | Data Type | Business Meaning |
|---|---|---|
| platform_account_id | VARCHAR(64) | Natural key within that platform (PK) |
| identity_id | BIGINT (nullable) | FK → identities; **nullable** to allow unlinked/orphaned accounts |
| login_name | VARCHAR(100) | The actual username/UPN used to authenticate |
| email | VARCHAR(150) | Used as a correlation fallback key |
| account_status | ENUM | "Active","Disabled","Locked","Deleted" — the per-platform state, which can desynchronize across platforms (core to the "ghost access" anomaly) |
| created_date | DATE | Account provisioning date |
| disabled_date | DATE (nullable) | When deactivated in *this specific platform* — comparing across platforms surfaces offboarding gaps |
| last_login_date | DATE (nullable) | Drives dormancy detection (BR-E-10) |
| privilege_tier | ENUM | "Standard","Elevated","Admin" — per-platform privilege classification |

### 4.1 `ad_accounts.csv` — extensions
| Column | Example | Meaning |
|---|---|---|
| sam_account_name | "psubramaniam" | Legacy AD logon identifier |
| distinguished_name | "CN=Priya Subramaniam,OU=Finance,DC=corp,DC=com" | Full directory path; OU often implies department/role |
| ou_path | "Finance/India" | Organizational unit, used for scoping |
| is_service_account_flag | FALSE | Some orgs store service accounts inside the same AD table — flag distinguishes them |

### 4.2 `azure_accounts.csv` — extensions
| Column | Example | Meaning |
|---|---|---|
| upn | "priya.subramaniam@corp.onmicrosoft.com" | Azure AD User Principal Name |
| object_id | "a1b2c3d4-..." | Azure's internal GUID — primary key inside Azure, used for correlation to AD via sync |
| sync_source | ENUM "AD Synced","Cloud-Only","B2B Guest" | Distinguishes hybrid-synced accounts from cloud-native/guest accounts (relevant to "admin not in AD" edge case) |
| conditional_access_compliant | BOOLEAN | Supports security-posture-aware access decisions |

### 4.3 `aws_accounts.csv` — extensions
| Column | Example | Meaning |
|---|---|---|
| aws_account_number | "778812455123" | Which AWS account (org sub-account) this identity exists in |
| iam_user_or_role | ENUM "IAM User","Federated Role","Service Role" | Many AWS "accounts" are roles, not direct human users — central to the "admin in AWS but not in AD" edge case |
| arn | "arn:aws:iam::778812455123:user/psubramaniam" | Unique AWS identifier |
| access_key_active | BOOLEAN | Whether long-lived programmatic keys exist (vs. federated/temporary credentials only) |
| federation_source | VARCHAR(40) (nullable) | "Okta SSO" if access is federated rather than a standing IAM user |

### 4.4 `okta_accounts.csv` — extensions
| Column | Example | Meaning |
|---|---|---|
| okta_user_id | "00u1a2b3c4d5e" | Okta's internal ID |
| federated_apps_count | INT | Number of downstream SaaS apps reachable via this SSO identity — quantifies cascade risk if compromised |
| is_sso_broker_admin | BOOLEAN | Flags Okta-level admins, who implicitly control access to everything federated through it |

### 4.5 `salesforce_accounts.csv` — extensions
| Column | Example | Meaning |
|---|---|---|
| salesforce_user_id | "0051a000003Dabc" | Salesforce internal ID |
| profile_name | "System Administrator" | Salesforce's native role-equivalent object |
| permission_sets | "PS_FinanceExport,PS_BulkDataAccess" | Stacked permission sets — another inheritance layer distinct from AD/Azure groups |
| provisioned_by | ENUM "Central IT","Business Admin (Self-Service)" | Captures the business-team-driven provisioning pattern unique to SaaS apps (BR-I-10) |

### How identities connect across platforms
Each platform account links to the canonical `identities` table via the `identity_correlation_mapping` table (Step 2.6), using email/employee-ID matching with a confidence score — never a hard guarantee. This deliberately reflects the real-world difficulty described in Phase 1 (BR-I-03): some accounts will have **no match** (orphaned), some will have **low-confidence matches** (flagged for manual review), and most will have **high-confidence matches** via exact email/employee ID.

---

## STEP 5 — ROLE & PERMISSION MODEL

### Datasets
`roles.csv`, `permissions.csv`, `group_memberships.csv`, `role_assignments.csv`, `permission_assignments.csv`, `nested_group_relationships.csv` — fully specified in Steps 2.9–2.16 above.

### Direct vs. Inherited vs. Effective Permissions
- **Direct permissions:** rows in `permission_assignments` plus permissions attached directly to a `platform_role` an identity holds via `role_assignments`.
- **Inherited permissions:** permissions gained through `group_memberships` **plus** recursive resolution through `nested_group_relationships` (a user in Group A, where Group A is nested inside Group B, inherits everything Group B grants — and so on up the chain).
- **Effective permissions:** the union of direct + inherited, fully recursively resolved. This is **not stored as a physical table** — it is a computed view, because storing it directly would go stale the moment any underlying assignment changes. The data model provides everything needed to *compute* it (role_assignments + permission_assignments + group_memberships + nested_group_relationships + permissions), which is the realistic pattern used in real identity governance platforms.

This three-layer structure is what makes Phase 1's "nested group inheritance" anomaly detectable: a reviewer or analyst can compare an identity's *direct* permissions (small, easy to review) against their *effective* permissions (often much larger) to surface hidden over-privilege.

---

## STEP 6 — SERVICE ACCOUNT DESIGN: `service_accounts.csv`

**Primary Key:** `service_account_id`
**Foreign Keys:** `owner_person_id` → `persons.person_id`; `platform_id` → `platforms.platform_id`; `backup_owner_person_id` → `persons.person_id`

| Column | Data Type | Example | Business Meaning |
|---|---|---|---|
| service_account_id | BIGINT | 7710 | Surrogate key |
| account_name | VARCHAR(100) | "svc-billing-etl" | Service account identifier |
| platform_id | INT | 3 | Where it lives |
| owner_person_id | BIGINT (nullable) | 100120 | Accountable human owner (BR-E-06); **nullable** to model orphaned service accounts when the owner departs |
| backup_owner_person_id | BIGINT (nullable) | 100133 | Secondary accountability — best practice but frequently missing in real environments |
| purpose_description | VARCHAR(200) | "Nightly billing data export to data warehouse" | Business justification |
| criticality | ENUM | "Low","Medium","High","Mission-Critical" | Drives review priority and incident severity |
| privilege_level | ENUM | "Standard","Elevated","Admin" | Direct input to cross-platform admin concentration analysis |
| interactive_login_allowed | BOOLEAN | FALSE | Flags accounts that *could* be used like a human login — anomaly indicator if TRUE for a "pure automation" account |
| last_credential_rotation_date | DATE | 2026-04-01 | Core hygiene metric (anomaly: stale rotation) |
| rotation_policy_days | INT | 90 | Expected rotation cadence |
| created_date | DATE | 2021-09-12 | Lifecycle start |
| is_breakglass | BOOLEAN | FALSE | Flags emergency-access accounts (links to `breakglass_usage_log`) |
| status | ENUM | "Active","Disabled","Orphaned" | Current state |

### Relationship to human identities
Service accounts relate to humans through the `owner_person_id` / `backup_owner_person_id` fields — an intentionally **one-to-many, loosely enforced** relationship (one person can own many service accounts; ownership can lapse to null). This directly enables modeling the "Service Account Abuse" and "orphaned service account" anomalies from Phase 1: when `owner_person_id` references a `person` whose `status = 'Terminated'`, that service account becomes a detectable governance gap.

---

## STEP 7 — API TOKEN DESIGN: `api_tokens.csv`

**Primary Key:** `token_id`
**Foreign Keys:** `owner_person_id` → `persons.person_id` (nullable); `owner_service_account_id` → `service_accounts.service_account_id` (nullable); `platform_id` → `platforms.platform_id`

| Column | Data Type | Example | Business Meaning |
|---|---|---|---|
| token_id | BIGINT | 330221 | Surrogate key |
| token_label | VARCHAR(100) | "ci-pipeline-deploy-key" | Human-readable label |
| platform_id | INT | 3 | Which platform the token grants access to |
| owner_person_id | BIGINT (nullable) | 100533 | If owned by an individual developer |
| owner_service_account_id | BIGINT (nullable) | 7710 | If owned by a service account (more common) |
| scope | VARCHAR(255) | "s3:GetObject,s3:PutObject on arn:aws:s3:::billing-data/*" | Defines blast radius if leaked |
| issued_date | DATE | 2025-08-01 | Creation date |
| expiration_date | DATE (nullable) | NULL | **Null is the risk signal** — a token with no expiration (BR-E-07 violation) |
| last_used_date | DATE (nullable) | 2026-06-15 | Drives dormant-but-active-token detection |
| last_rotation_date | DATE | 2025-08-01 | If never rotated since issuance, flags hygiene failure |
| rotation_status | ENUM | "Current","Overdue","Never Rotated" | Direct hygiene indicator |
| usage_count_30d | INT | 14210 | Volume baseline for anomaly comparison |
| source_ip_diversity_30d | INT | 2 | Number of distinct source IPs in the last 30 days — sudden spikes indicate possible token theft/replay |
| status | ENUM | "Active","Revoked","Expired" | Current state |

### How token abuse becomes detectable
Token abuse is detected by combining several signals already present in this schema:
1. **No expiration set** (`expiration_date IS NULL`) combined with high `criticality`/broad `scope` — a standing risk even absent misuse.
2. **Usage volume or source IP diversity spikes** relative to the account's historical baseline (`usage_count_30d`, `source_ip_diversity_30d`) — a behavioral indicator of compromise or reuse outside intended automation.
3. **Continued `last_used_date` activity after the owning `person`'s `status` becomes "Terminated"** or after the owning `service_account`'s `status` becomes "Disabled" — a direct, high-confidence abuse signal.
4. **`rotation_status = 'Never Rotated'` combined with token age** — quantifies long-lived-credential exposure window.

---

## STEP 8 — ACCESS REVIEW DATA

### `access_reviews.csv` (campaign-level)
**Primary Key:** `review_id`

| Column | Data Type | Example | Business Meaning |
|---|---|---|---|
| review_id | INT | 41 | Surrogate key |
| review_name | VARCHAR(120) | "Q2 2026 — AWS Privileged Access Recertification" | Campaign identity |
| platform_id | INT (nullable) | 3 | Scope of the campaign (null = cross-platform) |
| review_type | ENUM | "Standard","Privileged","SoD-Focused","Contractor" | Distinguishes risk-weighted review types (BR-E-25) |
| campaign_start_date | DATE | 2026-04-01 | Start |
| campaign_due_date | DATE | 2026-04-15 | Deadline — supports SLA tracking on the review process itself |
| campaign_status | ENUM | "Open","Closed","Overdue" | Process health indicator |

### `review_decisions.csv` (line-item level)
**Primary Key:** `decision_id`
**Foreign Keys:** `review_id` → `access_reviews.review_id`; `reviewer_person_id` → `persons.person_id`; `identity_id` → `identities.identity_id`; `assignment_id` → `role_assignments.assignment_id` (nullable, if reviewing a specific grant)

| Column | Data Type | Example | Business Meaning |
|---|---|---|---|
| decision_id | BIGINT | 882013 | Surrogate key |
| review_id | INT | 41 | FK → access_reviews |
| identity_id | BIGINT | 500091 | Whose access is under review |
| assignment_id | BIGINT (nullable) | 990123 | The specific access item being attested (role, group, or permission) |
| reviewer_person_id | BIGINT | 100120 | Who made the decision |
| decision_date | DATE | 2026-04-10 | When decided |
| outcome | ENUM | "Approved","Revoked","Flagged for Investigation" | The actual decision |
| justification_text | VARCHAR(255) (nullable) | "Still required for quarterly close process" | Evidence of genuine scrutiny vs. rubber-stamping |
| revocation_executed_date | DATE (nullable) | 2026-04-18 | **Critical column:** confirms whether a "Revoked" decision was actually carried out downstream — closes the loop auditors specifically test (Phase 1 Auditor Question #6) |

### How auditors would use these datasets
Auditors join `access_reviews` + `review_decisions` against the live `role_assignments`/`group_memberships` tables to test two things: **(1) coverage** — did every in-scope identity actually get reviewed, by comparing the review's defined population against `decision_id` records produced; and **(2) effectiveness** — for every `outcome = 'Revoked'` decision, does `revocation_executed_date` exist and does the corresponding `role_assignments.status` actually show `'Revoked'`? A gap between decision and execution is precisely the evidence Phase 1's Auditor Question #6 calls for.

---

## STEP 9 — OFFBOARDING DATA: `offboarding_events.csv`

**Primary Key:** `offboarding_id`
**Foreign Keys:** `person_id` → `persons.person_id`

| Column | Data Type | Example | Business Meaning |
|---|---|---|---|
| offboarding_id | BIGINT | 6021 | Surrogate key |
| person_id | BIGINT | 100482 | Who is being offboarded |
| termination_date | DATE | 2026-05-01 | Official last working day (from `persons`) |
| termination_reason | ENUM | "Voluntary","Involuntary","End of Contract" | Drives expected SLA tightness (BR-I-09) |
| hr_notification_sent_at | DATETIME | 2026-05-01 09:00:00 | When IT/IAM was informed — surfaces HR-to-IT lag (BR-I-01) |
| expected_revocation_sla_hours | INT | 24 | Policy target (BR-E-05); tighter for involuntary terminations |
| platform_id | INT | 1 | One row per platform per offboarding event, to capture per-system revocation independently |
| expected_revocation_deadline | DATETIME | 2026-05-02 09:00:00 | `hr_notification_sent_at` + SLA |
| actual_revocation_at | DATETIME (nullable) | 2026-05-04 14:00:00 | When access was actually removed in *this* platform; **null = still not revoked**, the most severe finding |
| sla_breached | BOOLEAN | TRUE | Computed flag: `actual_revocation_at > expected_revocation_deadline` (or still null past deadline) |
| revoked_by | VARCHAR(64) | "svc-offboarding-bot" / "manual-helpdesk" | Distinguishes automated vs. manual (slower, less reliable) revocation |

### How offboarding failures become detectable
Because this table has **one row per platform per offboarding event**, it directly exposes partial offboarding: a person can show `sla_breached = FALSE` for AD and Azure AD (centrally automated) while showing `sla_breached = TRUE` or `actual_revocation_at IS NULL` for AWS or Salesforce (less centrally governed) — precisely modeling the "user disabled in AD but active in AWS" edge case from Phase 1, and giving a queryable, auditable trail for the "Offboarding Gap" anomaly.

---

## STEP 10 — ANOMALY SUPPORT: DATASET-TO-ANOMALY MAPPING

| Anomaly | Required Datasets | Key Columns | Detection Logic (description, not code) |
|---|---|---|---|
| **Offboarding Gap** | `offboarding_events`, `persons`, all 5 platform account tables | `actual_revocation_at`, `sla_breached`, `account_status`, `disabled_date` | For terminated persons, compare `account_status` across all platform tables against `persons.termination_date`; any platform still showing `Active` past the SLA deadline is a gap |
| **Dormant Admin** | platform account tables, `role_assignments`/`platform_roles`, `authentication_events` | `privilege_tier`, `last_login_date`, `event_timestamp` | Identify accounts with `privilege_tier IN ('Elevated','Admin')` where `last_login_date` (or latest `authentication_events` row) exceeds the dormancy threshold (e.g., 60–90 days) |
| **Privilege Creep** | `role_assignments`, `persons` (job_title/department history), `group_memberships` | `granted_date`, `business_role_id`, `job_title` | Compare an identity's current effective access against what their *current* business role template (`roles`) defines; flag access items present but not in the current template, especially those granted under a *previous* role/department |
| **Service Account Abuse** | `service_accounts`, `authentication_events`, `persons` | `interactive_login_allowed`, `session_type`, `owner_person_id`, `persons.status` | Flag service accounts with `interactive_login_allowed = FALSE` that nonetheless show `session_type = 'Interactive'` events, or whose `owner_person_id` maps to a terminated person |
| **Token Abuse** | `api_tokens`, `authentication_events` (or token-specific usage logs) | `expiration_date`, `usage_count_30d`, `source_ip_diversity_30d`, `last_used_date` | Flag tokens with null `expiration_date`, sudden spikes in `usage_count_30d`/`source_ip_diversity_30d` vs. trailing baseline, or continued `last_used_date` activity after owner termination/disablement |
| **Cross-Platform Admin** | `identity_correlation_mapping`, `platform_roles`, `role_assignments` | `identity_id`, `privilege_tier`, `platform_id` | Group `role_assignments` joined to `platform_roles` by `identity_id`; flag any identity with `privilege_tier IN ('Admin','Super Admin')` on **2 or more distinct `platform_id` values** |
| **Orphaned Account** | `identities`, `identity_correlation_mapping`, `persons` | `identity_status`, `person_id` (nullable) | Flag `identities` rows where `person_id IS NULL` or where the linked `persons.status = 'Terminated'` but `identity_status != 'Orphaned'` (i.e., not yet flagged despite the underlying person being gone) |

---

## STEP 11 — RELATIONSHIP MAP (ER-STYLE)

```
persons ──< contracts (contractors only)
persons ──< identities (1:1, nullable on identities side for orphans)
persons ──< offboarding_events
persons ──< privilege_escalation_events (as requester/approver)
persons ──< service_accounts (as owner/backup owner)
persons ──< api_tokens (as direct owner, when not service-account-owned)
persons ──< review_decisions (as reviewer)
persons }──{ departments (many persons : 1 department)
persons }──{ vendors (contractors only, many : 1)

identities ──< identity_correlation_mapping >── platform accounts
                                                   (ad_accounts, azure_accounts,
                                                    aws_accounts, okta_accounts,
                                                    salesforce_accounts)

identities ──< role_assignments >── platform_roles >── permissions (via role-to-permission mapping, implicit through platform definitions)
identities ──< permission_assignments >── permissions (direct exceptions)
identities ──< review_decisions
identities ──< identity_risk_scores
identities ──< sod_violations >── sod_rules

platform accounts ──< group_memberships >── groups ──< nested_group_relationships (self-referencing)
platform accounts ──< authentication_events
platform accounts ──< mfa_enrollment
platform accounts ──< audit_log_events (as actor)

service_accounts ──< api_tokens
service_accounts ──< breakglass_usage_log (where is_breakglass = TRUE)
service_accounts }──{ persons (owner_person_id, backup_owner_person_id)

access_reviews ──< review_decisions
review_decisions }──{ role_assignments (the access item being attested)

offboarding_events }──{ persons
offboarding_events }──{ platforms (one row per platform per event)

roles (business) ──< role_assignments
roles }──{ departments (owning_department_id)

Legend:  ──<  = one-to-many     }──{  = many-to-one/lookup
```

**Reading the map:** `identities` is the structural hub of the entire model — every platform account, every role/permission grant, every review, and every risk score ultimately resolves back to it. `persons` is the *human* hub — every lifecycle, ownership, and approval record resolves back to it. The deliberate gap between these two hubs (an `identity` can exist without a linked `person`) is what makes orphaned-account and correlation-failure scenarios representable in the data, rather than modeled away by an overly clean schema.

---

## STEP 12 — ENTERPRISE SCALE RECOMMENDATIONS

| Entity | Recommended Volume | Justification |
|---|---|---|
| Employees | 5,000 (given) | Per scope |
| Contractors | 1,000 (given) | Per scope |
| Total persons | 6,000 | Sum |
| Departments | 35 | Realistic for a Fortune 500 — enough for meaningful SoD/role scoping without excessive granularity |
| Identities | ~6,150 | Slightly above persons count to include ~150 orphaned identities with no HR match (BR-I-20) — realistic governance-gap rate of ~2.5% |
| AD accounts | 5,400 | Most employees/long-tenure contractors have on-prem AD; not all newer contractors are provisioned here |
| Azure AD accounts | 5,900 | Broadest coverage (cloud mail/collab) plus ~300 cloud-only/B2B guest accounts with no AD counterpart |
| Okta accounts | 5,700 | SSO broker — near-universal coverage for anyone accessing federated apps |
| AWS IAM accounts (human) | 1,400 | Realistic subset — engineering, data, and cloud-ops functions only, not the whole company |
| AWS IAM roles (service) | 900 | Cloud-native environments typically have *more* roles/service identities than human IAM users |
| Salesforce accounts | 1,100 | Sales, marketing, and customer success functions only |
| **Total platform accounts (human)** | **~19,500** | Sum of the above — averages ~3.25 accounts per person, consistent with typical hybrid-platform sprawl |
| Service accounts | 850 | Large enterprises commonly run hundreds to low-thousands of service accounts across 5 platforms; ~170 per platform on average |
| API tokens | 2,400 | ~2.8 tokens per service account plus individual developer tokens — reflects realistic over-issuance |
| Business roles | 220 | Typical Fortune 500 job-architecture role count (not 1:1 with job titles, but close) |
| Platform roles/profiles | 650 | Platform-native roles tend to outnumber business roles due to fragmentation (e.g., dozens of AWS managed/custom policies, many Salesforce profiles/permission sets) |
| Permissions (atomic) | 4,500 | AWS alone has thousands of granular IAM actions; Salesforce, AD, and Okta add meaningfully more |
| Groups | 1,250 | Realistic AD/Azure AD/Okta group sprawl for an organization this size |
| Nested group relationships | 480 | A meaningful subset of groups (roughly 35–40%) are nested 1–4 levels deep, consistent with typical AD hygiene |
| Group memberships | 138,000 | Average ~8 group memberships per directory/SSO-capable account (5,400+5,900+5,700 ≈ 17,000 accounts × ~8) |
| Role assignments | 26,000 | Roughly 1.3 role assignments per platform account on average, accounting for multi-role identities |
| Permission assignments (direct exceptions) | 7,500 | Exceptions should be a meaningful minority of total access — modeling realistic "non-clean" environments |
| Access review campaigns | 22 | 4 quarters × ~5–6 scoped campaigns per quarter (e.g., per-platform plus a dedicated privileged-access and contractor campaign) |
| Review decisions | 42,000 | Reflects realistic in-scope population per campaign (privileged/contractor campaigns review fewer but more often; standard campaigns review broadly twice yearly) |
| Offboarding events (rows, 1 per platform per termination) | ~5,400 | ~900 actual terminations over the year (≈15% blended annual turnover across 6,000 persons) × ~6 platform rows each |
| Privilege escalation events | 4,800 | Reflects realistic just-in-time elevation usage among the ~850 privileged identities, averaging several elevations per privileged user per year |
| Authentication events | ~2.1 million | ~6,000 active identities × ~1 login/day average across 1 year, weighted down for weekends/contractors — by far the largest table; recommend partitioning by month |
| Audit log events | ~310,000 | Privileged-action volume scaled to the ~850 service accounts + ~650 platform-role holders performing regular administrative actions |
| SoD rules | 40 | Realistic count of meaningful conflict pairs for a mid-to-large enterprise, concentrated in Finance/Procurement/IT |
| SoD violations | 180 | A believable ~0.45% violation rate against the population holding any sensitive permission |
| MFA enrollment records | 19,500 | 1:1 with human platform accounts |
| Break-glass usage events | 65 | Genuinely rare by design — should never approach normal login volume |
| Identity risk score snapshots | 73,800 | Monthly scoring × ~6,150 identities × 12 months — supports trend reporting (Phase 1 Requirement #20) |

---

## FINAL OUTPUT

### 1. Final List of Datasets (28 tables)
`persons`, `departments`, `vendors`, `contracts`, `identities`, `identity_correlation_mapping`, `platforms`, `ad_accounts`, `azure_accounts`, `aws_accounts`, `okta_accounts`, `salesforce_accounts`, `roles`, `platform_roles`, `permissions`, `groups`, `nested_group_relationships`, `group_memberships`, `role_assignments`, `permission_assignments`, `service_accounts`, `api_tokens`, `access_reviews`, `review_decisions`, `offboarding_events`, `privilege_escalation_events`, `authentication_events`, `audit_log_events`, `sod_rules`, `sod_violations`, `mfa_enrollment`, `breakglass_usage_log`, `identity_risk_scores`

*(33 tables total when fully expanded — the 28 "core entities" from Step 1 map to 33 physical tables once the 5 platform-account tables and the roles/platform_roles split are counted individually.)*

### 2. Final Schema
Fully specified in Step 2 (master model) with platform-specific extensions in Step 4. Every table includes surrogate primary key, explicit foreign keys, realistic data types, and example values suitable for direct translation into a synthetic data generator's schema definitions.

### 3. Relationship Diagram
See Step 11 — `identities` and `persons` are the dual hubs; every governance, risk, and lifecycle table resolves back to one or both.

### 4. Required Columns Checklist (cross-cutting, must appear consistently)
- Every account/identity-bearing table: a status field reflecting current lifecycle state.
- Every grant table (`role_assignments`, `permission_assignments`, `group_memberships`): a `granted_date` (and `expiration_date` where time-bound access applies).
- Every approval-relevant table: an approver reference and a ticket/justification reference, **nullable**, so the absence of approval is itself representable (not silently excluded).
- Every cross-platform table: a `platform_id` foreign key, enabling per-platform breakdowns for every anomaly and metric.
- Every human-owned non-human entity (`service_accounts`, `api_tokens`): a nullable owner reference, so ownership lapse is representable.

### 5. Missing Data Considerations
A realistic synthetic dataset must **deliberately include**, not avoid, the following imperfections — they are what make the anomalies in Phase 1 detectable at all:
- A controlled percentage of `identity_correlation_mapping` rows with **low confidence scores** or **no mapping at all** (orphaned accounts).
- A controlled percentage of `offboarding_events` rows with **null `actual_revocation_at`** past the SLA deadline (unrevoked access).
- A controlled percentage of `service_accounts`/`api_tokens` with **null owner** (ownership lapse).
- A controlled percentage of `privilege_escalation_events` with **null `approval_ticket_ref`** (ungoverned escalation).
- A controlled percentage of `api_tokens` with **null `expiration_date`** (non-expiring tokens).
- Intentional **inconsistent naming/casing** in `full_name`/`login_name` fields across platform tables, to realistically stress-test identity correlation logic rather than assuming clean joins.
- A small population of **duplicate `persons` records** (simulating M&A-era or data-entry duplication) that never fully resolve to one `identity`.

### 6. Improvements for Future Iterations
- Add a `data_classification` dimension table linking `permissions` to specific regulated data types (PII, PHI, cardholder data) to support more precise compliance-scoped reporting.
- Add a `risk_model_version` field to `identity_risk_scores` so future scoring methodology changes don't corrupt historical trend comparisons.
- Consider a separate `geo_location_baseline` table per account to make source-IP/geo-velocity anomaly detection (token and login abuse) more directly supportable without inferring baselines from raw `authentication_events` alone.
- Consider versioning `roles`/`platform_roles` definitions over time (effective-dated role content), since role definitions themselves change and historical access reviews need to reflect "what the role meant at the time," not just "what it means today."

---

*End of Phase 2 data model design. This document intentionally stops at the data layer — no code, no dashboards, no synthetic-data-generation logic.*
