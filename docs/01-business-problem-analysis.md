# Hybrid Identity Governance — Business Problem Deep-Dive
### Executive Problem Understanding, Stakeholder Mapping, Business Rules, Lifecycle, Risk, and Threat Analysis

*Scope note: This document analyzes the business problem only. It does not propose architecture, technology, datasets, or solution design.*

---

## STEP 1 — EXECUTIVE PROBLEM UNDERSTANDING

### 1. What problem is being solved
Every employee, contractor, application, and machine in a modern enterprise needs a "digital identity" — a username, login, or token — to do its job. The problem is that no single system controls all of these identities. A person might have an Active Directory (AD) account for their laptop, an Azure AD account for email, an AWS IAM account for cloud infrastructure, an Okta account as a single sign-on broker, and a Salesforce account for CRM access. Each of these is provisioned, changed, and removed somewhat independently. The business problem is **the absence of a single, trustworthy, real-time answer to the question: "Who has access to what, why, and is that still appropriate?"** Without that answer, organizations cannot reliably prevent unauthorized access, prove compliance, or respond quickly to a breach.

### 2. Why identity sprawl exists
Identity sprawl is not a mistake — it is the natural byproduct of how businesses grow:
- Every new SaaS tool, cloud platform, or acquired company brings its own identity store.
- IT historically optimized for "get the employee working fast," not "track every access grant centrally."
- Decentralized teams (cloud engineering, sales ops, regional IT) provision access independently to move quickly.
- Legacy systems were never built to federate identity, so duplicate or parallel accounts were the easiest workaround.
- Mergers and acquisitions inject entire foreign identity ecosystems that are rarely fully reconciled.

The result: the same human being can exist as five or six different "identities" across systems, with no guaranteed link between them.

### 3. Why organizations struggle to control privileges
- **Provisioning is easy; de-provisioning is hard.** Granting access is a single click; finding and removing every place that access lives is a hunt across many systems.
- **Role changes don't trigger access changes.** When someone moves teams, old access is rarely revoked — only new access is added. This produces "privilege creep."
- **No single owner.** Identity touches HR, IT, Security, Cloud, and individual application owners — and when everyone is partially responsible, no one is fully accountable.
- **Manual review processes don't scale.** Quarterly access reviews conducted by spreadsheet cannot keep pace with thousands of identities across dozens of systems.
- **Business pressure favors speed over friction.** Productivity is rewarded; access restriction is often seen as a blocker, so it gets bypassed or delayed.

### 4. Why cross-platform identities create risk
A single human identity fragmented across AD, Azure AD, AWS, Okta, and Salesforce means:
- An attacker only needs to compromise the *weakest-governed* platform to get a foothold, then pivot.
- Disabling someone in one system (e.g., AD, after termination) does **not** automatically disable them everywhere else — leaving "ghost access."
- Privilege visibility is fragmented: a person might look like a low-privilege user in AD but be a full administrator in AWS, and no single dashboard shows both.
- Correlating "this AD account" and "this AWS account" belong to the same human is itself a hard data problem — names, emails, and usernames often don't match cleanly.

### 5. Why attackers exploit identity gaps
Identity has become the primary attack surface because:
- Compromising a valid credential is far cheaper and stealthier than exploiting a software vulnerability — there is no "patch" for a stolen password.
- Once attackers have one set of valid credentials, they look for **privilege escalation paths** — nested groups, forgotten admin rights, or service accounts with broad permissions.
- Offboarding failures leave **valid, working accounts for people who no longer work at the company** — a near-perfect entry point, since it raises no immediate suspicion.
- API tokens and service accounts are often long-lived, broadly scoped, and unmonitored, making them attractive, durable footholds.
- Cross-platform sprawl means attackers can move from a low-value system to a high-value system (cloud infrastructure, financial data, customer data) by hopping identity boundaries.

### 6. Why auditors care
Auditors (internal and external, plus regulators) care about identity governance because it underpins nearly every other control:
- **Financial controls (SOX)** depend on proving that only authorized people can modify financial systems and that duties are segregated.
- **Data protection regulations (GDPR, HIPAA, etc.)** require organizations to demonstrate that only the right people can access sensitive personal or health data.
- **Security frameworks (ISO 27001, NIST CSF, PCI-DSS)** all treat access control as a foundational control domain.
- Auditors need **evidence**, not assurances — a list of who has access, when it was approved, when it was last reviewed, and proof that terminated employees lost access on time.
- Identity failures are one of the most common root causes cited in breach post-mortems and audit findings, making this a perennial focus area.

---

## STEP 2 — STAKEHOLDER ANALYSIS

| Stakeholder | Responsibilities | Pain Points | Success Criteria |
|---|---|---|---|
| **Employee** | Use granted access to perform job duties; request access changes when needed | Slow access provisioning; confusing request processes; losing access incorrectly | Has exactly the access needed, when needed, with minimal friction |
| **Manager** | Approve access requests for direct reports; validate access during reviews | Doesn't understand technical access being approved; review fatigue; approves "rubber-stamp" style | Confidence that approvals reflect real business need; low time burden |
| **HR Team** | Maintain authoritative employee data (hire, role change, termination dates) | Data entry delays; disconnect between HR system and IT systems; late termination notices | HR events (hire/move/leave) reliably and quickly reflected in access state |
| **IAM / Identity Governance Team** | Own provisioning/de-provisioning policy, certify identity lifecycle processes, run access reviews | Fragmented systems, manual reconciliation, lack of authoritative cross-platform view | Single source of truth for "who has access to what" |
| **Privileged Access Management (PAM) Team** | Manage and monitor elevated/admin accounts, enforce just-in-time privilege, break-glass accounts | Hard-to-track standing privileged access; shared admin credentials; emergency access not logged | All privileged access is time-bound, monitored, and justified |
| **Security Operations (SecOps) Team** | Detect and respond to anomalous identity behavior, investigate alerts | Alert fatigue; lack of identity context in security telemetry; siloed logs per platform | Fast detection and response to identity-based threats |
| **Cloud / Platform Engineering Team** | Provision and manage cloud IAM roles, service accounts, API tokens | Pressure to move fast; security seen as a blocker; sprawling permission sets | Cloud access is scoped to least privilege without slowing delivery |
| **Application/System Owners** | Define who should have access to their specific application, certify access during reviews | Don't always know who has access already; reluctant to revoke access they're unsure about | Accurate, current understanding of their application's access list |
| **Compliance Officer** | Ensure identity controls meet regulatory obligations (SOX, HIPAA, GDPR, PCI-DSS) | Difficulty obtaining timely, accurate evidence across disparate systems | Defensible, audit-ready evidence trail |
| **Internal Auditor** | Test identity controls for design and operating effectiveness | Manual sampling is slow and incomplete; systems don't reconcile cleanly | Statistically sound assurance that controls work as intended |
| **External Auditor / Regulator** | Independently validate compliance and control effectiveness | Limited access to systems; relies on internally produced evidence | High-confidence, third-party-verifiable evidence |
| **CISO** | Owns overall security risk posture, reports risk to the board | Lacks unified visibility across identity sprawl; reactive instead of proactive risk management | Quantifiable, demonstrable reduction in identity-related risk |
| **Legal / Risk Management** | Assess liability exposure from access-related incidents | Uncertainty about scope of exposure after an incident (who *could* have accessed what) | Clear, fast answers during incident/breach investigations |
| **Help Desk / Service Desk** | Execute access requests, password resets, account unlocks | High ticket volume from access issues; no visibility into broader access context | Reduced ticket volume; clear escalation paths for risky requests |
| **Procurement / Vendor Management** | Manage third-party and contractor account lifecycles | Contractor access frequently outlives the contract | Automatic alignment of access with contract terms |
| **DevOps Team** | Creates and uses service accounts, API tokens, CI/CD credentials | Tokens proliferate quickly, get hardcoded, rarely rotated | Tokens are tracked, scoped, and rotated systematically |
| **Board of Directors / Audit Committee** | Oversee enterprise risk, approve major security investments | Receives risk reports without enough granularity to act on | Confidence that identity risk is measured and trending down |
| **Business Unit Leaders** | Accountable for their unit's data and systems | Often unaware of how much access exists within their domain | Visibility into and control over access within their span of ownership |

---

## STEP 3 — BUSINESS RULE EXTRACTION

### A. Explicit Business Rules
*(Rules that any mature identity governance program states outright as policy or control requirement.)*

| Rule ID | Business Rule | Evidence/Basis | Business Impact |
|---|---|---|---|
| BR-E-01 | Every employee must have a unique digital identity linked to an HR record | Standard IAM/HR integration practice | Prevents anonymous or untraceable access |
| BR-E-02 | Access must be provisioned only after manager or system-owner approval | Standard access request workflow | Prevents unauthorized self-service privilege grants |
| BR-E-03 | Privileged/admin access requires an additional approval layer beyond standard access | PAM program design | Reduces blast radius of compromised credentials |
| BR-E-04 | Access must be periodically reviewed/recertified (e.g., quarterly or annually) | SOX/ISO 27001 access review requirement | Surfaces and removes stale or excessive access |
| BR-E-05 | Offboarded employees' access must be revoked within a defined SLA (e.g., same day) | Standard termination control | Prevents former employee access abuse |
| BR-E-06 | Service accounts must have a named, accountable human owner | PAM/service account governance practice | Removes ambiguity on who is responsible if misused |
| BR-E-07 | API tokens must have a defined expiration | Secure credential management practice | Limits the lifespan of a stolen/leaked token |
| BR-E-08 | Cross-platform admin rights require documented business justification | Least privilege principle | Reduces unnecessary concentration of power |
| BR-E-09 | Segregation of duties (SoD) must be enforced for sensitive transaction pairs | SOX control requirement | Prevents fraud through self-approval |
| BR-E-10 | Dormant accounts beyond a defined inactivity threshold must be disabled | Standard account hygiene control | Shrinks the attack surface of unused credentials |
| BR-E-11 | All privileged actions must be logged | Audit/forensic requirement | Enables investigation and accountability |
| BR-E-12 | MFA is required for all administrative/privileged accounts | Security baseline control | Reduces risk of credential-only compromise |
| BR-E-13 | Role changes must trigger a re-evaluation of existing access | Joiner-Mover-Leaver (JML) policy | Prevents privilege creep across role transitions |
| BR-E-14 | Contractor/vendor access must expire automatically at contract end date | Vendor management policy | Prevents indefinite third-party access |
| BR-E-15 | Shared/generic accounts are prohibited or tightly controlled with compensating controls | Accountability principle | Preserves individual traceability of actions |
| BR-E-16 | Temporary elevated access must auto-expire after a defined window | Just-in-time access principle | Prevents "temporary" from becoming permanent |
| BR-E-17 | New hires receive baseline ("birthright") access via role-based provisioning | Standard onboarding workflow | Speeds onboarding while limiting initial scope |
| BR-E-18 | Terminated identities must be removed from *all* connected systems, not just the primary directory | Full lifecycle de-provisioning requirement | Prevents ghost access in secondary systems |
| BR-E-19 | All platforms must periodically reconcile their identity list against the authoritative HR source of truth | Identity reconciliation control | Surfaces orphaned/unauthorized accounts |
| BR-E-20 | Orphaned accounts with no matching HR record must be flagged for investigation | Reconciliation control | Identifies untracked or rogue accounts |
| BR-E-21 | Privilege escalation events require an associated change ticket or approval record | Change management policy | Creates an auditable justification trail |
| BR-E-22 | Audit logs must be retained for a defined regulatory period | Compliance requirement (varies by industry) | Enables retrospective investigation and regulatory response |
| BR-E-23 | Access requests must follow the principle of least privilege | Security baseline principle | Minimizes unnecessary exposure |
| BR-E-24 | High-risk/sensitive roles require background checks prior to provisioning | HR/security policy | Reduces insider threat risk at the source |
| BR-E-25 | Vendor/contractor accounts must be reviewed on a more frequent cadence than employee accounts | Elevated third-party risk policy | Reduces dwell time of inappropriate third-party access |

### B. Implicit Business Rules
*(Norms and assumptions that govern real-world behavior but are rarely written down.)*

| Rule ID | Implicit Rule | Why It's Implicit | Business Impact |
|---|---|---|---|
| BR-I-01 | HR data is trusted as accurate without independent verification | No system formally validates HR data quality for IAM purposes | Bad HR data silently corrupts downstream access decisions |
| BR-I-02 | Identity sprawl is tolerated until an audit or incident forces remediation | No proactive, continuous control — reactive posture is the norm | Risk accumulates invisibly between review cycles |
| BR-I-03 | Cross-platform identity correlation relies on imperfect matching (name/email) | No universal identity key exists across all platforms | Some identities are simply never linked or reconciled |
| BR-I-04 | Business urgency informally overrides strict process compliance | "Need it today" requests get expedited outside normal approval rigor | Creates an unofficial fast-track bypassing controls |
| BR-I-05 | Managers approve access without security expertise, based on role title alone | No technical training requirement exists for approvers | Approvals are often uninformed "rubber stamps" |
| BR-I-06 | Cloud/platform teams self-govern their own admin rights with limited central oversight | Central IAM team often lacks authority over cloud-native consoles | Cloud platforms become the weakest-governed link |
| BR-I-07 | Security teams assume logs exist and are complete across all platforms | No formal logging-completeness verification process | Investigations hit blind spots when logs are missing |
| BR-I-08 | "Break-glass" emergency accounts are accepted as a necessary exception to normal control | Operational necessity outweighs strict governance in emergencies | Creates a permanent, semi-monitored privileged backdoor |
| BR-I-09 | Voluntary departures get faster, less scrutinized offboarding than for-cause terminations | Process is informally risk-weighted by perceived hostility | Inconsistent revocation speed creates uneven risk |
| BR-I-10 | Later-integrated systems (newer SaaS apps) are under-governed relative to core systems | Governance maturity lags integration speed | Newest tools are often the least monitored |
| BR-I-11 | Larger organizations implicitly accept more sprawl as "cost of doing business" | Scale outpaces governance investment | Risk grows disproportionately with organizational size |
| BR-I-12 | API/service tokens are treated as lower-risk than human credentials | No formal risk-equivalence policy exists | Tokens often carry broader, longer-lived privilege than human accounts |
| BR-I-13 | Employees keep old access "just in case" after a role change | No automatic access removal on role change | Privilege creep accumulates silently over a career |
| BR-I-14 | Auditors assume a documented control is a working control unless proven otherwise | Sampling-based testing, not full population testing | Control failures can persist undetected between audit cycles |
| BR-I-15 | No single function owns "identity governance" holistically until a failure occurs | Cross-functional responsibility is diffused by default | Accountability gaps delay response to systemic issues |
| BR-I-16 | The business implicitly prioritizes productivity/speed over security friction | Default behavior favors fast access over verified access | Security controls are the first thing bypassed under pressure |
| BR-I-17 | Compliance frameworks drive control rigor more than actual risk assessment | Programs are often built to "pass audit" rather than minimize risk | Some high-risk areas outside framework scope go unaddressed |
| BR-I-18 | Service accounts are assumed "safe because automated" | No human-equivalent scrutiny applied to non-human identities | Service accounts often hold the broadest unmonitored privilege |
| BR-I-19 | Nested group memberships obscure true effective access from most stakeholders | Group nesting is rarely fully visualized or audited | Reviewers approve access without understanding real scope |
| BR-I-20 | Each new SaaS/IaaS platform introduces its own local identity model by default | No mandate to federate identity at onboarding time | Sprawl is structurally guaranteed to increase over time |
| BR-I-21 | Risk scoring of identities is inconsistent across teams | No shared, agreed risk model exists between Security, Audit, and IAM | Same identity may be rated differently by different teams |
| BR-I-22 | "Temporary" access tends to become permanent without enforcement automation | Expiry is policy, not system-enforced, in many environments | Temporary grants silently become standing privilege |
| BR-I-23 | Decentralized administration creates accountability diffusion | Multiple admins per platform with no single accountable owner | Harder to pinpoint responsibility when something goes wrong |
| BR-I-24 | A written policy is assumed to guarantee enforcement | No systematic verification that policy = practice | Gap between "policy on paper" and "what actually happens" |
| BR-I-25 | Identity data quality (duplicates, typos, inconsistent naming) is implicitly poor in legacy systems | No enterprise-wide identity data quality standard enforced | Reconciliation and review accuracy suffers |
| BR-I-26 | M&A activity introduces orphaned/duplicate/conflicting identities for years | No standard M&A identity integration playbook is consistently applied | Acquired entities remain weak links long after deal close |
| BR-I-27 | Risk is implicitly considered "managed" if a review *occurred*, regardless of what action resulted from it | Process completion is conflated with risk reduction | Reviews can become a checkbox exercise rather than a control |

**Total business rules identified: 52 (25 explicit + 27 implicit)**

---

## STEP 4 — HYBRID IDENTITY LIFECYCLE RECONSTRUCTION

### Stage-by-stage breakdown

**1. Hiring**
- *What happens:* HR creates an employee record with role, department, manager, and start date.
- *Data created:* Employee ID, job title, cost center, employment type, manager hierarchy.
- *Risks:* Data entry errors; delayed HR record creation; role mapped to incorrect access template.

**2. Provisioning**
- *What happens:* Based on role, baseline ("birthright") access is granted across relevant systems (AD, email, core apps).
- *Data created:* Account objects in each system, initial group memberships, credentials.
- *Risks:* Over-provisioning by default ("just give them what the last person in this role had"); accounts created in some systems but not others; inconsistent naming across platforms breaking future correlation.

**3. Role Assignment**
- *What happens:* Specific application and platform access is mapped to the employee's functional role.
- *Data created:* Role-to-entitlement mappings, group/role assignments per platform.
- *Risks:* Roles defined inconsistently across systems; "role explosion" (too many granular roles to manage); access granted based on convenience rather than defined role.

**4. Access Usage**
- *What happens:* Employee actively uses granted access to perform their job.
- *Data created:* Login events, access logs, application usage telemetry.
- *Risks:* Usage isn't monitored for anomalies; unused entitlements aren't flagged; usage patterns aren't fed back into review decisions.

**5. Role Change (Mover)**
- *What happens:* Employee changes teams, gets promoted, or changes function.
- *Data created:* Updated HR record (new title/manager/department), new access requests.
- *Risks:* New access is added but old access is rarely removed — the classic "privilege creep" failure point; cross-platform changes lag behind the HR update.

**6. Privilege Escalation**
- *What happens:* Employee receives temporary or permanent elevated/admin rights for a specific task or project.
- *Data created:* Elevation request/approval record, time-bound grant (ideally), activity logs during elevated session.
- *Risks:* Elevation isn't time-bound in practice; approval process is weak or after-the-fact; elevated access isn't tied to a specific, auditable business need.

**7. Review (Recertification)**
- *What happens:* Managers/system owners periodically review and attest to existing access.
- *Data created:* Review campaign records, attestation decisions (approve/revoke), exceptions.
- *Risks:* Reviewers rubber-stamp without real scrutiny; review covers some platforms but not others; revoke decisions aren't actually executed downstream.

**8. Offboarding**
- *What happens:* HR records termination/resignation; notification (ideally automated) triggers de-provisioning across systems.
- *Data created:* Termination date, last working day, offboarding ticket/workflow record.
- *Risks:* Notification delay between HR and IT; some systems (especially cloud/SaaS not centrally managed) are missed entirely; for-cause terminations need *faster* action than voluntary ones, but processes often treat them the same — or worse, slower.

**9. Account Removal / Deactivation**
- *What happens:* Accounts are disabled or deleted across all connected systems; access logs are archived per retention policy.
- *Data created:* Deactivation timestamp per system, final audit trail, data retention/archival record.
- *Risks:* Accounts disabled in AD but left active in AWS/Salesforce/Okta ("ghost access"); service accounts tied to the departing employee are forgotten entirely; archived data isn't actually retrievable when needed for investigation.

### Lifecycle Diagram (textual)

```
 HIRE ──▶ PROVISION ──▶ ROLE ASSIGNMENT ──▶ ACCESS USAGE
                                                  │
                     ┌────────────────────────────┘
                     ▼
              ROLE CHANGE (MOVER) ──▶ PRIVILEGE ESCALATION (as needed)
                     │                          │
                     └───────────┬──────────────┘
                                 ▼
                         PERIODIC REVIEW
                                 │
                 ┌───────────────┴───────────────┐
                 ▼                                ▼
         CONTINUES IN ROLE                  OFFBOARDING (LEAVER)
                                                   │
                                                   ▼
                                      ACCOUNT REMOVAL (per platform)
                                                   │
                                                   ▼
                                       AUDIT TRAIL / LOG RETENTION
```

The critical insight: **every arrow in this diagram is a potential point of desynchronization across AD, Azure AD, AWS, Okta, and Salesforce.** Each platform can independently fall out of step with the "true" state defined by HR, and nothing in a typical environment guarantees they stay aligned in real time.

---

## STEP 5 — CROSS-PLATFORM RELATIONSHIP ANALYSIS

### Platform-by-platform identity role

- **Active Directory (AD):** Often the historical "core" identity store for on-premises resources (laptops, file shares, internal apps). Frequently the source that other systems sync *from*.
- **Azure AD (Entra ID):** Cloud directory, frequently synchronized from on-prem AD via directory sync tools, but can also contain cloud-only identities (guests, B2B partners) that have no AD counterpart.
- **AWS IAM:** Manages access to cloud infrastructure. Identities here may be humans (via federation/SSO) or, just as commonly, **roles and service accounts** with no direct 1:1 human mapping at all.
- **Okta:** Frequently sits as an identity broker/SSO layer on top of AD/Azure AD, federating access into many downstream SaaS apps — meaning a failure here can cascade into dozens of connected applications at once.
- **Salesforce:** A business application with its own internal user/profile/permission-set model, often provisioned semi-independently by business teams rather than central IT.
- **Service Accounts:** Non-human identities used by applications, scripts, and integrations. They typically cut across all of the above platforms and are the least likely to have a clear human owner.
- **API Tokens:** Credentials (often tied to service accounts or individual developers) used for programmatic access — frequently the least visible and least governed identity type of all.

### How identities relate across platforms
- A single human is typically represented by **multiple, loosely-linked accounts**: one in AD, a synced or separate one in Azure AD, a federated session in Okta, an IAM role/user in AWS, and a distinct user record in Salesforce.
- Correlation between these accounts usually relies on **soft matching keys** — email address, employee ID (if propagated), or display name — which are prone to mismatch, especially after name changes, duplicate accounts, or manual provisioning errors.
- **Service accounts and API tokens often have no human counterpart at all**, but may still be "owned" informally by a person or team that created them — ownership that is rarely tracked formally and is often lost when that person leaves.

### How privilege inheritance works
- **Nested groups** (a group inside a group inside a group) mean a user's *effective* access can be far broader than what's directly visible on their account — this is one of the most common sources of unintentional over-privilege.
- **Role-based access in AWS** can chain: a user assumes a role, which may itself have permission to assume further roles, creating privilege paths that are not obvious from a single point-in-time look at any one identity.
- **SSO/federation (Okta)** means that gaining access to the identity broker can implicitly grant downstream access to every connected application — privilege inheritance isn't just within a platform, it's *across* platforms.
- **Salesforce permission sets and profiles** can stack, similarly obscuring true effective access behind multiple layers of assignment.

### How risk propagates across platforms
- A compromised low-privilege AD account can be used to discover or pivot toward higher-privilege accounts in Azure AD or AWS if cross-platform trust relationships exist (e.g., federated SSO, shared credentials, or saved sessions).
- A forgotten or over-permissioned **service account** is a particularly dangerous propagation vector because it often has standing access across multiple platforms simultaneously and is rarely subject to MFA or interactive monitoring.
- **Offboarding gaps** mean risk doesn't stay contained to one platform — a terminated employee disabled in AD but still active in AWS represents risk that has effectively "escaped" the primary control point.
- Because no platform has full visibility into the others, risk that is "contained" from one team's perspective (e.g., Cloud team sees a tightly-scoped AWS role) may actually be amplified by something invisible to them (e.g., that same identity also holds Salesforce admin rights).

---

## STEP 6 — RISK REGISTER

| Risk | Description | Likelihood | Impact | Why It Matters |
|---|---|---|---|---|
| Offboarded employee retains access | Account not disabled in all systems after termination | High | High | Direct path to unauthorized access by a known-hostile or simply unmonitored party |
| Over-privileged users | Employees accumulate access beyond current role needs | High | Medium-High | Expands blast radius if account is compromised |
| Dormant privileged accounts | Admin-level accounts unused for extended periods | Medium | High | Attractive, low-noise target for attackers; often missed by reviews |
| Cross-platform admin concentration | Same identity holds admin rights on multiple platforms | Medium | High | Single compromise yields broad, multi-system impact |
| Privilege escalation without oversight | Elevated access granted without time-bound or logged approval | Medium | High | Creates untracked, potentially permanent privileged paths |
| Service account sprawl | Numerous service accounts with unclear ownership | High | Medium-High | Hard to monitor, rarely rotated, broad standing privilege |
| API token leakage/long-lived tokens | Tokens hardcoded, undocumented, or never expiring | Medium | High | Easily exfiltrated and reused without raising alerts |
| Shared/generic accounts | Multiple people use one set of credentials | Medium | Medium | Destroys individual accountability and complicates investigations |
| Nested group over-grant | Group inheritance grants more access than intended | High | Medium | Hidden risk invisible to standard, flat access reviews |
| Inconsistent identity correlation | Same human represented inconsistently across systems | High | Medium | Undermines accuracy of any centralized access view |
| Rubber-stamp access reviews | Reviewers approve without real scrutiny | High | Medium | Review process becomes a compliance formality, not a real control |
| HR-to-IT sync delay | Lag between HR event and system provisioning/de-provisioning | Medium | High | Time window where access state is wrong (over- or under-provisioned) |
| Orphaned accounts | Accounts with no matching active HR record | Medium | Medium-High | Untraceable, possibly unauthorized, possibly malicious |
| M&A identity conflicts | Duplicate/conflicting identities from acquired entities | Medium | Medium | Slows integration and creates long-term blind spots |
| Contractor access overrun | Vendor/contractor access outlives the contract | Medium | Medium | Access persists with no ongoing business justification |
| SoD violations | Same person can both initiate and approve sensitive transactions | Low-Medium | High | Direct fraud exposure, especially for financial systems |
| Logging gaps across platforms | Inconsistent or missing audit logs in some systems | Medium | High | Investigations stall or fail without complete evidence |
| Break-glass account misuse | Emergency access used outside genuine emergencies, poorly monitored | Low | High | Bypasses normal controls with minimal oversight |
| Inconsistent risk scoring | Same identity assessed differently by different teams | Medium | Medium | Leads to inconsistent prioritization of remediation |
| Manual, spreadsheet-based reviews | Reviews don't scale to identity/system volume | High | Medium | Increases likelihood of missed or incomplete reviews |

---

## STEP 7 — ANOMALY ANALYSIS

**Offboarding Gaps**
- *Definition:* A terminated employee's access is not fully revoked across all systems.
- *Root Cause:* No automated, cross-platform de-provisioning trigger; manual processes miss less-central systems.
- *Business Impact:* Continued (often unbilled, unnoticed) access by someone with no employment relationship.
- *Security Impact:* High — a known, "free" entry point requiring no exploitation, just usage of valid credentials.
- *Why Auditors Care:* It is one of the most commonly tested, most commonly failed controls in access audits.

**Over-Privileged Users**
- *Definition:* Users hold access beyond what their current role requires.
- *Root Cause:* Privilege creep from role changes; broad default provisioning templates; no automatic access removal.
- *Business Impact:* Increases potential damage from both insider misuse and external compromise.
- *Security Impact:* Expands the practical attack surface of every credential compromise.
- *Why Auditors Care:* Directly tests least-privilege and SoD control effectiveness.

**Dormant Admins**
- *Definition:* Privileged accounts that have not been used in an extended period but remain active.
- *Root Cause:* No automated dormancy detection tied to privileged accounts specifically; reviews focus on "who has access," not "who's using it."
- *Business Impact:* Maintains unnecessary risk surface with zero offsetting business benefit.
- *Security Impact:* High-value, low-noise target — compromise may go undetected longer since no legitimate baseline activity exists to compare against.
- *Why Auditors Care:* Demonstrates whether privileged access reviews are actually risk-based.

**Cross-Platform Admin Accounts**
- *Definition:* A single identity holds administrative rights across multiple, otherwise-independent systems.
- *Root Cause:* Convenience-driven provisioning; lack of centralized oversight of cumulative privilege.
- *Business Impact:* Concentrates enterprise-wide risk in a small number of accounts.
- *Security Impact:* A single compromised credential can yield multi-system, potentially organization-wide impact.
- *Why Auditors Care:* Tests whether privilege is genuinely scoped to need, or aggregated for convenience.

**Privilege Escalation**
- *Definition:* An identity gains higher access than originally granted, legitimately or otherwise.
- *Root Cause:* Weak approval gating on elevation requests; exploitable misconfigurations (e.g., role-chaining in cloud IAM).
- *Business Impact:* Can result in unauthorized changes to critical systems or data.
- *Security Impact:* Often the pivotal step in a real-world breach, turning limited access into full compromise.
- *Why Auditors Care:* Validates whether elevation is genuinely controlled or merely policy on paper.

**Token Abuse**
- *Definition:* API tokens used outside their intended scope, timeframe, or by an unauthorized party.
- *Root Cause:* Tokens without expiration, scope limits, or rotation; tokens leaked via code repos or logs.
- *Business Impact:* Can enable large-scale automated data access or exfiltration.
- *Security Impact:* Tokens often bypass MFA and interactive monitoring entirely.
- *Why Auditors Care:* Non-human credential governance is frequently an audit blind spot, making it a focus area.

**Credential Misuse**
- *Definition:* Valid credentials used in ways inconsistent with authorized purpose (e.g., shared, reused, used outside normal patterns).
- *Root Cause:* Weak credential hygiene practices; lack of behavioral monitoring.
- *Business Impact:* Undermines the integrity of "who did what" across the business.
- *Security Impact:* Makes detection harder since the credential itself is technically "valid."
- *Why Auditors Care:* Directly threatens the non-repudiation principle audits rely on.

**Service Account Abuse**
- *Definition:* Non-human accounts used for unintended purposes, or with excessive standing privilege.
- *Root Cause:* No formal ownership/lifecycle management equivalent to human identity governance.
- *Business Impact:* Service disruptions or data exposure if misused or compromised.
- *Security Impact:* Frequently the path of least resistance for attackers due to weak monitoring.
- *Why Auditors Care:* Non-human identity governance maturity is a recurring audit gap across industries.

---

## STEP 8 — EDGE CASE ANALYSIS

| Edge Case | Why It's Difficult |
|---|---|
| User disabled in AD but active in AWS | No platform has authority to enforce state in another; requires cross-system reconciliation that often doesn't exist in real time |
| Admin in AWS but not in AD | Suggests the account was provisioned outside the "normal" HR-driven workflow entirely — hard to trace origin or justification |
| Nested group inheritance | Effective access isn't visible from a flat account view; requires recursive resolution that most manual reviews skip |
| Temporary admin rights that never expire | Distinguishing "temporary that should auto-expire" from "permanent that was mislabeled" requires tracking original intent, which is often lost |
| Shared service accounts | No way to attribute specific actions to a specific human; legitimate technical need (automation) conflicts with accountability principle |
| Dormant privileged users | Hard to distinguish "legitimately inactive but still needed" (e.g., break-glass) from "should have been removed long ago" |
| Token rotation failures | Tokens may continue working past intended rotation if old tokens aren't actively revoked, not just replaced |
| Identity correlation mismatches | Same person may appear as different "identities" across systems due to name changes, typos, or independent provisioning — false negatives (missed links) and false positives (wrong links) are both possible |
| Contractor converted to full-time employee | Old contractor account and new employee account may coexist, creating duplicate or conflicting access trails |
| Re-hired employees | Old account may be reactivated with stale, outdated permissions rather than re-provisioned cleanly |
| Cross-border/multi-entity employees | Same person may need different access profiles in different regulatory jurisdictions, complicating a single "role" model |
| Break-glass emergency access usage | Legitimate by design, but indistinguishable from misuse without strong contextual logging of *why* it was invoked |

---

## STEP 9 — AUDITOR THINKING: TOP 25 QUESTIONS

1. **Can you produce a complete list of all active identities across every platform?** — Evidence: full identity inventory export per platform; Data: account status, creation date, last login.
2. **How do you prove every active account maps to a valid, current employee or approved third party?** — Evidence: HR-to-IT reconciliation report; Data: HR active employee roster vs. system account list.
3. **What is the average time between termination and full access revocation?** — Evidence: offboarding SLA report; Data: termination date vs. deactivation timestamp per system.
4. **Can you show that every privileged account has a documented business justification?** — Evidence: privileged access approval records; Data: justification field per privileged grant.
5. **How are segregation-of-duties conflicts identified and remediated?** — Evidence: SoD conflict report and remediation log; Data: role-to-permission matrix, conflict rule set.
6. **What evidence exists that access reviews actually result in revocations, not just attestations?** — Evidence: review campaign outcome report; Data: approve/revoke counts and downstream execution confirmation.
7. **How do you detect and handle orphaned accounts with no HR match?** — Evidence: orphaned account report; Data: reconciliation exception list.
8. **What is your policy and evidence for dormant account handling?** — Evidence: dormancy policy document and enforcement log; Data: last-login timestamps vs. policy threshold.
9. **How are service accounts inventoried and assigned ownership?** — Evidence: service account registry; Data: owner field, creation date, last credential rotation.
10. **What controls exist over API token issuance, scope, and expiration?** — Evidence: token management policy and token inventory; Data: scope, expiry, issuance approver.
11. **How is privileged access time-bound, and what enforces the expiration?** — Evidence: just-in-time access logs; Data: grant timestamp, expiration timestamp, actual revocation timestamp.
12. **Can you demonstrate MFA enforcement on all administrative accounts?** — Evidence: MFA enrollment/enforcement report; Data: per-account MFA status.
13. **How are nested group memberships accounted for in access reviews?** — Evidence: effective access resolution methodology; Data: expanded group membership trees.
14. **What is the process when a role change occurs — how is old access removed?** — Evidence: mover workflow documentation and execution logs; Data: pre/post role-change entitlement diff.
15. **How do you verify logging completeness across all identity platforms?** — Evidence: logging coverage assessment; Data: per-platform log retention and completeness checks.
16. **What evidence exists of break-glass account usage and post-use review?** — Evidence: break-glass usage log and post-incident review record; Data: usage timestamp, justification, reviewer sign-off.
17. **How is contractor/vendor access tied to contract terms?** — Evidence: vendor access lifecycle policy; Data: contract end date vs. account expiration date.
18. **What is the process for validating access for re-hired employees?** — Evidence: re-hire provisioning procedure; Data: old vs. new account comparison.
19. **How is identity correlation accuracy measured across platforms?** — Evidence: identity matching/reconciliation accuracy report; Data: match confidence scores, manual exception rate.
20. **What controls exist for shared/generic accounts, and how is usage attributed?** — Evidence: shared account policy and compensating control log; Data: checkout/usage logs.
21. **How are M&A-introduced identities reconciled into the governance program?** — Evidence: M&A identity integration plan and status; Data: integration completion percentage, exception list.
22. **What is the escalation path when a high-risk identity anomaly is detected?** — Evidence: incident response/escalation procedure; Data: detection-to-resolution time logs.
23. **How do you ensure access requests follow least-privilege rather than role-template convenience?** — Evidence: access request approval rationale records; Data: requested vs. granted scope comparison.
24. **What is the audit log retention policy, and is it being met in practice?** — Evidence: retention policy document and storage verification; Data: actual log retention duration per system.
25. **How is the effectiveness of the identity governance program itself measured and reported to leadership?** — Evidence: governance KPI/metrics report to CISO/board; Data: trend data on key risk indicators over time.

---

## STEP 10 — SECURITY TEAM THINKING: TOP 25 QUESTIONS

1. **Which identities currently hold privileged access across more than one platform?** — Why it matters: concentrated risk; Visibility needed: cross-platform privilege aggregation view.
2. **Which privileged accounts have not authenticated in the last 30/60/90 days?** — Why it matters: dormant high-value targets; Visibility needed: last-login data joined with privilege level.
3. **Are there any active accounts with no corresponding active HR record?** — Why it matters: potential rogue or forgotten accounts; Visibility needed: HR-to-system reconciliation feed.
4. **What does the actual effective access look like once nested groups are fully expanded?** — Why it matters: hidden over-privilege; Visibility needed: recursive group resolution.
5. **Which service accounts have interactive login capability (vs. pure automation use)?** — Why it matters: unusual use of non-human identity suggests compromise or misconfiguration; Visibility needed: login type classification per service account.
6. **Which API tokens have no expiration date set?** — Why it matters: indefinite exposure window if leaked; Visibility needed: token metadata inventory.
7. **How quickly is access actually removed after a termination event fires?** — Why it matters: measures real offboarding control effectiveness; Visibility needed: termination-to-deactivation time-series data.
8. **Are there accounts active in a secondary system (e.g., AWS) but disabled in the primary directory (AD)?** — Why it matters: classic "ghost access" indicator; Visibility needed: cross-platform status comparison.
9. **What privilege escalation events have occurred without a corresponding ticket/approval?** — Why it matters: untracked elevation is a top breach vector; Visibility needed: escalation event log vs. approval system.
10. **Which identities can assume roles that grant access beyond their visible direct permissions (role chaining)?** — Why it matters: hidden privilege paths; Visibility needed: role assumption graph/path analysis.
11. **Are there multiple human users sharing a single credential set?** — Why it matters: destroys accountability, complicates detection; Visibility needed: concurrent session/location anomaly detection.
12. **Which identities show login behavior inconsistent with their historical pattern?** — Why it matters: early indicator of credential compromise; Visibility needed: behavioral baseline and anomaly detection.
13. **Are break-glass/emergency accounts used outside declared emergency windows?** — Why it matters: potential misuse of an inherently high-trust mechanism; Visibility needed: usage timestamps vs. declared incident windows.
14. **What is the current count and trend of dormant privileged accounts?** — Why it matters: tracks whether risk is growing or shrinking over time; Visibility needed: trend reporting, not just point-in-time snapshots.
15. **Which accounts hold access that conflicts with segregation-of-duties rules?** — Why it matters: fraud and error risk; Visibility needed: SoD rule engine output.
16. **Are MFA enforcement gaps present on any privileged or sensitive accounts?** — Why it matters: single-factor admin access is a critical exposure; Visibility needed: MFA status per privileged account.
17. **Which identities were recently part of a role change, and has old access been removed?** — Why it matters: privilege creep window; Visibility needed: entitlement diff pre/post role change.
18. **What identities are linked to recently departed third parties/contractors?** — Why it matters: contractor access is a frequently exploited, frequently neglected category; Visibility needed: contract status feed tied to access records.
19. **Are there orphaned service accounts whose original creator/owner has left the company?** — Why it matters: unmonitored, unmaintained, high-privilege accounts; Visibility needed: service account ownership vs. current employee roster.
20. **What percentage of total privileged access is actively being used vs. simply held?** — Why it matters: identifies pure risk-with-no-benefit access; Visibility needed: usage-to-grant ratio reporting.
21. **Which cross-platform admin concentrations represent single points of catastrophic compromise?** — Why it matters: prioritizes remediation by blast radius; Visibility needed: aggregated privilege-by-identity scoring.
22. **Are there gaps in logging coverage across any of the identity platforms in scope?** — Why it matters: undermines detection and investigation capability; Visibility needed: log source completeness audit.
23. **What anomalies exist in token usage patterns (volume, source IP, time of day)?** — Why it matters: tokens often bypass standard monitoring; Visibility needed: token usage telemetry and baselining.
24. **How many identities have access that was never actually approved through a formal process?** — Why it matters: indicates control bypass, not just gaps; Visibility needed: access-grant-to-approval-record matching.
25. **What is the current risk score trend for the highest-privilege identities in the environment?** — Why it matters: focuses limited attention on highest-consequence accounts; Visibility needed: consistent, longitudinal identity risk scoring.

---

## STEP 11 — ATTACKER THINKING: TOP 20 ATTACK PATHS

1. **Use a terminated employee's still-active credential** → Works because offboarding missed a secondary system. *Control failure:* cross-platform de-provisioning.
2. **Phish a low-privilege user, then pivot via nested group membership** → Works because effective access is broader than it appears. *Control failure:* no recursive review of group inheritance.
3. **Compromise a dormant admin account** → Works because no one notices login activity on an account no one is watching. *Control failure:* no dormancy-based monitoring on privileged accounts.
4. **Extract a hardcoded API token from a code repository** → Works because tokens are long-lived and broadly scoped. *Control failure:* no token expiration/rotation enforcement.
5. **Exploit role-chaining in cloud IAM to escalate from a low-privilege role to an admin role** → Works because permission boundaries aren't analyzed holistically. *Control failure:* no path-based privilege analysis.
6. **Target a shared/generic service account credential** → Works because shared credentials are often weakly protected and widely known internally. *Control failure:* lack of individual accountability/credential hygiene.
7. **Abuse a "temporary" admin grant that was never revoked** → Works because expiration is policy-based, not system-enforced. *Control failure:* no automated time-bound access expiration.
8. **Pivot from a compromised SSO/Okta session into every downstream federated application at once** → Works because SSO broadly trusts a single authentication event. *Control failure:* insufficient step-up authentication for sensitive downstream apps.
9. **Use a contractor account that outlived its contract** → Works because vendor offboarding isn't tied to contract dates automatically. *Control failure:* no contract-to-access lifecycle linkage.
10. **Exploit inconsistent identity correlation to "hide" a duplicate or rogue account** → Works because no one entity reconciles all platforms against one source of truth. *Control failure:* weak/no cross-platform identity reconciliation.
11. **Abuse a break-glass account outside a real emergency** → Works because emergency access often has lighter real-time scrutiny than normal privileged access. *Control failure:* insufficient post-use review of emergency access.
12. **Target an orphaned account with no current HR owner** → Works because no one is actively monitoring or rotating its credentials. *Control failure:* no orphaned-account detection process.
13. **Use a re-hired employee's stale, reactivated old account** → Works because re-provisioning reused an outdated permission set instead of starting clean. *Control failure:* no clean re-provisioning standard for re-hires.
14. **Escalate via a service account with excessive standing privilege across multiple platforms** → Works because service accounts are rarely scrutinized like human identities. *Control failure:* no least-privilege enforcement for non-human identities.
15. **Exploit unrotated credentials for a service/API account after key personnel departure** → Works because credential rotation isn't tied to personnel changes. *Control failure:* no rotation-on-departure trigger.
16. **Leverage M&A-era duplicate/conflicting accounts that were never fully reconciled** → Works because integration backlog leaves long-term blind spots. *Control failure:* incomplete M&A identity integration.
17. **Use SoD gaps to both request and approve a fraudulent change** → Works because the same identity holds conflicting capabilities. *Control failure:* no automated SoD conflict detection.
18. **Exploit logging blind spots in a less-monitored platform to operate undetected post-compromise** → Works because not all platforms are equally instrumented. *Control failure:* inconsistent logging coverage across the identity ecosystem.
19. **Use privilege creep from multiple past role changes to assemble unusually broad access on one identity** → Works because access accumulates and is never trimmed. *Control failure:* no automatic access removal on role change.
20. **Target the single cross-platform "super admin" identity that exists for convenience** → Works because consolidating admin rights into a few accounts is operationally convenient but creates a catastrophic single point of failure. *Control failure:* no limit on cross-platform privilege concentration.

---

## STEP 12 — FINAL INTELLIGENCE REPORT

### Top 20 Insights
1. The core problem is not lack of access *control* — it's lack of access *visibility* across fragmented systems.
2. Provisioning is structurally easier than de-provisioning, creating a built-in bias toward access accumulation.
3. Identity sprawl is a natural consequence of growth, not a one-time mistake to "fix."
4. The weakest-governed platform in the stack defines the organization's real identity risk, not the strongest.
5. Privilege creep, not initial over-provisioning, is the dominant long-term driver of excessive access.
6. Non-human identities (service accounts, tokens) are routinely under-governed relative to human identities, despite often carrying more risk.
7. Cross-platform identity correlation is itself an unsolved data quality problem, not just a technical integration task.
8. Nested group inheritance routinely hides true effective access from both reviewers and security teams.
9. Offboarding speed and completeness — not policy existence — is the real differentiator between mature and immature programs.
10. Access reviews frequently measure *process completion*, not *risk reduction*.
11. Break-glass/emergency access is a necessary but persistently under-scrutinized control exception.
12. Compliance frameworks shape governance investment more than actual measured risk does.
13. HR data quality and timeliness is a hidden dependency underlying the entire identity lifecycle.
14. M&A activity is a long-tail, multi-year source of identity governance debt.
15. Contractor/vendor access lifecycle is consistently weaker than employee lifecycle management.
16. Security, Audit, and IAM teams often use inconsistent definitions of "risk," undermining unified prioritization.
17. The business structurally favors speed of access over rigor of access — security friction is informally penalized.
18. Logging completeness varies significantly by platform, creating uneven investigative capability.
19. SoD violations are a fraud-relevant risk distinct from, but related to, general over-privilege.
20. Most identity-related breaches exploit *valid* credentials and *legitimate-looking* access paths, not software vulnerabilities.

### Top 20 Risks
1. Ghost access from incomplete offboarding.
2. Privilege creep from unmanaged role changes.
3. Dormant privileged accounts as stealth targets.
4. Cross-platform admin concentration creating single points of failure.
5. Untracked/unbound privilege escalation.
6. Service account sprawl with unclear ownership.
7. Long-lived, unscoped API tokens.
8. Shared/generic account usage destroying accountability.
9. Hidden over-privilege via nested group inheritance.
10. Inconsistent identity correlation across platforms.
11. Rubber-stamp, low-rigor access reviews.
12. HR-to-IT synchronization delays.
13. Orphaned accounts with no current owner.
14. Unresolved M&A identity conflicts.
15. Contractor access outliving contract terms.
16. Segregation-of-duties violations enabling fraud.
17. Inconsistent or incomplete audit logging.
18. Break-glass account misuse or weak post-use review.
19. Inconsistent risk scoring across stakeholder teams.
20. Manual, non-scalable review processes.

### Top 20 Requirements the Future Solution MUST Satisfy
1. Provide a single, reconciled view of identity across all in-scope platforms.
2. Detect and flag orphaned accounts with no matching HR record.
3. Surface effective access including fully-expanded nested group inheritance.
4. Track and enforce time-bound expiration of privileged/temporary access.
5. Maintain a service account registry with named ownership and rotation status.
6. Maintain an API token inventory with scope and expiration tracking.
7. Measure and report time-to-revocation after termination events.
8. Detect cross-platform admin concentration on individual identities.
9. Detect dormant privileged accounts based on actual usage data.
10. Support segregation-of-duties conflict detection.
11. Provide evidence-grade audit trails sufficient for internal/external audit use.
12. Distinguish for-cause terminations requiring expedited handling.
13. Track contractor/vendor access against contract lifecycle dates.
14. Provide consistent identity risk scoring usable by Security, Audit, and IAM alike.
15. Support detection of privilege escalation events lacking corresponding approval records.
16. Identify role-change events where old access was not subsequently removed.
17. Support post-use review tracking for break-glass/emergency access.
18. Identify logging coverage gaps across connected platforms.
19. Support reconciliation workflows for M&A-introduced identities.
20. Provide trend-over-time reporting, not just point-in-time snapshots, for leadership and audit committee visibility.

### Top 10 Things Hackathon Teams Will Probably Miss
1. **Identity correlation is a data quality problem, not just a join key problem** — name/email matching will produce false positives and false negatives that need explicit handling, not silent assumption of clean matches.
2. **Non-human identities (service accounts, tokens) need their own governance model** — teams often design only for human employees.
3. **Nested/recursive group resolution** — many teams will only look at directly-assigned permissions and miss inherited access entirely.
4. **The distinction between "access exists" and "access is used"** — teams will flag all privileged accounts as risky without distinguishing active misuse risk from simple dormancy.
5. **Break-glass/emergency access as a deliberate exception category** — teams may treat all elevated access uniformly and either over-flag legitimate emergency access or fail to scrutinize it post-use.
6. **Time dimension of risk** — a point-in-time snapshot misses the difference between an access grant that just happened and one that's been dormant for a year.
7. **For-cause vs. voluntary termination urgency differences** — most teams will treat all offboarding identically.
8. **Contract-to-access lifecycle linkage for contractors/vendors**, distinct from employee lifecycle.
9. **M&A-driven identity duplication/conflict scenarios** — an often-overlooked but very real source of edge cases.
10. **The difference between a control existing on paper (policy) and a control being enforced in practice (system-verified)** — many solutions will assume policy compliance rather than verifying it.

### Top 10 Opportunities for Innovation
1. Probabilistic, confidence-scored identity correlation across platforms rather than brittle exact-match logic.
2. Effective-access computation that fully resolves nested groups and role-chaining automatically.
3. Usage-weighted risk scoring that distinguishes "has access" from "actively uses access."
4. Automated, contract-linked lifecycle management for contractor/vendor identities.
5. Continuous, real-time reconciliation against HR data instead of periodic batch reviews.
6. A unified risk-scoring model shared across Security, Audit, and IAM to eliminate inconsistent prioritization.
7. Automated detection of privilege creep by comparing current entitlements against role-change history.
8. Post-use, context-aware review automation for break-glass/emergency access.
9. Cross-platform "blast radius" visualization showing the true consequence of a single identity's compromise.
10. Service account and API token lifecycle management modeled with the same rigor as human identity governance, including ownership succession when the original owner departs.

---

*End of business problem analysis. This document intentionally stops short of architecture, dataset, or solution design, per scope.*
