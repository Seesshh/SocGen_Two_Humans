"""
src/intelligence/generate_llm_narratives.py

Incident Narrative Generator for the Hybrid Identity Governance platform
(Phase 4 incident narrative design, Phase 5 MVP scope).

Generates Executive Summary, Technical Summary, Business Impact, Compliance
Impact, and Recommended Actions for every incident — entirely template-based,
no external LLM call required. Named templates are provided for the 6
anomaly types specified (Offboarding Gap, Dormant Admin, Cross Platform
Admin, Privilege Creep, Service Account Abuse, Token Abuse); any other
anomaly type (e.g. Orphaned Account, or a future addition) falls through to
a generic but still fully-populated template rather than failing.

Inputs:  incidents.csv, identity_risk_scores.csv
Output:  incident_narratives.csv
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, List

import pandas as pd

# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #

DATA_DIR: Path = Path("data/synthetic_data")
OUTPUT_DIR: Path = Path("data/synthetic_data")

REQUIRED_INPUTS: Dict[str, str] = {
    "incidents": "incidents.csv",
    "identity_risk_scores": "identity_risk_scores.csv",
}

LOGGER = logging.getLogger("generate_llm_narratives")


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


def save_csv(df: pd.DataFrame, filename: str) -> Path:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    path = OUTPUT_DIR / filename
    df.to_csv(path, index=False)
    LOGGER.info("Saved %s (%d rows, %d columns)", path, len(df), len(df.columns))
    return path


# --------------------------------------------------------------------------- #
# Template data structure
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class NarrativeTemplate:
    executive_summary: str
    technical_summary: str
    business_impact: str
    compliance_impact: str
    recommended_actions: str


def _identity_label(row: pd.Series) -> str:
    name = row.get("full_name")
    if isinstance(name, str) and name.strip():
        return name
    return f"Identity {row.get('identity_id')}"


def _systems_label(row: pd.Series) -> str:
    systems = row.get("affected_systems")
    if isinstance(systems, str) and systems.strip() and "Unspecified" not in systems:
        return systems.replace(";", ", ")
    return "the affected system(s)"


def _evidence_excerpt(row: pd.Series, max_len: int = 280) -> str:
    text = str(row.get("evidence_summary", "")).strip()
    if len(text) <= max_len:
        return text
    return text[:max_len].rsplit(" ", 1)[0] + "..."


# --------------------------------------------------------------------------- #
# Named templates for the 6 specified anomaly types
# --------------------------------------------------------------------------- #

def _template_offboarding_gap(row: pd.Series) -> NarrativeTemplate:
    who, systems = _identity_label(row), _systems_label(row)
    return NarrativeTemplate(
        executive_summary=(
            f"A former employee's access ({who}) was not revoked after departure and remained active on "
            f"{systems} beyond policy, creating a window of unauthorized access."
        ),
        technical_summary=(
            f"Offboarding event for {who} did not complete within the SLA on {systems}. "
            f"Evidence: {_evidence_excerpt(row)}"
        ),
        business_impact=(
            f"{who} retained the ability to access systems and data they were authorized for during "
            f"employment, for a period after their departure — exposure scales with how long the gap persists."
        ),
        compliance_impact=(
            "Violates the offboarding/access-termination SLA control; this is a control auditors specifically "
            "sample for under SOX and ISO 27001 access-termination testing."
        ),
        recommended_actions=(
            f"Disable the account on {systems} immediately. Confirm no activity occurred during the gap window "
            "via audit/authentication logs. Root-cause why automated offboarding did not cover this platform, "
            "and remediate the integration gap."
        ),
    )


def _template_dormant_admin(row: pd.Series) -> NarrativeTemplate:
    who, systems = _identity_label(row), _systems_label(row)
    return NarrativeTemplate(
        executive_summary=(
            f"An administrative account belonging to {who} has not been used in months but remains fully "
            f"active and privileged on {systems} — unnecessary standing risk with no offsetting business activity."
        ),
        technical_summary=f"Dormant admin-tier account detected for {who} on {systems}. Evidence: {_evidence_excerpt(row)}",
        business_impact=(
            "An unused but live privileged credential is an attractive, low-noise target — malicious use would "
            "not stand out against any recent legitimate baseline, since none exists."
        ),
        compliance_impact=(
            "Relevant to dormant-account hygiene and least-privilege testing — a direct audit question of "
            "'why does this person still have this if they haven't used it?'"
        ),
        recommended_actions=(
            f"Confirm continued business need for this access with {who} and their manager. Revoke if not "
            "needed. If needed only occasionally, convert to just-in-time elevation rather than standing admin."
        ),
    )


def _template_cross_platform_admin(row: pd.Series) -> NarrativeTemplate:
    who, systems = _identity_label(row), _systems_label(row)
    return NarrativeTemplate(
        executive_summary=(
            f"{who} holds administrative privileges concurrently across multiple platforms ({systems}), "
            "creating a single point of compromise with multi-system impact."
        ),
        technical_summary=f"Cross-platform admin concentration detected for {who}. Evidence: {_evidence_excerpt(row)}",
        business_impact=(
            "A single compromised credential or insider-misuse event for this identity could result in "
            "unauthorized changes across every platform listed simultaneously."
        ),
        compliance_impact=(
            "Relevant to least-privilege and segregation-of-duties principles; auditors typically flag broad "
            "cross-system admin concentration on sight, regardless of whether a named SoD rule exists for it."
        ),
        recommended_actions=(
            f"Require documented business justification for {who}'s multi-platform admin access. Evaluate "
            "splitting into platform-scoped roles, or converting standing access to time-bound/just-in-time "
            "elevation. Add to the next privileged access review with mandatory manager and platform-owner sign-off."
        ),
    )


def _template_privilege_creep(row: pd.Series) -> NarrativeTemplate:
    who, systems = _identity_label(row), _systems_label(row)
    return NarrativeTemplate(
        executive_summary=(
            f"{who} retains access from a prior role or responsibility on {systems} that was never revoked "
            "after their responsibilities changed."
        ),
        technical_summary=f"Stale privilege grant detected for {who}. Evidence: {_evidence_excerpt(row)}",
        business_impact=(
            "Unbounded access accumulation increases blast radius without a corresponding business need — "
            "this access serves no current function but remains exploitable if the credential is compromised."
        ),
        compliance_impact=(
            "Directly relevant to least-privilege testing; a mover-triggered access review failure is a "
            "common, specifically-named audit finding."
        ),
        recommended_actions=(
            f"Execute targeted revocation of {who}'s stale access tied to the prior role. Enable automatic "
            "mover-triggered access review so future role changes don't recreate this gap."
        ),
    )


def _template_service_account_abuse(row: pd.Series) -> NarrativeTemplate:
    systems = _systems_label(row)
    return NarrativeTemplate(
        executive_summary=(
            f"A service account showed interactive login activity on {systems} despite being configured for "
            "automation-only use, consistent with potential credential misuse."
        ),
        technical_summary=f"Service account abuse pattern detected on {systems}. Evidence: {_evidence_excerpt(row)}",
        business_impact=(
            "Interactive use of an automation identity bypasses the monitoring and accountability controls "
            "built around human accounts, and may indicate the account's owner has departed or the credential "
            "has been exposed."
        ),
        compliance_impact=(
            "Relevant to service-account governance and non-human identity hygiene controls — an increasingly "
            "common audit focus area as automation identities proliferate."
        ),
        recommended_actions=(
            "Disable interactive login capability (or the account itself) pending investigation. Identify who "
            "performed the interactive session. Reassign ownership if the registered owner has left the company."
        ),
    )


def _template_token_abuse(row: pd.Series) -> NarrativeTemplate:
    systems = _systems_label(row)
    return NarrativeTemplate(
        executive_summary=(
            f"An API token on {systems} showed a sharp, unexplained spike in usage volume and originating "
            "locations, consistent with potential credential theft or unauthorized reuse."
        ),
        technical_summary=f"Token usage anomaly detected on {systems}. Evidence: {_evidence_excerpt(row)}",
        business_impact=(
            "Activity at this volume, if unauthorized, could indicate large-scale data exfiltration or "
            "fraudulent automated activity, scoped to whatever this token's permissions allow."
        ),
        compliance_impact=(
            "Relevant to token/credential hygiene controls, and to regulated-data-handling requirements if the "
            "token's scope touches in-scope regulated data."
        ),
        recommended_actions=(
            "Revoke and rotate the token immediately. Review all actions taken during the anomalous usage "
            "window via audit logs. Determine the likely exposure source (code repository, log file) and "
            "implement IP allowlisting going forward."
        ),
    )


def _template_generic(row: pd.Series) -> NarrativeTemplate:
    who, systems = _identity_label(row), _systems_label(row)
    incident_type = row.get("incident_type", "an access governance anomaly")
    return NarrativeTemplate(
        executive_summary=f"{who} was flagged for {incident_type} on {systems}, warranting investigation.",
        technical_summary=f"Anomaly type: {incident_type}. Evidence: {_evidence_excerpt(row)}",
        business_impact=(
            "This finding represents a deviation from expected access governance baselines; impact scales "
            "with the privilege level and systems involved."
        ),
        compliance_impact="Relevant to general access governance and least-privilege control testing.",
        recommended_actions=row.get("recommended_remediation", "Escalate to the identity governance team for investigation."),
    )


TEMPLATE_DISPATCH: Dict[str, Callable[[pd.Series], NarrativeTemplate]] = {
    "OFFBOARDING_GAP": _template_offboarding_gap,
    "DORMANT_ADMIN": _template_dormant_admin,
    "CROSS_PLATFORM_ADMIN": _template_cross_platform_admin,
    "PRIVILEGE_CREEP": _template_privilege_creep,
    "SERVICE_ACCOUNT_ABUSE": _template_service_account_abuse,
    "TOKEN_ABUSE": _template_token_abuse,
}


def _primary_anomaly_type(incident_type: str) -> str:
    """incident_type is either a single anomaly_type, or a string like
    'Multi-Anomaly (TYPE_A, TYPE_B)' — extract the first listed type to pick
    the lead template; the multi-anomaly context still flows through via the
    full evidence_summary embedded in every template's technical_summary."""
    if not isinstance(incident_type, str):
        return ""
    match = re.search(r"\(([^)]+)\)", incident_type)
    if match:
        first = match.group(1).split(",")[0].strip()
        return first
    return incident_type.strip()


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #

def generate_narratives(incidents_df: pd.DataFrame, risk_scores_df: pd.DataFrame) -> pd.DataFrame:
    LOGGER.info("Generating narratives for %d incidents", len(incidents_df))
    risk_context = risk_scores_df.set_index("identity_id")

    records: List[Dict] = []
    template_usage: Dict[str, int] = {}

    for _, incident in incidents_df.iterrows():
        anomaly_key = _primary_anomaly_type(incident.get("incident_type", ""))
        template_fn = TEMPLATE_DISPATCH.get(anomaly_key, _template_generic)
        usage_key = anomaly_key if anomaly_key in TEMPLATE_DISPATCH else "GENERIC"
        template_usage[usage_key] = template_usage.get(usage_key, 0) + 1

        narrative = template_fn(incident)

        identity_id = incident.get("identity_id")
        risk_row = risk_context.loc[identity_id] if identity_id in risk_context.index else None

        records.append(
            {
                "incident_id": incident["incident_id"],
                "identity_id": identity_id,
                "full_name": incident.get("full_name"),
                "incident_type": incident.get("incident_type"),
                "severity": incident.get("severity"),
                "underlying_risk_score": risk_row["risk_score"] if risk_row is not None else incident.get("underlying_risk_score"),
                "underlying_risk_band": risk_row["risk_band"] if risk_row is not None else incident.get("underlying_risk_band"),
                "executive_summary": narrative.executive_summary,
                "technical_summary": narrative.technical_summary,
                "business_impact": narrative.business_impact,
                "compliance_impact": narrative.compliance_impact,
                "recommended_actions": narrative.recommended_actions,
            }
        )

    df = pd.DataFrame.from_records(records)
    LOGGER.info("Template usage distribution: %s", template_usage)
    return df


# --------------------------------------------------------------------------- #
# Main execution block
# --------------------------------------------------------------------------- #

def main() -> None:
    configure_logging()
    LOGGER.info("Starting incident narrative generation (template-based, no external LLM)")

    incidents_df = load_required("incidents")
    risk_scores_df = load_required("identity_risk_scores")

    narratives_df = generate_narratives(incidents_df, risk_scores_df)
    save_csv(narratives_df, "incident_narratives.csv")

    LOGGER.info(
        "Summary -> narratives generated: %d | Critical: %d | High: %d",
        len(narratives_df),
        (narratives_df["severity"] == "Critical").sum(),
        (narratives_df["severity"] == "High").sum(),
    )
    LOGGER.info("Incident narrative generation complete")


if __name__ == "__main__":
    main()
