"""
generate_executive_report.py

Generates a downloadable PDF executive report for the Hybrid Identity
Governance platform: Executive Summary, Risk Score, Top Risks,
Recommendations, Compliance Status.

Output: executive_report.pdf
"""

from __future__ import annotations

import logging
from datetime import date
from pathlib import Path
from typing import Dict, List

import pandas as pd
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle,
)

DATA_DIR = Path("data/synthetic_data")
OUTPUT_DIR = Path("data/synthetic_data")
REFERENCE_DATE = date(2026, 6, 20)

RISK_BAND_COLORS = {
    "Critical": colors.HexColor("#FF4B4B"), "High": colors.HexColor("#FF9F1C"),
    "Medium": colors.HexColor("#FFD60A"), "Low": colors.HexColor("#2ECC71"),
}

LOGGER = logging.getLogger("generate_executive_report")


def configure_logging() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)-8s | %(message)s")


def load_data() -> Dict[str, pd.DataFrame]:
    def _load(name: str) -> pd.DataFrame:
        path = DATA_DIR / name
        return pd.read_csv(path) if path.exists() else pd.DataFrame()

    return {
        "identity_risk_scores": _load("identity_risk_scores.csv"),
        "incidents": _load("incidents.csv"),
        "alerts": _load("alerts.csv"),
        "offboarding_events": _load("offboarding_events.csv"),
        "service_accounts": _load("service_accounts.csv"),
        "api_tokens": _load("api_tokens.csv"),
    }


def build_executive_summary_text(data: Dict[str, pd.DataFrame]) -> str:
    scores = data["identity_risk_scores"]
    incidents = data["incidents"]
    alerts = data["alerts"]

    total_identities = scores["identity_id"].nunique() if not scores.empty else 0
    avg_score = scores["risk_score"].mean() if not scores.empty else 0
    critical_count = (scores["risk_band"] == "Critical").sum() if not scores.empty else 0
    high_count = (scores["risk_band"] == "High").sum() if not scores.empty else 0
    incident_count = len(incidents)
    critical_incidents = (incidents["severity"] == "Critical").sum() if not incidents.empty else 0
    alert_count = len(alerts)

    return (
        f"As of {REFERENCE_DATE.strftime('%B %d, %Y')}, the Hybrid Identity Governance platform evaluated "
        f"{total_identities:,} identities across five integrated platforms (Active Directory, Azure AD, AWS IAM, "
        f"Okta, and Salesforce). The detection engine generated {alert_count:,} individual alerts, correlated "
        f"into {incident_count:,} investigation-ready incidents, of which {critical_incidents:,} were classified "
        f"Critical severity. The organization's average identity risk score is {avg_score:.1f} out of 100, with "
        f"{critical_count:,} identities in the Critical risk band and {high_count:,} in the High risk band. "
        f"This report summarizes the highest-priority findings and recommended remediation actions."
    )


def build_compliance_summary_text(data: Dict[str, pd.DataFrame]) -> str:
    ob = data["offboarding_events"]
    if ob.empty:
        return "No offboarding event data available for this reporting period."
    total = len(ob)
    breached = ob["sla_breached"].sum() if "sla_breached" in ob.columns else 0
    compliance_pct = 100 * (1 - breached / total) if total else 0
    pending = ob["actual_revocation_at"].isna().sum() if "actual_revocation_at" in ob.columns else 0
    return (
        f"Offboarding access revocation SLA compliance stands at {compliance_pct:.1f}% across {total:,} "
        f"tracked revocation events. {pending:,} revocations remain pending as of this report's generation date, "
        f"representing the organization's current exposure window from incomplete employee/contractor offboarding."
    )


def get_top_risks_table_data(data: Dict[str, pd.DataFrame], n: int = 10) -> List[List[str]]:
    scores = data["identity_risk_scores"]
    header = ["Identity", "Entity Type", "Risk Score", "Risk Band", "Top Risk Reason"]
    if scores.empty:
        return [header]
    top = scores.sort_values("risk_score", ascending=False).head(n)
    rows = [header]
    for _, row in top.iterrows():
        reason = str(row.get("top_risk_reason", ""))
        reason = reason if len(reason) <= 60 else reason[:57] + "..."
        rows.append([
            str(row.get("full_name") or row.get("identity_id")),
            str(row.get("entity_type", "")),
            f"{row.get('risk_score', 0):.1f}",
            str(row.get("risk_band", "")),
            reason,
        ])
    return rows


def get_recommendations(data: Dict[str, pd.DataFrame], n: int = 10) -> List[str]:
    alerts = data["alerts"]
    if alerts.empty or "recommendation" not in alerts.columns:
        return ["No alert-derived recommendations available — run the rule engine to populate alerts.csv."]
    top_rules = alerts.groupby("rule_name").size().sort_values(ascending=False).head(n)
    recs = []
    for rule_name, count in top_rules.items():
        sample_rec = alerts[alerts["rule_name"] == rule_name]["recommendation"].iloc[0]
        recs.append(f"[{rule_name}, {count} occurrence(s)] {sample_rec}")
    return recs


def build_pdf(data: Dict[str, pd.DataFrame], output_path: Path) -> None:
    doc = SimpleDocTemplate(
        str(output_path), pagesize=letter,
        topMargin=0.75 * inch, bottomMargin=0.75 * inch,
        leftMargin=0.75 * inch, rightMargin=0.75 * inch,
    )
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("ReportTitle", parent=styles["Title"], fontSize=20, spaceAfter=6)
    subtitle_style = ParagraphStyle("ReportSubtitle", parent=styles["Normal"], fontSize=11, textColor=colors.grey)
    heading_style = ParagraphStyle("SectionHeading", parent=styles["Heading1"], fontSize=14, spaceBefore=18, spaceAfter=8)
    body_style = ParagraphStyle("Body", parent=styles["Normal"], fontSize=10.5, leading=15)

    story = []

    story.append(Paragraph("Identity Governance Executive Report", title_style))
    story.append(Paragraph(f"Reporting period ending {REFERENCE_DATE.strftime('%B %d, %Y')}", subtitle_style))
    story.append(Spacer(1, 18))

    story.append(Paragraph("Executive Summary", heading_style))
    story.append(Paragraph(build_executive_summary_text(data), body_style))

    story.append(Paragraph("Organization Risk Score", heading_style))
    scores = data["identity_risk_scores"]
    if not scores.empty:
        band_counts = scores["risk_band"].value_counts()
        band_table_data = [["Risk Band", "Identity Count"]] + [
            [band, str(int(band_counts.get(band, 0)))] for band in ["Critical", "High", "Medium", "Low"]
        ]
        band_table = Table(band_table_data, colWidths=[2.5 * inch, 2.5 * inch])
        band_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1A1D29")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.lightgrey),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.whitesmoke, colors.white]),
            ("FONTSIZE", (0, 0), (-1, -1), 10),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ]))
        story.append(band_table)
    story.append(Spacer(1, 12))

    story.append(Paragraph("Top 10 Risks", heading_style))
    top_risks_data = get_top_risks_table_data(data, 10)
    top_risks_table = Table(top_risks_data, colWidths=[1.3 * inch, 1.0 * inch, 0.8 * inch, 0.8 * inch, 2.2 * inch])
    top_risks_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1A1D29")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.lightgrey),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.whitesmoke, colors.white]),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    story.append(top_risks_table)

    story.append(PageBreak())
    story.append(Paragraph("Recommendations", heading_style))
    for rec in get_recommendations(data, 10):
        story.append(Paragraph(f"&bull; {rec}", body_style))
        story.append(Spacer(1, 4))

    story.append(Paragraph("Compliance Status", heading_style))
    story.append(Paragraph(build_compliance_summary_text(data), body_style))

    story.append(Spacer(1, 24))
    story.append(Paragraph(
        "This report was generated automatically from the Hybrid Identity Governance platform's "
        "detection and risk scoring pipeline. All figures trace directly to underlying evidence "
        "available in the platform's Identity Risk Registry and Incident Investigation pages.",
        ParagraphStyle("Footer", parent=styles["Normal"], fontSize=8, textColor=colors.grey),
    ))

    doc.build(story)


def main() -> None:
    configure_logging()
    LOGGER.info("Generating executive report")
    data = load_data()
    output_path = OUTPUT_DIR / "executive_report.pdf"
    build_pdf(data, output_path)
    LOGGER.info("Saved %s (%.1f KB)", output_path, output_path.stat().st_size / 1024)


if __name__ == "__main__":
    main()
