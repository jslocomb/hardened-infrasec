#!/usr/bin/env python3
"""
cmmc_gap_report.py — CMMC Level 2 / NIST 800-171 Gap Report Generator
Ingests control mappings from YAML and outputs a formatted HTML + PDF report.

Usage:
    python3 cmmc_gap_report.py --input controls.yaml --output-dir ./reports
    python3 cmmc_gap_report.py --input controls.yaml --html-only
    python3 cmmc_gap_report.py --input controls.yaml --pdf-only
"""

import argparse
import json
import os
import sys
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional

import yaml

# ── Data Models ────────────────────────────────────────────────────────────────

STATUS_ORDER = {"Not Implemented": 0, "Partial": 1, "Implemented": 2}
RISK_ORDER    = {"High": 0, "Medium": 1, "Low": 2}
RISK_COLOR    = {"High": "#d32f2f", "Medium": "#f57c00", "Low": "#388e3c"}
STATUS_COLOR  = {
    "Not Implemented": "#b71c1c",
    "Partial":         "#e65100",
    "Implemented":     "#1b5e20",
}
STATUS_BG = {
    "Not Implemented": "#ffebee",
    "Partial":         "#fff3e0",
    "Implemented":     "#e8f5e9",
}


@dataclass
class Control:
    id: str
    family: str
    family_name: str
    title: str
    requirement: str
    status: str
    implementation: str
    evidence: list
    gaps: list
    risk: str
    cmmc_practice: str
    remediation: str = ""

    @property
    def has_gaps(self):
        return len(self.gaps) > 0

    @property
    def status_score(self):
        return STATUS_ORDER.get(self.status, 0)

    @property
    def risk_score(self):
        return RISK_ORDER.get(self.risk, 2)


@dataclass
class AssessmentSummary:
    total: int = 0
    implemented: int = 0
    partial: int = 0
    not_implemented: int = 0
    high_risk: int = 0
    medium_risk: int = 0
    low_risk: int = 0
    total_gaps: int = 0
    families: dict = field(default_factory=dict)

    @property
    def compliance_score(self):
        if self.total == 0:
            return 0
        score = (self.implemented * 1.0 + self.partial * 0.5) / self.total * 100
        return round(score, 1)

    @property
    def score_color(self):
        s = self.compliance_score
        if s >= 80:
            return "#388e3c"
        elif s >= 50:
            return "#f57c00"
        else:
            return "#d32f2f"


# ── Loader ─────────────────────────────────────────────────────────────────────

def load_controls(yaml_path: str) -> tuple[dict, list[Control]]:
    with open(yaml_path) as f:
        data = yaml.safe_load(f)

    metadata = data.get("metadata", {})
    controls = []
    for c in data.get("controls", []):
        ctrl = Control(
            id=c["id"],
            family=c["family"],
            family_name=c["family_name"],
            title=c["title"],
            requirement=c["requirement"],
            status=c["status"],
            implementation=c.get("implementation", ""),
            evidence=c.get("evidence", []),
            gaps=c.get("gaps", []),
            risk=c.get("risk", "Medium"),
            cmmc_practice=c.get("cmmc_practice", ""),
            remediation=c.get("remediation", ""),
        )
        controls.append(ctrl)

    return metadata, controls


# ── Analysis ──────────────────────────────────────────────────────────────────

def analyze(controls: list[Control]) -> AssessmentSummary:
    s = AssessmentSummary(total=len(controls))
    families = {}

    for c in controls:
        # Status counts
        if c.status == "Implemented":
            s.implemented += 1
        elif c.status == "Partial":
            s.partial += 1
        else:
            s.not_implemented += 1

        # Risk counts
        if c.risk == "High":
            s.high_risk += 1
        elif c.risk == "Medium":
            s.medium_risk += 1
        else:
            s.low_risk += 1

        s.total_gaps += len(c.gaps)

        # Per-family
        fam = c.family_name
        if fam not in families:
            families[fam] = {"total": 0, "implemented": 0, "partial": 0, "not_implemented": 0}
        families[fam]["total"] += 1
        if c.status == "Implemented":
            families[fam]["implemented"] += 1
        elif c.status == "Partial":
            families[fam]["partial"] += 1
        else:
            families[fam]["not_implemented"] += 1

    s.families = families
    return s


# ── HTML Report ───────────────────────────────────────────────────────────────

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>CMMC Level 2 Gap Report — {system_name}</title>
<style>
  :root {{
    --brand:    #1a237e;
    --brand2:   #283593;
    --accent:   #0d47a1;
    --surface:  #f8f9fc;
    --border:   #dde1eb;
    --text:     #1a1f36;
    --muted:    #6b7280;
    --red-bg:   #ffebee;
    --red-fg:   #b71c1c;
    --amber-bg: #fff3e0;
    --amber-fg: #e65100;
    --green-bg: #e8f5e9;
    --green-fg: #1b5e20;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    color: var(--text);
    background: #fff;
    font-size: 13px;
    line-height: 1.6;
  }}

  /* ── Cover ── */
  .cover {{
    background: linear-gradient(135deg, var(--brand) 0%, #0d47a1 60%, #1565c0 100%);
    color: #fff;
    padding: 56px 64px 48px;
    position: relative;
    page-break-after: always;
  }}
  .cover-badge {{
    display: inline-block;
    background: rgba(255,255,255,0.15);
    border: 1px solid rgba(255,255,255,0.3);
    color: #fff;
    font-size: 11px;
    font-weight: 700;
    letter-spacing: 0.12em;
    text-transform: uppercase;
    padding: 4px 12px;
    border-radius: 4px;
    margin-bottom: 20px;
  }}
  .cover h1 {{
    font-size: 32px;
    font-weight: 800;
    letter-spacing: -0.5px;
    margin-bottom: 8px;
    line-height: 1.2;
  }}
  .cover-sub {{
    font-size: 16px;
    opacity: 0.85;
    margin-bottom: 40px;
  }}
  .cover-meta {{
    display: grid;
    grid-template-columns: repeat(2, 1fr);
    gap: 16px;
    max-width: 600px;
  }}
  .cover-meta-item label {{
    font-size: 10px;
    text-transform: uppercase;
    letter-spacing: 0.1em;
    opacity: 0.65;
    display: block;
  }}
  .cover-meta-item span {{
    font-size: 13px;
    font-weight: 600;
  }}
  .cover-score-box {{
    position: absolute;
    top: 56px;
    right: 64px;
    background: rgba(255,255,255,0.12);
    border: 2px solid rgba(255,255,255,0.25);
    border-radius: 12px;
    padding: 20px 28px;
    text-align: center;
  }}
  .cover-score-box .score-num {{
    font-size: 48px;
    font-weight: 900;
    line-height: 1;
    color: #fff;
  }}
  .cover-score-box .score-label {{
    font-size: 11px;
    opacity: 0.75;
    letter-spacing: 0.08em;
    text-transform: uppercase;
    margin-top: 4px;
  }}

  /* ── Layout ── */
  .page {{ padding: 40px 64px; max-width: 1100px; margin: 0 auto; }}
  .section {{ margin-bottom: 48px; }}
  h2 {{
    font-size: 18px;
    font-weight: 700;
    color: var(--brand);
    border-bottom: 2px solid var(--brand);
    padding-bottom: 8px;
    margin-bottom: 20px;
  }}
  h3 {{
    font-size: 14px;
    font-weight: 700;
    color: var(--brand2);
    margin-bottom: 10px;
  }}

  /* ── Stat Cards ── */
  .stat-grid {{
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 16px;
    margin-bottom: 24px;
  }}
  .stat-card {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 16px 20px;
  }}
  .stat-card .stat-val {{
    font-size: 28px;
    font-weight: 800;
    line-height: 1;
    margin-bottom: 4px;
  }}
  .stat-card .stat-lbl {{
    font-size: 11px;
    color: var(--muted);
    text-transform: uppercase;
    letter-spacing: 0.08em;
  }}
  .stat-card.red   {{ border-left: 4px solid #d32f2f; }}
  .stat-card.amber {{ border-left: 4px solid #f57c00; }}
  .stat-card.green {{ border-left: 4px solid #388e3c; }}
  .stat-card.blue  {{ border-left: 4px solid #1565c0; }}

  /* ── Family Table ── */
  table {{
    width: 100%;
    border-collapse: collapse;
    font-size: 12px;
  }}
  th {{
    background: var(--brand);
    color: #fff;
    text-align: left;
    padding: 8px 12px;
    font-weight: 600;
    letter-spacing: 0.04em;
    font-size: 11px;
    text-transform: uppercase;
  }}
  td {{
    padding: 8px 12px;
    border-bottom: 1px solid var(--border);
    vertical-align: middle;
  }}
  tr:nth-child(even) td {{ background: var(--surface); }}
  tr:hover td {{ background: #eef2ff; }}

  /* ── Progress Bar ── */
  .prog-wrap {{
    display: flex;
    align-items: center;
    gap: 8px;
  }}
  .prog {{
    flex: 1;
    height: 8px;
    background: var(--border);
    border-radius: 4px;
    overflow: hidden;
  }}
  .prog-fill {{
    height: 100%;
    border-radius: 4px;
    background: linear-gradient(90deg, #388e3c, #66bb6a);
  }}
  .prog-pct {{ font-size: 11px; font-weight: 700; color: var(--muted); width: 35px; text-align: right; }}

  /* ── Badges ── */
  .badge {{
    display: inline-block;
    padding: 2px 8px;
    border-radius: 4px;
    font-size: 11px;
    font-weight: 700;
    letter-spacing: 0.03em;
  }}
  .badge-implemented {{ background: var(--green-bg); color: var(--green-fg); }}
  .badge-partial      {{ background: var(--amber-bg); color: var(--amber-fg); }}
  .badge-not          {{ background: var(--red-bg);   color: var(--red-fg);   }}
  .badge-risk-high    {{ background: #ffcdd2; color: #b71c1c; }}
  .badge-risk-medium  {{ background: #ffe0b2; color: #e65100; }}
  .badge-risk-low     {{ background: var(--green-bg); color: var(--green-fg); }}

  /* ── Control Cards ── */
  .control-card {{
    border: 1px solid var(--border);
    border-radius: 8px;
    margin-bottom: 16px;
    overflow: hidden;
    page-break-inside: avoid;
  }}
  .control-header {{
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 12px 16px;
    background: var(--surface);
    border-bottom: 1px solid var(--border);
  }}
  .ctrl-id {{
    font-family: 'Courier New', monospace;
    font-weight: 700;
    font-size: 13px;
    color: var(--accent);
    white-space: nowrap;
  }}
  .ctrl-title {{ flex: 1; font-weight: 600; font-size: 13px; }}
  .ctrl-practice {{ font-size: 10px; color: var(--muted); font-family: monospace; }}
  .control-body {{ padding: 16px; }}
  .control-body p {{ margin-bottom: 8px; color: #374151; }}
  .control-body .label {{
    font-size: 10px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.1em;
    color: var(--muted);
    margin-bottom: 4px;
    margin-top: 12px;
  }}
  .control-body .label:first-child {{ margin-top: 0; }}

  .evidence-list, .gap-list, .remediation-list {{
    list-style: none;
    padding: 0;
  }}
  .evidence-list li {{
    padding: 3px 0 3px 18px;
    position: relative;
    font-family: monospace;
    font-size: 11.5px;
    color: #374151;
  }}
  .evidence-list li::before {{ content: "✓"; position: absolute; left: 0; color: #388e3c; font-size: 11px; }}

  .gap-list li {{
    padding: 4px 0 4px 20px;
    position: relative;
    color: #7f1d1d;
    background: #fff5f5;
    border-left: 3px solid #ef4444;
    padding-left: 10px;
    margin-bottom: 4px;
    border-radius: 0 4px 4px 0;
    font-size: 12px;
  }}

  .remediation-box {{
    background: #eff6ff;
    border-left: 3px solid #3b82f6;
    padding: 10px 14px;
    border-radius: 0 6px 6px 0;
    font-size: 12px;
    color: #1e3a5f;
    margin-top: 8px;
  }}

  /* ── Family Section Header ── */
  .family-header {{
    background: linear-gradient(90deg, var(--brand) 0%, var(--brand2) 100%);
    color: #fff;
    padding: 10px 20px;
    border-radius: 6px 6px 0 0;
    margin-bottom: 0;
    display: flex;
    align-items: center;
    gap: 12px;
    margin-top: 32px;
  }}
  .family-header h3 {{ color: #fff; margin: 0; font-size: 13px; }}
  .family-code {{
    font-family: monospace;
    font-size: 12px;
    background: rgba(255,255,255,0.2);
    padding: 2px 8px;
    border-radius: 4px;
  }}

  /* ── Footer ── */
  .report-footer {{
    text-align: center;
    color: var(--muted);
    font-size: 11px;
    border-top: 1px solid var(--border);
    padding: 20px;
    margin-top: 40px;
  }}

  /* ── Print ── */
  @media print {{
    body {{ font-size: 11px; }}
    .cover {{ padding: 40px 48px 32px; }}
    .page {{ padding: 28px 48px; }}
    .control-card {{ page-break-inside: avoid; }}
    .family-header {{ page-break-before: auto; }}
  }}
</style>
</head>
<body>

<!-- ══ COVER PAGE ══════════════════════════════════════════════════════════ -->
<div class="cover">
  <div class="cover-badge">CMMC Level 2 · NIST SP 800-171</div>
  <h1>Gap Assessment Report</h1>
  <div class="cover-sub">{system_name}</div>

  <div class="cover-score-box">
    <div class="score-num">{compliance_score}%</div>
    <div class="score-label">Compliance Score</div>
  </div>

  <div class="cover-meta">
    <div class="cover-meta-item">
      <label>Organization</label>
      <span>{organization}</span>
    </div>
    <div class="cover-meta-item">
      <label>Assessor</label>
      <span>{assessor}</span>
    </div>
    <div class="cover-meta-item">
      <label>Assessment Date</label>
      <span>{assessment_date}</span>
    </div>
    <div class="cover-meta-item">
      <label>Classification</label>
      <span>{classification}</span>
    </div>
    <div class="cover-meta-item">
      <label>Report Version</label>
      <span>{version}</span>
    </div>
    <div class="cover-meta-item">
      <label>Controls Assessed</label>
      <span>{total} of 110 (sample set)</span>
    </div>
  </div>
</div>

<!-- ══ EXECUTIVE SUMMARY ═══════════════════════════════════════════════════ -->
<div class="page">
<div class="section">
  <h2>Executive Summary</h2>

  <div class="stat-grid">
    <div class="stat-card green">
      <div class="stat-val" style="color:#388e3c">{implemented}</div>
      <div class="stat-lbl">Implemented</div>
    </div>
    <div class="stat-card amber">
      <div class="stat-val" style="color:#f57c00">{partial}</div>
      <div class="stat-lbl">Partially Implemented</div>
    </div>
    <div class="stat-card red">
      <div class="stat-val" style="color:#d32f2f">{not_implemented}</div>
      <div class="stat-lbl">Not Implemented</div>
    </div>
    <div class="stat-card blue">
      <div class="stat-val" style="color:#1565c0">{total_gaps}</div>
      <div class="stat-lbl">Total Gap Items</div>
    </div>
  </div>

  <div class="stat-grid">
    <div class="stat-card red">
      <div class="stat-val" style="color:#d32f2f">{high_risk}</div>
      <div class="stat-lbl">High Risk Controls</div>
    </div>
    <div class="stat-card amber">
      <div class="stat-val" style="color:#f57c00">{medium_risk}</div>
      <div class="stat-lbl">Medium Risk Controls</div>
    </div>
    <div class="stat-card green">
      <div class="stat-val" style="color:#388e3c">{low_risk}</div>
      <div class="stat-lbl">Low Risk Controls</div>
    </div>
    <div class="stat-card blue">
      <div class="stat-val" style="color:#1565c0">{compliance_score}%</div>
      <div class="stat-lbl">Overall Compliance Score</div>
    </div>
  </div>

  <p style="color:#374151; margin-top:8px; font-size:12.5px;">
    This assessment covers <strong>{total}</strong> NIST SP 800-171 Rev 2 controls mapped against the
    {system_name}. The overall compliance score of <strong>{compliance_score}%</strong> 
    reflects full implementation credit (1.0×) and partial implementation credit (0.5×).
    Priority remediation focus should target <strong>{high_risk} high-risk gaps</strong> before 
    any CMMC Level 2 Third-Party Assessment Organization (C3PAO) engagement.
  </p>
</div>

<!-- ══ CONTROL FAMILY SUMMARY ═════════════════════════════════════════════ -->
<div class="section">
  <h2>Control Family Coverage</h2>
  <table>
    <thead>
      <tr>
        <th>Control Family</th>
        <th style="width:80px">Total</th>
        <th style="width:100px">Implemented</th>
        <th style="width:100px">Partial</th>
        <th style="width:110px">Not Implemented</th>
        <th style="width:200px">Coverage</th>
      </tr>
    </thead>
    <tbody>
{family_rows}
    </tbody>
  </table>
</div>

<!-- ══ HIGH-RISK FINDINGS ═════════════════════════════════════════════════ -->
<div class="section">
  <h2>High-Risk Findings</h2>
{high_risk_cards}
</div>

<!-- ══ ALL CONTROLS BY FAMILY ═════════════════════════════════════════════ -->
<div class="section">
  <h2>Detailed Control Assessment</h2>
{all_control_cards}
</div>

</div><!-- .page -->

<div class="report-footer">
  CMMC Level 2 Gap Report · {system_name} · Generated {generated_at} · 
  NIST SP 800-171 Rev 2 / CMMC 2.0 Level 2 · DISTRIBUTION RESTRICTED
</div>

</body>
</html>"""


def _badge_status(status: str) -> str:
    cls = {
        "Implemented": "badge-implemented",
        "Partial": "badge-partial",
        "Not Implemented": "badge-not",
    }.get(status, "badge-partial")
    return f'<span class="badge {cls}">{status}</span>'


def _badge_risk(risk: str) -> str:
    cls = {
        "High": "badge-risk-high",
        "Medium": "badge-risk-medium",
        "Low": "badge-risk-low",
    }.get(risk, "badge-risk-medium")
    return f'<span class="badge {cls}">⚑ {risk} Risk</span>'


def _control_card(c: Control, show_family_tag: bool = False) -> str:
    evidence_html = ""
    if c.evidence:
        items = "".join(f"<li>{e}</li>" for e in c.evidence)
        evidence_html = f'<div class="label">Evidence Artifacts</div><ul class="evidence-list">{items}</ul>'

    gaps_html = ""
    if c.gaps:
        items = "".join(f"<li>{g}</li>" for g in c.gaps)
        gaps_html = f'<div class="label">⚠ Identified Gaps</div><ul class="gap-list">{items}</ul>'

    remediation_html = ""
    if c.remediation:
        remediation_html = f'<div class="label">Recommended Remediation</div><div class="remediation-box">{c.remediation}</div>'

    impl_html = ""
    if c.implementation:
        impl_html = f'<div class="label">Implementation Notes</div><p>{c.implementation}</p>'

    return f"""<div class="control-card">
  <div class="control-header">
    <span class="ctrl-id">{c.id}</span>
    <span class="ctrl-title">{c.title}</span>
    {_badge_status(c.status)}
    {_badge_risk(c.risk)}
    <span class="ctrl-practice">{c.cmmc_practice}</span>
  </div>
  <div class="control-body">
    <div class="label">Requirement</div>
    <p style="font-style:italic;color:#4b5563;">{c.requirement}</p>
    {impl_html}
    {evidence_html}
    {gaps_html}
    {remediation_html}
  </div>
</div>"""


def _family_row(name: str, data: dict) -> str:
    total = data["total"]
    impl  = data["implemented"]
    part  = data["partial"]
    notim = data["not_implemented"]
    pct   = round((impl + part * 0.5) / total * 100, 0) if total > 0 else 0
    color = "#388e3c" if pct >= 80 else ("#f57c00" if pct >= 50 else "#d32f2f")
    return f"""<tr>
  <td><strong>{name}</strong></td>
  <td style="text-align:center">{total}</td>
  <td style="text-align:center;color:#388e3c;font-weight:700">{impl}</td>
  <td style="text-align:center;color:#f57c00;font-weight:700">{part}</td>
  <td style="text-align:center;color:#d32f2f;font-weight:700">{notim}</td>
  <td>
    <div class="prog-wrap">
      <div class="prog"><div class="prog-fill" style="width:{pct}%;background:linear-gradient(90deg,{color},{color}cc)"></div></div>
      <span class="prog-pct">{int(pct)}%</span>
    </div>
  </td>
</tr>"""


def generate_html(metadata: dict, controls: list[Control], summary: AssessmentSummary) -> str:
    # Family rows
    family_rows = "\n".join(_family_row(k, v) for k, v in summary.families.items())

    # High-risk cards
    high_risk = [c for c in controls if c.risk == "High"]
    high_risk_cards = "\n".join(_control_card(c) for c in high_risk)
    if not high_risk_cards:
        high_risk_cards = '<p style="color:#388e3c;font-weight:600">✓ No high-risk gaps identified.</p>'

    # All controls grouped by family
    from collections import defaultdict
    by_family = defaultdict(list)
    for c in controls:
        by_family[c.family_name].append(c)

    all_cards = []
    for fam_name, fam_controls in by_family.items():
        family_code = fam_controls[0].family
        all_cards.append(f'<div class="family-header"><span class="family-code">{family_code}</span><h3>{fam_name}</h3></div>')
        for c in fam_controls:
            all_cards.append(_control_card(c))

    all_control_cards = "\n".join(all_cards)

    return HTML_TEMPLATE.format(
        system_name=metadata.get("system_name", "System"),
        organization=metadata.get("organization", ""),
        assessor=metadata.get("assessor", ""),
        assessment_date=metadata.get("assessment_date", ""),
        classification=metadata.get("classification", ""),
        version=metadata.get("version", "1.0"),
        total=summary.total,
        implemented=summary.implemented,
        partial=summary.partial,
        not_implemented=summary.not_implemented,
        high_risk=summary.high_risk,
        medium_risk=summary.medium_risk,
        low_risk=summary.low_risk,
        total_gaps=summary.total_gaps,
        compliance_score=summary.compliance_score,
        family_rows=family_rows,
        high_risk_cards=high_risk_cards,
        all_control_cards=all_control_cards,
        generated_at=datetime.now().strftime("%Y-%m-%d %H:%M UTC"),
    )


# ── PDF Report ────────────────────────────────────────────────────────────────

def generate_pdf(metadata: dict, controls: list[Control], summary: AssessmentSummary, output_path: str):
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import inch
    from reportlab.platypus import (
        HRFlowable,
        PageBreak,
        Paragraph,
        SimpleDocTemplate,
        Spacer,
        Table,
        TableStyle,
    )
    from reportlab.platypus.flowables import KeepTogether

    BRAND   = colors.HexColor("#1a237e")
    BRAND2  = colors.HexColor("#283593")
    RED     = colors.HexColor("#d32f2f")
    AMBER   = colors.HexColor("#f57c00")
    GREEN   = colors.HexColor("#388e3c")
    BLUE    = colors.HexColor("#1565c0")
    SURFACE = colors.HexColor("#f8f9fc")
    BORDER  = colors.HexColor("#dde1eb")
    MUTED   = colors.HexColor("#6b7280")
    RED_BG  = colors.HexColor("#ffebee")
    AMBER_BG= colors.HexColor("#fff3e0")
    GREEN_BG= colors.HexColor("#e8f5e9")

    styles = getSampleStyleSheet()

    def S(name, **kw):
        base = styles.get(name, styles["Normal"])
        return ParagraphStyle(name + "_custom_" + str(id(kw)), parent=base, **kw)

    title_style   = S("Title",   fontSize=22, textColor=colors.white, spaceAfter=4, leading=26)
    sub_style     = S("Normal",  fontSize=12, textColor=colors.white, spaceAfter=12, leading=16)
    h2_style      = S("Heading2",fontSize=14, textColor=BRAND, spaceBefore=16, spaceAfter=8, fontName="Helvetica-Bold")
    h3_style      = S("Heading3",fontSize=11, textColor=BRAND2, spaceBefore=8, spaceAfter=6, fontName="Helvetica-Bold")
    body_style    = S("Normal",  fontSize=9,  leading=13, spaceAfter=4)
    small_style   = S("Normal",  fontSize=8,  leading=12, textColor=MUTED)
    code_style    = S("Code",    fontSize=8,  leading=12, fontName="Courier", textColor=colors.HexColor("#374151"))
    req_style     = S("Normal",  fontSize=8.5,leading=13, textColor=colors.HexColor("#4b5563"), spaceAfter=6)
    label_style   = S("Normal",  fontSize=7.5,fontName="Helvetica-Bold", textColor=MUTED,
                       spaceBefore=8, spaceAfter=3, leading=10)
    gap_style     = S("Normal",  fontSize=8.5,leading=12, textColor=colors.HexColor("#7f1d1d"),
                       leftIndent=8, spaceAfter=2)
    remed_style   = S("Normal",  fontSize=8.5,leading=12.5, textColor=colors.HexColor("#1e3a5f"),
                       leftIndent=8)

    doc = SimpleDocTemplate(
        output_path,
        pagesize=letter,
        leftMargin=0.75*inch,
        rightMargin=0.75*inch,
        topMargin=0.75*inch,
        bottomMargin=0.75*inch,
        title=f"CMMC L2 Gap Report — {metadata.get('system_name','')}",
        author=metadata.get("assessor", ""),
    )

    story = []

    # ── Cover ──
    cover_data = [
        [Paragraph("CMMC Level 2 · NIST SP 800-171", S("Normal", fontSize=9, textColor=colors.white))],
        [Paragraph("Gap Assessment Report", title_style)],
        [Paragraph(metadata.get("system_name",""), sub_style)],
        [Spacer(1, 0.1*inch)],
        [Paragraph(f"<b>Organization:</b> {metadata.get('organization','')}", S("Normal", fontSize=9, textColor=colors.white))],
        [Paragraph(f"<b>Assessor:</b> {metadata.get('assessor','')}", S("Normal", fontSize=9, textColor=colors.white))],
        [Paragraph(f"<b>Assessment Date:</b> {metadata.get('assessment_date','')}", S("Normal", fontSize=9, textColor=colors.white))],
        [Paragraph(f"<b>Classification:</b> {metadata.get('classification','')}", S("Normal", fontSize=9, textColor=colors.white))],
        [Spacer(1, 0.15*inch)],
        [Paragraph(f"Overall Compliance Score: <b>{summary.compliance_score}%</b>  |  Controls Assessed: <b>{summary.total}</b>", S("Normal", fontSize=10, textColor=colors.white))],
    ]
    cover_table = Table(cover_data, colWidths=[7*inch])
    cover_table.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,-1), BRAND),
        ("TOPPADDING",    (0,0), (-1,-1), 6),
        ("BOTTOMPADDING", (0,0), (-1,-1), 6),
        ("LEFTPADDING",   (0,0), (-1,-1), 24),
        ("RIGHTPADDING",  (0,0), (-1,-1), 24),
        ("ROWBACKGROUNDS",(0,0), (-1,-1), [BRAND]),
    ]))
    story.append(cover_table)
    story.append(PageBreak())

    # ── Executive Summary header ──
    story.append(Paragraph("Executive Summary", h2_style))
    story.append(HRFlowable(width="100%", thickness=1.5, color=BRAND, spaceAfter=12))

    # Stat table
    stat_data = [
        ["STATUS", "", "", ""],
        [
            Paragraph(f"<b>{summary.implemented}</b><br/>Implemented", S("Normal", fontSize=9, alignment=1)),
            Paragraph(f"<b>{summary.partial}</b><br/>Partial", S("Normal", fontSize=9, alignment=1)),
            Paragraph(f"<b>{summary.not_implemented}</b><br/>Not Implemented", S("Normal", fontSize=9, alignment=1)),
            Paragraph(f"<b>{summary.total_gaps}</b><br/>Total Gap Items", S("Normal", fontSize=9, alignment=1)),
        ],
        ["RISK", "", "", ""],
        [
            Paragraph(f"<b>{summary.high_risk}</b><br/>High Risk", S("Normal", fontSize=9, alignment=1)),
            Paragraph(f"<b>{summary.medium_risk}</b><br/>Medium Risk", S("Normal", fontSize=9, alignment=1)),
            Paragraph(f"<b>{summary.low_risk}</b><br/>Low Risk", S("Normal", fontSize=9, alignment=1)),
            Paragraph(f"<b>{summary.compliance_score}%</b><br/>Compliance Score", S("Normal", fontSize=9, alignment=1)),
        ],
    ]
    cw = [1.75*inch] * 4
    stat_tbl = Table(stat_data, colWidths=cw, rowHeights=[18, 42, 18, 42])
    stat_tbl.setStyle(TableStyle([
        # Section headers
        ("SPAN",        (0,0), (3,0)),
        ("SPAN",        (0,2), (3,2)),
        ("BACKGROUND",  (0,0), (3,0), BRAND2),
        ("BACKGROUND",  (0,2), (3,2), BRAND2),
        ("TEXTCOLOR",   (0,0), (3,0), colors.white),
        ("TEXTCOLOR",   (0,2), (3,2), colors.white),
        ("FONTNAME",    (0,0), (-1,-1), "Helvetica-Bold"),
        ("FONTSIZE",    (0,0), (3,0), 8),
        ("FONTSIZE",    (0,2), (3,2), 8),
        ("ALIGN",       (0,0), (-1,-1), "CENTER"),
        ("VALIGN",      (0,0), (-1,-1), "MIDDLE"),
        # Data rows colors
        ("BACKGROUND",  (0,1), (0,1), GREEN_BG),
        ("BACKGROUND",  (1,1), (1,1), AMBER_BG),
        ("BACKGROUND",  (2,1), (2,1), RED_BG),
        ("BACKGROUND",  (3,1), (3,1), colors.HexColor("#e3f2fd")),
        ("BACKGROUND",  (0,3), (0,3), RED_BG),
        ("BACKGROUND",  (1,3), (1,3), AMBER_BG),
        ("BACKGROUND",  (2,3), (2,3), GREEN_BG),
        ("BACKGROUND",  (3,3), (3,3), colors.HexColor("#e3f2fd")),
        ("BOX",         (0,0), (-1,-1), 0.5, BORDER),
        ("INNERGRID",   (0,0), (-1,-1), 0.5, BORDER),
    ]))
    story.append(stat_tbl)
    story.append(Spacer(1, 0.15*inch))

    narrative = (
        f"This assessment covers {summary.total} NIST SP 800-171 Rev 2 controls mapped against "
        f"the {metadata.get('system_name','')}. The overall compliance score of "
        f"{summary.compliance_score}% reflects full (1.0×) and partial (0.5×) implementation credit. "
        f"Priority remediation should target {summary.high_risk} high-risk gap(s) before any "
        f"CMMC Level 2 C3PAO engagement."
    )
    story.append(Paragraph(narrative, body_style))
    story.append(Spacer(1, 0.2*inch))

    # ── Family Coverage ──
    story.append(Paragraph("Control Family Coverage", h2_style))
    story.append(HRFlowable(width="100%", thickness=1.5, color=BRAND, spaceAfter=8))

    fam_header = ["Control Family", "Total", "Impl.", "Partial", "Not Impl.", "Coverage %"]
    fam_rows   = [fam_header]
    fam_styles = [
        ("BACKGROUND", (0,0), (-1,0), BRAND),
        ("TEXTCOLOR",  (0,0), (-1,0), colors.white),
        ("FONTNAME",   (0,0), (-1,0), "Helvetica-Bold"),
        ("FONTSIZE",   (0,0), (-1,-1), 8.5),
        ("ALIGN",      (1,0), (-1,-1), "CENTER"),
        ("VALIGN",     (0,0), (-1,-1), "MIDDLE"),
        ("ROWBACKGROUNDS", (0,1), (-1,-1), [colors.white, SURFACE]),
        ("BOX",        (0,0), (-1,-1), 0.5, BORDER),
        ("INNERGRID",  (0,0), (-1,-1), 0.5, BORDER),
        ("TOPPADDING", (0,0), (-1,-1), 5),
        ("BOTTOMPADDING", (0,0), (-1,-1), 5),
    ]

    for row_i, (fam_name, fam_data) in enumerate(summary.families.items(), start=1):
        t  = fam_data["total"]
        im = fam_data["implemented"]
        pa = fam_data["partial"]
        ni = fam_data["not_implemented"]
        pct = round((im + pa * 0.5) / t * 100) if t > 0 else 0
        fam_rows.append([fam_name, str(t), str(im), str(pa), str(ni), f"{pct}%"])
        # Color pct cell
        pct_color = GREEN if pct >= 80 else (AMBER if pct >= 50 else RED)
        fam_styles.append(("TEXTCOLOR", (5, row_i), (5, row_i), pct_color))
        fam_styles.append(("FONTNAME", (5, row_i), (5, row_i), "Helvetica-Bold"))
        if im > 0:
            fam_styles.append(("TEXTCOLOR", (2, row_i), (2, row_i), GREEN))
        if pa > 0:
            fam_styles.append(("TEXTCOLOR", (3, row_i), (3, row_i), AMBER))
        if ni > 0:
            fam_styles.append(("TEXTCOLOR", (4, row_i), (4, row_i), RED))

    fam_tbl = Table(fam_rows, colWidths=[2.5*inch, 0.55*inch, 0.55*inch, 0.6*inch, 0.75*inch, 0.8*inch])
    fam_tbl.setStyle(TableStyle(fam_styles))
    story.append(fam_tbl)
    story.append(PageBreak())

    # ── High-Risk Findings ──
    story.append(Paragraph("High-Risk Findings", h2_style))
    story.append(HRFlowable(width="100%", thickness=1.5, color=RED, spaceAfter=8))

    high_risk = [c for c in controls if c.risk == "High"]
    if not high_risk:
        story.append(Paragraph("✓ No high-risk gaps identified.", S("Normal", textColor=GREEN, fontSize=10)))
    else:
        for c in high_risk:
            story.extend(_pdf_control_block(c, styles, label_style, req_style, code_style, gap_style, remed_style, BRAND, RED, AMBER, GREEN, RED_BG, AMBER_BG, GREEN_BG, SURFACE, BORDER, MUTED))

    story.append(PageBreak())

    # ── All Controls ──
    story.append(Paragraph("Detailed Control Assessment", h2_style))
    story.append(HRFlowable(width="100%", thickness=1.5, color=BRAND, spaceAfter=8))

    from collections import defaultdict
    by_family = defaultdict(list)
    for c in controls:
        by_family[c.family_name].append(c)

    for fam_name, fam_controls in by_family.items():
        family_code = fam_controls[0].family
        fam_hdr = Table([[Paragraph(f"{family_code} — {fam_name}", S("Normal", fontSize=11, textColor=colors.white, fontName="Helvetica-Bold"))]],
                        colWidths=[7*inch])
        fam_hdr.setStyle(TableStyle([
            ("BACKGROUND",    (0,0), (-1,-1), BRAND2),
            ("TOPPADDING",    (0,0), (-1,-1), 6),
            ("BOTTOMPADDING", (0,0), (-1,-1), 6),
            ("LEFTPADDING",   (0,0), (-1,-1), 12),
        ]))
        story.append(Spacer(1, 0.12*inch))
        story.append(fam_hdr)
        story.append(Spacer(1, 0.06*inch))

        for c in fam_controls:
            block = _pdf_control_block(c, styles, label_style, req_style, code_style, gap_style, remed_style,
                                       BRAND, RED, AMBER, GREEN, RED_BG, AMBER_BG, GREEN_BG, SURFACE, BORDER, MUTED)
            story.extend(block)

    # ── Footer via onPage ──
    generated = datetime.now().strftime("%Y-%m-%d %H:%M UTC")

    def footer(canvas, doc):
        canvas.saveState()
        canvas.setFont("Helvetica", 7.5)
        canvas.setFillColor(MUTED)
        w, h = letter
        canvas.drawString(0.75*inch, 0.5*inch,
            f"CMMC L2 Gap Report · {metadata.get('system_name','')} · Generated {generated} · Page {doc.page}")
        canvas.drawRightString(w - 0.75*inch, 0.5*inch, "DISTRIBUTION RESTRICTED")
        canvas.restoreState()

    doc.build(story, onFirstPage=footer, onLaterPages=footer)


def _pdf_control_block(c, styles, label_style, req_style, code_style, gap_style, remed_style,
                        BRAND, RED, AMBER, GREEN, RED_BG, AMBER_BG, GREEN_BG, SURFACE, BORDER, MUTED):
    from reportlab.lib import colors
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.platypus import HRFlowable, Paragraph, Spacer, Table, TableStyle
    from reportlab.platypus.flowables import KeepTogether

    STATUS_COLOR_RL = {
        "Implemented":     GREEN,
        "Partial":         AMBER,
        "Not Implemented": RED,
    }
    RISK_COLOR_RL = {"High": RED, "Medium": AMBER, "Low": GREEN}

    def S(name, **kw):
        base = styles.get(name, styles["Normal"])
        return ParagraphStyle(name + "_b_" + str(id(kw)), parent=base, **kw)

    status_color = STATUS_COLOR_RL.get(c.status, AMBER)
    risk_color   = RISK_COLOR_RL.get(c.risk, AMBER)

    # Header row
    hdr_data = [[
        Paragraph(f"<b>{c.id}</b>", S("Normal", fontName="Courier-Bold", fontSize=9, textColor=BRAND)),
        Paragraph(f"<b>{c.title}</b>", S("Normal", fontSize=9, fontName="Helvetica-Bold")),
        Paragraph(f"<b>{c.status}</b>", S("Normal", fontSize=8, textColor=status_color, alignment=1)),
        Paragraph(f"<b>{c.risk} Risk</b>", S("Normal", fontSize=8, textColor=risk_color, alignment=1)),
        Paragraph(c.cmmc_practice, S("Normal", fontSize=7.5, fontName="Courier", textColor=MUTED, alignment=2)),
    ]]
    hdr_tbl = Table(hdr_data, colWidths=[0.6*inch, 3.2*inch, 1*inch, 0.8*inch, 1.3*inch])
    hdr_tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,-1), SURFACE),
        ("VALIGN",        (0,0), (-1,-1), "MIDDLE"),
        ("TOPPADDING",    (0,0), (-1,-1), 5),
        ("BOTTOMPADDING", (0,0), (-1,-1), 5),
        ("LEFTPADDING",   (0,0), (0,0), 6),
        ("BOX",           (0,0), (-1,-1), 0.5, BORDER),
    ]))

    items = [hdr_tbl]

    body_rows = []
    body_styles = [
        ("FONTSIZE",   (0,0), (-1,-1), 8.5),
        ("VALIGN",     (0,0), (-1,-1), "TOP"),
        ("TOPPADDING", (0,0), (-1,-1), 4),
        ("BOTTOMPADDING", (0,0), (-1,-1), 4),
        ("LEFTPADDING",   (0,0), (-1,-1), 8),
        ("BOX",        (0,0), (-1,-1), 0.5, BORDER),
    ]
    row_i = 0

    body_rows.append([Paragraph("REQUIREMENT", label_style),
                      Paragraph(c.requirement, req_style)])
    row_i += 1

    if c.implementation:
        body_rows.append([Paragraph("IMPLEMENTATION", label_style),
                          Paragraph(c.implementation, S("Normal", fontSize=8.5, leading=13))])
        row_i += 1

    if c.evidence:
        ev_items = "<br/>".join(f"✓  {e}" for e in c.evidence)
        body_rows.append([Paragraph("EVIDENCE", label_style),
                          Paragraph(ev_items, code_style)])
        row_i += 1

    if c.gaps:
        gap_text = "<br/>".join(f"⚠  {g}" for g in c.gaps)
        body_rows.append([Paragraph("GAPS", label_style),
                          Paragraph(gap_text, S("Normal", fontSize=8.5, leading=13, textColor=colors.HexColor("#7f1d1d")))])
        body_styles.append(("BACKGROUND", (0, row_i), (-1, row_i), RED_BG))
        row_i += 1

    if c.remediation:
        body_rows.append([Paragraph("REMEDIATION", label_style),
                          Paragraph(c.remediation, remed_style)])
        body_styles.append(("BACKGROUND", (0, row_i), (-1, row_i), colors.HexColor("#eff6ff")))
        row_i += 1

    if body_rows:
        body_tbl = Table(body_rows, colWidths=[1*inch, 6*inch])
        body_tbl.setStyle(TableStyle(body_styles))
        items.append(body_tbl)

    items.append(Spacer(1, 0.1*inch))
    return [KeepTogether(items)]


# ── CLI ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="CMMC Level 2 Gap Report Generator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--input",      default="controls.yaml", help="Path to control mappings YAML")
    parser.add_argument("--output-dir", default="./reports",     help="Output directory")
    parser.add_argument("--html-only",  action="store_true",      help="Generate HTML only")
    parser.add_argument("--pdf-only",   action="store_true",      help="Generate PDF only")
    parser.add_argument("--sort",       choices=["risk","id","status"], default="id",
                        help="Sort controls by: risk (high first), id, or status")
    args = parser.parse_args()

    # Load
    print(f"[+] Loading controls from: {args.input}")
    metadata, controls = load_controls(args.input)

    # Sort
    if args.sort == "risk":
        controls.sort(key=lambda c: (c.risk_score, c.id))
    elif args.sort == "status":
        controls.sort(key=lambda c: (c.status_score, c.id))
    else:
        controls.sort(key=lambda c: c.id)

    # Analyze
    summary = analyze(controls)
    print(f"[+] Assessed {summary.total} controls")
    print(f"    Implemented:     {summary.implemented}")
    print(f"    Partial:         {summary.partial}")
    print(f"    Not Implemented: {summary.not_implemented}")
    print(f"    Compliance Score:{summary.compliance_score}%")
    print(f"    Total Gaps:      {summary.total_gaps}")
    print(f"    High Risk:       {summary.high_risk}")

    os.makedirs(args.output_dir, exist_ok=True)
    date_str = datetime.now().strftime("%Y%m%d")
    base = f"cmmc_gap_report_{date_str}"

    # HTML
    if not args.pdf_only:
        html_path = os.path.join(args.output_dir, f"{base}.html")
        html = generate_html(metadata, controls, summary)
        with open(html_path, "w") as f:
            f.write(html)
        print(f"[+] HTML report: {html_path}")

    # PDF
    if not args.html_only:
        pdf_path = os.path.join(args.output_dir, f"{base}.pdf")
        print("[+] Generating PDF (reportlab)...")
        generate_pdf(metadata, controls, summary, pdf_path)
        print(f"[+] PDF report:  {pdf_path}")

    print("[✓] Done.")


if __name__ == "__main__":
    main()
