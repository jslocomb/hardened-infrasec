#!/usr/bin/env python3
"""
stride-threatmodel: CLI tool for STRIDE threat model analysis and risk register generation.

Ingests a STRIDE YAML threat model and outputs a prioritized risk register
with CMMC/NIST control mapping. Designed for CMMC Level 2 compliance workflows.

Usage:
    python stride_threatmodel.py <input.yaml> [options]
"""

import argparse
import csv
import json
import sys
from dataclasses import dataclass, field, asdict
from datetime import datetime
from io import StringIO
from pathlib import Path
from typing import Optional

import yaml

# ─── ANSI color helpers ───────────────────────────────────────────────────────

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"

RED = "\033[31m"
YELLOW = "\033[33m"
GREEN = "\033[32m"
CYAN = "\033[36m"
BLUE = "\033[34m"
MAGENTA = "\033[35m"
WHITE = "\033[97m"
GRAY = "\033[90m"

BG_RED = "\033[41m"
BG_YELLOW = "\033[43m"
BG_GREEN = "\033[42m"
BG_BLUE = "\033[44m"


def no_color(text: str) -> str:
    """Strip ANSI escape codes for non-TTY output."""
    import re
    return re.sub(r'\033\[[0-9;]*m', '', text)


def colorize(text: str, *codes: str, use_color: bool = True) -> str:
    if not use_color:
        return text
    return "".join(codes) + text + RESET


# ─── Data models ─────────────────────────────────────────────────────────────

@dataclass
class Mitigation:
    id: str
    description: str
    nist_control: str
    cmmc_practice: str
    effort: str      # low / medium / high
    priority: str    # low / medium / high / critical


@dataclass
class Threat:
    id: str
    stride_category: str
    title: str
    description: str
    affected_assets: list[str]
    attack_vector: str
    attack_complexity: str
    privileges_required: str
    user_interaction: str
    cvss_base: float
    likelihood: str
    existing_controls: list[str]
    mitigations: list[Mitigation]

    # Computed
    risk_score: float = 0.0
    risk_level: str = ""
    asset_sensitivity_max: str = ""


@dataclass
class Asset:
    id: str
    name: str
    type: str
    sensitivity: str   # low / medium / high / critical
    description: str


@dataclass
class RiskEntry:
    rank: int
    threat_id: str
    stride_category: str
    title: str
    risk_score: float
    risk_level: str
    cvss_base: float
    likelihood: str
    affected_assets: list[str]
    asset_sensitivity_max: str
    existing_controls: int
    mitigations: list[Mitigation]
    top_nist_controls: list[str]
    top_cmmc_practices: list[str]


# ─── Scoring engine ───────────────────────────────────────────────────────────

SENSITIVITY_WEIGHT = {
    "low": 1.0,
    "medium": 1.5,
    "high": 2.0,
    "critical": 3.0,
}

LIKELIHOOD_WEIGHT = {
    "low": 0.5,
    "medium": 1.0,
    "high": 1.5,
}

STRIDE_WEIGHT = {
    "Spoofing": 1.1,
    "Tampering": 1.2,
    "Repudiation": 0.9,
    "Information Disclosure": 1.1,
    "Denial of Service": 1.0,
    "Elevation of Privilege": 1.3,
}

RISK_THRESHOLDS = [
    (20.0, "CRITICAL"),
    (14.0, "HIGH"),
    (8.0,  "MEDIUM"),
    (0.0,  "LOW"),
]

RISK_COLORS = {
    "CRITICAL": RED + BOLD,
    "HIGH":     YELLOW + BOLD,
    "MEDIUM":   CYAN,
    "LOW":      GREEN,
}


def compute_risk_score(
    cvss: float,
    likelihood: str,
    sensitivity: str,
    stride_category: str,
    existing_control_count: int,
) -> float:
    """
    Risk Score = CVSS × Likelihood × Asset Sensitivity × STRIDE Weight × Control Discount

    Control Discount: each existing control reduces score by 5%, capped at 30% reduction.
    """
    base = cvss
    base *= LIKELIHOOD_WEIGHT.get(likelihood, 1.0)
    base *= SENSITIVITY_WEIGHT.get(sensitivity, 1.0)
    base *= STRIDE_WEIGHT.get(stride_category, 1.0)

    discount = min(0.30, existing_control_count * 0.05)
    base *= (1.0 - discount)

    return round(base, 2)


def risk_level(score: float) -> str:
    for threshold, level in RISK_THRESHOLDS:
        if score >= threshold:
            return level
    return "LOW"


def max_sensitivity(asset_ids: list[str], asset_map: dict[str, Asset]) -> str:
    order = ["low", "medium", "high", "critical"]
    best = "low"
    for aid in asset_ids:
        if aid in asset_map:
            s = asset_map[aid].sensitivity.lower()
            if order.index(s) > order.index(best):
                best = s
    return best


# ─── Parser ───────────────────────────────────────────────────────────────────

def parse_yaml(path: Path) -> tuple[dict, list[Asset], list[Threat]]:
    with open(path) as f:
        raw = yaml.safe_load(f)

    metadata = raw.get("metadata", {})

    assets = []
    for a in raw.get("assets", []):
        assets.append(Asset(
            id=a["id"],
            name=a["name"],
            type=a["type"],
            sensitivity=a["sensitivity"],
            description=a.get("description", ""),
        ))

    asset_map = {a.id: a for a in assets}

    threats = []
    for t in raw.get("threats", []):
        mits = []
        for m in t.get("mitigations", []):
            mits.append(Mitigation(
                id=m["id"],
                description=m["description"],
                nist_control=m["nist_control"],
                cmmc_practice=m["cmmc_practice"],
                effort=m["effort"],
                priority=m["priority"],
            ))

        affected = t.get("affected_assets", [])
        sensitivity = max_sensitivity(affected, asset_map)
        controls = t.get("existing_controls", [])
        category = t["stride_category"]
        cvss = float(t.get("cvss_base", 5.0))
        likelihood = t.get("likelihood", "medium").lower()

        score = compute_risk_score(
            cvss=cvss,
            likelihood=likelihood,
            sensitivity=sensitivity,
            stride_category=category,
            existing_control_count=len(controls),
        )

        threat = Threat(
            id=t["id"],
            stride_category=category,
            title=t["title"],
            description=t.get("description", ""),
            affected_assets=affected,
            attack_vector=t.get("attack_vector", ""),
            attack_complexity=t.get("attack_complexity", ""),
            privileges_required=t.get("privileges_required", ""),
            user_interaction=t.get("user_interaction", ""),
            cvss_base=cvss,
            likelihood=likelihood,
            existing_controls=controls,
            mitigations=mits,
            risk_score=score,
            risk_level=risk_level(score),
            asset_sensitivity_max=sensitivity,
        )
        threats.append(threat)

    return metadata, assets, threats


def build_risk_register(threats: list[Threat], asset_map: dict[str, Asset]) -> list[RiskEntry]:
    sorted_threats = sorted(threats, key=lambda t: t.risk_score, reverse=True)

    register = []
    for rank, t in enumerate(sorted_threats, 1):
        nist = list(dict.fromkeys(m.nist_control for m in t.mitigations))
        cmmc = list(dict.fromkeys(m.cmmc_practice for m in t.mitigations))

        asset_names = []
        for aid in t.affected_assets:
            if aid in asset_map:
                asset_names.append(asset_map[aid].name)
            else:
                asset_names.append(aid)

        register.append(RiskEntry(
            rank=rank,
            threat_id=t.id,
            stride_category=t.stride_category,
            title=t.title,
            risk_score=t.risk_score,
            risk_level=t.risk_level,
            cvss_base=t.cvss_base,
            likelihood=t.likelihood,
            affected_assets=asset_names,
            asset_sensitivity_max=t.asset_sensitivity_max,
            existing_controls=len(t.existing_controls),
            mitigations=t.mitigations,
            top_nist_controls=nist,
            top_cmmc_practices=cmmc,
        ))

    return register


# ─── Output formatters ────────────────────────────────────────────────────────

def fmt_risk_badge(level: str, use_color: bool) -> str:
    color = RISK_COLORS.get(level, "")
    width = 8
    label = f" {level:<{width-2}} "
    return colorize(label, color, use_color=use_color)


def fmt_effort(effort: str, use_color: bool) -> str:
    colors = {"low": GREEN, "medium": YELLOW, "high": RED}
    c = colors.get(effort.lower(), WHITE)
    return colorize(effort.upper(), c, use_color=use_color)


def fmt_stride(category: str, use_color: bool) -> str:
    colors = {
        "Spoofing":               MAGENTA,
        "Tampering":              RED,
        "Repudiation":            YELLOW,
        "Information Disclosure": CYAN,
        "Denial of Service":      BLUE,
        "Elevation of Privilege": RED + BOLD,
    }
    abbrevs = {
        "Spoofing":               "S",
        "Tampering":              "T",
        "Repudiation":            "R",
        "Information Disclosure": "I",
        "Denial of Service":      "D",
        "Elevation of Privilege": "E",
    }
    c = colors.get(category, WHITE)
    abbr = abbrevs.get(category, "?")
    return colorize(f"[{abbr}] {category}", c, use_color=use_color)


def print_summary_banner(metadata: dict, threats: list[Threat], use_color: bool) -> None:
    system = metadata.get("system", "Unknown")
    cmmc = metadata.get("cmmc_level", "?")
    author = metadata.get("author", "?")
    date = metadata.get("date", "?")

    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for t in threats:
        counts[t.risk_level] = counts.get(t.risk_level, 0) + 1

    w = 70
    border = colorize("═" * w, CYAN, use_color=use_color)
    title_line = colorize(" STRIDE THREAT MODEL — RISK REGISTER ", CYAN + BOLD, use_color=use_color)

    print(f"\n{border}")
    print(f"  {title_line}")
    print(border)
    print(colorize(f"  System      : {system}", WHITE, use_color=use_color))
    print(colorize(f"  CMMC Level  : {cmmc}   │  Author: {author}   │  Date: {date}", GRAY, use_color=use_color))
    print(colorize(f"  Generated   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", GRAY, use_color=use_color))
    print(border)

    # Risk distribution bar
    total = len(threats)
    print(colorize(f"\n  RISK DISTRIBUTION  ({total} threats)\n", BOLD, use_color=use_color))
    for level in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        count = counts[level]
        bar_len = int((count / max(total, 1)) * 30)
        bar = "█" * bar_len
        color = RISK_COLORS.get(level, "")
        print(f"  {colorize(f'{level:<8}', color, use_color=use_color)}  "
              f"{colorize(bar, color, use_color=use_color)}"
              f"  {colorize(str(count), BOLD, use_color=use_color)}")
    print()


def print_register_terminal(register: list[RiskEntry], asset_map: dict[str, Asset],
                             use_color: bool, verbose: bool, top_n: Optional[int]) -> None:
    entries = register[:top_n] if top_n else register

    for entry in entries:
        badge = fmt_risk_badge(entry.risk_level, use_color)
        stride = fmt_stride(entry.stride_category, use_color)

        # Header row
        rank_str = colorize(f"#{entry.rank:02d}", BOLD + WHITE, use_color=use_color)
        score_str = colorize(f"Score: {entry.risk_score:.1f}", BOLD, use_color=use_color)
        cvss_str = colorize(f"CVSS: {entry.cvss_base}", DIM, use_color=use_color)

        sep = colorize("─" * 68, GRAY, use_color=use_color)
        print(sep)
        print(f"  {rank_str}  {badge}  {score_str}  {cvss_str}")
        print(f"      {stride}")
        print(f"      {colorize(entry.title, BOLD + WHITE, use_color=use_color)}")

        # Assets
        asset_str = ", ".join(entry.affected_assets)
        sens_color = RISK_COLORS.get(entry.asset_sensitivity_max.upper(), WHITE)
        print(f"      {colorize('Assets:', DIM, use_color=use_color)} "
              f"{colorize(asset_str, GRAY, use_color=use_color)}  "
              f"[sensitivity: {colorize(entry.asset_sensitivity_max.upper(), sens_color, use_color=use_color)}]")

        # Controls & likelihood
        lik_color = {"low": GREEN, "medium": YELLOW, "high": RED}.get(entry.likelihood, WHITE)
        print(f"      {colorize('Likelihood:', DIM, use_color=use_color)} "
              f"{colorize(entry.likelihood.upper(), lik_color, use_color=use_color)}  │  "
              f"{colorize('Existing controls:', DIM, use_color=use_color)} {entry.existing_controls}")

        if verbose:
            print()

        # Mitigations
        if entry.mitigations:
            print(f"\n      {colorize('MITIGATIONS', BOLD + CYAN, use_color=use_color)}")
            for mit in entry.mitigations:
                pri_color = RISK_COLORS.get(mit.priority.upper(), WHITE)
                effort_str = fmt_effort(mit.effort, use_color)
                print(f"        {colorize('▸', CYAN, use_color=use_color)} "
                      f"[{colorize(mit.id, GRAY, use_color=use_color)}] "
                      f"{mit.description}")
                print(f"          {colorize('Priority:', DIM, use_color=use_color)} "
                      f"{colorize(mit.priority.upper(), pri_color, use_color=use_color)}  │  "
                      f"{colorize('Effort:', DIM, use_color=use_color)} {effort_str}  │  "
                      f"{colorize('NIST:', DIM, use_color=use_color)} {colorize(mit.nist_control, BLUE, use_color=use_color)}  │  "
                      f"{colorize('CMMC:', DIM, use_color=use_color)} {colorize(mit.cmmc_practice, MAGENTA, use_color=use_color)}")

        print()


def print_cmmc_coverage(register: list[RiskEntry], use_color: bool) -> None:
    """Print a rollup of CMMC practices covered by mitigations."""
    practice_counts: dict[str, int] = {}
    nist_counts: dict[str, int] = {}

    for entry in register:
        for mit in entry.mitigations:
            practice_counts[mit.cmmc_practice] = practice_counts.get(mit.cmmc_practice, 0) + 1
            nist_counts[mit.nist_control] = nist_counts.get(mit.nist_control, 0) + 1

    border = colorize("═" * 68, CYAN, use_color=use_color)
    print(border)
    print(colorize("  CMMC LEVEL 2 PRACTICE COVERAGE ROLLUP", BOLD + CYAN, use_color=use_color))
    print(border)

    # Group by domain prefix (AC, AU, CM, IA, SC, SI)
    domains: dict[str, list[str]] = {}
    for p in sorted(practice_counts.keys()):
        domain = p.split(".")[0] if "." in p else p[:2]
        domains.setdefault(domain, []).append(p)

    domain_names = {
        "AC": "Access Control",
        "AU": "Audit & Accountability",
        "CM": "Configuration Management",
        "IA": "Identification & Authentication",
        "SC": "System & Communications Protection",
        "SI": "System & Information Integrity",
    }

    for domain, practices in sorted(domains.items()):
        dname = domain_names.get(domain, domain)
        print(f"\n  {colorize(dname, BOLD + WHITE, use_color=use_color)} ({colorize(domain, CYAN, use_color=use_color)})")
        for p in practices:
            count = practice_counts[p]
            nist = [k for k, v in nist_counts.items() if k in [
                m.nist_control for e in register for m in e.mitigations if m.cmmc_practice == p
            ]]
            nist_str = ", ".join(sorted(set(nist)))
            print(f"    {colorize('✓', GREEN, use_color=use_color)} "
                  f"{colorize(p, MAGENTA, use_color=use_color)}"
                  f"  [{count} mitigation(s)]  "
                  f"{colorize(nist_str, BLUE + DIM, use_color=use_color)}")

    print()


# ─── Export formatters ────────────────────────────────────────────────────────

def export_json(register: list[RiskEntry], metadata: dict, path: Path) -> None:
    out = {
        "metadata": metadata,
        "generated": datetime.now().isoformat(),
        "risk_register": [],
    }
    for entry in register:
        row = {
            "rank": entry.rank,
            "threat_id": entry.threat_id,
            "stride_category": entry.stride_category,
            "title": entry.title,
            "risk_score": entry.risk_score,
            "risk_level": entry.risk_level,
            "cvss_base": entry.cvss_base,
            "likelihood": entry.likelihood,
            "asset_sensitivity_max": entry.asset_sensitivity_max,
            "affected_assets": entry.affected_assets,
            "existing_controls": entry.existing_controls,
            "nist_controls": entry.top_nist_controls,
            "cmmc_practices": entry.top_cmmc_practices,
            "mitigations": [asdict(m) for m in entry.mitigations],
        }
        out["risk_register"].append(row)

    with open(path, "w") as f:
        json.dump(out, f, indent=2)
    print(f"  ✓ JSON exported → {path}")


def export_csv(register: list[RiskEntry], path: Path) -> None:
    fieldnames = [
        "rank", "threat_id", "stride_category", "title",
        "risk_score", "risk_level", "cvss_base", "likelihood",
        "asset_sensitivity_max", "affected_assets", "existing_controls",
        "nist_controls", "cmmc_practices",
        "mit_ids", "mit_priorities", "mit_efforts",
    ]
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for entry in register:
            writer.writerow({
                "rank": entry.rank,
                "threat_id": entry.threat_id,
                "stride_category": entry.stride_category,
                "title": entry.title,
                "risk_score": entry.risk_score,
                "risk_level": entry.risk_level,
                "cvss_base": entry.cvss_base,
                "likelihood": entry.likelihood,
                "asset_sensitivity_max": entry.asset_sensitivity_max,
                "affected_assets": "; ".join(entry.affected_assets),
                "existing_controls": entry.existing_controls,
                "nist_controls": "; ".join(entry.top_nist_controls),
                "cmmc_practices": "; ".join(entry.top_cmmc_practices),
                "mit_ids": "; ".join(m.id for m in entry.mitigations),
                "mit_priorities": "; ".join(m.priority for m in entry.mitigations),
                "mit_efforts": "; ".join(m.effort for m in entry.mitigations),
            })
    print(f"  ✓ CSV exported  → {path}")


def export_markdown(register: list[RiskEntry], metadata: dict, path: Path) -> None:
    lines = []
    system = metadata.get("system", "Unknown")
    cmmc = metadata.get("cmmc_level", "?")

    lines.append(f"# STRIDE Risk Register — {system}")
    lines.append(f"\n**CMMC Level:** {cmmc}  ")
    lines.append(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  ")
    lines.append(f"**Total Threats:** {len(register)}\n")

    # Summary table
    lines.append("## Risk Summary\n")
    lines.append("| Rank | ID | Category | Title | Risk Score | Level | CVSS | Likelihood |")
    lines.append("|------|----|----------|-------|-----------|-------|------|------------|")
    for entry in register:
        lines.append(
            f"| {entry.rank} | {entry.threat_id} | {entry.stride_category} | "
            f"{entry.title} | {entry.risk_score} | **{entry.risk_level}** | "
            f"{entry.cvss_base} | {entry.likelihood} |"
        )

    lines.append("\n## Detailed Findings\n")
    for entry in register:
        lines.append(f"### #{entry.rank:02d} — {entry.threat_id}: {entry.title}\n")
        lines.append(f"| Field | Value |")
        lines.append(f"|-------|-------|")
        lines.append(f"| **Risk Level** | {entry.risk_level} |")
        lines.append(f"| **Risk Score** | {entry.risk_score} |")
        lines.append(f"| **CVSS Base** | {entry.cvss_base} |")
        lines.append(f"| **STRIDE** | {entry.stride_category} |")
        lines.append(f"| **Likelihood** | {entry.likelihood.upper()} |")
        lines.append(f"| **Affected Assets** | {', '.join(entry.affected_assets)} |")
        lines.append(f"| **Asset Sensitivity** | {entry.asset_sensitivity_max.upper()} |")
        lines.append(f"| **Existing Controls** | {entry.existing_controls} |")
        lines.append(f"| **NIST Controls** | {', '.join(entry.top_nist_controls)} |")
        lines.append(f"| **CMMC Practices** | {', '.join(entry.top_cmmc_practices)} |")

        if entry.mitigations:
            lines.append(f"\n**Mitigations:**\n")
            for mit in entry.mitigations:
                lines.append(f"- **[{mit.id}]** {mit.description}")
                lines.append(f"  - Priority: `{mit.priority}` | Effort: `{mit.effort}` | "
                              f"NIST: `{mit.nist_control}` | CMMC: `{mit.cmmc_practice}`")

        lines.append("")

    # CMMC rollup
    lines.append("## CMMC Practice Coverage\n")
    practices: dict[str, list[str]] = {}
    for entry in register:
        for mit in entry.mitigations:
            practices.setdefault(mit.cmmc_practice, []).append(mit.id)
    for p, mits in sorted(practices.items()):
        lines.append(f"- `{p}` — addressed by: {', '.join(mits)}")

    with open(path, "w") as f:
        f.write("\n".join(lines))
    print(f"  ✓ Markdown exported → {path}")


# ─── Main CLI ─────────────────────────────────────────────────────────────────

def main() -> int:
    parser = argparse.ArgumentParser(
        prog="stride-threatmodel",
        description="STRIDE threat model analyzer — outputs a prioritized risk register",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python stride_threatmodel.py examples/homelab-k8s.yaml
  python stride_threatmodel.py model.yaml --top 5 --verbose
  python stride_threatmodel.py model.yaml --output json --out-file register.json
  python stride_threatmodel.py model.yaml --output all --out-prefix homelab
  python stride_threatmodel.py model.yaml --filter-category "Elevation of Privilege"
  python stride_threatmodel.py model.yaml --filter-level CRITICAL --no-color
        """,
    )

    parser.add_argument("input", type=Path, help="Path to STRIDE YAML threat model")
    parser.add_argument("--output", choices=["terminal", "json", "csv", "markdown", "all"],
                        default="terminal", help="Output format (default: terminal)")
    parser.add_argument("--out-file", type=Path, default=None,
                        help="Output file path (for json/csv/markdown)")
    parser.add_argument("--out-prefix", type=str, default="risk_register",
                        help="Filename prefix when --output=all (default: risk_register)")
    parser.add_argument("--top", type=int, default=None,
                        help="Show only top N risks")
    parser.add_argument("--verbose", action="store_true",
                        help="Show full descriptions and additional detail")
    parser.add_argument("--no-color", action="store_true",
                        help="Disable ANSI color output")
    parser.add_argument("--filter-level", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
                        default=None, help="Show only threats at or above this risk level")
    parser.add_argument("--filter-category", type=str, default=None,
                        help="Filter to a specific STRIDE category")
    parser.add_argument("--cmmc-coverage", action="store_true",
                        help="Print CMMC practice coverage rollup")
    parser.add_argument("--no-register", action="store_true",
                        help="Skip risk register output (useful with --cmmc-coverage)")

    args = parser.parse_args()

    # ── validate input
    if not args.input.exists():
        print(f"ERROR: File not found: {args.input}", file=sys.stderr)
        return 1

    use_color = not args.no_color and sys.stdout.isatty()
    # Force color on for terminal output even if piped when not --no-color
    if args.output == "terminal" and not args.no_color:
        use_color = True

    # ── parse
    try:
        metadata, assets, threats = parse_yaml(args.input)
    except Exception as e:
        print(f"ERROR: Failed to parse {args.input}: {e}", file=sys.stderr)
        return 1

    asset_map = {a.id: a for a in assets}

    # ── filter
    filtered = threats
    LEVEL_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    if args.filter_level:
        min_idx = LEVEL_ORDER.index(args.filter_level)
        filtered = [t for t in filtered if LEVEL_ORDER.index(t.risk_level) >= min_idx]
    if args.filter_category:
        filtered = [t for t in filtered if t.stride_category.lower() == args.filter_category.lower()]

    # ── build register
    register = build_risk_register(filtered, asset_map)

    # ── output
    if args.output in ("terminal", "all"):
        print_summary_banner(metadata, filtered, use_color)

        if not args.no_register:
            print_register_terminal(register, asset_map, use_color, args.verbose, args.top)

        if args.cmmc_coverage or args.output == "all":
            print_cmmc_coverage(register, use_color)

    if args.output in ("json", "all"):
        out_path = args.out_file or Path(f"{args.out_prefix}.json")
        export_json(register, metadata, out_path)

    if args.output in ("csv", "all"):
        out_path = args.out_file or Path(f"{args.out_prefix}.csv")
        export_csv(register, out_path)

    if args.output in ("markdown", "all"):
        out_path = args.out_file or Path(f"{args.out_prefix}.md")
        export_markdown(register, metadata, out_path)

    if args.output in ("json", "csv", "markdown", "all"):
        print()

    return 0


if __name__ == "__main__":
    sys.exit(main())
