#!/usr/bin/env bash
# setup_cmmc_structure.sh
# Extracts ~/Downloads/gap/files.zip and installs files into the
# homelab-k8s repo cmmc/ structure.
#
# Usage:
#   chmod +x setup_cmmc_structure.sh
#   ./setup_cmmc_structure.sh
#   ./setup_cmmc_structure.sh --repo /Users/jason/Projects/homelab-k8s   # override repo path
#   ./setup_cmmc_structure.sh --dry-run                      # preview only

set -euo pipefail

# ── Config ────────────────────────────────────────────────────────────────────
ZIP_PATH="${HOME}/Downloads/gap/files.zip"
REPO_ROOT="${HOME}/homelab-k8s"          # default; override with --repo
DRY_RUN=false
EXTRACT_TMP="${TMPDIR:-/tmp}/cmmc_extract_$$"

# ── Arg parsing ───────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --repo)    REPO_ROOT="$2"; shift 2 ;;
    --dry-run) DRY_RUN=true; shift ;;
    -h|--help)
      grep '^#' "$0" | sed 's/^# \?//'
      exit 0 ;;
    *) echo "Unknown arg: $1"; exit 1 ;;
  esac
done

# ── Colors ────────────────────────────────────────────────────────────────────
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; BOLD='\033[1m'; NC='\033[0m'
info()  { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
error() { echo -e "${RED}[✗]${NC} $*" >&2; }
dry()   { echo -e "${YELLOW}[dry-run]${NC} $*"; }
step()  { echo -e "\n${BOLD}── $* ──${NC}"; }

# ── Helpers ───────────────────────────────────────────────────────────────────
run() {
  if $DRY_RUN; then
    dry "$*"
  else
    eval "$*"
  fi
}

mkd() {
  # mkdir -p with dry-run awareness
  if $DRY_RUN; then
    dry "mkdir -p $1"
  else
    mkdir -p "$1"
    info "Created dir: $1"
  fi
}

install_file() {
  local src="$1" dst="$2"
  if $DRY_RUN; then
    dry "cp $src → $dst"
    return
  fi
  if [[ ! -f "$src" ]]; then
    warn "Source not found, skipping: $src"
    return
  fi
  cp "$src" "$dst"
  info "Installed: $(basename "$src") → ${dst#"$REPO_ROOT/"}"
}

# ── Preflight ─────────────────────────────────────────────────────────────────
step "Preflight checks"

if ! command -v unzip &>/dev/null; then
  error "unzip not found. Install with: sudo dnf install -y unzip"
  exit 1
fi

if [[ ! -f "$ZIP_PATH" ]]; then
  error "Zip not found at: $ZIP_PATH"
  error "Place files.zip at ~/Downloads/gap/files.zip and re-run."
  exit 1
fi
info "Zip found: $ZIP_PATH"

if [[ ! -d "$REPO_ROOT" ]]; then
  error "Repo not found at: $REPO_ROOT"
  error "Run with --repo /correct/path/to/homelab-k8s"
  exit 1
fi
info "Repo root: $REPO_ROOT"

if $DRY_RUN; then
  warn "DRY RUN — no files will be written"
fi

# ── Extract ───────────────────────────────────────────────────────────────────
step "Extracting zip"

if ! $DRY_RUN; then
  rm -rf "$EXTRACT_TMP"
  mkdir -p "$EXTRACT_TMP"
  unzip -q "$ZIP_PATH" -d "$EXTRACT_TMP"
  info "Extracted to: $EXTRACT_TMP"
  # Flatten one wrapper directory if present (common with zip on macOS/Windows)
  INNER=$(ls "$EXTRACT_TMP")
  INNER_COUNT=$(echo "$INNER" | wc -l | tr -d ' ')
  if [[ "$INNER_COUNT" -eq 1 ]] && [[ -d "$EXTRACT_TMP/$INNER" ]]; then
    EXTRACT_TMP="$EXTRACT_TMP/$INNER"
    info "Detected single top-level dir, descending into: $INNER"
  fi
  info "Zip contents:"
  find "$EXTRACT_TMP" -type f | sed "s|$EXTRACT_TMP/||" | sort | while read -r f; do
    echo "    $f"
  done
else
  dry "unzip $ZIP_PATH -d $EXTRACT_TMP"
fi

# ── Build directory structure ─────────────────────────────────────────────────
step "Creating cmmc/ directory structure"

CMMC="$REPO_ROOT/cmmc"
GAP="$CMMC/gap-report"
REPORTS="$GAP/reports"
SSP="$CMMC/ssp"

mkd "$CMMC"
mkd "$GAP"
mkd "$REPORTS"
mkd "$SSP"

# ── Install files ─────────────────────────────────────────────────────────────
step "Installing files"

# Main generator script
install_file "$EXTRACT_TMP/cmmc_gap_report.py"  "$GAP/cmmc_gap_report.py"

# Control mappings YAML
install_file "$EXTRACT_TMP/controls.yaml"        "$GAP/controls.yaml"

# Generated report artifacts go in reports/
install_file "$EXTRACT_TMP/cmmc_gap_report.html" "$REPORTS/cmmc_gap_report.html"
install_file "$EXTRACT_TMP/cmmc_gap_report.pdf"  "$REPORTS/cmmc_gap_report.pdf"

# ── Write supporting files ────────────────────────────────────────────────────
step "Writing supporting files"

# requirements.txt
REQ_FILE="$GAP/requirements.txt"
if $DRY_RUN; then
  dry "write $REQ_FILE"
else
  cat > "$REQ_FILE" <<'EOF'
reportlab>=4.0
pyyaml>=6.0
jinja2>=3.1
EOF
  info "Wrote: cmmc/gap-report/requirements.txt"
fi

# Makefile
MAKEFILE="$GAP/Makefile"
if $DRY_RUN; then
  dry "write $MAKEFILE"
else
  cat > "$MAKEFILE" <<'EOF'
.PHONY: report report-html report-pdf clean install

VENV     := .venv
PYTHON   := $(VENV)/bin/python
PIP      := $(VENV)/bin/pip
CONTROLS := controls.yaml
OUT_DIR  := reports

install: $(VENV)/bin/activate

$(VENV)/bin/activate: requirements.txt
	python3 -m venv $(VENV)
	$(PIP) install -q -r requirements.txt
	touch $(VENV)/bin/activate

report: install
	$(PYTHON) cmmc_gap_report.py --input $(CONTROLS) --output-dir $(OUT_DIR)

report-html: install
	$(PYTHON) cmmc_gap_report.py --input $(CONTROLS) --output-dir $(OUT_DIR) --html-only

report-pdf: install
	$(PYTHON) cmmc_gap_report.py --input $(CONTROLS) --output-dir $(OUT_DIR) --pdf-only

report-by-risk: install
	$(PYTHON) cmmc_gap_report.py --input $(CONTROLS) --output-dir $(OUT_DIR) --sort risk

clean:
	rm -rf $(OUT_DIR)/*.html $(OUT_DIR)/*.pdf
EOF
  info "Wrote: cmmc/gap-report/Makefile"
fi

# .gitkeep for reports/ and ssp/
if ! $DRY_RUN; then
  touch "$REPORTS/.gitkeep"
  touch "$SSP/.gitkeep"
  info "Wrote: .gitkeep files"
fi

# cmmc/README.md
README="$CMMC/README.md"
if $DRY_RUN; then
  dry "write $README"
else
  ASSESS_DATE=$(date +%Y-%m-%d)
  cat > "$README" <<EOF
# CMMC Level 2 Compliance Artifacts

Compliance automation and assessment artifacts for the **AWS RKE2 Kubernetes Lab**,
aligned to NIST SP 800-171 Rev 2 and CMMC 2.0 Level 2.

---

## Structure

\`\`\`
cmmc/
├── gap-report/
│   ├── cmmc_gap_report.py   # Gap report generator (Python)
│   ├── controls.yaml        # NIST 800-171 control mappings (source of truth)
│   ├── requirements.txt     # Python dependencies
│   ├── Makefile             # Convenience targets
│   └── reports/             # Generated outputs (gitignored)
└── ssp/                     # System Security Plan artifacts
\`\`\`

## Quick Start

\`\`\`bash
cd cmmc/gap-report
make report               # Generate HTML + PDF
make report-by-risk       # Sort findings by risk level
make report-html          # HTML only
make report-pdf           # PDF only
\`\`\`

Or directly:

\`\`\`bash
pip install -r requirements.txt
python3 cmmc_gap_report.py --input controls.yaml --output-dir reports
\`\`\`

## CMMC Control Family Coverage

| Family | Controls Assessed |
|--------|------------------|
| AC — Access Control | 3.1.x |
| AU — Audit & Accountability | 3.3.x |
| CM — Configuration Management | 3.4.x |
| IA — Identification & Authentication | 3.5.x |
| SI — System & Information Integrity | 3.14.x |

## Assessment Summary (${ASSESS_DATE})

| Metric | Value |
|--------|-------|
| Controls Assessed | 21 |
| Implemented | 12 |
| Partially Implemented | 6 |
| Not Implemented | 3 |
| Compliance Score | 71.4% |
| High-Risk Gaps | 3 |

> **Note:** This is a homelab portfolio environment demonstrating CMMC L2
> compliance automation. Not a production CUI system.

## GovCloud Transferability

Control mappings and automation patterns transfer directly to AWS GovCloud
(IL2/IL4). The generator is infrastructure-agnostic — swap \`controls.yaml\`
for a production assessment dataset.
EOF
  info "Wrote: cmmc/README.md"
fi

# ── Update .gitignore ─────────────────────────────────────────────────────────
step "Updating .gitignore"

GITIGNORE="$REPO_ROOT/.gitignore"
IGNORE_ENTRY="cmmc/gap-report/reports/*.html
cmmc/gap-report/reports/*.pdf
cmmc/gap-report/.venv/"

if $DRY_RUN; then
  dry "append to $GITIGNORE"
elif grep -q "cmmc/gap-report/reports" "$GITIGNORE" 2>/dev/null; then
  warn ".gitignore already has cmmc/gap-report/reports entry, skipping"
else
  echo "" >> "$GITIGNORE"
  echo "# CMMC gap report — generated artifacts" >> "$GITIGNORE"
  echo "$IGNORE_ENTRY" >> "$GITIGNORE"
  info "Updated: .gitignore"
fi

# ── Summary ───────────────────────────────────────────────────────────────────
step "Result"

if ! $DRY_RUN; then
  echo ""
  echo -e "${BOLD}Files installed:${NC}"
  find "$CMMC" -type f | sort | while read -r f; do
    echo "  ${f#"$REPO_ROOT/"}"
  done
  echo ""
  info "Cleanup: rm -rf /tmp/cmmc_extract_*"
  rm -rf "/tmp/cmmc_extract_$$" 2>/dev/null || true
fi

echo ""
echo -e "${GREEN}${BOLD}Done.${NC} Next steps:"
echo "  cd $REPO_ROOT"
echo "  git add cmmc/ .gitignore"
echo "  git commit -m 'feat(cmmc): add gap report generator and control mappings'"
echo "  git push"
