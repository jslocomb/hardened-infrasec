# CMMC Level 2 Compliance Artifacts

Compliance automation and assessment artifacts for the **AWS RKE2 Kubernetes Lab**,
aligned to NIST SP 800-171 Rev 2 and CMMC 2.0 Level 2.

---

## Structure

```
cmmc/
├── gap-report/
│   ├── cmmc_gap_report.py   # Gap report generator (Python)
│   ├── controls.yaml        # NIST 800-171 control mappings (source of truth)
│   ├── requirements.txt     # Python dependencies
│   ├── Makefile             # Convenience targets
│   └── reports/             # Generated outputs (gitignored)
└── ssp/                     # System Security Plan artifacts
```

## Quick Start

```bash
cd cmmc/gap-report
make report               # Generate HTML + PDF
make report-by-risk       # Sort findings by risk level
make report-html          # HTML only
make report-pdf           # PDF only
```

Or directly:

```bash
pip install -r requirements.txt
python3 cmmc_gap_report.py --input controls.yaml --output-dir reports
```

## CMMC Control Family Coverage

| Family | Controls Assessed |
|--------|------------------|
| AC — Access Control | 3.1.x |
| AU — Audit & Accountability | 3.3.x |
| CM — Configuration Management | 3.4.x |
| IA — Identification & Authentication | 3.5.x |
| SI — System & Information Integrity | 3.14.x |

## Assessment Summary (2026-04-04)

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
(IL2/IL4). The generator is infrastructure-agnostic — swap `controls.yaml`
for a production assessment dataset.
