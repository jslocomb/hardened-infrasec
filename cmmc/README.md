# CMMC Level 2 Compliance Automation

This directory contains compliance automation tooling and assessment artifacts for the **AWS RKE2 Kubernetes Lab**, aligned to NIST SP 800-171 Rev 2 and CMMC 2.0 Level 2. It is structured to be immediately legible to a C3PAO assessor or DoD hiring manager — compliance is treated as a first-class engineering concern, not an afterthought.

---

## Directory Structure

```
cmmc/
├── README.md                  # This file
├── gap-report/
│   ├── cmmc_gap_report.py     # Gap report generator (Python)
│   ├── controls.yaml          # NIST 800-171 control mappings — source of truth
│   ├── requirements.txt       # Python dependencies (reportlab, pyyaml, jinja2)
│   ├── Makefile               # Convenience targets: make report, make clean
│   └── reports/               # Generated HTML/PDF outputs — gitignored
│       └── .gitkeep
└── ssp/                       # System Security Plan narrative artifacts
    └── .gitkeep
```

---

## Gap Report Generator

`gap-report/cmmc_gap_report.py` ingests `controls.yaml` and produces a formatted auditor-facing gap report in HTML and PDF. It is designed to demonstrate the kind of compliance automation expected in DoD cloud-native and defense contractor environments.

### What It Produces

- **Cover page** — system name, assessor, assessment date, classification, and overall compliance score
- **Executive summary** — implemented / partial / not-implemented counts, risk distribution, total gap items
- **Control family coverage table** — per-domain completion percentages
- **High-risk findings section** — critical gaps isolated at the top for assessor triage
- **Full control detail** — for every control: requirement text, implementation notes, evidence artifacts, gap bullet list, and recommended remediation

### Quick Start

```bash
cd cmmc/gap-report

# Install dependencies (virtualenv recommended)
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# Generate HTML + PDF
python3 cmmc_gap_report.py --input controls.yaml --output-dir reports

# Or via make
make report
```

### Makefile Targets

| Target | Description |
|---|---|
| `make report` | Generate HTML + PDF (default) |
| `make report-html` | HTML only |
| `make report-pdf` | PDF only |
| `make report-by-risk` | Sort all findings by risk level (High first) |
| `make clean` | Remove generated report files |
| `make install` | Create virtualenv and install dependencies |

### CLI Options

```
python3 cmmc_gap_report.py [OPTIONS]

Options:
  --input PATH          Path to control mappings YAML  [default: controls.yaml]
  --output-dir PATH     Output directory               [default: ./reports]
  --sort {id,risk,status}
                        Sort controls by ID, risk level, or status
  --html-only           Generate HTML report only
  --pdf-only            Generate PDF report only
```

---

## Control Mappings — `controls.yaml`

`controls.yaml` is the authoritative source of truth for this assessment. It maps each evaluated NIST 800-171 control to the actual implementation in this environment, including evidence artifacts, identified gaps, and remediation guidance.

This file functions as a living SSP-lite. It is what an assessor reads to understand control disposition. Keeping it accurate and current is more important than any generated report.

### Control Structure

Each entry in `controls.yaml` follows this schema:

```yaml
- id: "3.5.3"
  family: "IA"
  family_name: "Identification & Authentication"
  title: "Use multifactor authentication"
  requirement: "Full NIST 800-171 requirement text."
  status: "Not Implemented"          # Implemented | Partial | Not Implemented
  implementation: "Narrative of what is actually deployed."
  evidence:
    - "Specific artifact or config path that demonstrates the control"
  gaps:
    - "Specific, scoped description of what is missing"
  risk: "High"                       # High | Medium | Low
  remediation: "Concrete remediation steps with tooling."
  cmmc_practice: "IA.L2-3.5.3"
```

### Control Families Assessed

| Family Code | Family Name | Controls |
|---|---|---|
| AC | Access Control | 3.1.x |
| AU | Audit & Accountability | 3.3.x |
| CM | Configuration Management | 3.4.x |
| IA | Identification & Authentication | 3.5.x |
| SI | System & Information Integrity | 3.14.x |

NIST SP 800-171 Rev 2 defines 110 controls across 14 families. This assessment covers a representative subset mapped against the current lab stack. Coverage expands as the environment matures.

### Compliance Scoring

The compliance score weights partial implementations at 0.5×:

```
Score = (Implemented × 1.0 + Partial × 0.5) / Total × 100
```

This matches the scoring approach used by CMMC assessment methodology to reflect that partial controls reduce but do not eliminate residual risk.

---

## Current Assessment Summary

> Last assessed: 2026-04-04

| Metric | Value |
|---|---|
| Controls Assessed | 21 |
| Implemented | 12 |
| Partially Implemented | 6 |
| Not Implemented | 3 |
| Compliance Score | 71.4% |
| Total Gap Items | 27 |
| High-Risk Gaps | 3 |

### High-Risk Gaps (Priority Remediation)

| Control | Title | Gap Summary |
|---|---|---|
| AC.L2-3.1.20 | External System Connections | GitHub mirror and external API connections not formally authorized; no ISA/MOU documented |
| IA.L2-3.5.3 | Multifactor Authentication | No MFA on SSH, AWX web UI, or GitLab; FreeIPA OTP not configured |
| CM.L2-3.4.8 | Deny-by-Default Software Policy | No application allowlisting; `fapolicyd` not deployed |

These three controls should be remediated before any C3PAO engagement.

---

## Infrastructure Context

The control mappings in `controls.yaml` are specific to this lab environment:

| Component | Role |
|---|---|
| AWS us-west-2 | Cloud provider |
| RKE2 on Rocky Linux 9.7 | Kubernetes distribution (RHEL-compatible, DoD-relevant) |
| FreeIPA 4.12.2 | Identity, LDAP, HBAC, password policy |
| AWX 24.6.1 | Ansible automation, job execution audit trail |
| Splunk Enterprise | SIEM, log aggregation, audit log retention |
| AIDE | File integrity monitoring |
| Falco 0.43.0 | Runtime threat detection |
| Terraform + GitLab CI | IaC, configuration baseline, change control |
| NetBox v4.5.5 | CMDB, dynamic AWX inventory |

Rocky Linux 9.7 is used deliberately for its RHEL binary compatibility — directly relevant to DoD on-prem and AWS GovCloud (IL2/IL4) environments where RHEL is the standard OS baseline.

---

## GovCloud Transferability

The control mappings, automation patterns, and tooling in this directory transfer directly to AWS GovCloud (IL2/IL4) deployments. The generator is infrastructure-agnostic — `controls.yaml` is the only file that changes between environments. In a production engagement this file would be populated from a formal assessment against a GovCloud workload rather than a homelab stack.

---

## SSP Placeholder — `ssp/`

The `ssp/` directory is reserved for System Security Plan narrative artifacts. A full SSP includes system boundary definition, data flow diagrams, interconnection agreements, and control implementation narratives beyond what `controls.yaml` captures. That documentation lives here when written.

Stubbing this directory now signals to an assessor that the SSP lifecycle has been considered in the repository design.

---

## .gitignore Notes

Generated report files are excluded from source control. They are build artifacts — reproducible on demand from `controls.yaml`.

```
# In repo root .gitignore
cmmc/gap-report/reports/*.html
cmmc/gap-report/reports/*.pdf
cmmc/gap-report/.venv/
```

The `.gitkeep` file in `reports/` preserves the directory in the repository without committing generated outputs.

---

## References

- [NIST SP 800-171 Rev 2](https://csrc.nist.gov/publications/detail/sp/800-171/rev-2/final)
- [CMMC 2.0 Model Overview](https://www.acq.osd.mil/cmmc/documentation.html)
- [CMMC Assessment Process (CAP)](https://www.acq.osd.mil/cmmc/cap.html)
- [DoD Cloud Computing Security Requirements Guide (CC SRG)](https://dl.dod.cyber.mil/wp-content/uploads/cloud/zip/U_Cloud_Computing_SRG_V1R4.zip)
