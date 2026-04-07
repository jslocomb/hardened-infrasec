# stride-threatmodel

A CLI tool that ingests a STRIDE threat model YAML and outputs a prioritized risk register with CMMC Level 2 / NIST 800-171 control mapping.

Built as part of the [homelab-k8s](https://github.com/jslocomb/homelab-k8s) CMMC Level 2 portfolio project.

---

## Features

- **STRIDE-aware scoring** — each category carries a calibrated weight (Elevation of Privilege > Tampering > Spoofing/Info Disclosure > DoS > Repudiation)
- **Multi-factor risk score** — `CVSS × Likelihood × Asset Sensitivity × STRIDE Weight × Control Discount`
- **CMMC Level 2 / NIST 800-171 mapping** — every mitigation maps to a CMMC practice and NIST control family
- **CMMC coverage rollup** — grouped by domain (AC, AU, CM, IA, SC, SI) with practice-level tracking
- **Multiple output formats** — rich terminal, JSON, CSV, Markdown
- **Filtering** — by risk level threshold or STRIDE category
- **25 unit tests** covering scoring, parsing, register building, and all export formats

---

## Installation

```bash
pip install pyyaml
```

No other dependencies. Python 3.10+ required.

---

## Usage

```bash
# Basic terminal output
python stride_threatmodel.py examples/homelab-k8s.yaml

# Top 5 risks only
python stride_threatmodel.py examples/homelab-k8s.yaml --top 5

# All output formats at once
python stride_threatmodel.py examples/homelab-k8s.yaml --output all --out-prefix homelab

# Only CRITICAL and HIGH risks
python stride_threatmodel.py examples/homelab-k8s.yaml --filter-level HIGH

# Filter to a specific STRIDE category
python stride_threatmodel.py examples/homelab-k8s.yaml --filter-category "Elevation of Privilege"

# CMMC coverage rollup only (no register)
python stride_threatmodel.py examples/homelab-k8s.yaml --cmmc-coverage --no-register

# CI-friendly (no color, JSON out)
python stride_threatmodel.py examples/homelab-k8s.yaml --no-color --output json --out-file register.json
```

---

## Risk Scoring Formula

```
Risk Score = CVSS_Base
           × Likelihood_Weight       (low=0.5, medium=1.0, high=1.5)
           × Asset_Sensitivity       (low=1.0, medium=1.5, high=2.0, critical=3.0)
           × STRIDE_Category_Weight  (EoP=1.3, Tampering=1.2, Spoofing/ID=1.1, DoS=1.0, Repudiation=0.9)
           × Control_Discount        (5% per existing control, capped at 30%)
```

| Score   | Level    |
|---------|----------|
| ≥ 20.0  | CRITICAL |
| ≥ 14.0  | HIGH     |
| ≥ 8.0   | MEDIUM   |
| < 8.0   | LOW      |

---

## YAML Threat Model Schema

```yaml
metadata:
  system: my-system
  cmmc_level: 2
  author: your.name
  date: "2025-01-01"

assets:
  - id: asset-001
    name: Kubernetes API Server
    type: compute          # compute | identity | datastore | service | network
    sensitivity: high      # low | medium | high | critical
    description: "..."

threats:
  - id: T-001
    stride_category: Spoofing     # Spoofing | Tampering | Repudiation |
                                   # Information Disclosure | Denial of Service |
                                   # Elevation of Privilege
    title: "Threat title"
    description: "..."
    affected_assets: [asset-001]
    attack_vector: Network         # CVSS AV values
    attack_complexity: Low
    privileges_required: None
    user_interaction: None
    cvss_base: 8.1
    likelihood: medium             # low | medium | high
    existing_controls:
      - "Description of control already in place"
    mitigations:
      - id: M-001
        description: "What to do"
        nist_control: IA-5         # NIST 800-171 control
        cmmc_practice: IA.L2-3.5.3
        effort: low                # low | medium | high
        priority: high             # low | medium | high | critical
```

See [`examples/homelab-k8s.yaml`](examples/homelab-k8s.yaml) for a complete real-world example
covering all six STRIDE categories across an RKE2/FreeIPA/Splunk stack.

---

## CMMC Control Mapping

Mitigations in the example model cover the following CMMC Level 2 domains:

| Domain | Practices |
|--------|-----------|
| Access Control (AC) | AC.L2-3.1.5, AC.L2-3.1.6 |
| Audit & Accountability (AU) | AU.L2-3.3.1, AU.L2-3.3.2, AU.L2-3.3.5 |
| Configuration Management (CM) | CM.L2-3.4.2, CM.L2-3.4.5, CM.L2-3.4.6, CM.L2-3.4.7 |
| Identification & Authentication (IA) | IA.L2-3.5.3 |
| System & Communications Protection (SC) | SC.L2-3.13.9, SC.L2-3.13.10, SC.L2-3.13.16 |
| System & Information Integrity (SI) | SI.L2-3.14.6 |

---

## CI Integration

```yaml
# .github/workflows/threat-model.yml
- name: Run STRIDE risk assessment
  run: |
    pip install pyyaml
    python tools/stride_threatmodel.py threat-model/homelab-k8s.yaml \
      --no-color \
      --output all \
      --out-prefix threat-model/risk_register

- name: Upload risk register artifacts
  uses: actions/upload-artifact@v4
  with:
    name: risk-register
    path: threat-model/risk_register.*
```

---

## Running Tests

```bash
python -m pytest tests/ -v
```

25 tests covering:
- Scoring formula correctness and edge cases
- Risk level boundary conditions
- Asset sensitivity aggregation
- Risk register sort order and deduplication
- YAML parsing (full example + minimal)
- JSON, CSV, and Markdown export correctness

---

## Relation to homelab-k8s

This tool operationalizes the STRIDE threat modeling work documented in the
homelab-k8s portfolio:

- The example YAML models real threats against the production RKE2/FreeIPA/Splunk/AWX stack
- Mitigations map directly to implemented or planned controls in the abbreviated SSP
- The JSON output can be ingested by AWX surveys or Splunk lookups for automated tracking
- Designed to run in GitHub Actions CI as a gate on threat model changes

CMMC practices referenced align with the control mapping table in the project README.
