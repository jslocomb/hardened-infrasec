"""
Tests for stride_threatmodel.py
"""

import json
import sys
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).parent.parent))
from stride_threatmodel import (
    Asset,
    Mitigation,
    Threat,
    compute_risk_score,
    risk_level,
    max_sensitivity,
    build_risk_register,
    parse_yaml,
    export_json,
    export_csv,
    export_markdown,
)


# ─── Scoring tests ────────────────────────────────────────────────────────────

class TestComputeRiskScore:
    def test_baseline_medium(self):
        score = compute_risk_score(5.0, "medium", "medium", "Spoofing", 0)
        assert score > 0

    def test_critical_asset_higher(self):
        high = compute_risk_score(7.0, "high", "critical", "Elevation of Privilege", 0)
        low = compute_risk_score(7.0, "high", "low", "Elevation of Privilege", 0)
        assert high > low

    def test_controls_reduce_score(self):
        no_controls = compute_risk_score(8.0, "high", "high", "Tampering", 0)
        with_controls = compute_risk_score(8.0, "high", "high", "Tampering", 4)
        assert with_controls < no_controls

    def test_control_discount_capped_at_30(self):
        six_controls = compute_risk_score(8.0, "medium", "high", "Tampering", 6)
        ten_controls = compute_risk_score(8.0, "medium", "high", "Tampering", 10)
        # Beyond 6 controls, discount should be capped (no further reduction)
        assert six_controls == ten_controls

    def test_eop_weighted_highest(self):
        eop = compute_risk_score(8.0, "medium", "high", "Elevation of Privilege", 0)
        dos = compute_risk_score(8.0, "medium", "high", "Denial of Service", 0)
        assert eop > dos

    def test_low_likelihood_reduces(self):
        low = compute_risk_score(8.0, "low", "high", "Tampering", 0)
        high = compute_risk_score(8.0, "high", "high", "Tampering", 0)
        assert low < high


class TestRiskLevel:
    def test_critical(self):
        assert risk_level(25.0) == "CRITICAL"

    def test_high(self):
        assert risk_level(16.0) == "HIGH"

    def test_medium(self):
        assert risk_level(10.0) == "MEDIUM"

    def test_low(self):
        assert risk_level(2.0) == "LOW"

    def test_boundary_critical(self):
        assert risk_level(20.0) == "CRITICAL"

    def test_boundary_high(self):
        assert risk_level(14.0) == "HIGH"


class TestMaxSensitivity:
    def setup_method(self):
        self.asset_map = {
            "a1": Asset("a1", "Low Asset", "compute", "low", ""),
            "a2": Asset("a2", "High Asset", "compute", "high", ""),
            "a3": Asset("a3", "Critical Asset", "compute", "critical", ""),
        }

    def test_returns_highest(self):
        result = max_sensitivity(["a1", "a2"], self.asset_map)
        assert result == "high"

    def test_critical_wins(self):
        result = max_sensitivity(["a1", "a2", "a3"], self.asset_map)
        assert result == "critical"

    def test_missing_asset_ignored(self):
        result = max_sensitivity(["a1", "nonexistent"], self.asset_map)
        assert result == "low"

    def test_empty_list(self):
        result = max_sensitivity([], self.asset_map)
        assert result == "low"


# ─── Register tests ───────────────────────────────────────────────────────────

def make_threat(tid, category, cvss, likelihood, sensitivity_score, controls=0):
    """Helper to create a minimal Threat for testing."""
    mits = [Mitigation("M-X", "Test mitigation", "AC-1", "AC.L2-3.1.1", "low", "high")]
    score = compute_risk_score(cvss, likelihood, "high", category, controls)
    return Threat(
        id=tid, stride_category=category,
        title=f"Threat {tid}", description="",
        affected_assets=[], attack_vector="Network",
        attack_complexity="Low", privileges_required="None",
        user_interaction="None", cvss_base=cvss,
        likelihood=likelihood, existing_controls=["ctrl"] * controls,
        mitigations=mits,
        risk_score=score,
        risk_level=risk_level(score),
        asset_sensitivity_max="high",
    )


class TestBuildRiskRegister:
    def test_sorted_descending(self):
        threats = [
            make_threat("T-1", "Denial of Service", 5.0, "low", 1.0),
            make_threat("T-2", "Elevation of Privilege", 9.8, "high", 3.0),
            make_threat("T-3", "Tampering", 7.0, "medium", 2.0),
        ]
        register = build_risk_register(threats, {})
        scores = [e.risk_score for e in register]
        assert scores == sorted(scores, reverse=True)

    def test_ranks_sequential(self):
        threats = [make_threat(f"T-{i}", "Spoofing", 5.0, "medium", 1.5) for i in range(5)]
        register = build_risk_register(threats, {})
        assert [e.rank for e in register] == list(range(1, 6))

    def test_nist_deduped(self):
        mit1 = Mitigation("M-1", "desc", "AU-2", "AU.L2-3.3.1", "low", "high")
        mit2 = Mitigation("M-2", "desc", "AU-2", "AU.L2-3.3.1", "medium", "high")
        t = make_threat("T-1", "Spoofing", 5.0, "medium", 1.5)
        t.mitigations = [mit1, mit2]
        register = build_risk_register([t], {})
        assert register[0].top_nist_controls == ["AU-2"]


# ─── Parser integration test ──────────────────────────────────────────────────

class TestParseYaml:
    def test_parse_example_file(self, tmp_path):
        example = Path(__file__).parent.parent / "examples" / "homelab-k8s.yaml"
        if not example.exists():
            pytest.skip("Example file not found")
        metadata, assets, threats = parse_yaml(example)
        assert metadata["system"] == "homelab-k8s"
        assert len(assets) > 0
        assert len(threats) > 0

    def test_all_threats_have_scores(self, tmp_path):
        example = Path(__file__).parent.parent / "examples" / "homelab-k8s.yaml"
        if not example.exists():
            pytest.skip("Example file not found")
        _, _, threats = parse_yaml(example)
        for t in threats:
            assert t.risk_score > 0
            assert t.risk_level in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]

    def test_minimal_yaml(self, tmp_path):
        minimal = {
            "metadata": {"system": "test", "cmmc_level": 2},
            "assets": [
                {"id": "a1", "name": "Test", "type": "compute",
                 "sensitivity": "high", "description": ""}
            ],
            "threats": [
                {
                    "id": "T-1", "stride_category": "Spoofing",
                    "title": "Test threat", "description": "",
                    "affected_assets": ["a1"],
                    "attack_vector": "Network", "attack_complexity": "Low",
                    "privileges_required": "None", "user_interaction": "None",
                    "cvss_base": 6.0, "likelihood": "medium",
                    "existing_controls": [],
                    "mitigations": [
                        {"id": "M-1", "description": "Fix it",
                         "nist_control": "AC-1", "cmmc_practice": "AC.L2-3.1.1",
                         "effort": "low", "priority": "high"}
                    ]
                }
            ]
        }
        p = tmp_path / "minimal.yaml"
        p.write_text(yaml.dump(minimal))
        metadata, assets, threats = parse_yaml(p)
        assert len(threats) == 1
        assert threats[0].risk_score > 0


# ─── Export tests ─────────────────────────────────────────────────────────────

class TestExports:
    def setup_method(self):
        from stride_threatmodel import RiskEntry
        self.metadata = {"system": "test", "cmmc_level": 2}
        mit = Mitigation("M-1", "Test fix", "AC-1", "AC.L2-3.1.1", "low", "high")
        self.register = [
            RiskEntry(
                rank=1, threat_id="T-1", stride_category="Spoofing",
                title="Test threat", risk_score=18.5, risk_level="CRITICAL",
                cvss_base=8.5, likelihood="high", affected_assets=["Asset A"],
                asset_sensitivity_max="critical", existing_controls=1,
                mitigations=[mit], top_nist_controls=["AC-1"],
                top_cmmc_practices=["AC.L2-3.1.1"],
            )
        ]

    def test_json_export(self, tmp_path):
        p = tmp_path / "out.json"
        export_json(self.register, self.metadata, p)
        assert p.exists()
        with open(p) as f:
            data = json.load(f)
        assert data["metadata"]["system"] == "test"
        assert len(data["risk_register"]) == 1
        assert data["risk_register"][0]["threat_id"] == "T-1"

    def test_csv_export(self, tmp_path):
        p = tmp_path / "out.csv"
        export_csv(self.register, p)
        assert p.exists()
        lines = p.read_text().splitlines()
        assert len(lines) == 2  # header + 1 data row
        assert "T-1" in lines[1]

    def test_markdown_export(self, tmp_path):
        p = tmp_path / "out.md"
        export_markdown(self.register, self.metadata, p)
        assert p.exists()
        content = p.read_text()
        assert "# STRIDE Risk Register" in content
        assert "T-1" in content
        assert "CMMC Practice Coverage" in content
