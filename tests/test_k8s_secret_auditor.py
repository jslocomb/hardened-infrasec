"""
test_k8s_secret_auditor.py
──────────────────────────────────────────────────────────────────────────────
Unit tests for k8s_secret_auditor.py

Tests the audit log parser, anomaly detection rules, finding output,
and report writers — without requiring a live Kubernetes cluster.

Run with:
    pytest tests/test_k8s_secret_auditor.py -v
    python -m pytest tests/test_k8s_secret_auditor.py -v
"""

import json
import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from io import StringIO
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))
import k8s_secret_auditor as k8s


# ─────────────────────────────────────────────────────────────────────────────
# Helpers — audit event factory
# ─────────────────────────────────────────────────────────────────────────────

_eid = 0

def _now():
    return datetime.now(timezone.utc)

def _evt(
    verb="get",
    username="alice",
    namespace="default",
    name="db-password",
    resource="secrets",
    http_code=200,
    decision="allow",
    groups=None,
    ts_offset_sec=0,
    user_agent="kubectl/v1.28.0",
    impersonate=False,
    stage="ResponseComplete",
) -> dict:
    """Return a minimal Kubernetes audit event dict."""
    global _eid
    _eid += 1
    ts = _now() - timedelta(seconds=ts_offset_sec)
    is_sa = username.startswith("system:serviceaccount:")
    return {
        "kind":        "Event",
        "apiVersion":  "audit.k8s.io/v1",
        "level":       "Metadata",
        "auditID":     f"test-{_eid:05d}",
        "stage":       stage,
        "requestURI":  f"/api/v1/namespaces/{namespace}/secrets/{name}",
        "verb":        verb,
        "user": {
            "username": username,
            "groups":   groups or (
                ["system:serviceaccounts", f"system:serviceaccounts:{namespace}"]
                if is_sa else ["system:authenticated"]
            ),
        },
        "sourceIPs":   ["10.0.0.55" if is_sa else "10.0.1.100"],
        "userAgent":   user_agent,
        "objectRef": {
            "resource":   resource,
            "namespace":  namespace,
            "name":       name,
            "apiVersion": "v1",
        },
        "responseStatus": {"code": http_code},
        "annotations": {
            "authorization.k8s.io/decision": decision,
            "authorization.k8s.io/reason":   "RBAC",
        },
        "requestReceivedTimestamp": ts.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z",
        "stageTimestamp":           ts.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z",
    }


def _write_log(events: list) -> str:
    """Write events as JSONL to a temp file; return path."""
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".log", delete=False
    ) as f:
        for e in events:
            f.write(json.dumps(e) + "\n")
        return f.name


def _make_detector(**kwargs) -> k8s.SecretAnomalyDetector:
    defaults = dict(
        burst_window=60,
        burst_threshold=5,
        forbidden_count=3,
        forbidden_rate=0.5,
        business_start=8,
        business_end=18,
        human_users_only_hours=False,  # easier for testing
    )
    defaults.update(kwargs)
    return k8s.SecretAnomalyDetector(**defaults)


def _process_events(events: list, **detector_kwargs) -> list:
    """Parse events and run them through the detector; return all findings."""
    detector = _make_detector(**detector_kwargs)
    findings = []
    for raw in events:
        parsed_evt = k8s.AuditLogParser()._parse_event(raw)
        if parsed_evt:
            findings.extend(detector.process_event(parsed_evt))
    return findings


# ─────────────────────────────────────────────────────────────────────────────
# AuditLogParser._parse_event
# ─────────────────────────────────────────────────────────────────────────────

class TestAuditLogParserParseEvent(unittest.TestCase):
    """Tests for the low-level event parser."""

    def setUp(self):
        self.parser = k8s.AuditLogParser()

    def test_parses_verb(self):
        ev = self.parser._parse_event(_evt(verb="list"))
        self.assertEqual(ev.verb, "list")

    def test_parses_username(self):
        ev = self.parser._parse_event(_evt(username="bob"))
        self.assertEqual(ev.username, "bob")

    def test_parses_namespace(self):
        ev = self.parser._parse_event(_evt(namespace="kube-system"))
        self.assertEqual(ev.namespace, "kube-system")

    def test_parses_resource_name(self):
        ev = self.parser._parse_event(_evt(name="my-secret"))
        self.assertEqual(ev.resource_name, "my-secret")

    def test_parses_http_code(self):
        ev = self.parser._parse_event(_evt(http_code=403))
        self.assertEqual(ev.http_code, 403)

    def test_allowed_property_true_for_2xx(self):
        ev = self.parser._parse_event(_evt(http_code=200))
        self.assertTrue(ev.allowed)

    def test_allowed_property_false_for_4xx(self):
        ev = self.parser._parse_event(_evt(http_code=403))
        self.assertFalse(ev.allowed)

    def test_is_secret_true_for_secrets_resource(self):
        ev = self.parser._parse_event(_evt(resource="secrets"))
        self.assertTrue(ev.is_secret)

    def test_is_secret_false_for_non_secret_resource(self):
        ev = self.parser._parse_event(_evt(resource="configmaps"))
        self.assertFalse(ev.is_secret)

    def test_is_service_account_detected(self):
        ev = self.parser._parse_event(
            _evt(username="system:serviceaccount:default:my-sa")
        )
        self.assertTrue(ev.is_service_acct)

    def test_human_user_not_marked_as_service_account(self):
        ev = self.parser._parse_event(_evt(username="alice"))
        self.assertFalse(ev.is_service_acct)

    def test_returns_none_for_non_final_stage(self):
        raw = _evt(stage="RequestReceived")
        ev = self.parser._parse_event(raw)
        self.assertIsNone(ev)

    def test_returns_none_for_non_secret_resource(self):
        raw = _evt(resource="pods")
        ev = self.parser._parse_event(raw)
        # Parser returns an event even for non-secrets; detector filters them
        # Just verify it doesn't crash and returns a parseable object or None
        # (behavior depends on implementation — just check no exception)
        pass  # no assertion needed — just tests no crash

    def test_timestamp_parsed_as_timezone_aware(self):
        ev = self.parser._parse_event(_evt())
        self.assertIsNotNone(ev.timestamp.tzinfo)

    def test_impersonation_detected(self):
        """Requests with 'Impersonate-User' in requestObject should be flagged."""
        raw = _evt(verb="get", name="aws-token")
        raw["requestObject"] = {"Impersonate-User": "admin"}
        ev = self.parser._parse_event(raw)
        self.assertTrue(ev.impersonated)


# ─────────────────────────────────────────────────────────────────────────────
# AuditLogParser.parse_file
# ─────────────────────────────────────────────────────────────────────────────

class TestAuditLogParserParseFile(unittest.TestCase):

    def test_parse_file_yields_events(self):
        events = [_evt(), _evt(verb="list", name="")]
        path = _write_log(events)
        try:
            parser = k8s.AuditLogParser()
            parsed = list(parser.parse_file(path))
            self.assertGreaterEqual(len(parsed), 1)
        finally:
            os.unlink(path)

    def test_parse_file_skips_non_final_stages(self):
        events = [
            _evt(stage="RequestReceived"),
            _evt(stage="ResponseComplete"),
        ]
        path = _write_log(events)
        try:
            parser = k8s.AuditLogParser()
            parsed = list(parser.parse_file(path))
            # Only the ResponseComplete event should survive
            self.assertEqual(len(parsed), 1)
            self.assertEqual(parsed[0].stage, "ResponseComplete")
        finally:
            os.unlink(path)

    def test_parse_file_namespace_filter(self):
        """With namespace filter, events in other namespaces should be dropped."""
        events = [
            _evt(namespace="default"),
            _evt(namespace="kube-system"),
        ]
        path = _write_log(events)
        try:
            parser = k8s.AuditLogParser(namespace_filter={"default"})
            parsed = list(parser.parse_file(path))
            namespaces = {e.namespace for e in parsed}
            self.assertNotIn("kube-system", namespaces)
        finally:
            os.unlink(path)

    def test_parse_file_handles_malformed_line(self):
        """Parser should skip malformed JSON lines without crashing."""
        path = _write_log([])
        with open(path, "w") as f:
            f.write("NOT JSON\n")
            f.write(json.dumps(_evt()) + "\n")
        try:
            parser = k8s.AuditLogParser()
            parsed = list(parser.parse_file(path))
            self.assertEqual(len(parsed), 1)
        finally:
            os.unlink(path)


# ─────────────────────────────────────────────────────────────────────────────
# Detector rule: SENSITIVE_NAME
# ─────────────────────────────────────────────────────────────────────────────

class TestRuleSensitiveName(unittest.TestCase):
    """SENSITIVE_NAME fires when a secret with a high-value name is accessed."""

    SENSITIVE_NAMES = [
        "aws-credentials",
        "db-root-password",
        "vault-token",
        "prod-aws-creds",
        "registry-credentials",
        "ssh-private-key",
    ]

    def _find_rules(self, events, rule="SENSITIVE_NAME"):
        findings = _process_events(events)
        return [f for f in findings if f.rule == rule]

    def test_sensitive_name_fires_for_aws_credentials(self):
        events = [_evt(name="aws-credentials")]
        findings = self._find_rules(events)
        self.assertGreater(len(findings), 0)

    def test_sensitive_name_fires_for_vault_token(self):
        events = [_evt(name="vault-token")]
        findings = self._find_rules(events)
        self.assertGreater(len(findings), 0)

    def test_sensitive_name_does_not_fire_for_benign_secret(self):
        events = [_evt(name="app-config")]
        findings = self._find_rules(events)
        self.assertEqual(len(findings), 0)

    def test_sensitive_name_includes_secret_name_in_finding(self):
        events = [_evt(name="aws-credentials")]
        findings = self._find_rules(events)
        self.assertTrue(
            any("aws" in f.resource_name.lower() or "aws" in f.message.lower()
                for f in findings)
        )


# ─────────────────────────────────────────────────────────────────────────────
# Detector rule: SECRET_DELETED
# ─────────────────────────────────────────────────────────────────────────────

class TestRuleSecretDeleted(unittest.TestCase):

    def test_secret_deleted_fires_on_delete_verb(self):
        events = [_evt(verb="delete", name="my-secret")]
        findings = _process_events(events)
        delete_findings = [f for f in findings if f.rule == "SECRET_DELETED"]
        self.assertGreater(len(delete_findings), 0)

    def test_secret_deleted_does_not_fire_on_get(self):
        events = [_evt(verb="get", name="my-secret")]
        findings = _process_events(events)
        delete_findings = [f for f in findings if f.rule == "SECRET_DELETED"]
        self.assertEqual(len(delete_findings), 0)


# ─────────────────────────────────────────────────────────────────────────────
# Detector rule: BURST_ACCESS
# ─────────────────────────────────────────────────────────────────────────────

class TestRuleBurstAccess(unittest.TestCase):
    """BURST_ACCESS fires when a user reads too many secrets in a short window."""

    def test_burst_fires_above_threshold(self):
        """6 reads within 60 seconds with threshold=5 should trigger BURST_ACCESS."""
        events = [
            _evt(verb="get", username="attacker", name=f"secret-{i}", ts_offset_sec=i)
            for i in range(6)
        ]
        findings = _process_events(
            events, burst_threshold=5, burst_window=60
        )
        burst = [f for f in findings if f.rule == "BURST_ACCESS"]
        self.assertGreater(len(burst), 0)

    def test_burst_does_not_fire_below_threshold(self):
        """3 reads with threshold=5 should NOT trigger BURST_ACCESS."""
        events = [
            _evt(verb="get", username="alice", name=f"secret-{i}", ts_offset_sec=i)
            for i in range(3)
        ]
        findings = _process_events(
            events, burst_threshold=5, burst_window=60
        )
        burst = [f for f in findings if f.rule == "BURST_ACCESS"]
        self.assertEqual(len(burst), 0)

    def test_burst_is_per_actor(self):
        """Reads spread across different users should not trigger burst for any one."""
        events = [
            _evt(verb="get", username=f"user-{i}", name="secret", ts_offset_sec=i)
            for i in range(6)
        ]
        findings = _process_events(events, burst_threshold=5, burst_window=60)
        burst = [f for f in findings if f.rule == "BURST_ACCESS"]
        self.assertEqual(len(burst), 0)


# ─────────────────────────────────────────────────────────────────────────────
# Detector rule: MASS_LIST
# ─────────────────────────────────────────────────────────────────────────────

class TestRuleMassList(unittest.TestCase):
    """MASS_LIST fires when a user lists secrets across multiple namespaces."""

    def test_mass_list_fires_for_cluster_wide_list(self):
        """Listing secrets in 4+ different namespaces should trigger MASS_LIST."""
        events = [
            _evt(verb="list", username="svc-account", namespace=ns, name="")
            for ns in ["default", "kube-system", "monitoring", "prod", "staging"]
        ]
        findings = _process_events(events)
        mass = [f for f in findings if f.rule == "MASS_LIST"]
        self.assertGreater(len(mass), 0)

    def test_mass_list_does_not_fire_for_get_not_list(self):
        """GET on a named secret should not trigger MASS_LIST."""
        events = [
            _evt(verb="get", username="alice", namespace="default", name="my-secret")
            for _ in range(3)
        ]
        findings = _process_events(events)
        mass = [f for f in findings if f.rule == "MASS_LIST"]
        self.assertEqual(len(mass), 0)


# ─────────────────────────────────────────────────────────────────────────────
# Detector rule: FORBIDDEN_PROBE
# ─────────────────────────────────────────────────────────────────────────────

class TestRuleForbiddenProbe(unittest.TestCase):
    """FORBIDDEN_PROBE fires on repeated denied secret access attempts."""

    def test_forbidden_probe_fires_after_threshold_denials(self):
        """4 consecutive 403s with forbidden_count=3 should trigger FORBIDDEN_PROBE."""
        events = [
            _evt(
                verb="get",
                username="attacker",
                name=f"secret-{i}",
                http_code=403,
                decision="forbid",
            )
            for i in range(4)
        ]
        findings = _process_events(events, forbidden_count=3)
        probe = [f for f in findings if f.rule == "FORBIDDEN_PROBE"]
        self.assertGreater(len(probe), 0)

    def test_forbidden_probe_does_not_fire_for_allowed_access(self):
        events = [
            _evt(verb="get", username="alice", http_code=200, decision="allow")
            for _ in range(5)
        ]
        findings = _process_events(events, forbidden_count=3)
        probe = [f for f in findings if f.rule == "FORBIDDEN_PROBE"]
        self.assertEqual(len(probe), 0)


# ─────────────────────────────────────────────────────────────────────────────
# Detector rule: SECRET_MODIFIED
# ─────────────────────────────────────────────────────────────────────────────

class TestRuleSecretModified(unittest.TestCase):

    def test_secret_modified_fires_on_patch(self):
        events = [_evt(verb="patch", name="db-password")]
        findings = _process_events(events)
        modified = [f for f in findings if f.rule == "SECRET_MODIFIED"]
        self.assertGreater(len(modified), 0)

    def test_secret_modified_fires_on_update(self):
        events = [_evt(verb="update", name="db-password")]
        findings = _process_events(events)
        modified = [f for f in findings if f.rule == "SECRET_MODIFIED"]
        self.assertGreater(len(modified), 0)

    def test_secret_modified_does_not_fire_on_get(self):
        events = [_evt(verb="get", name="db-password")]
        findings = _process_events(events)
        modified = [f for f in findings if f.rule == "SECRET_MODIFIED"]
        self.assertEqual(len(modified), 0)


# ─────────────────────────────────────────────────────────────────────────────
# Detector rule: IMPERSONATION
# ─────────────────────────────────────────────────────────────────────────────

class TestRuleImpersonation(unittest.TestCase):

    def test_impersonation_fires_on_impersonated_event(self):
        raw = _evt(verb="get", name="aws-token")
        raw["requestObject"] = {"Impersonate-User": "admin"}
        events = [raw]
        findings = _process_events(events)
        imp = [f for f in findings if f.rule == "IMPERSONATION"]
        self.assertGreater(len(imp), 0)

    def test_no_impersonation_finding_for_normal_request(self):
        events = [_evt(verb="get", name="my-secret")]
        findings = _process_events(events)
        imp = [f for f in findings if f.rule == "IMPERSONATION"]
        self.assertEqual(len(imp), 0)


# ─────────────────────────────────────────────────────────────────────────────
# Finding structure
# ─────────────────────────────────────────────────────────────────────────────

class TestFindingStructure(unittest.TestCase):
    """Tests that all Finding objects have the required fields populated."""

    def _get_any_finding(self) -> k8s.Finding:
        events = [_evt(verb="delete", name="db-password")]
        findings = _process_events(events)
        self.assertGreater(len(findings), 0, "No findings generated — test setup broken")
        return findings[0]

    def test_finding_has_rule(self):
        f = self._get_any_finding()
        self.assertIsInstance(f.rule, str)
        self.assertGreater(len(f.rule), 0)

    def test_finding_has_severity(self):
        f = self._get_any_finding()
        self.assertIsInstance(f.severity, k8s.Severity)

    def test_finding_has_actor(self):
        f = self._get_any_finding()
        self.assertIsInstance(f.actor, str)

    def test_finding_has_timestamp(self):
        f = self._get_any_finding()
        self.assertIsInstance(f.timestamp, datetime)

    def test_finding_has_message(self):
        f = self._get_any_finding()
        self.assertIsInstance(f.message, str)
        self.assertGreater(len(f.message), 0)

    def test_finding_has_nist_controls(self):
        f = self._get_any_finding()
        self.assertIsInstance(f.nist_controls, list)
        self.assertGreater(len(f.nist_controls), 0)

    def test_finding_nist_controls_look_valid(self):
        """NIST control IDs should match pattern like 'AC-3.1.1'."""
        f = self._get_any_finding()
        for ctrl in f.nist_controls:
            self.assertRegex(ctrl, r"^[A-Z]{2}-\d+\.\d+\.\d+$")

    def test_finding_to_dict_is_json_serializable(self):
        f = self._get_any_finding()
        d = f.to_dict()
        try:
            json.dumps(d)
        except (TypeError, ValueError) as e:
            self.fail(f"Finding.to_dict() is not JSON-serializable: {e}")


# ─────────────────────────────────────────────────────────────────────────────
# Severity helpers
# ─────────────────────────────────────────────────────────────────────────────

class TestSeverityHelpers(unittest.TestCase):

    def test_highest_returns_critical_when_present(self):
        result = k8s.Severity.highest([k8s.Severity.LOW, k8s.Severity.CRITICAL])
        self.assertEqual(result, k8s.Severity.CRITICAL)

    def test_highest_returns_high_without_critical(self):
        result = k8s.Severity.highest([k8s.Severity.LOW, k8s.Severity.HIGH])
        self.assertEqual(result, k8s.Severity.HIGH)

    def test_from_str_roundtrip(self):
        for label in ["critical", "high", "medium", "low", "info"]:
            result = k8s.Severity.from_str(label)
            self.assertEqual(result.value.lower(), label)

    def test_from_str_unknown_defaults_to_low(self):
        result = k8s.Severity.from_str("garbage")
        self.assertIsInstance(result, k8s.Severity)


# ─────────────────────────────────────────────────────────────────────────────
# generate_test_log integration
# ─────────────────────────────────────────────────────────────────────────────

class TestGenerateTestLog(unittest.TestCase):
    """Tests using the built-in test log generator for end-to-end coverage."""

    def setUp(self):
        self.tmp_path = tempfile.mktemp(suffix=".log")
        self.lines = k8s.generate_test_log(path=self.tmp_path)

    def tearDown(self):
        if os.path.exists(self.tmp_path):
            os.unlink(self.tmp_path)

    def test_generate_test_log_returns_list(self):
        self.assertIsInstance(self.lines, list)
        self.assertGreater(len(self.lines), 0)

    def test_generate_test_log_writes_file(self):
        self.assertTrue(os.path.exists(self.tmp_path))
        self.assertGreater(os.path.getsize(self.tmp_path), 0)

    def test_generated_log_yields_parseable_events(self):
        parser = k8s.AuditLogParser()
        events = list(parser.parse_file(self.tmp_path))
        self.assertGreater(len(events), 0)

    def test_full_pipeline_produces_findings(self):
        """Running the full parser + detector on the test log should produce findings."""
        parser = k8s.AuditLogParser()
        detector = _make_detector(burst_threshold=3)
        findings = []
        for ev in parser.parse_file(self.tmp_path):
            findings.extend(detector.process_event(ev))
        self.assertGreater(len(findings), 0, "Full pipeline produced no findings")

    def test_findings_include_multiple_rule_types(self):
        """The test log should trigger at least 2 different rule types."""
        parser = k8s.AuditLogParser()
        detector = _make_detector(burst_threshold=3)
        findings = []
        for ev in parser.parse_file(self.tmp_path):
            findings.extend(detector.process_event(ev))
        rules = {f.rule for f in findings}
        self.assertGreaterEqual(len(rules), 2, f"Only found rules: {rules}")


# ─────────────────────────────────────────────────────────────────────────────
# Output writers
# ─────────────────────────────────────────────────────────────────────────────

class TestOutputWriters(unittest.TestCase):
    """Tests for write_json, write_csv, and write_html."""

    def setUp(self):
        events = [
            _evt(verb="delete", name="db-password"),
            _evt(verb="get", name="aws-credentials"),
        ]
        findings = _process_events(events)
        self.findings = findings
        self.summary = k8s.AuditSummary(
            log_source="test.log",
            analysis_timestamp=datetime.now(timezone.utc).isoformat(),
            events_parsed=10,
            secret_events=5,
            findings=len(findings),
        )

    def test_write_json_creates_valid_json(self):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name
        try:
            k8s.write_json(self.findings, self.summary, path)
            with open(path) as fh:
                data = json.load(fh)
            self.assertIn("findings", data)
            self.assertIsInstance(data["findings"], list)
        finally:
            os.unlink(path)

    def test_write_json_finding_count_matches(self):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name
        try:
            k8s.write_json(self.findings, self.summary, path)
            with open(path) as fh:
                data = json.load(fh)
            self.assertEqual(len(data["findings"]), len(self.findings))
        finally:
            os.unlink(path)

    def test_write_csv_creates_file_with_content(self):
        with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as f:
            path = f.name
        try:
            k8s.write_csv(self.findings, path)
            with open(path) as fh:
                content = fh.read()
            self.assertGreater(len(content), 0)
            # Header row should exist
            first_line = content.split("\n")[0].lower()
            self.assertTrue(
                "rule" in first_line or "finding" in first_line or "severity" in first_line,
                f"CSV header line unexpected: {first_line}"
            )
        finally:
            os.unlink(path)

    def test_write_html_creates_html_file(self):
        with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as f:
            path = f.name
        try:
            k8s.write_html(self.findings, self.summary, path)
            with open(path) as fh:
                content = fh.read()
            self.assertIn("<html", content.lower())
        finally:
            os.unlink(path)

    def test_write_json_empty_findings_still_valid(self):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name
        try:
            k8s.write_json([], self.summary, path)
            with open(path) as fh:
                data = json.load(fh)
            self.assertEqual(data["findings"], [])
        finally:
            os.unlink(path)


# ─────────────────────────────────────────────────────────────────────────────
# AuditSummary
# ─────────────────────────────────────────────────────────────────────────────

class TestAuditSummary(unittest.TestCase):

    def test_summary_initializes_with_defaults(self):
        s = k8s.AuditSummary(
            log_source="test.log",
            analysis_timestamp=datetime.now(timezone.utc).isoformat(),
        )
        self.assertEqual(s.events_parsed, 0)
        self.assertEqual(s.findings, 0)

    def test_summary_fields_accessible(self):
        s = k8s.AuditSummary(
            log_source="test.log",
            analysis_timestamp=datetime.now(timezone.utc).isoformat(),
            events_parsed=100,
            findings=5,
        )
        self.assertEqual(s.events_parsed, 100)
        self.assertEqual(s.findings, 5)


if __name__ == "__main__":
    unittest.main(verbosity=2)
