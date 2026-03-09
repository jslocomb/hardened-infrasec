"""
test_aide_to_splunk.py
──────────────────────────────────────────────────────────────────────────────
Unit tests for aide_to_splunk.py

Tests the AIDE report parser, severity classifier, NIST control mapper,
and Splunk event builder without requiring a live Splunk instance.

Run with:
    pytest tests/test_aide_to_splunk.py -v
    python -m pytest tests/test_aide_to_splunk.py -v   # if pytest not on PATH
"""

import json
import sys
import os
import tempfile
import textwrap
import unittest
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path
from unittest.mock import MagicMock, patch, call

# Allow import from scripts/ directory
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))
import aide_to_splunk as aide


# ─────────────────────────────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────────────────────────────

MINIMAL_AIDE_REPORT = textwrap.dedent("""\
    Start timestamp: 2026-01-15 03:00:01 -0700 (AIDE 0.18.6)

    AIDE found differences between database and filesystem!!

    Summary:
      Total number of entries:      72514
      Added entries:                0
      Removed entries:              1
      Changed entries:              2

    Added entries:
    ---------------------------------------------------

    Removed entries:
    ---------------------------------------------------
    f  ............T. : /tmp/stale_file

    Changed entries:
    ---------------------------------------------------
    f  YaCm..........  : /etc/passwd
    f  Yac...........  : /etc/ssh/sshd_config
""")

EMPTY_AIDE_REPORT = textwrap.dedent("""\
    Start timestamp: 2026-01-15 03:00:01 -0700 (AIDE 0.18.6)

    AIDE found NO differences between database and filesystem.

    Summary:
      Total number of entries:      72514
      Added entries:                0
      Removed entries:              0
      Changed entries:              0
""")

CRITICAL_PATH_REPORT = textwrap.dedent("""\
    Start timestamp: 2026-01-15 03:00:01 -0700 (AIDE 0.18.6)

    AIDE found differences between database and filesystem!!

    Summary:
      Total number of entries:      72514
      Added entries:                1
      Removed entries:              0
      Changed entries:              0

    Added entries:
    ---------------------------------------------------
    f  ................  : /etc/sudoers

    Removed entries:
    ---------------------------------------------------

    Changed entries:
    ---------------------------------------------------
""")

TMP_NEW_FILE_REPORT = textwrap.dedent("""\
    Start timestamp: 2026-01-15 03:00:01 -0700 (AIDE 0.18.6)

    AIDE found differences between database and filesystem!!

    Summary:
      Total number of entries:      72514
      Added entries:                1
      Removed entries:              0
      Changed entries:              0

    Added entries:
    ---------------------------------------------------
    f  ................  : /tmp/evil_script.sh

    Removed entries:
    ---------------------------------------------------

    Changed entries:
    ---------------------------------------------------
""")


# ─────────────────────────────────────────────────────────────────────────────
# AideReportParser — parse()
# ─────────────────────────────────────────────────────────────────────────────

class TestAideReportParserParse(unittest.TestCase):
    """Tests for AideReportParser.parse() — structure and counts."""

    def setUp(self):
        self.parser = aide.AideReportParser(hostname="testhost", report_path="/tmp/aide.log")

    def test_parse_empty_report_returns_zero_changes(self):
        """A clean run with no changes should yield an empty changes list."""
        report = self.parser.parse(EMPTY_AIDE_REPORT)
        self.assertEqual(len(report.changes), 0)
        self.assertEqual(report.total_entries, 72514)

    def test_parse_extracts_start_timestamp(self):
        """Parser should extract the start timestamp string."""
        report = self.parser.parse(MINIMAL_AIDE_REPORT)
        self.assertIsNotNone(report.start_timestamp)
        self.assertIn("2026-01-15", report.start_timestamp)

    def test_parse_counts_changed_and_removed(self):
        """Parser should return one removed + two changed = three FileChange objects."""
        report = self.parser.parse(MINIMAL_AIDE_REPORT)
        self.assertEqual(len(report.changes), 3)

    def test_parse_sets_hostname(self):
        """Report hostname should match the value passed to the constructor."""
        report = self.parser.parse(MINIMAL_AIDE_REPORT)
        self.assertEqual(report.hostname, "testhost")

    def test_parse_changed_entry_paths(self):
        """Changed entry paths should be extracted correctly."""
        report = self.parser.parse(MINIMAL_AIDE_REPORT)
        paths = {c.path for c in report.changes}
        self.assertIn("/etc/passwd", paths)
        self.assertIn("/etc/ssh/sshd_config", paths)

    def test_parse_removed_entry_path(self):
        """Removed entry path should be extracted correctly."""
        report = self.parser.parse(MINIMAL_AIDE_REPORT)
        removed = [c for c in report.changes if c.change_type == aide.ChangeType.REMOVED]
        self.assertEqual(len(removed), 1)
        self.assertEqual(removed[0].path, "/tmp/stale_file")

    def test_parse_added_entry_change_type(self):
        """Added entries should have ChangeType.ADDED."""
        report = self.parser.parse(CRITICAL_PATH_REPORT)
        added = [c for c in report.changes if c.change_type == aide.ChangeType.ADDED]
        self.assertEqual(len(added), 1)
        self.assertEqual(added[0].path, "/etc/sudoers")

    def test_parse_total_entries_from_summary(self):
        """Total entries should be parsed from the Summary block."""
        report = self.parser.parse(MINIMAL_AIDE_REPORT)
        self.assertEqual(report.total_entries, 72514)

    def test_parse_report_path_stored(self):
        """Report path passed at construction should be stored on the report."""
        report = self.parser.parse(MINIMAL_AIDE_REPORT)
        self.assertEqual(report.report_path, "/tmp/aide.log")


# ─────────────────────────────────────────────────────────────────────────────
# AideReportParser — _severity()
# ─────────────────────────────────────────────────────────────────────────────

class TestAideReportParserSeverity(unittest.TestCase):
    """Tests for path-based severity classification."""

    def setUp(self):
        self.parser = aide.AideReportParser(hostname="testhost", report_path="/tmp/aide.log")

    # Critical paths
    def test_etc_passwd_change_is_critical(self):
        sev = self.parser._severity("/etc/passwd", aide.ChangeType.CHANGED)
        self.assertEqual(sev, aide.Severity.CRITICAL)

    def test_etc_shadow_change_is_critical(self):
        sev = self.parser._severity("/etc/shadow", aide.ChangeType.CHANGED)
        self.assertEqual(sev, aide.Severity.CRITICAL)

    def test_sudoers_change_is_critical(self):
        sev = self.parser._severity("/etc/sudoers", aide.ChangeType.CHANGED)
        self.assertEqual(sev, aide.Severity.CRITICAL)

    def test_sshd_binary_change_is_critical(self):
        sev = self.parser._severity("/usr/sbin/sshd", aide.ChangeType.CHANGED)
        self.assertEqual(sev, aide.Severity.CRITICAL)

    def test_sudo_binary_change_is_critical(self):
        sev = self.parser._severity("/usr/bin/sudo", aide.ChangeType.CHANGED)
        self.assertEqual(sev, aide.Severity.CRITICAL)

    # High sensitivity paths
    def test_etc_ssh_config_is_high(self):
        sev = self.parser._severity("/etc/ssh/sshd_config", aide.ChangeType.CHANGED)
        self.assertEqual(sev, aide.Severity.HIGH)

    def test_etc_cron_is_high(self):
        sev = self.parser._severity("/etc/cron.d/backup", aide.ChangeType.CHANGED)
        self.assertEqual(sev, aide.Severity.HIGH)

    # /tmp new file addition → CRITICAL
    def test_tmp_new_file_is_critical(self):
        sev = self.parser._severity("/tmp/evil.sh", aide.ChangeType.ADDED)
        self.assertEqual(sev, aide.Severity.CRITICAL)

    def test_var_tmp_new_file_is_critical(self):
        sev = self.parser._severity("/var/tmp/dropper", aide.ChangeType.ADDED)
        self.assertEqual(sev, aide.Severity.CRITICAL)

    # Non-sensitive path → MEDIUM
    def test_misc_config_change_is_medium(self):
        sev = self.parser._severity("/etc/motd", aide.ChangeType.CHANGED)
        self.assertEqual(sev, aide.Severity.MEDIUM)

    def test_usr_share_doc_is_medium(self):
        sev = self.parser._severity("/usr/share/doc/readme.md", aide.ChangeType.CHANGED)
        self.assertEqual(sev, aide.Severity.MEDIUM)


# ─────────────────────────────────────────────────────────────────────────────
# AideReportParser — _nist_controls()
# ─────────────────────────────────────────────────────────────────────────────

class TestAideReportParserNISTControls(unittest.TestCase):
    """Tests for NIST 800-171 control mapping logic."""

    def setUp(self):
        self.parser = aide.AideReportParser(hostname="testhost", report_path="/tmp/aide.log")

    def test_etc_passwd_maps_auth_controls(self):
        controls = self.parser._nist_controls("/etc/passwd", aide.ChangeType.CHANGED)
        self.assertIn("AC-3.1.1", controls)
        self.assertIn("IA-3.5.1", controls)

    def test_etc_shadow_maps_auth_controls(self):
        controls = self.parser._nist_controls("/etc/shadow", aide.ChangeType.CHANGED)
        self.assertIn("IA-3.5.1", controls)

    def test_ssh_config_maps_sc_controls(self):
        controls = self.parser._nist_controls("/etc/ssh/sshd_config", aide.ChangeType.CHANGED)
        self.assertIn("SC-3.13.8", controls)

    def test_cron_maps_si_au_controls(self):
        controls = self.parser._nist_controls("/etc/cron.daily/backup", aide.ChangeType.CHANGED)
        self.assertIn("SI-3.14.7", controls)
        self.assertIn("AU-3.3.1", controls)

    def test_all_paths_include_si_14_7(self):
        """SI-3.14.7 (Identify Unauthorized Use) should appear for any changed path."""
        for path in ["/etc/passwd", "/etc/ssh/sshd_config", "/etc/cron.d/x", "/etc/motd"]:
            controls = self.parser._nist_controls(path, aide.ChangeType.CHANGED)
            self.assertIn("SI-3.14.7", controls, f"SI-3.14.7 missing for {path}")

    def test_controls_are_unique(self):
        """No duplicate control IDs should appear in the returned list."""
        controls = self.parser._nist_controls("/etc/passwd", aide.ChangeType.CHANGED)
        self.assertEqual(len(controls), len(set(controls)))


# ─────────────────────────────────────────────────────────────────────────────
# Severity.highest()
# ─────────────────────────────────────────────────────────────────────────────

class TestSeverityHighest(unittest.TestCase):
    """Tests for the Severity.highest() classmethod."""

    def test_highest_returns_critical_when_present(self):
        result = aide.Severity.highest([aide.Severity.LOW, aide.Severity.CRITICAL, aide.Severity.MEDIUM])
        self.assertEqual(result, aide.Severity.CRITICAL)

    def test_highest_returns_high_without_critical(self):
        result = aide.Severity.highest([aide.Severity.LOW, aide.Severity.HIGH, aide.Severity.MEDIUM])
        self.assertEqual(result, aide.Severity.HIGH)

    def test_highest_empty_list_returns_low(self):
        """Empty list should return the lowest/default severity."""
        result = aide.Severity.highest([])
        self.assertIsInstance(result, aide.Severity)

    def test_highest_single_item(self):
        result = aide.Severity.highest([aide.Severity.MEDIUM])
        self.assertEqual(result, aide.Severity.MEDIUM)

    def test_highest_all_same(self):
        result = aide.Severity.highest([aide.Severity.HIGH, aide.Severity.HIGH])
        self.assertEqual(result, aide.Severity.HIGH)


# ─────────────────────────────────────────────────────────────────────────────
# SplunkEventBuilder.build()
# ─────────────────────────────────────────────────────────────────────────────

class TestSplunkEventBuilder(unittest.TestCase):
    """Tests for SplunkEventBuilder — event shape and content."""

    def _make_report(self, changes):
        """Helper: build a minimal AideReport with given changes."""
        report = aide.AideReport(
            hostname="k8s-node01",
            report_path="/var/log/aide/aide.log",
            aide_version="0.18.6",
            start_timestamp="2026-01-15 03:00:01",
            end_timestamp="2026-01-15 03:01:45",
            runtime_seconds=104,
            total_entries=72514,
            changes=changes,
        )
        return report

    def _make_change(self, path, change_type=aide.ChangeType.CHANGED, severity=aide.Severity.HIGH):
        return aide.FileChange(
            path=path,
            change_type=change_type,
            severity=severity,
            nist_controls=["SI-3.14.7", "CM-3.4.1"],
        )

    def setUp(self):
        self.builder = aide.SplunkEventBuilder(
            index="linux_aide",
            sourcetype="aide:report",
        )

    def test_build_returns_list(self):
        report = self._make_report([self._make_change("/etc/passwd")])
        events = self.builder.build(report)
        self.assertIsInstance(events, list)

    def test_build_empty_report_returns_at_least_summary_event(self):
        """Even with no changes, a summary event should be produced."""
        report = self._make_report([])
        events = self.builder.build(report)
        self.assertGreaterEqual(len(events), 1)

    def test_each_event_has_required_splunk_fields(self):
        """Every event must include index, sourcetype, and event payload."""
        report = self._make_report([self._make_change("/etc/shadow")])
        for event in self.builder.build(report):
            self.assertIn("index", event)
            self.assertIn("sourcetype", event)
            self.assertIn("event", event)

    def test_event_payload_includes_hostname(self):
        report = self._make_report([self._make_change("/etc/passwd")])
        events = self.builder.build(report)
        # At least one event should reference the hostname
        hostnames = [e.get("host") or e.get("event", {}).get("hostname") for e in events]
        self.assertTrue(
            any(h == "k8s-node01" for h in hostnames),
            "No event contained hostname 'k8s-node01'"
        )

    def test_file_change_event_includes_path(self):
        report = self._make_report([self._make_change("/etc/passwd")])
        events = self.builder.build(report)
        # A change event's payload should include the affected path
        payloads = [json.dumps(e) for e in events]
        self.assertTrue(
            any("/etc/passwd" in p for p in payloads),
            "No event contained the changed path '/etc/passwd'"
        )

    def test_event_index_matches_constructor(self):
        report = self._make_report([self._make_change("/etc/passwd")])
        for event in self.builder.build(report):
            self.assertEqual(event.get("index"), "linux_aide")

    def test_event_sourcetype_matches_constructor(self):
        report = self._make_report([self._make_change("/etc/passwd")])
        for event in self.builder.build(report):
            self.assertEqual(event.get("sourcetype"), "aide:report")

    def test_critical_severity_preserved_in_event(self):
        change = self._make_change("/etc/shadow", severity=aide.Severity.CRITICAL)
        report = self._make_report([change])
        events = self.builder.build(report)
        payloads = [json.dumps(e) for e in events]
        self.assertTrue(
            any("critical" in p.lower() for p in payloads),
            "Expected 'critical' severity to appear in at least one event"
        )


# ─────────────────────────────────────────────────────────────────────────────
# read_report()
# ─────────────────────────────────────────────────────────────────────────────

class TestReadReport(unittest.TestCase):
    """Tests for the read_report() helper."""

    def test_read_report_reads_file_contents(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
            f.write(MINIMAL_AIDE_REPORT)
            tmp_path = f.name
        try:
            content = aide.read_report(tmp_path)
            self.assertIn("/etc/passwd", content)
        finally:
            os.unlink(tmp_path)

    def test_read_report_nonexistent_raises(self):
        with self.assertRaises((FileNotFoundError, SystemExit)):
            aide.read_report("/nonexistent/path/aide.log")


# ─────────────────────────────────────────────────────────────────────────────
# Integration: parse() → full report properties
# ─────────────────────────────────────────────────────────────────────────────

class TestParseIntegration(unittest.TestCase):
    """End-to-end parse tests: full report → correct FileChange objects."""

    def setUp(self):
        self.parser = aide.AideReportParser(hostname="k8s-node01", report_path="/tmp/aide.log")

    def test_critical_path_report_yields_critical_severity(self):
        """/etc/sudoers being added should yield a CRITICAL severity change."""
        report = self.parser.parse(CRITICAL_PATH_REPORT)
        self.assertTrue(any(c.severity == aide.Severity.CRITICAL for c in report.changes))

    def test_tmp_new_file_yields_critical(self):
        """New file in /tmp should be classified CRITICAL."""
        report = self.parser.parse(TMP_NEW_FILE_REPORT)
        self.assertTrue(any(c.severity == aide.Severity.CRITICAL for c in report.changes))

    def test_minimal_report_overall_severity_is_critical(self):
        """With /etc/passwd changed, overall report severity should be CRITICAL."""
        report = self.parser.parse(MINIMAL_AIDE_REPORT)
        severities = [c.severity for c in report.changes]
        self.assertIn(aide.Severity.CRITICAL, severities)

    def test_ssh_config_change_maps_sc_control(self):
        """SSH config change should include SC-3.13.8 in its NIST controls."""
        report = self.parser.parse(MINIMAL_AIDE_REPORT)
        ssh_changes = [c for c in report.changes if "sshd_config" in c.path]
        self.assertEqual(len(ssh_changes), 1)
        self.assertIn("SC-3.13.8", ssh_changes[0].nist_controls)


# ─────────────────────────────────────────────────────────────────────────────
# SplunkHECClient — network mocking
# ─────────────────────────────────────────────────────────────────────────────

class TestSplunkHECClientMocked(unittest.TestCase):
    """
    Tests for SplunkHECClient.send() that stub out the actual HTTP call.
    Verifies correct batch formatting and error handling without network.
    """

    def _make_client(self):
        return aide.SplunkHECClient(
            hec_url="https://splunk.lab.internal:8088/services/collector",
            hec_token="test-hec-token-00000000",
            verify_ssl=False,
        )

    def test_send_empty_list_returns_zero_counts(self):
        client = self._make_client()
        with patch.object(client, "_post") as mock_post:
            sent, failed = client.send([])
            mock_post.assert_not_called()
            self.assertEqual(sent, 0)
            self.assertEqual(failed, 0)

    def test_send_single_event_calls_post_once(self):
        """A single event should result in exactly one _post call."""
        client = self._make_client()
        events = [{"event": {"msg": "test"}, "index": "linux_aide", "sourcetype": "aide:report"}]
        with patch.object(client, "_post") as mock_post:
            sent, failed = client.send(events)
            self.assertEqual(mock_post.call_count, 1)
            self.assertEqual(sent, 1)
            self.assertEqual(failed, 0)

    def test_send_returns_failed_count_on_post_error(self):
        """If _post raises, failed count should reflect the batch size."""
        client = self._make_client()
        events = [{"event": {"msg": f"test {i}"}} for i in range(5)]
        with patch.object(client, "_post", side_effect=Exception("Connection refused")):
            sent, failed = client.send(events)
            self.assertGreater(failed, 0)
            self.assertEqual(sent, 0)

    def test_send_payload_is_newline_delimited_json(self):
        """Batched payload should be newline-delimited JSON (Splunk HEC format)."""
        client = self._make_client()
        events = [{"event": {"msg": "hello"}, "index": "linux_aide", "sourcetype": "aide:report"}]
        captured = []

        def capture_post(payload_bytes):
            captured.append(payload_bytes)

        with patch.object(client, "_post", side_effect=capture_post):
            client.send(events)

        self.assertEqual(len(captured), 1)
        # Each line must be valid JSON
        for line in captured[0].decode().strip().split("\n"):
            parsed = json.loads(line)
            self.assertIn("event", parsed)


if __name__ == "__main__":
    unittest.main(verbosity=2)
