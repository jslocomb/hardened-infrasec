"""
test_freeipa_account_auditor.py
──────────────────────────────────────────────────────────────────────────────
Unit tests for freeipa_account_auditor.py

Tests the IPA datetime parser, user entry parser, risk flag logic,
account auditor classification, and report helpers — all without
requiring a live FreeIPA server.

Run with:
    pytest tests/test_freeipa_account_auditor.py -v
    python -m pytest tests/test_freeipa_account_auditor.py -v
"""

import json
import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))
import freeipa_account_auditor as ipa


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _now():
    return datetime.now(timezone.utc)

def _ts(dt: datetime) -> dict:
    """Wrap a datetime as the IPA dict-style timestamp."""
    return {"__datetime__": dt.strftime(ipa.IPA_DATETIME_FORMAT)}

def _str_ts(dt: datetime) -> str:
    """Return a plain IPA string timestamp."""
    return dt.strftime(ipa.IPA_DATETIME_FORMAT)

def _ago(days: int) -> datetime:
    return _now() - timedelta(days=days)

def _future(days: int) -> datetime:
    return _now() + timedelta(days=days)

def _minimal_entry(**overrides) -> dict:
    """Return a minimal valid IPA user_find entry dict."""
    base = {
        "uid":                   ["testuser"],
        "cn":                    ["Test User"],
        "givenname":             ["Test"],
        "sn":                    ["User"],
        "mail":                  ["testuser@lab.internal"],
        "nsaccountlock":         False,
        "krbLastSuccessfulAuth": _ts(_ago(1)),
        "krbLastPwdChange":      _ts(_ago(30)),
        "krbPasswordExpiration": _ts(_future(60)),
        "krbPrincipalExpiration": None,
        "krbLoginFailedCount":   ["0"],
        "memberof_group":        ["ipausers"],
        "createTimestamp":       _ts(_ago(100)),
    }
    base.update(overrides)
    return base


def _make_auditor(**kwargs) -> ipa.AccountAuditor:
    """Return an AccountAuditor with a no-op client stub."""
    client = MagicMock()
    defaults = dict(
        inactive_days=90,
        password_days=365,
        never_days=30,
        failed_threshold=10,
        exclude_users=set(),
    )
    defaults.update(kwargs)
    return ipa.AccountAuditor(client=client, **defaults)


# ─────────────────────────────────────────────────────────────────────────────
# parse_ipa_datetime
# ─────────────────────────────────────────────────────────────────────────────

class TestParseIpaDatetime(unittest.TestCase):
    """Tests for the parse_ipa_datetime() utility."""

    def test_parses_string_form(self):
        """Plain IPA datetime string like '20250115080000Z' should parse correctly."""
        result = ipa.parse_ipa_datetime("20250115080000Z")
        self.assertIsNotNone(result)
        self.assertEqual(result.year, 2025)
        self.assertEqual(result.month, 1)
        self.assertEqual(result.day, 15)

    def test_parses_dict_form(self):
        """Dict form {'__datetime__': '20250115080000Z'} should parse correctly."""
        result = ipa.parse_ipa_datetime({"__datetime__": "20250115080000Z"})
        self.assertIsNotNone(result)
        self.assertEqual(result.year, 2025)

    def test_returns_none_for_none(self):
        self.assertIsNone(ipa.parse_ipa_datetime(None))

    def test_returns_none_for_empty_string(self):
        self.assertIsNone(ipa.parse_ipa_datetime(""))

    def test_returns_none_for_empty_dict(self):
        self.assertIsNone(ipa.parse_ipa_datetime({}))

    def test_returns_none_for_invalid_string(self):
        self.assertIsNone(ipa.parse_ipa_datetime("not-a-date"))

    def test_result_is_timezone_aware(self):
        """Parsed datetime should be timezone-aware (UTC)."""
        result = ipa.parse_ipa_datetime("20250115080000Z")
        self.assertIsNotNone(result.tzinfo)

    def test_parses_list_containing_string(self):
        """IPA occasionally wraps scalar values in a list."""
        result = ipa.parse_ipa_datetime(["20250115080000Z"])
        self.assertIsNotNone(result)
        self.assertEqual(result.year, 2025)


# ─────────────────────────────────────────────────────────────────────────────
# extract_str / extract_list / extract_bool
# ─────────────────────────────────────────────────────────────────────────────

class TestExtractHelpers(unittest.TestCase):
    """Tests for the IPA list-unwrap helper functions."""

    def test_extract_str_unwraps_single_item_list(self):
        self.assertEqual(ipa.extract_str(["hello"]), "hello")

    def test_extract_str_returns_string_directly(self):
        self.assertEqual(ipa.extract_str("hello"), "hello")

    def test_extract_str_returns_default_for_none(self):
        self.assertEqual(ipa.extract_str(None), "")
        self.assertEqual(ipa.extract_str(None, default="N/A"), "N/A")

    def test_extract_str_returns_default_for_empty_list(self):
        self.assertEqual(ipa.extract_str([]), "")

    def test_extract_list_returns_list(self):
        self.assertEqual(ipa.extract_list(["a", "b"]), ["a", "b"])

    def test_extract_list_wraps_scalar(self):
        result = ipa.extract_list("single")
        self.assertIsInstance(result, list)
        self.assertIn("single", result)

    def test_extract_list_returns_empty_for_none(self):
        self.assertEqual(ipa.extract_list(None), [])

    def test_extract_bool_true(self):
        self.assertTrue(ipa.extract_bool(True))
        self.assertTrue(ipa.extract_bool("TRUE"))
        self.assertTrue(ipa.extract_bool(["TRUE"]))

    def test_extract_bool_false(self):
        self.assertFalse(ipa.extract_bool(False))
        self.assertFalse(ipa.extract_bool(None))
        self.assertFalse(ipa.extract_bool("FALSE"))


# ─────────────────────────────────────────────────────────────────────────────
# parse_user_entry
# ─────────────────────────────────────────────────────────────────────────────

class TestParseUserEntry(unittest.TestCase):
    """Tests for the parse_user_entry() function."""

    def test_parses_uid(self):
        entry = _minimal_entry(uid=["jsmith"])
        account = ipa.parse_user_entry(entry)
        self.assertEqual(account.uid, "jsmith")

    def test_parses_display_name(self):
        entry = _minimal_entry(cn=["John Smith"])
        account = ipa.parse_user_entry(entry)
        self.assertEqual(account.cn, "John Smith")

    def test_parses_email(self):
        entry = _minimal_entry(mail=["jsmith@lab.internal"])
        account = ipa.parse_user_entry(entry)
        self.assertEqual(account.mail, "jsmith@lab.internal")

    def test_email_none_when_absent(self):
        entry = _minimal_entry(mail=None)
        account = ipa.parse_user_entry(entry)
        self.assertIsNone(account.mail)

    def test_parses_group_memberships(self):
        entry = _minimal_entry(memberof_group=["admins", "ipausers"])
        account = ipa.parse_user_entry(entry)
        self.assertIn("admins", account.groups)
        self.assertIn("ipausers", account.groups)

    def test_privileged_flag_set_for_admin_group(self):
        entry = _minimal_entry(memberof_group=["admins"])
        account = ipa.parse_user_entry(entry)
        self.assertTrue(account.is_privileged)

    def test_privileged_flag_not_set_for_no_groups(self):
        """Account with empty group list should not be marked privileged."""
        entry = _minimal_entry(memberof_group=[])
        account = ipa.parse_user_entry(entry)
        self.assertFalse(account.is_privileged)

    def test_account_locked_flag(self):
        entry = _minimal_entry(nsaccountlock=True)
        account = ipa.parse_user_entry(entry)
        self.assertTrue(account.locked)

    def test_account_not_locked_by_default(self):
        entry = _minimal_entry(nsaccountlock=False)
        account = ipa.parse_user_entry(entry)
        self.assertFalse(account.locked)

    def test_last_auth_parsed(self):
        expected = _ago(5)
        entry = _minimal_entry(krbLastSuccessfulAuth=_ts(expected))
        account = ipa.parse_user_entry(entry)
        self.assertIsNotNone(account.last_successful_auth)
        self.assertAlmostEqual(
            account.last_successful_auth.timestamp(), expected.timestamp(), delta=60
        )

    def test_last_auth_none_when_never_logged_in(self):
        entry = _minimal_entry(krbLastSuccessfulAuth=None)
        account = ipa.parse_user_entry(entry)
        self.assertIsNone(account.last_successful_auth)

    def test_password_expiration_parsed(self):
        exp = _future(30)
        entry = _minimal_entry(krbPasswordExpiration=_ts(exp))
        account = ipa.parse_user_entry(entry)
        self.assertIsNotNone(account.pwd_expiration)

    def test_failed_login_count_parsed(self):
        entry = _minimal_entry(krbLoginFailedCount=["15"])
        account = ipa.parse_user_entry(entry)
        self.assertEqual(account.failed_login_count, 15)

    def test_failed_login_defaults_to_zero(self):
        entry = _minimal_entry(krbLoginFailedCount=None)
        account = ipa.parse_user_entry(entry)
        self.assertEqual(account.failed_login_count, 0)


# ─────────────────────────────────────────────────────────────────────────────
# RiskFlag severity
# ─────────────────────────────────────────────────────────────────────────────

class TestRiskFlagSeverity(unittest.TestCase):
    """Tests for the RiskFlag.severity property."""

    def test_privileged_inactive_is_critical(self):
        flags = ipa.RiskFlag.PRIVILEGED_INACTIVE
        self.assertEqual(flags.severity, "critical")

    def test_principal_expired_is_critical(self):
        flags = ipa.RiskFlag.PRINCIPAL_EXPIRED
        self.assertEqual(flags.severity, "critical")

    def test_account_locked_is_high(self):
        flags = ipa.RiskFlag.ACCOUNT_LOCKED
        self.assertEqual(flags.severity, "high")

    def test_never_logged_in_is_high(self):
        flags = ipa.RiskFlag.NEVER_LOGGED_IN
        self.assertEqual(flags.severity, "high")

    def test_inactive_is_high(self):
        flags = ipa.RiskFlag.INACTIVE
        self.assertEqual(flags.severity, "high")

    def test_password_expired_is_high(self):
        flags = ipa.RiskFlag.PASSWORD_EXPIRED
        self.assertEqual(flags.severity, "high")

    def test_stale_password_is_medium(self):
        flags = ipa.RiskFlag.STALE_PASSWORD
        self.assertEqual(flags.severity, "medium")

    def test_high_failed_logins_is_medium(self):
        flags = ipa.RiskFlag.HIGH_FAILED_LOGINS
        self.assertEqual(flags.severity, "medium")

    def test_no_groups_is_low(self):
        flags = ipa.RiskFlag.NO_GROUPS
        self.assertEqual(flags.severity, "low")

    def test_combined_critical_dominates(self):
        """When multiple flags set, severity should reflect highest."""
        flags = ipa.RiskFlag.STALE_PASSWORD | ipa.RiskFlag.PRIVILEGED_INACTIVE
        self.assertEqual(flags.severity, "critical")

    def test_none_flag_has_no_flags_listed(self):
        flags = ipa.RiskFlag.NONE
        self.assertEqual(flags.as_list(), [])


# ─────────────────────────────────────────────────────────────────────────────
# AccountAuditor.audit_account — risk flag assignment
# ─────────────────────────────────────────────────────────────────────────────

class TestAccountAuditorAuditAccount(unittest.TestCase):
    """Tests for AccountAuditor.audit_account() — risk flag detection logic."""

    def setUp(self):
        self.auditor = _make_auditor()

    def _account_from_entry(self, **overrides) -> ipa.UserAccount:
        return ipa.parse_user_entry(_minimal_entry(**overrides))

    def test_clean_active_account_has_no_flags(self):
        account = self._account_from_entry()
        result = self.auditor.audit_account(account)
        self.assertEqual(result.risk_flags, ipa.RiskFlag.NONE)

    def test_never_logged_in_flag(self):
        """Account created 45 days ago with no auth should get NEVER_LOGGED_IN."""
        account = self._account_from_entry(
            krbLastSuccessfulAuth=None,
            createTimestamp=_ts(_ago(45)),
        )
        result = self.auditor.audit_account(account)
        self.assertTrue(result.risk_flags & ipa.RiskFlag.NEVER_LOGGED_IN)

    def test_never_logged_in_not_flagged_if_recently_created(self):
        """Account created 5 days ago (within never_days=30) should not be flagged."""
        account = self._account_from_entry(
            krbLastSuccessfulAuth=None,
            createTimestamp=_ts(_ago(5)),
        )
        result = self.auditor.audit_account(account)
        self.assertFalse(result.risk_flags & ipa.RiskFlag.NEVER_LOGGED_IN)

    def test_inactive_account_flag(self):
        """Account with last auth 100+ days ago should get INACTIVE."""
        account = self._account_from_entry(
            krbLastSuccessfulAuth=_ts(_ago(100)),
        )
        result = self.auditor.audit_account(account)
        self.assertTrue(result.risk_flags & ipa.RiskFlag.INACTIVE)

    def test_active_account_not_flagged_inactive(self):
        """Account logged in 1 day ago should NOT get INACTIVE."""
        account = self._account_from_entry(
            krbLastSuccessfulAuth=_ts(_ago(1)),
        )
        result = self.auditor.audit_account(account)
        self.assertFalse(result.risk_flags & ipa.RiskFlag.INACTIVE)

    def test_locked_account_flag(self):
        account = self._account_from_entry(nsaccountlock=True)
        result = self.auditor.audit_account(account)
        self.assertTrue(result.risk_flags & ipa.RiskFlag.ACCOUNT_LOCKED)

    def test_password_expired_flag(self):
        account = self._account_from_entry(
            krbPasswordExpiration=_ts(_ago(1)),   # expired yesterday
        )
        result = self.auditor.audit_account(account)
        self.assertTrue(result.risk_flags & ipa.RiskFlag.PASSWORD_EXPIRED)

    def test_principal_expired_flag(self):
        account = self._account_from_entry(
            krbPrincipalExpiration=_ts(_ago(10)),
        )
        result = self.auditor.audit_account(account)
        self.assertTrue(result.risk_flags & ipa.RiskFlag.PRINCIPAL_EXPIRED)

    def test_stale_password_flag(self):
        """Password unchanged for 400 days with no expiry policy → STALE_PASSWORD."""
        account = self._account_from_entry(
            krbLastPwdChange=_ts(_ago(400)),
            krbPasswordExpiration=None,
        )
        result = self.auditor.audit_account(account)
        self.assertTrue(result.risk_flags & ipa.RiskFlag.STALE_PASSWORD)

    def test_no_groups_flag(self):
        account = self._account_from_entry(memberof_group=[])
        result = self.auditor.audit_account(account)
        self.assertTrue(result.risk_flags & ipa.RiskFlag.NO_GROUPS)

    def test_no_email_flag(self):
        account = self._account_from_entry(mail=None)
        result = self.auditor.audit_account(account)
        self.assertTrue(result.risk_flags & ipa.RiskFlag.NO_EMAIL)

    def test_privileged_inactive_flag_combo(self):
        """Admin account that is inactive → PRIVILEGED_INACTIVE (highest severity)."""
        account = self._account_from_entry(
            memberof_group=["admins"],
            krbLastSuccessfulAuth=_ts(_ago(100)),
        )
        result = self.auditor.audit_account(account)
        self.assertTrue(result.risk_flags & ipa.RiskFlag.PRIVILEGED_INACTIVE)
        self.assertEqual(result.risk_flags.severity, "critical")

    def test_high_failed_logins_flag(self):
        account = self._account_from_entry(
            krbLoginFailedCount=["20"],
        )
        result = self.auditor.audit_account(account)
        self.assertTrue(result.risk_flags & ipa.RiskFlag.HIGH_FAILED_LOGINS)

    def test_failed_logins_below_threshold_not_flagged(self):
        account = self._account_from_entry(
            krbLoginFailedCount=["5"],  # threshold = 10
        )
        result = self.auditor.audit_account(account)
        self.assertFalse(result.risk_flags & ipa.RiskFlag.HIGH_FAILED_LOGINS)


# ─────────────────────────────────────────────────────────────────────────────
# AccountAuditor — mock accounts from generate_mock_accounts()
# ─────────────────────────────────────────────────────────────────────────────

class TestAccountAuditorWithMockData(unittest.TestCase):
    """
    Integration-style tests using generate_mock_accounts() to exercise the
    full parse_user_entry + audit_account pipeline.
    """

    def setUp(self):
        self.auditor = _make_auditor(exclude_users=set())
        raw_entries = ipa.generate_mock_accounts()
        self.accounts = [ipa.parse_user_entry(e) for e in raw_entries]
        self.audited = [self.auditor.audit_account(a) for a in self.accounts]

    def test_at_least_one_clean_account(self):
        """There should be at least one account with no risk flags."""
        clean = [a for a in self.audited if a.risk_flags == ipa.RiskFlag.NONE]
        self.assertGreater(len(clean), 0, "Expected at least one clean account")

    def test_at_least_one_flagged_account(self):
        """There should be at least one account with risk flags."""
        flagged = [a for a in self.audited if a.risk_flags != ipa.RiskFlag.NONE]
        self.assertGreater(len(flagged), 0, "Expected at least one flagged account")

    def test_at_least_one_critical_account(self):
        """Mock data should include at least one critical-severity account."""
        critical = [a for a in self.audited if a.risk_flags.severity == "critical"]
        self.assertGreater(len(critical), 0, "Expected at least one critical account")

    def test_all_accounts_have_uid(self):
        for a in self.audited:
            self.assertNotEqual(a.uid, "", f"Account has empty uid: {a}")


# ─────────────────────────────────────────────────────────────────────────────
# account_to_dict
# ─────────────────────────────────────────────────────────────────────────────

class TestAccountToDict(unittest.TestCase):
    """Tests for the account_to_dict() serializer."""

    def _audited_account(self, **overrides) -> ipa.UserAccount:
        auditor = _make_auditor()
        entry = _minimal_entry(**overrides)
        account = ipa.parse_user_entry(entry)
        return auditor.audit_account(account)

    def test_dict_contains_uid(self):
        account = self._audited_account(uid=["jsmith"])
        d = ipa.account_to_dict(account)
        self.assertEqual(d["uid"], "jsmith")

    def test_dict_contains_severity(self):
        account = self._audited_account(nsaccountlock=True)
        d = ipa.account_to_dict(account)
        self.assertIn("severity", d)
        self.assertEqual(d["severity"], account.risk_flags.severity)

    def test_dict_contains_risk_flags_list(self):
        account = self._audited_account(nsaccountlock=True)
        d = ipa.account_to_dict(account)
        self.assertIn("risk_flags", d)
        self.assertIsInstance(d["risk_flags"], list)

    def test_clean_account_has_empty_risk_flags(self):
        account = self._audited_account()
        d = ipa.account_to_dict(account)
        self.assertEqual(d["risk_flags"], [])

    def test_dict_is_json_serializable(self):
        """account_to_dict output must be JSON-serializable."""
        account = self._audited_account()
        d = ipa.account_to_dict(account)
        try:
            json.dumps(d)
        except (TypeError, ValueError) as e:
            self.fail(f"account_to_dict result is not JSON-serializable: {e}")


# ─────────────────────────────────────────────────────────────────────────────
# write_json / write_csv outputs
# ─────────────────────────────────────────────────────────────────────────────

class TestWriteOutputs(unittest.TestCase):
    """Tests for JSON and CSV output writers."""

    def setUp(self):
        auditor = _make_auditor()
        entries = ipa.generate_mock_accounts()
        accounts = [ipa.parse_user_entry(e) for e in entries]
        self.accounts = [auditor.audit_account(a) for a in accounts]
        self.summary = ipa.AuditSummary(
            server="ipa01.lab.internal",
            bind_user="admin",
            audit_timestamp=datetime.now(timezone.utc).isoformat(),
            total_users=len(self.accounts),
        )

    def test_write_json_creates_valid_json_file(self):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name
        try:
            ipa.write_json(self.accounts, self.summary, path)
            with open(path) as fh:
                data = json.load(fh)
            self.assertIn("accounts", data)
            self.assertIsInstance(data["accounts"], list)
        finally:
            os.unlink(path)

    def test_write_json_account_count_matches(self):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name
        try:
            ipa.write_json(self.accounts, self.summary, path)
            with open(path) as fh:
                data = json.load(fh)
            self.assertEqual(len(data["accounts"]), len(self.accounts))
        finally:
            os.unlink(path)

    def test_write_csv_creates_file(self):
        with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as f:
            path = f.name
        try:
            ipa.write_csv(self.accounts, path)
            with open(path) as fh:
                content = fh.read()
            self.assertGreater(len(content), 0)
            # CSV header should contain uid
            self.assertIn("uid", content.lower())
        finally:
            os.unlink(path)

    def test_write_html_creates_file(self):
        with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as f:
            path = f.name
        try:
            ipa.write_html(self.accounts, self.summary, path)
            with open(path) as fh:
                content = fh.read()
            self.assertIn("<html", content.lower())
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main(verbosity=2)
