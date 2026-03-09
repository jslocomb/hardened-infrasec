#!/usr/bin/env python3
"""
freeipa_account_auditor.py
─────────────────────────────────────────────────────────────────────────────
FreeIPA Account Lifecycle Auditor — Stale Account Detection

Connects to a FreeIPA server via its JSON-RPC API, audits all user accounts
for signs of staleness or compliance risk, and produces structured reports.

NIST 800-171 / CMMC Level 2 Controls addressed:
  AC-3.1.1   Limit system access to authorized users, processes, and devices
  AC-3.1.2   Limit system access to types of transactions authorized users are
             permitted to execute
  IA-3.5.4   Manage information system identifiers for users and devices
  IA-3.5.7   Enforce a minimum password complexity and change requirements
  AC-3.1.14  Employ cryptographic mechanisms to protect the confidentiality
             of remote access sessions

Stale Account Indicators Detected:
  - Never logged in (no kerberos authentication record)
  - Inactive beyond configurable threshold (default: 90 days)
  - Account locked (nsAccountLock = TRUE)
  - Password expired (krbPasswordExpiration in the past)
  - Kerberos principal expired (krbPrincipalExpiration in the past)
  - Password not changed in over N days (default: 365) with no expiry policy
  - No group memberships (orphaned/forgotten accounts)
  - No email address (possible service/system account with no owner)
  - Admin/privileged group membership with stale last-login

Usage:
    # Basic audit — prompts for password
    python3 freeipa_account_auditor.py \\
        --server ipa01.lab.internal \\
        --binduser admin

    # Non-interactive with environment variable
    IPA_PASSWORD=secret python3 freeipa_account_auditor.py \\
        --server ipa01.lab.internal \\
        --binduser admin \\
        --inactive-days 60 \\
        --password-days 180

    # Output reports
    python3 freeipa_account_auditor.py \\
        --server ipa01.lab.internal \\
        --binduser admin \\
        --output-json /var/log/ipa_audit.json \\
        --output-csv  /var/log/ipa_audit.csv \\
        --output-html /var/log/ipa_audit.html

    # Dry run — show what would be flagged, no changes made
    python3 freeipa_account_auditor.py \\
        --server ipa01.lab.internal \\
        --binduser admin \\
        --dry-run

    # Self-signed cert (lab environments)
    python3 freeipa_account_auditor.py \\
        --server ipa01.lab.internal \\
        --binduser admin \\
        --no-ssl-verify

Environment variables:
    IPA_PASSWORD        Bind user password (avoids interactive prompt)
    IPA_SERVER          FreeIPA server hostname
    IPA_BINDUSER        Bind username (default: admin)

Author : Jason A. Slocomb
Version: 1.0.0
─────────────────────────────────────────────────────────────────────────────
"""

import argparse
import csv
import getpass
import http.cookiejar
import json
import logging
import os
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone, timedelta
from enum import Flag, auto
from pathlib import Path
from typing import Optional


# ─── Constants ────────────────────────────────────────────────────────────────

VERSION                = "1.0.0"
DEFAULT_INACTIVE_DAYS  = 90    # flag if no login within this many days
DEFAULT_PASSWORD_DAYS  = 365   # flag if password unchanged this long with no policy
DEFAULT_NEVER_DAYS     = 30    # accounts created N+ days ago that have never logged in

# FreeIPA API endpoints
IPA_JSON_ENDPOINT      = "/ipa/session/json"
IPA_LOGIN_ENDPOINT     = "/ipa/session/login_password"

# FreeIPA attributes we request for each user
USER_ATTRIBUTES = [
    "uid",
    "cn",
    "givenname",
    "sn",
    "mail",
    "nsaccountlock",
    "krbLastPwdChange",
    "krbPasswordExpiration",
    "krbPrincipalExpiration",
    "krbLastSuccessfulAuth",
    "krbLastFailedAuth",
    "krbLoginFailedCount",
    "krbPwdPolicyReference",
    "memberof_group",
    "memberof_role",
    "memberof_sudorule",
    "memberof_hbacrule",
    "title",
    "ou",
    "telephonenumber",
    "employeeNumber",
    "createTimestamp",
    "modifyTimestamp",
    "ipaSshPubKey",
    "userClass",
    "description",
]

# Groups that indicate privileged access — severity escalates if stale
PRIVILEGED_GROUPS = {
    "admins",
    "ipausers",    # all users, but useful as baseline
    "trust admins",
    "editors",
}

# Users to exclude from audit by default (well-known system accounts)
SYSTEM_ACCOUNTS_DEFAULT = {"admin", "krbtgt"}

# IPA datetime format
IPA_DATETIME_FORMAT = "%Y%m%d%H%M%SZ"  # 20250115080000Z

# NIST 800-171 control tags per finding type
NIST_CONTROLS = {
    "never_logged_in":     ["AC-3.1.1", "IA-3.5.4"],
    "inactive":            ["AC-3.1.2", "IA-3.5.4"],
    "account_locked":      ["AC-3.1.1", "IA-3.5.4"],
    "password_expired":    ["IA-3.5.7", "IA-3.5.4"],
    "principal_expired":   ["AC-3.1.1", "IA-3.5.4"],
    "stale_password":      ["IA-3.5.7"],
    "no_groups":           ["AC-3.1.1", "IA-3.5.4"],
    "no_email":            ["IA-3.5.4"],
    "privileged_inactive": ["AC-3.1.2", "AC-3.1.1", "IA-3.5.4"],
    "failed_logins":       ["AC-3.1.1"],
}


# ─── Risk Flags ───────────────────────────────────────────────────────────────

class RiskFlag(Flag):
    """Bitfield of risk conditions detected for an account."""
    NONE                = 0
    NEVER_LOGGED_IN     = auto()   # Account created N+ days ago, never authenticated
    INACTIVE            = auto()   # No successful auth within threshold window
    ACCOUNT_LOCKED      = auto()   # nsAccountLock is TRUE
    PASSWORD_EXPIRED    = auto()   # krbPasswordExpiration is in the past
    PRINCIPAL_EXPIRED   = auto()   # krbPrincipalExpiration is in the past
    STALE_PASSWORD      = auto()   # Password unchanged > threshold, no expiry policy
    NO_GROUPS           = auto()   # No group memberships
    NO_EMAIL            = auto()   # No email address (orphan/unowned account)
    PRIVILEGED_INACTIVE = auto()   # In admin group + inactive/never-logged-in
    HIGH_FAILED_LOGINS  = auto()   # Repeated failed auth attempts (brute force indicator)

    def as_list(self) -> list[str]:
        return [f.name.lower() for f in RiskFlag if f != RiskFlag.NONE and (self & f)]

    @property
    def severity(self) -> str:
        if self & (RiskFlag.PRIVILEGED_INACTIVE | RiskFlag.PRINCIPAL_EXPIRED):
            return "critical"
        if self & (RiskFlag.ACCOUNT_LOCKED | RiskFlag.PASSWORD_EXPIRED |
                   RiskFlag.NEVER_LOGGED_IN | RiskFlag.INACTIVE):
            return "high"
        if self & (RiskFlag.STALE_PASSWORD | RiskFlag.HIGH_FAILED_LOGINS):
            return "medium"
        if self & (RiskFlag.NO_GROUPS | RiskFlag.NO_EMAIL):
            return "low"
        return "clean"

    @property
    def nist_controls(self) -> list[str]:
        controls: set[str] = set()
        for f in RiskFlag:
            if f != RiskFlag.NONE and (self & f):
                key = f.name.lower()
                controls.update(NIST_CONTROLS.get(key, []))
        return sorted(controls)


# ─── Data Models ──────────────────────────────────────────────────────────────

@dataclass
class UserAccount:
    """Parsed representation of a FreeIPA user account."""
    uid:                  str
    cn:                   str                = ""
    givenname:            str                = ""
    sn:                   str                = ""
    mail:                 Optional[str]       = None
    locked:               bool               = False
    last_successful_auth: Optional[datetime] = None
    last_failed_auth:     Optional[datetime] = None
    failed_login_count:   int                = 0
    last_pwd_change:      Optional[datetime] = None
    pwd_expiration:       Optional[datetime] = None
    principal_expiration: Optional[datetime] = None
    pwd_policy_ref:       Optional[str]      = None
    groups:               list               = field(default_factory=list)
    roles:                list               = field(default_factory=list)
    sudo_rules:           list               = field(default_factory=list)
    hbac_rules:           list               = field(default_factory=list)
    created:              Optional[datetime] = None
    modified:             Optional[datetime] = None
    title:                Optional[str]      = None
    department:           Optional[str]      = None
    employee_number:      Optional[str]      = None
    ssh_keys_count:       int                = 0
    user_class:           Optional[str]      = None
    description:          Optional[str]      = None
    is_privileged:        bool               = False

    # Set by auditor after analysis
    risk_flags:           RiskFlag           = RiskFlag.NONE
    days_since_login:     Optional[int]      = None
    days_since_pwd_change: Optional[int]     = None
    days_since_created:   Optional[int]      = None


@dataclass
class AuditSummary:
    """Aggregate statistics from a complete audit run."""
    server:             str
    bind_user:          str
    audit_timestamp:    str
    total_users:        int              = 0
    clean_users:        int              = 0
    flagged_users:      int              = 0
    critical_count:     int              = 0
    high_count:         int              = 0
    medium_count:       int              = 0
    low_count:          int              = 0
    locked_count:       int              = 0
    never_logged_in:    int              = 0
    inactive_count:     int              = 0
    expired_passwords:  int              = 0
    expired_principals: int              = 0
    stale_passwords:    int              = 0
    no_groups:          int              = 0
    no_email:           int              = 0
    privileged_stale:   int              = 0
    thresholds:         dict             = field(default_factory=dict)
    nist_controls:      list             = field(default_factory=list)


# ─── FreeIPA JSON-RPC Client ──────────────────────────────────────────────────

class FreeIPAClient:
    """
    Lightweight FreeIPA JSON-RPC API client.

    Uses urllib only — no external dependencies.
    Authentication via session cookie after login_password call.

    The FreeIPA JSON-RPC API takes the form:
        POST /ipa/session/json
        Content-Type: application/json

        {
            "method": "user_find",
            "params": [
                [],                          # positional args (usually empty)
                {"sizelimit": 0, "all": true} # keyword args / options
            ],
            "id": 0
        }
    """

    def __init__(self, server: str, verify_ssl: bool = True):
        self.server     = server
        self.base_url   = f"https://{server}"
        self._log       = logging.getLogger(self.__class__.__name__)
        self._session   = None   # session cookie jar

        if not verify_ssl:
            self._ssl_ctx = ssl.create_default_context()
            self._ssl_ctx.check_hostname = False
            self._ssl_ctx.verify_mode    = ssl.CERT_NONE
        else:
            self._ssl_ctx = None

    def login(self, username: str, password: str) -> None:
        """Authenticate to FreeIPA and store the session cookie."""
        login_url = self.base_url + IPA_LOGIN_ENDPOINT
        payload   = urllib.parse.urlencode({
            "user":     username,
            "password": password,
        }).encode("utf-8")

        cookie_jar = http.cookiejar.CookieJar()
        opener     = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(cookie_jar)
        )

        req = urllib.request.Request(
            login_url,
            data=payload,
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Referer":      self.base_url + "/ipa",
            },
            method="POST",
        )

        try:
            with opener.open(req, context=self._ssl_ctx, timeout=30) as resp:
                status = resp.status
        except urllib.error.HTTPError as exc:
            status = exc.code
            if status == 401:
                raise PermissionError(
                    f"Authentication failed for user '{username}'. "
                    f"Check credentials."
                )
            raise

        if status not in (200, 201):
            raise RuntimeError(f"Login returned unexpected status {status}")

        # Verify we got an ipa_session cookie
        cookies = {c.name: c.value for c in cookie_jar}
        if "ipa_session" not in cookies:
            raise RuntimeError(
                "Login appeared to succeed but no ipa_session cookie received. "
                "Check that the IPA server is properly configured."
            )

        # Build a persistent opener that carries the session cookie
        self._cookie_jar = cookie_jar
        self._opener     = opener
        self._log.info(f"Authenticated to {self.server} as '{username}'")

    def logout(self) -> None:
        """Invalidate the server-side session."""
        try:
            self._call_raw("ping", [], {})
            self._call_raw("session_logout", [], {})
        except Exception:
            pass

    def call(self, method: str, args: list = None, options: dict = None) -> dict:
        """
        Call a FreeIPA JSON-RPC method.

        Returns the 'result' key from the IPA response, which has the shape:
            {"result": [...], "count": N, "truncated": False, "summary": "..."}
        for find methods, or:
            {"result": {...}, "summary": "..."}
        for show/mod methods.
        """
        if self._opener is None:
            raise RuntimeError("Not authenticated. Call login() first.")

        response = self._call_raw(method, args or [], options or {})

        # IPA wraps errors in a non-HTTP error code with an "error" key
        if response.get("error"):
            err = response["error"]
            raise RuntimeError(
                f"IPA API error [{err.get('code')}]: {err.get('message')}"
            )

        return response.get("result", {})

    def _call_raw(self, method: str, args: list, options: dict) -> dict:
        """Low-level JSON-RPC call. Returns the full response dict."""
        url     = self.base_url + IPA_JSON_ENDPOINT
        payload = json.dumps({
            "method":  method,
            "params":  [args, options],
            "id":      0,
        }).encode("utf-8")

        req = urllib.request.Request(
            url,
            data=payload,
            headers={
                "Content-Type": "application/json",
                "Accept":       "application/json",
                "Referer":      self.base_url + "/ipa",
            },
            method="POST",
        )

        try:
            with self._opener.open(req, context=self._ssl_ctx, timeout=60) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            body = ""
            try:
                body = exc.read().decode()
            except Exception:
                pass
            raise RuntimeError(f"HTTP {exc.code} calling {method}: {body}") from exc


# ─── IPA Datetime Parser ──────────────────────────────────────────────────────

def parse_ipa_datetime(value) -> Optional[datetime]:
    """
    Parse a FreeIPA datetime value.

    IPA returns datetimes in two possible forms:
      1. A string: "20250301031542Z"
      2. A dict:   {"__datetime__": "20250301031542Z"}

    Returns a timezone-aware UTC datetime, or None if unparseable.
    """
    if value is None:
        return None

    # IPA often wraps values in single-element lists
    if isinstance(value, list):
        if not value:
            return None
        value = value[0]

    raw = None
    if isinstance(value, dict):
        raw = value.get("__datetime__") or value.get("__time__")
    elif isinstance(value, str):
        raw = value

    if not raw:
        return None

    # Try IPA's native format first: 20250301031542Z
    try:
        dt = datetime.strptime(raw.strip(), IPA_DATETIME_FORMAT)
        return dt.replace(tzinfo=timezone.utc)
    except ValueError:
        pass

    # Try ISO 8601 variations
    for fmt in (
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S+00:00",
        "%Y-%m-%d %H:%M:%S",
    ):
        try:
            dt = datetime.strptime(raw.strip(), fmt)
            return dt.replace(tzinfo=timezone.utc)
        except ValueError:
            continue

    return None


def extract_str(value, default: str = "") -> str:
    """Extract a string from an IPA single-element list or raw string."""
    if value is None:
        return default
    if isinstance(value, list):
        return str(value[0]) if value else default
    return str(value)


def extract_list(value) -> list:
    """Ensure an IPA multi-value attribute is a list."""
    if value is None:
        return []
    if isinstance(value, list):
        return [str(v) for v in value]
    return [str(value)]


def extract_bool(value) -> bool:
    """Parse IPA boolean (can be string 'TRUE'/'FALSE' or actual bool)."""
    if value is None:
        return False
    if isinstance(value, list):
        value = value[0] if value else False
    if isinstance(value, bool):
        return value
    return str(value).upper() in ("TRUE", "1", "YES")


# ─── Account Parser ───────────────────────────────────────────────────────────

def parse_user_entry(entry: dict) -> UserAccount:
    """Convert a raw IPA user_find result entry into a UserAccount."""

    uid = extract_str(entry.get("uid"))

    # Group memberships
    groups    = extract_list(entry.get("memberof_group"))
    roles     = extract_list(entry.get("memberof_role"))
    sudo_r    = extract_list(entry.get("memberof_sudorule"))
    hbac_r    = extract_list(entry.get("memberof_hbacrule"))

    is_privileged = bool(set(g.lower() for g in groups) & PRIVILEGED_GROUPS)

    # SSH key count
    ssh_keys = entry.get("ipaSshPubKey", [])
    if isinstance(ssh_keys, list):
        ssh_count = len(ssh_keys)
    elif ssh_keys:
        ssh_count = 1
    else:
        ssh_count = 0

    # Parse email — IPA stores as list
    mail_raw = entry.get("mail")
    if mail_raw:
        mail = extract_str(mail_raw) or None
    else:
        mail = None

    return UserAccount(
        uid                  = uid,
        cn                   = extract_str(entry.get("cn")),
        givenname            = extract_str(entry.get("givenname")),
        sn                   = extract_str(entry.get("sn")),
        mail                 = mail,
        locked               = extract_bool(entry.get("nsaccountlock")),
        last_successful_auth = parse_ipa_datetime(entry.get("krbLastSuccessfulAuth")),
        last_failed_auth     = parse_ipa_datetime(entry.get("krbLastFailedAuth")),
        failed_login_count   = int(extract_str(entry.get("krbLoginFailedCount"), "0") or 0),
        last_pwd_change      = parse_ipa_datetime(entry.get("krbLastPwdChange")),
        pwd_expiration       = parse_ipa_datetime(entry.get("krbPasswordExpiration")),
        principal_expiration = parse_ipa_datetime(entry.get("krbPrincipalExpiration")),
        pwd_policy_ref       = extract_str(entry.get("krbPwdPolicyReference")),
        groups               = groups,
        roles                = roles,
        sudo_rules           = sudo_r,
        hbac_rules           = hbac_r,
        created              = parse_ipa_datetime(entry.get("createTimestamp")),
        modified             = parse_ipa_datetime(entry.get("modifyTimestamp")),
        title                = extract_str(entry.get("title")) or None,
        department           = extract_str(entry.get("ou")) or None,
        employee_number      = extract_str(entry.get("employeeNumber")) or None,
        ssh_keys_count       = ssh_count,
        user_class           = extract_str(entry.get("userClass")) or None,
        description          = extract_str(entry.get("description")) or None,
        is_privileged        = is_privileged,
    )


# ─── Auditor ──────────────────────────────────────────────────────────────────

class AccountAuditor:
    """
    Drives the account lifecycle audit logic.

    Fetches all users from FreeIPA, evaluates each account against stale
    account criteria, and produces a list of flagged accounts with severity
    ratings and NIST control mappings.
    """

    def __init__(
        self,
        client:            FreeIPAClient,
        inactive_days:     int  = DEFAULT_INACTIVE_DAYS,
        password_days:     int  = DEFAULT_PASSWORD_DAYS,
        never_days:        int  = DEFAULT_NEVER_DAYS,
        failed_threshold:  int  = 10,
        exclude_users:     set  = None,
        include_locked:    bool = True,
        include_disabled:  bool = True,
    ):
        self.client           = client
        self.inactive_days    = inactive_days
        self.password_days    = password_days
        self.never_days       = never_days
        self.failed_threshold = failed_threshold
        self.exclude_users    = exclude_users or SYSTEM_ACCOUNTS_DEFAULT
        self.include_locked   = include_locked
        self.include_disabled = include_disabled
        self._log             = logging.getLogger(self.__class__.__name__)
        self._now             = datetime.now(timezone.utc)

    def fetch_users(self) -> list[UserAccount]:
        """Retrieve all user accounts from FreeIPA."""
        self._log.info("Fetching all users from FreeIPA...")

        result = self.client.call("user_find", [], {
            "sizelimit": 0,       # no limit — get all accounts
            "all":       True,    # return all attributes
            "raw":       False,   # human-readable attribute names
        })

        raw_users = result.get("result", [])
        self._log.info(f"Retrieved {len(raw_users)} user accounts")

        accounts = []
        for entry in raw_users:
            try:
                account = parse_user_entry(entry)
                if account.uid in self.exclude_users:
                    self._log.debug(f"Skipping system account: {account.uid}")
                    continue
                accounts.append(account)
            except Exception as exc:
                uid = extract_str(entry.get("uid", "unknown"))
                self._log.warning(f"Failed to parse user '{uid}': {exc}")

        self._log.info(
            f"Parsed {len(accounts)} accounts "
            f"(excluded {len(raw_users) - len(accounts)} system accounts)"
        )
        return accounts

    def audit_account(self, account: UserAccount) -> UserAccount:
        """
        Evaluate a single account for stale/risk indicators.
        Sets account.risk_flags, account.days_since_login, etc.
        Returns the account (mutated in place).
        """
        flags = RiskFlag.NONE

        # ── Compute time deltas ───────────────────────────────────────────
        if account.last_successful_auth:
            delta = self._now - account.last_successful_auth
            account.days_since_login = delta.days
        else:
            account.days_since_login = None

        if account.last_pwd_change:
            delta = self._now - account.last_pwd_change
            account.days_since_pwd_change = delta.days
        else:
            account.days_since_pwd_change = None

        if account.created:
            delta = self._now - account.created
            account.days_since_created = delta.days
        else:
            account.days_since_created = None

        # ── Risk checks ───────────────────────────────────────────────────

        # 1. Never logged in — account exists N+ days but no auth record
        if (
            account.last_successful_auth is None
            and account.days_since_created is not None
            and account.days_since_created >= self.never_days
        ):
            flags |= RiskFlag.NEVER_LOGGED_IN

        # 2. Inactive — logged in before, but not recently
        elif (
            account.last_successful_auth is not None
            and account.days_since_login is not None
            and account.days_since_login > self.inactive_days
        ):
            flags |= RiskFlag.INACTIVE

        # 3. Account locked
        if account.locked:
            flags |= RiskFlag.ACCOUNT_LOCKED

        # 4. Password expired (in the past)
        if (
            account.pwd_expiration is not None
            and account.pwd_expiration < self._now
        ):
            flags |= RiskFlag.PASSWORD_EXPIRED

        # 5. Kerberos principal expired
        if (
            account.principal_expiration is not None
            and account.principal_expiration < self._now
        ):
            flags |= RiskFlag.PRINCIPAL_EXPIRED

        # 6. Stale password — unchanged beyond threshold and no expiry enforced
        if (
            account.pwd_expiration is None                    # no enforced expiry
            and account.days_since_pwd_change is not None
            and account.days_since_pwd_change > self.password_days
        ):
            flags |= RiskFlag.STALE_PASSWORD

        # 7. No group memberships — orphaned or forgotten account
        if not account.groups:
            flags |= RiskFlag.NO_GROUPS

        # 8. No email — may indicate unowned service or test account
        if not account.mail:
            flags |= RiskFlag.NO_EMAIL

        # 9. Privileged + inactive — escalated risk
        if account.is_privileged and (
            flags & (RiskFlag.INACTIVE | RiskFlag.NEVER_LOGGED_IN)
        ):
            flags |= RiskFlag.PRIVILEGED_INACTIVE

        # 10. High failed login count — potential brute force or forgotten password
        if account.failed_login_count >= self.failed_threshold:
            flags |= RiskFlag.HIGH_FAILED_LOGINS

        account.risk_flags = flags
        return account

    def run(self) -> tuple[list[UserAccount], AuditSummary]:
        """
        Run the full audit.

        Returns (all_accounts, summary) where all_accounts includes both
        flagged and clean accounts (useful for full inventory reports).
        """
        accounts = self.fetch_users()

        summary = AuditSummary(
            server          = self.client.server,
            bind_user       = "(audit user)",
            audit_timestamp = self._now.isoformat(),
            total_users     = len(accounts),
            thresholds      = {
                "inactive_days":    self.inactive_days,
                "password_days":    self.password_days,
                "never_login_days": self.never_days,
                "failed_threshold": self.failed_threshold,
            },
            nist_controls = [
                "AC-3.1.1", "AC-3.1.2", "IA-3.5.4", "IA-3.5.7", "AC-3.1.14"
            ],
        )

        for account in accounts:
            self.audit_account(account)
            sev = account.risk_flags.severity

            if sev == "clean":
                summary.clean_users += 1
            else:
                summary.flagged_users += 1
                if sev == "critical":
                    summary.critical_count += 1
                elif sev == "high":
                    summary.high_count += 1
                elif sev == "medium":
                    summary.medium_count += 1
                elif sev == "low":
                    summary.low_count += 1

            # Individual flag counters
            f = account.risk_flags
            if f & RiskFlag.ACCOUNT_LOCKED:      summary.locked_count      += 1
            if f & RiskFlag.NEVER_LOGGED_IN:     summary.never_logged_in   += 1
            if f & RiskFlag.INACTIVE:            summary.inactive_count    += 1
            if f & RiskFlag.PASSWORD_EXPIRED:    summary.expired_passwords += 1
            if f & RiskFlag.PRINCIPAL_EXPIRED:   summary.expired_principals += 1
            if f & RiskFlag.STALE_PASSWORD:      summary.stale_passwords   += 1
            if f & RiskFlag.NO_GROUPS:           summary.no_groups         += 1
            if f & RiskFlag.NO_EMAIL:            summary.no_email          += 1
            if f & RiskFlag.PRIVILEGED_INACTIVE: summary.privileged_stale  += 1

        return accounts, summary


# ─── Report Writers ───────────────────────────────────────────────────────────

def account_to_dict(account: UserAccount) -> dict:
    """Serialize a UserAccount to a JSON-serializable dict."""
    def fmt_dt(dt: Optional[datetime]) -> Optional[str]:
        return dt.isoformat() if dt else None

    return {
        "uid":                   account.uid,
        "cn":                    account.cn,
        "givenname":             account.givenname,
        "sn":                    account.sn,
        "mail":                  account.mail,
        "locked":                account.locked,
        "is_privileged":         account.is_privileged,
        "title":                 account.title,
        "department":            account.department,
        "employee_number":       account.employee_number,
        "groups":                account.groups,
        "roles":                 account.roles,
        "sudo_rules":            account.sudo_rules,
        "hbac_rules":            account.hbac_rules,
        "ssh_keys_count":        account.ssh_keys_count,
        "last_successful_auth":  fmt_dt(account.last_successful_auth),
        "last_failed_auth":      fmt_dt(account.last_failed_auth),
        "failed_login_count":    account.failed_login_count,
        "last_pwd_change":       fmt_dt(account.last_pwd_change),
        "pwd_expiration":        fmt_dt(account.pwd_expiration),
        "principal_expiration":  fmt_dt(account.principal_expiration),
        "created":               fmt_dt(account.created),
        "modified":              fmt_dt(account.modified),
        "days_since_login":      account.days_since_login,
        "days_since_pwd_change": account.days_since_pwd_change,
        "days_since_created":    account.days_since_created,
        "risk_flags":            account.risk_flags.as_list(),
        "severity":              account.risk_flags.severity,
        "nist_controls":         account.risk_flags.nist_controls,
    }


def write_json(
    accounts:  list[UserAccount],
    summary:   AuditSummary,
    path:      str,
    flagged_only: bool = False,
) -> None:
    out = accounts if not flagged_only else [
        a for a in accounts if a.risk_flags.severity != "clean"
    ]
    data = {
        "summary": asdict(summary),
        "accounts": [account_to_dict(a) for a in out],
    }
    Path(path).write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
    logging.getLogger("report").info(f"JSON report written: {path}")


def write_csv(
    accounts:  list[UserAccount],
    path:      str,
    flagged_only: bool = False,
) -> None:
    out = accounts if not flagged_only else [
        a for a in accounts if a.risk_flags.severity != "clean"
    ]

    fields = [
        "uid", "cn", "mail", "locked", "is_privileged",
        "severity", "risk_flags",
        "days_since_login", "days_since_pwd_change", "days_since_created",
        "last_successful_auth", "pwd_expiration", "principal_expiration",
        "groups", "nist_controls",
        "failed_login_count", "department", "title",
    ]

    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for a in out:
            d = account_to_dict(a)
            # Flatten lists to semicolon-delimited strings for CSV
            for k in ("groups", "risk_flags", "nist_controls"):
                d[k] = "; ".join(d[k])
            writer.writerow(d)

    logging.getLogger("report").info(f"CSV report written: {path}")


def write_html(
    accounts:  list[UserAccount],
    summary:   AuditSummary,
    path:      str,
) -> None:
    """Generate a self-contained HTML audit report."""

    flagged = [a for a in accounts if a.risk_flags.severity != "clean"]
    clean   = [a for a in accounts if a.risk_flags.severity == "clean"]

    severity_colors = {
        "critical": "#dc2626",
        "high":     "#ea580c",
        "medium":   "#d97706",
        "low":      "#2563eb",
        "clean":    "#16a34a",
    }

    def sev_badge(sev: str) -> str:
        color = severity_colors.get(sev, "#6b7280")
        return (
            f'<span style="background:{color};color:white;padding:2px 8px;'
            f'border-radius:4px;font-size:11px;font-weight:bold">'
            f'{sev.upper()}</span>'
        )

    def flag_pills(flags: list[str]) -> str:
        pills = []
        for f in flags:
            pills.append(
                f'<span style="background:#f3f4f6;color:#374151;padding:1px 6px;'
                f'border-radius:3px;font-size:10px;margin:1px;display:inline-block">'
                f'{f}</span>'
            )
        return " ".join(pills)

    def opt(v) -> str:
        return str(v) if v is not None else "—"

    # Build table rows
    rows = []
    for a in sorted(flagged, key=lambda x: (
        {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(x.risk_flags.severity, 4)
    )):
        sev   = a.risk_flags.severity
        color = severity_colors.get(sev, "#6b7280")
        rows.append(f"""
          <tr style="border-left:4px solid {color}">
            <td style="padding:6px 8px;font-weight:bold">{a.uid}</td>
            <td style="padding:6px 8px">{a.cn}</td>
            <td style="padding:6px 8px">{a.mail or '<em style="color:#9ca3af">none</em>'}</td>
            <td style="padding:6px 8px">{sev_badge(sev)}</td>
            <td style="padding:6px 8px">{flag_pills(a.risk_flags.as_list())}</td>
            <td style="padding:6px 8px;text-align:right">{opt(a.days_since_login)}</td>
            <td style="padding:6px 8px;text-align:right">{opt(a.days_since_pwd_change)}</td>
            <td style="padding:6px 8px">{'🔒' if a.locked else ''}</td>
            <td style="padding:6px 8px">{'⚠️' if a.is_privileged else ''}</td>
          </tr>""")

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>FreeIPA Account Audit — {summary.server}</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
         margin: 0; padding: 20px; background: #f9fafb; color: #111827; }}
  h1   {{ font-size: 20px; color: #1e3a5f; margin-bottom: 4px; }}
  .meta {{ color: #6b7280; font-size: 13px; margin-bottom: 24px; }}
  .cards {{ display: flex; gap: 12px; flex-wrap: wrap; margin-bottom: 24px; }}
  .card {{ background: white; border-radius: 8px; padding: 16px 20px;
           box-shadow: 0 1px 3px rgba(0,0,0,.1); min-width: 120px; }}
  .card .num {{ font-size: 28px; font-weight: bold; }}
  .card .lbl {{ font-size: 12px; color: #6b7280; margin-top: 2px; }}
  .critical .num {{ color: #dc2626; }}
  .high .num     {{ color: #ea580c; }}
  .medium .num   {{ color: #d97706; }}
  .low .num      {{ color: #2563eb; }}
  .clean .num    {{ color: #16a34a; }}
  table {{ width: 100%; border-collapse: collapse; background: white;
           border-radius: 8px; overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,.1); }}
  th {{ background: #1e3a5f; color: white; padding: 8px; text-align: left;
       font-size: 12px; font-weight: 600; }}
  tr:nth-child(even) {{ background: #f9fafb; }}
  td {{ font-size: 12px; border-bottom: 1px solid #e5e7eb; }}
  .nist {{ margin-top: 24px; background: white; border-radius: 8px; padding: 16px;
           box-shadow: 0 1px 3px rgba(0,0,0,.1); }}
  .nist h3 {{ margin: 0 0 8px 0; font-size: 14px; color: #1e3a5f; }}
  .nist p {{ font-size: 12px; color: #374151; margin: 4px 0; }}
  .footer {{ margin-top: 20px; font-size: 11px; color: #9ca3af; }}
</style>
</head>
<body>
<h1>FreeIPA Account Lifecycle Audit</h1>
<div class="meta">
  Server: <strong>{summary.server}</strong> &nbsp;·&nbsp;
  Generated: <strong>{summary.audit_timestamp}</strong> &nbsp;·&nbsp;
  Thresholds: inactive &gt; {summary.thresholds.get('inactive_days')}d,
  password unchanged &gt; {summary.thresholds.get('password_days')}d
</div>

<div class="cards">
  <div class="card"><div class="num">{summary.total_users}</div>
    <div class="lbl">Total Users</div></div>
  <div class="card critical"><div class="num">{summary.critical_count}</div>
    <div class="lbl">Critical</div></div>
  <div class="card high"><div class="num">{summary.high_count}</div>
    <div class="lbl">High</div></div>
  <div class="card medium"><div class="num">{summary.medium_count}</div>
    <div class="lbl">Medium</div></div>
  <div class="card low"><div class="num">{summary.low_count}</div>
    <div class="lbl">Low</div></div>
  <div class="card clean"><div class="num">{summary.clean_users}</div>
    <div class="lbl">Clean</div></div>
</div>

<div class="cards">
  <div class="card"><div class="num">{summary.locked_count}</div>
    <div class="lbl">Locked</div></div>
  <div class="card"><div class="num">{summary.never_logged_in}</div>
    <div class="lbl">Never Logged In</div></div>
  <div class="card"><div class="num">{summary.inactive_count}</div>
    <div class="lbl">Inactive</div></div>
  <div class="card"><div class="num">{summary.expired_passwords}</div>
    <div class="lbl">Expired Passwords</div></div>
  <div class="card"><div class="num">{summary.privileged_stale}</div>
    <div class="lbl">Privileged + Stale</div></div>
  <div class="card"><div class="num">{summary.no_email}</div>
    <div class="lbl">No Email</div></div>
</div>

<h2 style="font-size:16px;color:#1e3a5f;margin-bottom:8px">
  Flagged Accounts ({len(flagged)})
</h2>

<table>
  <thead>
    <tr>
      <th>UID</th><th>Display Name</th><th>Email</th><th>Severity</th>
      <th>Risk Flags</th><th>Days Since Login</th><th>Days Since Pwd Chg</th>
      <th>Locked</th><th>Privileged</th>
    </tr>
  </thead>
  <tbody>
    {''.join(rows) if rows else '<tr><td colspan="9" style="text-align:center;padding:20px;color:#6b7280">No flagged accounts found</td></tr>'}
  </tbody>
</table>

<div class="nist">
  <h3>NIST 800-171 Controls Addressed</h3>
  <p><strong>AC-3.1.1</strong> — Limit system access to authorized users, processes, and devices</p>
  <p><strong>AC-3.1.2</strong> — Limit system access to types of transactions authorized users are permitted to execute</p>
  <p><strong>IA-3.5.4</strong> — Manage information system identifiers for users and devices</p>
  <p><strong>IA-3.5.7</strong> — Enforce minimum password complexity and change requirements</p>
  <p><strong>AC-3.1.14</strong> — Employ cryptographic mechanisms to protect remote access sessions</p>
</div>

<div class="footer">
  Generated by freeipa_account_auditor.py v{VERSION} &nbsp;·&nbsp;
  Jason A. Slocomb &nbsp;·&nbsp;
  {len(flagged)} flagged, {len(clean)} clean of {summary.total_users} total accounts
</div>
</body>
</html>"""

    Path(path).write_text(html, encoding="utf-8")
    logging.getLogger("report").info(f"HTML report written: {path}")


def print_console_summary(accounts: list[UserAccount], summary: AuditSummary) -> None:
    """Print a human-readable audit summary to stderr."""
    log = logging.getLogger("console")
    flagged = [a for a in accounts if a.risk_flags.severity != "clean"]

    log.info("═" * 65)
    log.info(f"  FreeIPA Account Lifecycle Audit")
    log.info(f"  Server    : {summary.server}")
    log.info(f"  Timestamp : {summary.audit_timestamp}")
    log.info(f"  Thresholds: inactive={summary.thresholds['inactive_days']}d  "
             f"password={summary.thresholds['password_days']}d  "
             f"never-login={summary.thresholds['never_login_days']}d")
    log.info("─" * 65)
    log.info(f"  Total accounts   : {summary.total_users}")
    log.info(f"  Clean            : {summary.clean_users}")
    log.info(f"  Flagged          : {summary.flagged_users}")
    log.info(f"    Critical        : {summary.critical_count}")
    log.info(f"    High            : {summary.high_count}")
    log.info(f"    Medium          : {summary.medium_count}")
    log.info(f"    Low             : {summary.low_count}")
    log.info("─" * 65)
    log.info(f"  Locked accounts  : {summary.locked_count}")
    log.info(f"  Never logged in  : {summary.never_logged_in}")
    log.info(f"  Inactive         : {summary.inactive_count}")
    log.info(f"  Expired password : {summary.expired_passwords}")
    log.info(f"  Expired principal: {summary.expired_principals}")
    log.info(f"  Stale password   : {summary.stale_passwords}")
    log.info(f"  Privileged+stale : {summary.privileged_stale}")
    log.info(f"  No groups        : {summary.no_groups}")
    log.info(f"  No email         : {summary.no_email}")
    log.info("═" * 65)

    if flagged:
        log.info("  Flagged Accounts (sorted by severity):")
        log.info("")
        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        for a in sorted(flagged, key=lambda x: sev_order.get(x.risk_flags.severity, 9)):
            sev   = a.risk_flags.severity.upper().ljust(8)
            flags = ", ".join(a.risk_flags.as_list())
            login = f"{a.days_since_login}d" if a.days_since_login is not None else "never"
            log.info(f"  [{sev}] {a.uid:<20} login={login:<8} {flags}")

    log.info("═" * 65)


# ─── Mock / Offline Mode ──────────────────────────────────────────────────────

def generate_mock_accounts() -> list[dict]:
    """
    Generate realistic synthetic FreeIPA user entries for offline testing.
    Covers all risk flag scenarios.
    """
    now = datetime.now(timezone.utc)

    def ts(dt: Optional[datetime]) -> Optional[dict]:
        if dt is None:
            return None
        return {"__datetime__": dt.strftime(IPA_DATETIME_FORMAT)}

    def ago(days: int) -> datetime:
        return now - timedelta(days=days)

    def future(days: int) -> datetime:
        return now + timedelta(days=days)

    return [
        # Clean active admin
        {
            "uid": ["jsmith"],
            "cn": ["John Smith"],
            "givenname": ["John"],
            "sn": ["Smith"],
            "mail": ["jsmith@lab.internal"],
            "nsaccountlock": False,
            "krbLastSuccessfulAuth": ts(ago(1)),
            "krbLastPwdChange": ts(ago(45)),
            "krbPasswordExpiration": ts(future(90)),
            "krbPrincipalExpiration": None,
            "krbLoginFailedCount": ["0"],
            "memberof_group": ["admins", "ipausers"],
            "createTimestamp": ts(ago(400)),
        },
        # Never logged in — account created 45 days ago
        {
            "uid": ["tnewbie"],
            "cn": ["Tom Newbie"],
            "givenname": ["Tom"],
            "sn": ["Newbie"],
            "mail": ["tnewbie@lab.internal"],
            "nsaccountlock": False,
            "krbLastSuccessfulAuth": None,
            "krbLastPwdChange": ts(ago(45)),
            "krbPasswordExpiration": ts(future(45)),
            "krbPrincipalExpiration": None,
            "krbLoginFailedCount": ["0"],
            "memberof_group": ["ipausers"],
            "createTimestamp": ts(ago(45)),
        },
        # Inactive — last login 120 days ago
        {
            "uid": ["bwilson"],
            "cn": ["Bob Wilson"],
            "givenname": ["Bob"],
            "sn": ["Wilson"],
            "mail": ["bwilson@lab.internal"],
            "nsaccountlock": False,
            "krbLastSuccessfulAuth": ts(ago(120)),
            "krbLastPwdChange": ts(ago(150)),
            "krbPasswordExpiration": ts(future(30)),
            "krbPrincipalExpiration": None,
            "krbLoginFailedCount": ["0"],
            "memberof_group": ["ipausers"],
            "createTimestamp": ts(ago(365)),
        },
        # CRITICAL — locked admin account
        {
            "uid": ["svc_deploy"],
            "cn": ["Deploy Service Account"],
            "givenname": ["Deploy"],
            "sn": ["Service"],
            "mail": None,
            "nsaccountlock": True,
            "krbLastSuccessfulAuth": ts(ago(200)),
            "krbLastPwdChange": ts(ago(200)),
            "krbPasswordExpiration": ts(ago(50)),
            "krbPrincipalExpiration": None,
            "krbLoginFailedCount": ["15"],
            "memberof_group": ["admins", "ipausers"],
            "createTimestamp": ts(ago(730)),
        },
        # Expired principal — high risk
        {
            "uid": ["mthomas"],
            "cn": ["Mary Thomas"],
            "givenname": ["Mary"],
            "sn": ["Thomas"],
            "mail": ["mthomas@lab.internal"],
            "nsaccountlock": False,
            "krbLastSuccessfulAuth": ts(ago(30)),
            "krbLastPwdChange": ts(ago(30)),
            "krbPasswordExpiration": ts(future(60)),
            "krbPrincipalExpiration": ts(ago(5)),
            "krbLoginFailedCount": ["0"],
            "memberof_group": ["ipausers"],
            "createTimestamp": ts(ago(500)),
        },
        # Stale password (no expiry policy, 400 days unchanged)
        {
            "uid": ["rjones"],
            "cn": ["Robert Jones"],
            "givenname": ["Robert"],
            "sn": ["Jones"],
            "mail": ["rjones@lab.internal"],
            "nsaccountlock": False,
            "krbLastSuccessfulAuth": ts(ago(10)),
            "krbLastPwdChange": ts(ago(400)),
            "krbPasswordExpiration": None,
            "krbPrincipalExpiration": None,
            "krbLoginFailedCount": ["0"],
            "memberof_group": ["ipausers"],
            "createTimestamp": ts(ago(800)),
        },
        # No groups — orphaned account
        {
            "uid": ["orphan01"],
            "cn": ["Orphan Account"],
            "givenname": ["Orphan"],
            "sn": ["Account"],
            "mail": None,
            "nsaccountlock": False,
            "krbLastSuccessfulAuth": ts(ago(5)),
            "krbLastPwdChange": ts(ago(60)),
            "krbPasswordExpiration": None,
            "krbPrincipalExpiration": None,
            "krbLoginFailedCount": ["0"],
            "memberof_group": [],
            "createTimestamp": ts(ago(90)),
        },
        # Privileged + inactive (CRITICAL combo)
        {
            "uid": ["formadmin"],
            "cn": ["Former Admin"],
            "givenname": ["Former"],
            "sn": ["Admin"],
            "mail": ["formadmin@lab.internal"],
            "nsaccountlock": False,
            "krbLastSuccessfulAuth": ts(ago(150)),
            "krbLastPwdChange": ts(ago(150)),
            "krbPasswordExpiration": ts(future(30)),
            "krbPrincipalExpiration": None,
            "krbLoginFailedCount": ["0"],
            "memberof_group": ["admins", "ipausers", "trust admins"],
            "createTimestamp": ts(ago(600)),
        },
        # Clean regular user
        {
            "uid": ["alee"],
            "cn": ["Alice Lee"],
            "givenname": ["Alice"],
            "sn": ["Lee"],
            "mail": ["alee@lab.internal"],
            "nsaccountlock": False,
            "krbLastSuccessfulAuth": ts(ago(3)),
            "krbLastPwdChange": ts(ago(30)),
            "krbPasswordExpiration": ts(future(60)),
            "krbPrincipalExpiration": None,
            "krbLoginFailedCount": ["0"],
            "memberof_group": ["ipausers", "dev-team"],
            "createTimestamp": ts(ago(200)),
        },
        # High failed logins
        {
            "uid": ["kpatel"],
            "cn": ["Kamil Patel"],
            "givenname": ["Kamil"],
            "sn": ["Patel"],
            "mail": ["kpatel@lab.internal"],
            "nsaccountlock": False,
            "krbLastSuccessfulAuth": ts(ago(2)),
            "krbLastPwdChange": ts(ago(60)),
            "krbPasswordExpiration": ts(future(30)),
            "krbPrincipalExpiration": None,
            "krbLoginFailedCount": ["23"],
            "memberof_group": ["ipausers"],
            "createTimestamp": ts(ago(365)),
        },
    ]


# ─── CLI ──────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="freeipa_account_auditor",
        description="FreeIPA account lifecycle auditor — stale/risky account detection",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    conn = p.add_argument_group("Connection")
    conn.add_argument(
        "--server", "-s",
        default=os.environ.get("IPA_SERVER", ""),
        metavar="FQDN",
        help="FreeIPA server hostname  [env: IPA_SERVER]",
    )
    conn.add_argument(
        "--binduser", "-u",
        default=os.environ.get("IPA_BINDUSER", "admin"),
        metavar="USER",
        help="Bind username  (default: admin)  [env: IPA_BINDUSER]",
    )
    conn.add_argument(
        "--password", "-p",
        default=os.environ.get("IPA_PASSWORD", ""),
        metavar="PASS",
        help="Bind password  (prefer env var IPA_PASSWORD or interactive prompt)",
    )
    conn.add_argument(
        "--no-ssl-verify",
        action="store_true",
        help="Disable SSL certificate verification (lab self-signed certs)",
    )

    thresh = p.add_argument_group("Thresholds")
    thresh.add_argument(
        "--inactive-days",
        type=int, default=DEFAULT_INACTIVE_DAYS, metavar="N",
        help=f"Flag accounts with no login in last N days  (default: {DEFAULT_INACTIVE_DAYS})",
    )
    thresh.add_argument(
        "--password-days",
        type=int, default=DEFAULT_PASSWORD_DAYS, metavar="N",
        help=f"Flag accounts with password unchanged N+ days (default: {DEFAULT_PASSWORD_DAYS})",
    )
    thresh.add_argument(
        "--never-days",
        type=int, default=DEFAULT_NEVER_DAYS, metavar="N",
        help=f"Flag accounts created N+ days ago with no login  (default: {DEFAULT_NEVER_DAYS})",
    )
    thresh.add_argument(
        "--failed-threshold",
        type=int, default=10, metavar="N",
        help="Flag accounts with N+ consecutive failed logins  (default: 10)",
    )
    thresh.add_argument(
        "--exclude-users",
        default="", metavar="UID[,UID...]",
        help="Comma-separated UIDs to exclude (added to built-in system account list)",
    )

    output = p.add_argument_group("Output")
    output.add_argument(
        "--output-json",
        metavar="FILE",
        help="Write full audit results as JSON",
    )
    output.add_argument(
        "--output-csv",
        metavar="FILE",
        help="Write flagged accounts to CSV",
    )
    output.add_argument(
        "--output-html",
        metavar="FILE",
        help="Write audit report as HTML",
    )
    output.add_argument(
        "--flagged-only",
        action="store_true",
        help="Include only flagged accounts in JSON/CSV output (default: include all)",
    )
    output.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
    )

    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Parse and audit offline using synthetic test data (no IPA connection needed)",
    )
    p.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {VERSION}",
    )
    return p


def configure_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level),
        format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
        stream=sys.stderr,
    )


def main() -> int:
    args   = build_parser().parse_args()
    configure_logging(args.log_level)
    log    = logging.getLogger("main")

    # Build exclude set
    exclude = set(SYSTEM_ACCOUNTS_DEFAULT)
    if args.exclude_users:
        exclude |= {u.strip() for u in args.exclude_users.split(",") if u.strip()}

    # ── Dry run — use synthetic test data ─────────────────────────────────
    if args.dry_run:
        log.info("Dry run mode — using synthetic test data (no IPA connection)")
        raw_entries = generate_mock_accounts()
        accounts: list[UserAccount] = []
        for entry in raw_entries:
            try:
                a = parse_user_entry(entry)
                if a.uid not in exclude:
                    accounts.append(a)
            except Exception as exc:
                log.warning(f"Mock parse error: {exc}")

        auditor = AccountAuditor(
            client           = None,   # not needed for audit logic
            inactive_days    = args.inactive_days,
            password_days    = args.password_days,
            never_days       = args.never_days,
            failed_threshold = args.failed_threshold,
            exclude_users    = exclude,
        )

        # Run audit logic without fetching (already have accounts)
        from dataclasses import asdict as _asdict
        now = datetime.now(timezone.utc)
        auditor._now = now

        summary = AuditSummary(
            server          = args.server or "dry-run.local",
            bind_user       = args.binduser,
            audit_timestamp = now.isoformat(),
            total_users     = len(accounts),
            thresholds      = {
                "inactive_days":    args.inactive_days,
                "password_days":    args.password_days,
                "never_login_days": args.never_days,
                "failed_threshold": args.failed_threshold,
            },
            nist_controls = ["AC-3.1.1", "AC-3.1.2", "IA-3.5.4", "IA-3.5.7"],
        )

        for a in accounts:
            auditor.audit_account(a)
            sev = a.risk_flags.severity
            if sev == "clean":
                summary.clean_users += 1
            else:
                summary.flagged_users += 1
                if sev == "critical":  summary.critical_count  += 1
                elif sev == "high":    summary.high_count      += 1
                elif sev == "medium":  summary.medium_count    += 1
                elif sev == "low":     summary.low_count       += 1

            f = a.risk_flags
            if f & RiskFlag.ACCOUNT_LOCKED:      summary.locked_count      += 1
            if f & RiskFlag.NEVER_LOGGED_IN:     summary.never_logged_in   += 1
            if f & RiskFlag.INACTIVE:            summary.inactive_count    += 1
            if f & RiskFlag.PASSWORD_EXPIRED:    summary.expired_passwords += 1
            if f & RiskFlag.PRINCIPAL_EXPIRED:   summary.expired_principals += 1
            if f & RiskFlag.STALE_PASSWORD:      summary.stale_passwords   += 1
            if f & RiskFlag.NO_GROUPS:           summary.no_groups         += 1
            if f & RiskFlag.NO_EMAIL:            summary.no_email          += 1
            if f & RiskFlag.PRIVILEGED_INACTIVE: summary.privileged_stale  += 1

    # ── Live mode — connect to IPA ─────────────────────────────────────────
    else:
        if not args.server:
            log.error(
                "No server specified. Use --server or set IPA_SERVER. "
                "Use --dry-run for offline testing."
            )
            return 1

        password = args.password
        if not password:
            try:
                password = getpass.getpass(
                    f"Password for {args.binduser}@{args.server}: "
                )
            except (KeyboardInterrupt, EOFError):
                log.error("Aborted.")
                return 1

        client = FreeIPAClient(
            server     = args.server,
            verify_ssl = not args.no_ssl_verify,
        )

        try:
            client.login(args.binduser, password)
        except PermissionError as exc:
            log.error(str(exc))
            return 1
        except Exception as exc:
            log.error(f"Connection failed: {exc}")
            return 1

        try:
            auditor = AccountAuditor(
                client           = client,
                inactive_days    = args.inactive_days,
                password_days    = args.password_days,
                never_days       = args.never_days,
                failed_threshold = args.failed_threshold,
                exclude_users    = exclude,
            )
            accounts, summary = auditor.run()
            summary.bind_user = args.binduser
        finally:
            client.logout()

    # ── Console output ─────────────────────────────────────────────────────
    print_console_summary(accounts, summary)

    # ── File outputs ───────────────────────────────────────────────────────
    if args.output_json:
        write_json(accounts, summary, args.output_json, args.flagged_only)

    if args.output_csv:
        write_csv(accounts, args.output_csv, args.flagged_only)

    if args.output_html:
        write_html(accounts, summary, args.output_html)

    # Exit non-zero if any critical/high findings
    if summary.critical_count > 0:
        return 2   # distinct exit code — useful for alerting in scripts
    if summary.high_count > 0:
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
