#!/usr/bin/env python3
"""
aide_to_splunk.py
─────────────────────────────────────────────────────────────────────────────
AIDE File Integrity Report Parser → Splunk HEC Ingest

Parses AIDE (Advanced Intrusion Detection Environment) report output and
ships structured events to a Splunk HTTP Event Collector (HEC) endpoint.

Designed for NIST 800-171 / CMMC Level 2 compliance environments.

NIST 800-171 Controls addressed:
  SI-3.14.7  Identify unauthorized use of organizational systems
  AU-3.3.1   Create and retain system audit records
  CM-3.4.1   Establish and maintain baseline configurations
  CM-3.4.3   Track, review, approve/disapprove changes to systems

Usage:
    # Basic — parse and send to Splunk
    python3 aide_to_splunk.py \\
        --report /var/log/aide/aide.log \\
        --hec-url https://splunk.lab.internal:8088 \\
        --hec-token xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx

    # Dry run — parse only, print JSON to stdout
    python3 aide_to_splunk.py --report /var/log/aide/aide.log --dry-run

    # Read from stdin (pipe directly from AIDE)
    aide --check 2>&1 | python3 aide_to_splunk.py --report -

    # Save parsed events to file as well as sending to Splunk
    python3 aide_to_splunk.py --report aide.log --output-json events.json

Environment variables (alternatives to CLI flags):
    SPLUNK_HEC_URL      HEC base URL, e.g. https://splunk.lab.internal:8088
    SPLUNK_HEC_TOKEN    HEC authentication token
    SPLUNK_INDEX        Target index          (default: os_logs)
    SPLUNK_SOURCETYPE   Sourcetype            (default: aide:report)
    AIDE_HOSTNAME       Override reported hostname

Typical cron invocation on each monitored node:
    0 4 * * * root aide --check 2>&1 | \\
        SPLUNK_HEC_URL=https://splunk.lab.internal:8088 \\
        SPLUNK_HEC_TOKEN=<token> \\
        python3 /usr/local/bin/aide_to_splunk.py --report - --no-ssl-verify

Author : Jason A. Slocomb
Version: 1.1.0
─────────────────────────────────────────────────────────────────────────────
"""

import argparse
import json
import logging
import os
import re
import socket
import ssl
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Optional


# ─── Constants ────────────────────────────────────────────────────────────────

VERSION             = "1.1.0"
DEFAULT_INDEX       = "os_logs"
DEFAULT_SOURCETYPE  = "aide:report"
HEC_ENDPOINT_PATH   = "/services/collector/event"
HEC_BATCH_SIZE      = 50       # events per HTTP POST
HEC_TIMEOUT_SECONDS = 30
MAX_REPORT_SIZE_MB  = 50


# AIDE attribute flag characters → human-readable names
# These appear in the flags column of AIDE entry lines
AIDE_ATTR_MAP = {
    "p": "permissions",
    "i": "inode",
    "n": "link_count",
    "u": "user",
    "g": "group",
    "s": "size",
    "b": "block_count",
    "m": "mtime",
    "a": "atime",
    "c": "ctime",
    "S": "size_increased",
    "C": "checksum",
    "h": "hardlink",
    "X": "selinux_context",
    "A": "acl",
    "F": "xattrs",
    "E": "capabilities",
    "I": "inode_number",
    "T": "type",
}

# First character of AIDE flag string → file object type
AIDE_TYPE_MAP = {
    "f": "file",
    "d": "directory",
    "l": "symlink",
    "p": "pipe",
    "s": "socket",
    "b": "block_device",
    "c": "char_device",
    "D": "door",
}

# Paths that warrant HIGH or CRITICAL severity
HIGH_SEVERITY_PATHS = [
    re.compile(r"^/etc/(passwd|shadow|shadow-|gshadow|group|sudoers)$"),
    re.compile(r"^/etc/sudoers\.d/"),
    re.compile(r"^/etc/ssh/"),
    re.compile(r"^/etc/pam\.d/"),
    re.compile(r"^/etc/security/"),
    re.compile(r"^/etc/cron"),
    re.compile(r"^/etc/systemd/system/"),
    re.compile(r"^/usr/sbin/(sshd|sudo|su|login|passwd|useradd|usermod|userdel)$"),
    re.compile(r"^/usr/bin/(sudo|su|passwd|crontab|at)$"),
    re.compile(r"^/bin/(sh|bash|dash|zsh|ksh)$"),
    re.compile(r"^/sbin/(init|shutdown|reboot|auditd)$"),
    re.compile(r"^/root/"),
    re.compile(r"^/(tmp|var/tmp|dev/shm)/"),
    re.compile(r"\.(sh|py|pl|rb|php|elf|so)$"),
]

# Paths that change routinely — low value to alert on
EXPECTED_CHANGE_PATHS = [
    re.compile(r"^/var/log/"),
    re.compile(r"^/var/run/"),
    re.compile(r"^/var/cache/"),
    re.compile(r"^/var/spool/"),
    re.compile(r"^/proc/"),
    re.compile(r"^/sys/"),
    re.compile(r"\.log(\.\d+)?(\.gz)?$"),
    re.compile(r"/(lastlog|wtmp|utmp)$"),
]

# Specific file paths that are always CRITICAL when changed
CRITICAL_PATHS = {
    "/etc/passwd",
    "/etc/shadow",
    "/etc/shadow-",
    "/etc/gshadow",
    "/etc/sudoers",
    "/usr/sbin/sshd",
    "/usr/bin/sudo",
    "/bin/su",
    "/usr/bin/su",
}

# NIST 800-171 control sets by path category
NIST_CONTROL_MAP = {
    "auth_files":    ["AC-3.1.1", "IA-3.5.1", "SI-3.14.7", "CM-3.4.1"],
    "ssh_config":    ["SC-3.13.8", "AC-3.1.2", "CM-3.4.1",  "SI-3.14.7"],
    "cron":          ["SI-3.14.7", "CM-3.4.3", "AU-3.3.1"],
    "system_binary": ["SI-3.14.7", "CM-3.4.1", "CM-3.4.3"],
    "tmp_addition":  ["SI-3.14.7", "CM-3.4.3", "AU-3.3.1"],
    "default":       ["SI-3.14.7", "CM-3.4.1", "AU-3.3.1"],
}


# ─── Data Models ──────────────────────────────────────────────────────────────

class ChangeType(str, Enum):
    ADDED   = "added"
    REMOVED = "removed"
    CHANGED = "changed"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"
    INFO     = "info"

    @classmethod
    def highest(cls, items: list) -> "Severity":
        order = [cls.CRITICAL, cls.HIGH, cls.MEDIUM, cls.LOW, cls.INFO]
        for s in order:
            if s in items:
                return s
        return cls.INFO


@dataclass
class FileChange:
    """One file-level change detected by AIDE."""
    path:               str
    change_type:        ChangeType
    file_type:          str    = "file"
    attributes_changed: list   = field(default_factory=list)
    attribute_details:  dict   = field(default_factory=dict)
    severity:           Severity = Severity.MEDIUM
    nist_controls:      list   = field(default_factory=list)


@dataclass
class AideReport:
    """Complete parsed representation of one AIDE run."""
    hostname:          str
    report_path:       str
    aide_version:      Optional[str] = None
    start_timestamp:   Optional[str] = None
    end_timestamp:     Optional[str] = None
    runtime_seconds:   Optional[int] = None
    total_entries:     int           = 0
    added_count:       int           = 0
    removed_count:     int           = 0
    changed_count:     int           = 0
    differences_found: bool          = False
    changes:           list          = field(default_factory=list)
    parse_warnings:    list          = field(default_factory=list)


# ─── Parser ───────────────────────────────────────────────────────────────────

class AideReportParser:
    """
    Parse AIDE text report output into a structured AideReport.

    AIDE report structure:

        AIDE 0.17.4 found differences between database and filesystem!!

        Start timestamp: 2025-03-01 03:15:42 -0800 (AIDE 0.17.4)

        Summary:
          Total number of entries:      42891
          Added entries:                3
          Removed entries:              1
          Changed entries:              7

        ---------------------------------------------------
        Added entries:
        ---------------------------------------------------

        f++++++++++++++++: /path/to/new/file

        ---------------------------------------------------
        Changed entries:
        ---------------------------------------------------

        f =.... mc.. .. .: /etc/passwd
        f <.... mc.iCsh..: /var/log/auth.log   (<  = size decreased)

        ---------------------------------------------------
        Detailed information about changes:
        ---------------------------------------------------

        File: /etc/passwd
          SHA512   : OLD = abc123...
                     NEW = def456...
    """

    # ── Compiled patterns ──────────────────────────────────────────────────

    RE_DIFFERENCES = re.compile(r"AIDE\s+([\d.]+)\s+found differences",    re.I)
    RE_NO_DIFF     = re.compile(r"AIDE\s+([\d.]+)\s+found no differences", re.I)
    RE_START_TS    = re.compile(r"Start timestamp:\s+(.+?)\s+\(")
    RE_END_TS      = re.compile(r"End timestamp:\s+(.+?)\s+\(runtime")
    RE_RUNTIME     = re.compile(r"runtime:\s+(?:(\d+)m[,\s]+)?(\d+)s\)")
    RE_TOTAL       = re.compile(r"Total number of entries:\s+(\d+)")
    RE_SUM_ADD     = re.compile(r"Added entries:\s+(\d+)")
    RE_SUM_REM     = re.compile(r"Removed entries:\s+(\d+)")
    RE_SUM_CHG     = re.compile(r"Changed entries:\s+(\d+)")

    # Entry line examples:
    #   f++++++++++++++++: /path/to/file
    #   f =.... mc.. .. .: /etc/passwd
    #   f <.... mc.iCsh..: /var/log/auth.log
    # Note: < and > (size change direction) must be in the character class.
    RE_ENTRY = re.compile(r"^([fdlpsbcD][+\-=<> \.a-zA-Z]+):\s+(.+)$")

    # Detail section patterns
    RE_DETAIL_PATH = re.compile(r"^(?:File|Directory|Symlink):\s+(.+)$")
    RE_DETAIL_OLD  = re.compile(r"^\s+(\w[\w ]+?)\s*:\s*OLD\s*=\s*(.*)$")
    RE_DETAIL_NEW  = re.compile(r"^\s+NEW\s*=\s*(.*)$")

    # Section header text lines (appear between dashes)
    RE_SEC_ADDED   = re.compile(r"Added entries",        re.I)
    RE_SEC_REMOVED = re.compile(r"Removed entries",      re.I)
    RE_SEC_CHANGED = re.compile(r"Changed entries",      re.I)
    RE_SEC_DETAIL  = re.compile(r"Detailed information", re.I)
    RE_DIVIDER     = re.compile(r"^-{10,}$")

    def __init__(self, hostname: str, report_path: str):
        self.hostname    = hostname
        self.report_path = report_path
        self._log        = logging.getLogger(self.__class__.__name__)

    def parse(self, text: str) -> AideReport:
        report = AideReport(hostname=self.hostname, report_path=self.report_path)

        # Track parser state
        in_summary          = False   # True while inside the Summary: block
        current_section     = None    # None | ChangeType | "detail"
        current_detail_path = None
        current_attr_name   = None
        change_index        = {}      # path -> FileChange, for merging detail data

        for raw_line in text.splitlines():
            line     = raw_line          # preserve indentation for detail matching
            stripped = raw_line.strip()

            if not stripped or self.RE_DIVIDER.match(stripped):
                continue

            # ── Version / differences found ───────────────────────────────
            m = self.RE_DIFFERENCES.search(line)
            if m:
                report.differences_found = True
                report.aide_version      = m.group(1)
                continue

            m = self.RE_NO_DIFF.search(line)
            if m:
                report.differences_found = False
                report.aide_version      = m.group(1)
                continue

            # ── Timestamps ────────────────────────────────────────────────
            m = self.RE_START_TS.search(line)
            if m:
                report.start_timestamp = m.group(1).strip()
                continue

            m = self.RE_END_TS.search(line)
            if m:
                report.end_timestamp = m.group(1).strip()
                m2 = self.RE_RUNTIME.search(line)
                if m2:
                    report.runtime_seconds = int(m2.group(1) or 0) * 60 + int(m2.group(2))
                continue

            # ── Summary block ─────────────────────────────────────────────
            # "Summary:" line opens the block; first section header closes it.
            if stripped == "Summary:":
                in_summary = True
                continue

            if in_summary:
                m = self.RE_TOTAL.search(line)
                if m:
                    report.total_entries = int(m.group(1))
                    continue
                m = self.RE_SUM_ADD.search(line)
                if m:
                    report.added_count = int(m.group(1))
                    continue
                m = self.RE_SUM_REM.search(line)
                if m:
                    report.removed_count = int(m.group(1))
                    continue
                m = self.RE_SUM_CHG.search(line)
                if m:
                    report.changed_count = int(m.group(1))
                    continue

            # ── Section transitions ────────────────────────────────────────
            # Section names appear as plain text lines between dashes.
            if self.RE_SEC_ADDED.search(stripped):
                in_summary          = False
                current_section     = ChangeType.ADDED
                current_detail_path = None
                current_attr_name   = None
                continue

            if self.RE_SEC_REMOVED.search(stripped):
                in_summary          = False
                current_section     = ChangeType.REMOVED
                current_detail_path = None
                current_attr_name   = None
                continue

            if self.RE_SEC_CHANGED.search(stripped):
                in_summary          = False
                current_section     = ChangeType.CHANGED
                current_detail_path = None
                current_attr_name   = None
                continue

            if self.RE_SEC_DETAIL.search(stripped):
                in_summary          = False
                current_section     = "detail"
                current_detail_path = None
                current_attr_name   = None
                continue

            # ── Detail section ────────────────────────────────────────────
            if current_section == "detail":
                m = self.RE_DETAIL_PATH.match(stripped)
                if m:
                    current_detail_path = m.group(1).strip()
                    current_attr_name   = None
                    continue

                if current_detail_path:
                    # "  SHA512   : OLD = abc123" — note: match on raw_line for indent
                    m = self.RE_DETAIL_OLD.match(line)
                    if m:
                        current_attr_name = m.group(1).strip()
                        fc = change_index.get(current_detail_path)
                        if fc:
                            fc.attribute_details.setdefault(current_attr_name, {})
                            fc.attribute_details[current_attr_name]["old"] = m.group(2).strip()
                        continue

                    # "             NEW = def456"
                    m = self.RE_DETAIL_NEW.match(line)
                    if m and current_attr_name:
                        fc = change_index.get(current_detail_path)
                        if fc:
                            fc.attribute_details.setdefault(current_attr_name, {})
                            fc.attribute_details[current_attr_name]["new"] = m.group(1).strip()
                        continue

                continue  # skip unrecognised lines in detail section

            # ── Entry lines ───────────────────────────────────────────────
            if current_section in (ChangeType.ADDED, ChangeType.REMOVED, ChangeType.CHANGED):
                m = self.RE_ENTRY.match(stripped)
                if m:
                    flags_str = m.group(1)
                    path      = m.group(2).strip()
                    fc = FileChange(
                        path               = path,
                        change_type        = current_section,
                        file_type          = AIDE_TYPE_MAP.get(flags_str[0], "file"),
                        attributes_changed = self._decode_flags(flags_str[1:]),
                        severity           = self._severity(path, current_section),
                        nist_controls      = self._nist_controls(path, current_section),
                    )
                    report.changes.append(fc)
                    change_index[path] = fc

        self._validate(report)
        return report

    # ── Private helpers ───────────────────────────────────────────────────

    def _decode_flags(self, flags: str) -> list:
        """Translate AIDE flag characters into readable attribute names."""
        seen  = set()
        attrs = []
        for ch in flags:
            if ch in (".", " ", "=", "+", "-", "<", ">"):
                continue
            name = AIDE_ATTR_MAP.get(ch, f"attr_{ch}")
            if name not in seen:
                attrs.append(name)
                seen.add(name)
        return attrs

    def _severity(self, path: str, change_type: ChangeType) -> Severity:
        """Assign severity based on path sensitivity and change type."""
        # Specific always-critical files
        if path in CRITICAL_PATHS:
            return Severity.CRITICAL

        # Expected rotating / runtime files → always LOW
        for pat in EXPECTED_CHANGE_PATHS:
            if pat.search(path):
                return Severity.LOW

        # High-sensitivity path patterns
        for pat in HIGH_SEVERITY_PATHS:
            if pat.search(path):
                if change_type == ChangeType.ADDED:
                    # New file in world-writable dirs → CRITICAL
                    if re.search(r"^/(tmp|var/tmp|dev/shm)/", path):
                        return Severity.CRITICAL
                    return Severity.HIGH
                return Severity.HIGH   # removed or changed in sensitive path

        return Severity.MEDIUM

    def _nist_controls(self, path: str, change_type: ChangeType) -> list:
        """Map a file change to NIST 800-171 control identifiers."""
        if re.search(r"^/etc/(passwd|shadow|group|sudoers)", path):
            controls = list(NIST_CONTROL_MAP["auth_files"])
        elif re.search(r"^/etc/ssh/", path):
            controls = list(NIST_CONTROL_MAP["ssh_config"])
        elif re.search(r"^/etc/cron", path):
            controls = list(NIST_CONTROL_MAP["cron"])
        elif re.search(r"^/(tmp|var/tmp|dev/shm)/", path):
            controls = list(NIST_CONTROL_MAP["tmp_addition"])
        elif re.search(r"^/usr/(s?bin)/", path):
            controls = list(NIST_CONTROL_MAP["system_binary"])
        else:
            controls = list(NIST_CONTROL_MAP["default"])

        if change_type in (ChangeType.ADDED, ChangeType.REMOVED):
            if "CM-3.4.3" not in controls:
                controls.append("CM-3.4.3")

        return list(dict.fromkeys(controls))

    def _validate(self, report: AideReport) -> None:
        """Warn when parsed counts differ from summary counts."""
        counts = {
            ChangeType.ADDED:   (report.added_count,   "Added"),
            ChangeType.REMOVED: (report.removed_count, "Removed"),
            ChangeType.CHANGED: (report.changed_count, "Changed"),
        }
        for ct, (expected, label) in counts.items():
            got = sum(1 for c in report.changes if c.change_type == ct)
            if expected > 0 and got != expected:
                msg = (
                    f"{label} count mismatch: "
                    f"summary says {expected}, parsed {got}"
                )
                report.parse_warnings.append(msg)
                self._log.warning(msg)


# ─── Event Builder ────────────────────────────────────────────────────────────

class SplunkEventBuilder:
    """
    Convert an AideReport into Splunk HEC event dicts.

    Produces:
      - 1 summary event for the overall AIDE run
      - 1 event per FileChange
    """

    def __init__(self, index: str, sourcetype: str):
        self.index      = index
        self.sourcetype = sourcetype

    def build(self, report: AideReport) -> list[dict]:
        events   = []
        run_time = self._to_epoch(report.start_timestamp)
        sevs     = [c.severity for c in report.changes]

        # Summary event
        events.append(self._wrap(run_time, report, {
            "event_type":            "aide_run_summary",
            "aide_version":          report.aide_version,
            "differences_found":     report.differences_found,
            "total_entries_scanned": report.total_entries,
            "added_count":           report.added_count,
            "removed_count":         report.removed_count,
            "changed_count":         report.changed_count,
            "total_changes":         report.added_count + report.removed_count + report.changed_count,
            "start_timestamp":       report.start_timestamp,
            "end_timestamp":         report.end_timestamp,
            "runtime_seconds":       report.runtime_seconds,
            "severity":              Severity.highest(sevs).value if sevs else Severity.INFO.value,
            "parse_warnings":        report.parse_warnings,
            "nist_controls":         ["SI-3.14.7", "CM-3.4.1", "AU-3.3.1"],
        }))

        # Per-file events
        for fc in report.changes:
            ev = {
                "event_type":         "aide_file_change",
                "path":               fc.path,
                "change_type":        fc.change_type.value,
                "file_type":          fc.file_type,
                "attributes_changed": fc.attributes_changed,
                "severity":           fc.severity.value,
                "nist_controls":      fc.nist_controls,
                "requires_review":    fc.severity in (Severity.CRITICAL, Severity.HIGH),
            }
            if fc.attribute_details:
                ev["attribute_details"] = fc.attribute_details
            if "checksum" in fc.attributes_changed:
                ev["hash_changed"] = True
            events.append(self._wrap(run_time, report, ev))

        return events

    def _wrap(self, epoch: float, report: AideReport, event_data: dict) -> dict:
        return {
            "time":       epoch,
            "host":       report.hostname,
            "source":     report.report_path,
            "sourcetype": self.sourcetype,
            "index":      self.index,
            "event":      event_data,
        }

    @staticmethod
    def _to_epoch(ts: Optional[str]) -> float:
        if not ts:
            return datetime.now(timezone.utc).timestamp()
        for fmt in ("%Y-%m-%d %H:%M:%S %z", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%d %H:%M:%S"):
            try:
                return datetime.strptime(ts.strip(), fmt).timestamp()
            except ValueError:
                continue
        return datetime.now(timezone.utc).timestamp()


# ─── Splunk HEC Client ────────────────────────────────────────────────────────

class SplunkHECClient:
    """
    POST events to Splunk HEC in batches.
    Zero external dependencies — uses stdlib urllib only.
    """

    def __init__(
        self,
        hec_url:    str,
        hec_token:  str,
        index:      str  = DEFAULT_INDEX,
        sourcetype: str  = DEFAULT_SOURCETYPE,
        verify_ssl: bool = True,
    ):
        self.endpoint   = hec_url.rstrip("/") + HEC_ENDPOINT_PATH
        self.token      = hec_token
        self.index      = index
        self.sourcetype = sourcetype
        self._log       = logging.getLogger(self.__class__.__name__)

        if not verify_ssl:
            self._ssl_ctx = ssl.create_default_context()
            self._ssl_ctx.check_hostname = False
            self._ssl_ctx.verify_mode    = ssl.CERT_NONE
        else:
            self._ssl_ctx = None

    def send(self, events: list[dict]) -> tuple[int, int]:
        """Send events in batches. Returns (sent, failed)."""
        sent = failed = 0
        n_batches = (len(events) + HEC_BATCH_SIZE - 1) // HEC_BATCH_SIZE

        for i, start in enumerate(range(0, len(events), HEC_BATCH_SIZE), 1):
            batch   = events[start : start + HEC_BATCH_SIZE]
            payload = "\n".join(json.dumps(e) for e in batch).encode("utf-8")
            try:
                self._post(payload)
                sent += len(batch)
                self._log.debug(f"Batch {i}/{n_batches}: {len(batch)} events sent")
            except Exception as exc:
                failed += len(batch)
                self._log.error(f"Batch {i}/{n_batches} failed: {exc}")

        return sent, failed

    def _post(self, payload: bytes) -> None:
        req = urllib.request.Request(
            self.endpoint,
            data=payload,
            headers={
                "Authorization": f"Splunk {self.token}",
                "Content-Type":  "application/json",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(
                req, timeout=HEC_TIMEOUT_SECONDS, context=self._ssl_ctx
            ) as resp:
                result = json.loads(resp.read().decode())
                if result.get("code", 0) != 0:
                    raise RuntimeError(
                        f"HEC error code {result.get('code')}: {result.get('text')}"
                    )
        except urllib.error.HTTPError as exc:
            body = ""
            try:
                body = exc.read().decode()
            except Exception:
                pass
            raise RuntimeError(f"HTTP {exc.code} {exc.reason}: {body}") from exc


# ─── CLI ──────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="aide_to_splunk",
        description="Parse AIDE file integrity reports and ship to Splunk HEC",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--report", "-r", required=True, metavar="FILE",
                   help="AIDE report path, or '-' to read from stdin")
    p.add_argument("--hec-url", default=os.environ.get("SPLUNK_HEC_URL", ""),
                   metavar="URL", help="Splunk HEC base URL  [env: SPLUNK_HEC_URL]")
    p.add_argument("--hec-token", default=os.environ.get("SPLUNK_HEC_TOKEN", ""),
                   metavar="TOKEN", help="HEC token  [env: SPLUNK_HEC_TOKEN]")
    p.add_argument("--index", default=os.environ.get("SPLUNK_INDEX", DEFAULT_INDEX),
                   metavar="NAME", help=f"Splunk index  (default: {DEFAULT_INDEX})")
    p.add_argument("--sourcetype",
                   default=os.environ.get("SPLUNK_SOURCETYPE", DEFAULT_SOURCETYPE),
                   metavar="NAME", help=f"Sourcetype  (default: {DEFAULT_SOURCETYPE})")
    p.add_argument("--hostname",
                   default=os.environ.get("AIDE_HOSTNAME", socket.getfqdn()),
                   metavar="HOST", help="Hostname tag  (default: system FQDN)")
    p.add_argument("--no-ssl-verify", action="store_true",
                   help="Disable SSL verification (for self-signed lab certs)")
    p.add_argument("--dry-run", action="store_true",
                   help="Parse and print events as JSON; do not send to Splunk")
    p.add_argument("--output-json", metavar="FILE",
                   help="Write parsed events to a JSON file")
    p.add_argument("--log-level", default="INFO",
                   choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    p.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    return p


def configure_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level),
        format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
        stream=sys.stderr,
    )


def read_report(path: str) -> str:
    if path == "-":
        return sys.stdin.read()
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Report not found: {path}")
    mb = p.stat().st_size / (1024 * 1024)
    if mb > MAX_REPORT_SIZE_MB:
        raise ValueError(f"Report is {mb:.1f} MB — exceeds {MAX_REPORT_SIZE_MB} MB limit")
    return p.read_text(encoding="utf-8", errors="replace")


def print_run_summary(report: AideReport, event_count: int) -> None:
    log = logging.getLogger("summary")
    log.info("─" * 62)
    log.info(f"Host            : {report.hostname}")
    log.info(f"AIDE version    : {report.aide_version or 'unknown'}")
    log.info(f"Report          : {report.report_path}")
    log.info(f"Start           : {report.start_timestamp or 'unknown'}")
    if report.runtime_seconds is not None:
        log.info(f"Runtime         : {report.runtime_seconds}s")
    log.info("─" * 62)
    log.info(f"Entries scanned : {report.total_entries:,}")
    log.info(f"Differences     : {report.differences_found}")
    log.info(f"  Added         : {report.added_count}")
    log.info(f"  Removed       : {report.removed_count}")
    log.info(f"  Changed       : {report.changed_count}")
    log.info(f"HEC events built: {event_count}")

    for sev in (Severity.CRITICAL, Severity.HIGH):
        matches = [c for c in report.changes if c.severity == sev]
        if matches:
            log.warning(f"{sev.value.upper()} findings ({len(matches)}):")
            for c in matches:
                log.warning(f"  [{c.change_type.value}] {c.path}")

    for w in report.parse_warnings:
        log.warning(f"Parse warning: {w}")

    log.info("─" * 62)


def main() -> int:
    args = build_parser().parse_args()
    configure_logging(args.log_level)
    log = logging.getLogger("main")

    # Read
    try:
        log.info(f"Reading report: {args.report}")
        text = read_report(args.report)
    except (FileNotFoundError, ValueError) as exc:
        log.error(str(exc))
        return 1

    # Parse
    report = AideReportParser(
        hostname=args.hostname, report_path=args.report
    ).parse(text)

    # Build events
    events = SplunkEventBuilder(
        index=args.index, sourcetype=args.sourcetype
    ).build(report)

    print_run_summary(report, len(events))

    # Optional JSON dump
    if args.output_json:
        Path(args.output_json).write_text(
            json.dumps(events, indent=2, default=str), encoding="utf-8"
        )
        log.info(f"Events written: {args.output_json}")

    # Dry run
    if args.dry_run:
        log.info("Dry run — printing events to stdout")
        print(json.dumps(events, indent=2, default=str))
        return 0

    # Validate HEC config
    if not args.hec_url:
        log.error("No HEC URL. Set --hec-url or SPLUNK_HEC_URL. Use --dry-run to test.")
        return 1
    if not args.hec_token:
        log.error("No HEC token. Set --hec-token or SPLUNK_HEC_TOKEN.")
        return 1

    # Send
    log.info(f"Sending {len(events)} events → {args.hec_url}")
    client = SplunkHECClient(
        hec_url    = args.hec_url,
        hec_token  = args.hec_token,
        index      = args.index,
        sourcetype = args.sourcetype,
        verify_ssl = not args.no_ssl_verify,
    )
    sent, failed = client.send(events)
    log.info(f"Done: {sent} sent, {failed} failed")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
