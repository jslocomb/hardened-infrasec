#!/usr/bin/env python3
"""
k8s_secret_auditor.py
─────────────────────────────────────────────────────────────────────────────
Kubernetes Audit Log Analyzer — Secret Access Anomaly Detection

Parses Kubernetes API server audit logs and flags anomalous access patterns
against Secrets resources. Designed for NIST 800-171 / CMMC Level 2
compliance environments running RKE2 or kubeadm clusters.

NIST 800-171 Controls addressed:
  AC-3.1.1   Limit system access to authorized users, processes, and devices
  AC-3.1.3   Control the flow of CUI in accordance with approved authorizations
  SI-3.14.6  Monitor the information system to detect attacks and indicators
  SI-3.14.7  Identify unauthorized use of organizational systems
  SC-3.13.8  Implement cryptographic mechanisms to prevent unauthorized disclosure
  CM-3.4.3   Track, review, approve/disapprove changes to configurations
  IA-3.5.1   Identify information system users, processes, or devices
  AU-3.3.1   Create and retain system audit records

Anomaly Detection Rules:
  BURST_ACCESS       Same actor reads N+ secrets in a short window (harvesting)
  UNUSUAL_HOUR       Human user accesses secrets outside business hours
  FORBIDDEN_PROBE    Repeated 403/401 on secrets (permission probing)
  LIST_ENUMERATE     list+get pattern (secret enumeration)
  MASS_LIST          Cluster/namespace-wide secret listing
  CROSS_NAMESPACE    Actor reading from atypical namespaces
  SENSITIVE_NAME     Access to high-value secret names (aws-creds, kubeconfig)
  SECRET_DELETED     Deletion of secrets (sabotage / post-exfil cleanup)
  SECRET_MODIFIED    Patch/update of secrets (credential manipulation)
  IMPERSONATION      Requests with impersonation headers on secrets
  FORBIDDEN_RATE     Actor with high ratio of forbidden responses
  NODE_OVERSTEP      Node/kubelet accessing secrets outside its node scope
  WATCH_SECRETS      Persistent watch on secrets (exfiltration via streaming)
  DENIED_THEN_ALLOW  Same actor denied then later allowed (privilege escalation)
  EXEC_AFTER_SECRET  Pod exec shortly after secret read by same actor

Input:
  Kubernetes API server audit log in JSONL format (one JSON event per line).
  Supports plain text and gzip-compressed files, or stdin.

  Enable audit logging in your cluster (kube-apiserver flags):
    --audit-log-path=/var/log/kubernetes/audit.log
    --audit-log-maxage=30
    --audit-log-maxbackup=10
    --audit-log-maxsize=100
    --audit-policy-file=/etc/kubernetes/audit-policy.yaml

  Recommended audit policy to capture secret events at RequestResponse level:
    rules:
    - level: RequestResponse
      resources:
      - group: ""
        resources: ["secrets"]
    - level: Metadata
      omitStages: ["RequestReceived"]

Usage:
    # Analyze a log file
    python3 k8s_secret_auditor.py --log /var/log/kubernetes/audit.log

    # Pipe from kubectl or live log tail
    kubectl logs -n kube-system kube-apiserver-node01 | \\
        python3 k8s_secret_auditor.py --log -

    # Adjust thresholds and outputs
    python3 k8s_secret_auditor.py \\
        --log /var/log/kubernetes/audit.log \\
        --burst-window 60 \\
        --burst-threshold 10 \\
        --business-hours 8-18 \\
        --output-json audit_findings.json \\
        --output-html audit_findings.html \\
        --output-csv  audit_findings.csv

    # Generate synthetic test data and run against it
    python3 k8s_secret_auditor.py --generate-test-log /tmp/test_audit.log
    python3 k8s_secret_auditor.py --log /tmp/test_audit.log --output-html /tmp/report.html

    # Dry run with built-in synthetic events
    python3 k8s_secret_auditor.py --dry-run

Environment variables:
    K8S_AUDIT_LOG       Default log file path
    K8S_AUDIT_NAMESPACE Namespace filter (comma-separated)

Author : Jason A. Slocomb
Version: 1.0.0
─────────────────────────────────────────────────────────────────────────────
"""

import argparse
import collections
import csv
import gzip
import json
import logging
import os
import re
import sys
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from enum import Flag, auto, Enum
from pathlib import Path
from typing import Optional, Iterator


# ─── Constants ────────────────────────────────────────────────────────────────

VERSION = "1.0.0"

# Default thresholds (all tunable via CLI)
DEFAULT_BURST_WINDOW_SEC  = 60      # sliding window for burst detection
DEFAULT_BURST_THRESHOLD   = 5       # reads within window to trigger burst alert
DEFAULT_FORBIDDEN_COUNT   = 5       # consecutive 403/401 to trigger probe alert
DEFAULT_FORBIDDEN_RATE    = 0.50    # 50% forbidden ratio triggers rate alert
DEFAULT_BUSINESS_START    = 8       # 08:00 local hour
DEFAULT_BUSINESS_END      = 18      # 18:00 local hour
DEFAULT_WATCH_DURATION    = 300     # 5 min persistent watch triggers alert
MIN_EVENTS_FOR_RATE       = 10      # minimum events before computing forbidden rate
EXEC_WINDOW_SEC           = 300     # exec within 5m after secret read = alert

# High-value secret name patterns (credential harvesting targets)
SENSITIVE_SECRET_PATTERNS = [
    re.compile(r"aws[._-]?(cred|secret|key|access)", re.I),
    re.compile(r"(kubeconfig|kube-config)", re.I),
    re.compile(r"(etcd|postgres|mysql|mongo|redis|elastic)[._-]?(cred|pass|secret|auth)", re.I),
    re.compile(r"(ssh|tls|ssl|ca|cert)[._-]?(key|cred|secret|priv)", re.I),
    re.compile(r"(api[._-]?key|apikey|api[._-]?token)", re.I),
    re.compile(r"(service[._-]?account|sa)[._-]?(token|secret)", re.I),
    re.compile(r"(bootstrap[._-]?token|bootstrap)", re.I),
    re.compile(r"(vault|secret[._-]?store)", re.I),
    re.compile(r"(ghcr|docker|registry)[._-]?(cred|pull[._-]?secret|token|secret)", re.I),
    re.compile(r"(slack|pagerduty|webhook)[._-]?(token|key|secret)", re.I),
    re.compile(r"root[._-]?(cred|pass|secret|key)", re.I),
    re.compile(r"(prod|production)[._-]?(cred|pass|secret|key|db)", re.I),
]

# System actors that are expected to access many secrets (lower anomaly weight)
TRUSTED_SYSTEM_ACTORS = {
    "system:kube-controller-manager",
    "system:kube-scheduler",
    "system:kube-proxy",
    "system:apiserver",
}

# Verbs that constitute a read (get, list, watch)
READ_VERBS   = {"get", "list", "watch"}
WRITE_VERBS  = {"create", "update", "patch", "delete", "deletecollection"}
MUTATE_VERBS = {"create", "update", "patch"}

# K8s audit log stages we care about (final outcome only)
FINAL_STAGES = {"ResponseComplete", "Panic"}

# NIST 800-171 control assignments per anomaly type
NIST_MAP = {
    "BURST_ACCESS":      ["SI-3.14.7", "AC-3.1.1"],
    "UNUSUAL_HOUR":      ["SI-3.14.7", "AC-3.1.1"],
    "FORBIDDEN_PROBE":   ["SI-3.14.6", "AC-3.1.1"],
    "LIST_ENUMERATE":    ["SI-3.14.7", "AC-3.1.1", "AC-3.1.3"],
    "MASS_LIST":         ["AC-3.1.3", "SI-3.14.7"],
    "CROSS_NAMESPACE":   ["AC-3.1.1", "AC-3.1.3"],
    "SENSITIVE_NAME":    ["SC-3.13.8", "AC-3.1.1", "SI-3.14.7"],
    "SECRET_DELETED":    ["CM-3.4.3", "SI-3.14.7", "AU-3.3.1"],
    "SECRET_MODIFIED":   ["CM-3.4.3", "SI-3.14.7"],
    "IMPERSONATION":     ["IA-3.5.1", "AC-3.1.1"],
    "FORBIDDEN_RATE":    ["SI-3.14.6", "AC-3.1.1"],
    "NODE_OVERSTEP":     ["AC-3.1.1", "SI-3.14.7"],
    "WATCH_SECRETS":     ["AC-3.1.3", "SI-3.14.7"],
    "DENIED_THEN_ALLOW": ["AC-3.1.1", "IA-3.5.1"],
    "EXEC_AFTER_SECRET": ["SI-3.14.7", "AC-3.1.1"],
}


# ─── Risk Severity ────────────────────────────────────────────────────────────

class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"
    INFO     = "info"

    @classmethod
    def from_str(cls, s: str) -> "Severity":
        return cls(s.lower()) if s.lower() in cls._value2member_map_ else cls.INFO

    @classmethod
    def highest(cls, items: list) -> "Severity":
        order = [cls.CRITICAL, cls.HIGH, cls.MEDIUM, cls.LOW, cls.INFO]
        for s in order:
            if s in items:
                return s
        return cls.INFO


# ─── Data Models ──────────────────────────────────────────────────────────────

@dataclass
class AuditEvent:
    """Parsed and normalized Kubernetes audit log event."""
    audit_id:       str
    timestamp:      datetime
    stage:          str
    verb:           str
    username:       str
    user_groups:    list
    source_ips:     list
    user_agent:     str
    namespace:      str
    resource:       str
    resource_name:  str
    subresource:    str
    request_uri:    str
    http_code:      int
    decision:       str           # allow | forbid | ""
    impersonated:   bool          # request included impersonation headers
    is_secret:      bool          # targets the secrets resource
    is_service_acct: bool
    node_name:      str           # set if actor is a node/kubelet
    raw:            dict = field(repr=False, default_factory=dict)

    @property
    def allowed(self) -> bool:
        return self.http_code < 400

    @property
    def forbidden(self) -> bool:
        return self.http_code in (401, 403)

    @property
    def is_read(self) -> bool:
        return self.verb in READ_VERBS

    @property
    def is_write(self) -> bool:
        return self.verb in WRITE_VERBS

    @property
    def actor_key(self) -> str:
        """Stable identity key for grouping."""
        return self.username

    @property
    def is_sensitive_name(self) -> bool:
        return bool(self.resource_name) and any(
            p.search(self.resource_name) for p in SENSITIVE_SECRET_PATTERNS
        )


@dataclass
class Finding:
    """A detected anomaly with context and severity."""
    finding_id:    str
    rule:          str
    severity:      Severity
    actor:         str
    namespace:     str
    resource_name: str
    timestamp:     datetime
    message:       str
    evidence:      list           # list of audit_ids or descriptive strings
    nist_controls: list
    event_count:   int   = 1
    source_ips:    list  = field(default_factory=list)
    extra:         dict  = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "finding_id":    self.finding_id,
            "rule":          self.rule,
            "severity":      self.severity.value,
            "actor":         self.actor,
            "namespace":     self.namespace,
            "resource_name": self.resource_name,
            "timestamp":     self.timestamp.isoformat(),
            "message":       self.message,
            "evidence":      self.evidence[:20],   # cap for readability
            "nist_controls": self.nist_controls,
            "event_count":   self.event_count,
            "source_ips":    self.source_ips,
            "extra":         self.extra,
        }


@dataclass
class AuditSummary:
    """Aggregate statistics from one analysis run."""
    log_source:         str
    analysis_timestamp: str
    events_parsed:      int                   = 0
    events_skipped:     int                   = 0
    secret_events:      int                   = 0
    findings:           int                   = 0
    critical_count:     int                   = 0
    high_count:         int                   = 0
    medium_count:       int                   = 0
    low_count:          int                   = 0
    unique_actors:      int                   = 0
    unique_namespaces:  int                   = 0
    time_range_start:   Optional[str]         = None
    time_range_end:     Optional[str]         = None
    thresholds:         dict                  = field(default_factory=dict)
    nist_controls:      list                  = field(default_factory=list)
    top_actors:         list                  = field(default_factory=list)


# ─── Audit Log Parser ─────────────────────────────────────────────────────────

class AuditLogParser:
    """
    Parses Kubernetes audit log JSONL into AuditEvent objects.

    Handles:
     - Plain .log files (one JSON object per line)
     - Gzip-compressed files (.log.gz)
     - Stdin (line-buffered streaming)
     - Multi-event files wrapped in {"items": [...]} (audit sink format)
    """

    def __init__(self, namespace_filter: set = None):
        self.namespace_filter = namespace_filter or set()
        self._log = logging.getLogger(self.__class__.__name__)

    def parse_file(self, path: str) -> Iterator[AuditEvent]:
        """Yield AuditEvent objects from a file or stdin."""
        if path == "-":
            yield from self._parse_stream(sys.stdin)
            return

        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"Audit log not found: {path}")

        if path.endswith(".gz"):
            with gzip.open(path, "rt", encoding="utf-8", errors="replace") as fh:
                yield from self._parse_stream(fh)
        else:
            with open(path, encoding="utf-8", errors="replace") as fh:
                yield from self._parse_stream(fh)

    def _parse_stream(self, fh) -> Iterator[AuditEvent]:
        """Yield parsed events from a line-oriented stream."""
        for lineno, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError as exc:
                self._log.debug(f"Line {lineno}: JSON parse error — {exc}")
                continue

            # Handle audit sink wrapper format
            if obj.get("kind") == "EventList" and "items" in obj:
                for item in obj["items"]:
                    ev = self._parse_event(item)
                    if ev:
                        yield ev
                continue

            ev = self._parse_event(obj)
            if ev:
                yield ev

    def _parse_event(self, obj: dict) -> Optional[AuditEvent]:
        """Convert a raw audit event dict to an AuditEvent. Returns None to skip."""
        # Only process final-stage events (skip RequestReceived, ResponseStarted)
        stage = obj.get("stage", "")
        if stage not in FINAL_STAGES:
            return None

        # Parse timestamp
        ts_str = obj.get("requestReceivedTimestamp") or obj.get("stageTimestamp", "")
        try:
            ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00").replace(" ", "T"))
        except (ValueError, AttributeError):
            ts = datetime.now(timezone.utc)

        # User info
        user     = obj.get("user", {})
        username = user.get("username", "unknown")
        groups   = user.get("groups", [])

        # Source IPs
        source_ips = obj.get("sourceIPs", [])

        # Object reference
        obj_ref   = obj.get("objectRef") or {}
        resource  = obj_ref.get("resource", "")
        namespace = obj_ref.get("namespace", "") or ""
        name      = obj_ref.get("name", "") or ""
        subres    = obj_ref.get("subresource", "") or ""

        # Apply namespace filter
        if self.namespace_filter and namespace and namespace not in self.namespace_filter:
            return None

        # HTTP response code
        resp_status = obj.get("responseStatus") or {}
        http_code   = resp_status.get("code", 0)
        if isinstance(http_code, str):
            try:
                http_code = int(http_code)
            except ValueError:
                http_code = 0

        # Authorization decision from annotations
        annotations = obj.get("annotations") or {}
        decision    = annotations.get("authorization.k8s.io/decision", "")

        # Detect impersonation (extra in request info or in URI)
        req_obj    = obj.get("requestObject") or {}
        request_uri = obj.get("requestURI", "")
        impersonated = (
            "Impersonate-User" in str(obj.get("requestObject", ""))
            or "impersonate" in request_uri.lower()
            or any("impersonate" in str(v).lower() for v in annotations.values())
        )

        # Detect service accounts and nodes
        is_sa   = username.startswith("system:serviceaccount:")
        is_node = username.startswith("system:node:")
        node_name = username.split("system:node:", 1)[1] if is_node else ""

        is_secret = resource == "secrets"

        verb = obj.get("verb", "").lower()

        return AuditEvent(
            audit_id        = obj.get("auditID", str(uuid.uuid4())),
            timestamp       = ts,
            stage           = stage,
            verb            = verb,
            username        = username,
            user_groups     = groups,
            source_ips      = source_ips,
            user_agent      = obj.get("userAgent", ""),
            namespace       = namespace,
            resource        = resource,
            resource_name   = name,
            subresource     = subres,
            request_uri     = request_uri,
            http_code       = http_code,
            decision        = decision,
            impersonated    = impersonated,
            is_secret       = is_secret,
            is_service_acct = is_sa,
            node_name       = node_name,
            raw             = obj,
        )


# ─── State Tracker ────────────────────────────────────────────────────────────

class ActorState:
    """
    Tracks per-actor behavioral state across the event stream.

    Maintains sliding windows and counters needed for anomaly detection
    without storing every raw event in memory.
    """

    def __init__(self, username: str, burst_window: int, burst_threshold: int):
        self.username         = username
        self.burst_window     = burst_window
        self.burst_threshold  = burst_threshold

        # Sliding window of secret read timestamps for burst detection
        self._read_times:     list[datetime] = []

        # All namespaces this actor has been seen in
        self.namespaces_seen: set = set()

        # Namespaces with at least 3 events (baseline for cross-ns detection)
        self.home_namespaces: set = set()
        self._ns_counts:      collections.Counter = collections.Counter()

        # Forbidden / total counters for rate calculation
        self.total_secret_events:    int = 0
        self.forbidden_secret_events: int = 0
        self.consecutive_forbidden:  int = 0
        self.max_consecutive_forbidden: int = 0

        # Track list → get enumeration pattern
        self.listed_namespaces:  set = set()   # namespaces where list was performed
        self.list_timestamps:    list[datetime] = []

        # Track recent secret reads (for exec-after-secret detection)
        self.recent_reads:    list[tuple[datetime, str, str]] = []  # (ts, ns, name)

        # Track if actor had a denied→allowed transition
        self.had_denied:      bool = False
        self.had_allow_after_deny: bool = False

        # Watch tracking
        self.active_watches:  dict = {}   # audit_id -> start_ts
        self.watch_durations: list[float] = []

        # Timestamps of all secret access events
        self.all_event_times: list[datetime] = []

        # Source IPs seen
        self.source_ips: set = set()

    def record_event(self, ev: AuditEvent) -> None:
        """Update state from a new secret event."""
        self.total_secret_events += 1
        self.all_event_times.append(ev.timestamp)
        self.source_ips.update(ev.source_ips)

        if ev.namespace:
            self.namespaces_seen.add(ev.namespace)
            self._ns_counts[ev.namespace] += 1
            if self._ns_counts[ev.namespace] >= 3:
                self.home_namespaces.add(ev.namespace)

        if ev.forbidden:
            self.forbidden_secret_events += 1
            self.consecutive_forbidden += 1
            self.max_consecutive_forbidden = max(
                self.max_consecutive_forbidden, self.consecutive_forbidden
            )
            if not self.had_denied:
                self.had_denied = True
        else:
            if self.had_denied and ev.allowed and ev.is_read:
                self.had_allow_after_deny = True
            self.consecutive_forbidden = 0

        if ev.is_read and ev.allowed:
            self._read_times.append(ev.timestamp)
            self.recent_reads.append((ev.timestamp, ev.namespace, ev.resource_name))
            # Keep only last 200 reads in memory
            if len(self.recent_reads) > 200:
                self.recent_reads = self.recent_reads[-200:]

        if ev.verb == "list":
            self.listed_namespaces.add(ev.namespace)
            self.list_timestamps.append(ev.timestamp)

    @property
    def forbidden_rate(self) -> float:
        if self.total_secret_events < MIN_EVENTS_FOR_RATE:
            return 0.0
        return self.forbidden_secret_events / self.total_secret_events

    def reads_in_window(self, window_end: datetime, window_sec: int) -> list[datetime]:
        """Return read timestamps within [window_end - window_sec, window_end]."""
        cutoff = window_end - timedelta(seconds=window_sec)
        return [t for t in self._read_times if t >= cutoff]

    def prune_old_reads(self, before: datetime) -> None:
        """Remove old read timestamps to keep memory bounded."""
        cutoff = before - timedelta(seconds=self.burst_window * 10)
        self._read_times = [t for t in self._read_times if t >= cutoff]


# ─── Anomaly Detector ─────────────────────────────────────────────────────────

class SecretAnomalyDetector:
    """
    Streaming anomaly detector for Kubernetes secret access events.

    Processes events in chronological order, maintaining per-actor state,
    and emits Finding objects when anomalies are detected.

    Detection approach:
     - Some rules fire per-event (e.g. SENSITIVE_NAME, SECRET_DELETED)
     - Some rules fire on state transitions (e.g. BURST_ACCESS, LIST_ENUMERATE)
     - Some rules fire post-hoc on aggregated state (e.g. FORBIDDEN_RATE)
     - Cross-actor correlation is minimal by design (memory efficient)
    """

    def __init__(
        self,
        burst_window:       int   = DEFAULT_BURST_WINDOW_SEC,
        burst_threshold:    int   = DEFAULT_BURST_THRESHOLD,
        forbidden_count:    int   = DEFAULT_FORBIDDEN_COUNT,
        forbidden_rate:     float = DEFAULT_FORBIDDEN_RATE,
        business_start:     int   = DEFAULT_BUSINESS_START,
        business_end:       int   = DEFAULT_BUSINESS_END,
        watch_duration:     int   = DEFAULT_WATCH_DURATION,
        namespace_filter:   set   = None,
        exclude_actors:     set   = None,
        human_users_only_hours: bool = True,
    ):
        self.burst_window        = burst_window
        self.burst_threshold     = burst_threshold
        self.forbidden_count     = forbidden_count
        self.forbidden_rate_thr  = forbidden_rate
        self.business_start      = business_start
        self.business_end        = business_end
        self.watch_duration      = watch_duration
        self.namespace_filter    = namespace_filter or set()
        self.exclude_actors      = (exclude_actors or set()) | TRUSTED_SYSTEM_ACTORS
        self.human_hours_only    = human_users_only_hours

        self._actor_state:  dict[str, ActorState] = {}
        self._findings:     list[Finding] = []
        self._finding_ids:  set = set()  # deduplicate repeat firings

        # For exec-after-secret: track exec events by actor
        self._exec_events:  list[tuple[datetime, str]] = []  # (ts, username)

        # For DENIED_THEN_ALLOW: track transitions across stream
        self._denied_actors: dict[str, datetime] = {}
        self._allowed_after: set = set()

        self._log = logging.getLogger(self.__class__.__name__)

    # ── Public interface ───────────────────────────────────────────────────

    def process_event(self, ev: AuditEvent) -> list[Finding]:
        """
        Process one audit event. Returns any new findings triggered.
        Call this for every event (not just secret events) so exec tracking works.
        """
        new_findings = []

        # Track exec events for cross-correlation
        if ev.resource == "pods" and ev.subresource == "exec" and ev.allowed:
            self._exec_events.append((ev.timestamp, ev.username))
            # Prune old exec events (keep last hour)
            cutoff = ev.timestamp - timedelta(hours=1)
            self._exec_events = [
                (t, u) for t, u in self._exec_events if t >= cutoff
            ]

        # Only detailed analysis for secret events
        if not ev.is_secret:
            return new_findings

        # Skip excluded actors
        if ev.username in self.exclude_actors:
            return new_findings

        # Get or create actor state
        state = self._get_state(ev.username)
        state.record_event(ev)

        # ── Per-event rules ────────────────────────────────────────────────

        # IMPERSONATION
        if ev.impersonated and ev.is_secret:
            new_findings.extend(self._fire_if_new(
                rule          = "IMPERSONATION",
                severity      = Severity.CRITICAL,
                actor         = ev.username,
                namespace     = ev.namespace,
                resource_name = ev.resource_name,
                timestamp     = ev.timestamp,
                message       = (
                    f"Impersonation detected on secrets access: "
                    f"{ev.verb} {ev.namespace}/{ev.resource_name}"
                ),
                evidence      = [ev.audit_id],
                source_ips    = ev.source_ips,
                dedup_key     = f"IMPERSONATION:{ev.username}:{ev.namespace}:{ev.audit_id}",
            ))

        # SENSITIVE_NAME — access to high-value secret names
        if ev.is_sensitive_name and ev.allowed and ev.verb in ("get", "list"):
            new_findings.extend(self._fire_if_new(
                rule          = "SENSITIVE_NAME",
                severity      = Severity.HIGH,
                actor         = ev.username,
                namespace     = ev.namespace,
                resource_name = ev.resource_name,
                timestamp     = ev.timestamp,
                message       = (
                    f"Access to sensitive-named secret: "
                    f"{ev.verb} {ev.namespace}/{ev.resource_name}"
                ),
                evidence      = [ev.audit_id],
                source_ips    = ev.source_ips,
                dedup_key     = f"SENSITIVE:{ev.username}:{ev.namespace}:{ev.resource_name}",
            ))

        # SECRET_DELETED
        if ev.verb == "delete" and ev.allowed:
            new_findings.extend(self._fire_if_new(
                rule          = "SECRET_DELETED",
                severity      = Severity.HIGH,
                actor         = ev.username,
                namespace     = ev.namespace,
                resource_name = ev.resource_name,
                timestamp     = ev.timestamp,
                message       = (
                    f"Secret deleted by {ev.username}: "
                    f"{ev.namespace}/{ev.resource_name}"
                ),
                evidence      = [ev.audit_id],
                source_ips    = ev.source_ips,
                dedup_key     = f"DEL:{ev.username}:{ev.namespace}:{ev.resource_name}:{ev.audit_id}",
            ))

        # SECRET_MODIFIED — patch or update
        if ev.verb in ("patch", "update") and ev.allowed:
            new_findings.extend(self._fire_if_new(
                rule          = "SECRET_MODIFIED",
                severity      = Severity.HIGH,
                actor         = ev.username,
                namespace     = ev.namespace,
                resource_name = ev.resource_name,
                timestamp     = ev.timestamp,
                message       = (
                    f"Secret modified ({ev.verb}) by {ev.username}: "
                    f"{ev.namespace}/{ev.resource_name}"
                ),
                evidence      = [ev.audit_id],
                source_ips    = ev.source_ips,
                dedup_key     = f"MOD:{ev.username}:{ev.namespace}:{ev.resource_name}:{ev.audit_id}",
            ))

        # MASS_LIST — list secrets with no name (namespace-wide) or cluster-wide
        if ev.verb == "list" and ev.allowed and not ev.resource_name:
            scope = ev.namespace or "CLUSTER-WIDE"
            new_findings.extend(self._fire_if_new(
                rule          = "MASS_LIST",
                severity      = Severity.MEDIUM if ev.is_service_acct else Severity.HIGH,
                actor         = ev.username,
                namespace     = ev.namespace,
                resource_name = "(all)",
                timestamp     = ev.timestamp,
                message       = (
                    f"Mass secret listing by {ev.username} "
                    f"in scope: {scope}"
                ),
                evidence      = [ev.audit_id],
                source_ips    = ev.source_ips,
                dedup_key     = f"MLIST:{ev.username}:{scope}:{ev.audit_id}",
            ))

        # WATCH_SECRETS — persistent watch on secrets resource
        if ev.verb == "watch" and ev.allowed:
            new_findings.extend(self._fire_if_new(
                rule          = "WATCH_SECRETS",
                severity      = Severity.HIGH,
                actor         = ev.username,
                namespace     = ev.namespace,
                resource_name = ev.resource_name or "(all)",
                timestamp     = ev.timestamp,
                message       = (
                    f"Persistent secret watch established by {ev.username} "
                    f"in {ev.namespace or 'cluster-wide'}"
                ),
                evidence      = [ev.audit_id],
                source_ips    = ev.source_ips,
                dedup_key     = f"WATCH:{ev.username}:{ev.namespace}:{ev.audit_id}",
            ))

        # UNUSUAL_HOUR — human users outside business hours
        if (
            ev.allowed
            and ev.verb in ("get", "list")
            and not ev.is_service_acct
            and not ev.username.startswith("system:")
        ):
            hour = ev.timestamp.hour  # UTC — adjust if needed
            if not (self.business_start <= hour < self.business_end):
                new_findings.extend(self._fire_if_new(
                    rule          = "UNUSUAL_HOUR",
                    severity      = Severity.MEDIUM,
                    actor         = ev.username,
                    namespace     = ev.namespace,
                    resource_name = ev.resource_name,
                    timestamp     = ev.timestamp,
                    message       = (
                        f"Human user {ev.username} accessed secrets outside business hours "
                        f"(UTC {hour:02d}:xx): {ev.verb} {ev.namespace}/{ev.resource_name}"
                    ),
                    evidence      = [ev.audit_id],
                    source_ips    = ev.source_ips,
                    dedup_key     = f"HOUR:{ev.username}:{ev.namespace}:{ev.timestamp.date()}:{ev.resource_name}",
                    extra         = {"hour_utc": hour},
                ))

        # NODE_OVERSTEP — kubelet accessing secrets outside its node
        if ev.node_name and ev.allowed and ev.is_read:
            # A kubelet should only access secrets bound to pods on its own node.
            # Detecting this precisely requires pod scheduling data, but we can
            # flag any kubelet reading secrets from a namespace it doesn't own.
            # For lab: flag if a node reads more than 5 distinct secret names.
            node_reads = [(t, ns, n) for t, ns, n in state.recent_reads if n]
            if len(set(n for _, _, n in node_reads)) > 5:
                new_findings.extend(self._fire_if_new(
                    rule          = "NODE_OVERSTEP",
                    severity      = Severity.HIGH,
                    actor         = ev.username,
                    namespace     = ev.namespace,
                    resource_name = ev.resource_name,
                    timestamp     = ev.timestamp,
                    message       = (
                        f"Node {ev.node_name} reading excessive secrets "
                        f"({len(set(n for _, _, n in node_reads))} distinct names) — "
                        f"possible node compromise"
                    ),
                    evidence      = [ev.audit_id],
                    source_ips    = ev.source_ips,
                    dedup_key     = f"NODE:{ev.username}:{ev.timestamp.date()}",
                ))

        # ── State-transition rules ─────────────────────────────────────────

        # BURST_ACCESS — N reads within window
        if ev.is_read and ev.allowed:
            window_reads = state.reads_in_window(ev.timestamp, self.burst_window)
            if len(window_reads) >= self.burst_threshold:
                new_findings.extend(self._fire_if_new(
                    rule          = "BURST_ACCESS",
                    severity      = Severity.CRITICAL if len(window_reads) >= self.burst_threshold * 2 else Severity.HIGH,
                    actor         = ev.username,
                    namespace     = ev.namespace,
                    resource_name = ev.resource_name,
                    timestamp     = ev.timestamp,
                    message       = (
                        f"Burst secret access: {ev.username} read "
                        f"{len(window_reads)} secrets in {self.burst_window}s window"
                    ),
                    evidence      = [ev.audit_id],
                    source_ips    = ev.source_ips,
                    dedup_key     = (
                        f"BURST:{ev.username}:"
                        f"{int(ev.timestamp.timestamp() // self.burst_window)}"
                    ),
                    event_count   = len(window_reads),
                    extra         = {
                        "reads_in_window":  len(window_reads),
                        "window_seconds":   self.burst_window,
                    },
                ))

        # FORBIDDEN_PROBE — consecutive 403/401
        if ev.forbidden:
            if state.max_consecutive_forbidden >= self.forbidden_count:
                new_findings.extend(self._fire_if_new(
                    rule          = "FORBIDDEN_PROBE",
                    severity      = Severity.HIGH,
                    actor         = ev.username,
                    namespace     = ev.namespace,
                    resource_name = ev.resource_name,
                    timestamp     = ev.timestamp,
                    message       = (
                        f"Permission probing: {ev.username} received "
                        f"{state.max_consecutive_forbidden} consecutive Forbidden "
                        f"responses on secrets"
                    ),
                    evidence      = [ev.audit_id],
                    source_ips    = ev.source_ips,
                    dedup_key     = f"PROBE:{ev.username}:{ev.timestamp.date()}",
                    event_count   = state.max_consecutive_forbidden,
                ))

        # LIST_ENUMERATE — list followed by get on same namespace
        if (
            ev.verb == "get"
            and ev.namespace in state.listed_namespaces
            and ev.allowed
            and ev.resource_name
        ):
            new_findings.extend(self._fire_if_new(
                rule          = "LIST_ENUMERATE",
                severity      = Severity.MEDIUM,
                actor         = ev.username,
                namespace     = ev.namespace,
                resource_name = ev.resource_name,
                timestamp     = ev.timestamp,
                message       = (
                    f"Secret enumeration pattern: {ev.username} listed secrets in "
                    f"{ev.namespace} then fetched '{ev.resource_name}'"
                ),
                evidence      = [ev.audit_id],
                source_ips    = ev.source_ips,
                dedup_key     = f"ENUM:{ev.username}:{ev.namespace}:{ev.resource_name}",
            ))

        # CROSS_NAMESPACE — accessing secrets in unfamiliar namespace
        if (
            ev.namespace
            and ev.allowed
            and ev.is_read
            and state.total_secret_events > 10   # baseline established
            and state.home_namespaces             # has home namespaces
            and ev.namespace not in state.home_namespaces
        ):
            new_findings.extend(self._fire_if_new(
                rule          = "CROSS_NAMESPACE",
                severity      = Severity.MEDIUM,
                actor         = ev.username,
                namespace     = ev.namespace,
                resource_name = ev.resource_name,
                timestamp     = ev.timestamp,
                message       = (
                    f"Cross-namespace secret access: {ev.username} "
                    f"(home: {', '.join(sorted(state.home_namespaces))}) "
                    f"reading from '{ev.namespace}'"
                ),
                evidence      = [ev.audit_id],
                source_ips    = ev.source_ips,
                dedup_key     = f"XNSP:{ev.username}:{ev.namespace}:{ev.timestamp.date()}",
                extra         = {"home_namespaces": sorted(state.home_namespaces)},
            ))

        # EXEC_AFTER_SECRET — pod exec within 5m of secret read by same actor
        if ev.is_read and ev.allowed and ev.resource_name:
            cutoff = ev.timestamp - timedelta(seconds=EXEC_WINDOW_SEC)
            recent_execs = [
                (t, u) for t, u in self._exec_events
                if u == ev.username and t >= cutoff
            ]
            if recent_execs:
                new_findings.extend(self._fire_if_new(
                    rule          = "EXEC_AFTER_SECRET",
                    severity      = Severity.CRITICAL,
                    actor         = ev.username,
                    namespace     = ev.namespace,
                    resource_name = ev.resource_name,
                    timestamp     = ev.timestamp,
                    message       = (
                        f"Secret read follows recent pod exec: {ev.username} "
                        f"exec'd a pod within {EXEC_WINDOW_SEC}s before reading "
                        f"secret '{ev.namespace}/{ev.resource_name}'"
                    ),
                    evidence      = [ev.audit_id] + [str(t) for t, _ in recent_execs[:3]],
                    source_ips    = ev.source_ips,
                    dedup_key     = f"EXEC:{ev.username}:{ev.resource_name}:{ev.audit_id}",
                    extra         = {"exec_count": len(recent_execs)},
                ))

        # Prune old read times periodically
        if state.total_secret_events % 100 == 0:
            state.prune_old_reads(ev.timestamp)

        return new_findings

    def finalize(self) -> list[Finding]:
        """
        Run post-hoc rules that require seeing all events first.
        Call once after all events are processed.
        Returns additional findings.
        """
        late_findings = []

        for username, state in self._actor_state.items():
            # FORBIDDEN_RATE — high ratio of forbidden responses
            rate = state.forbidden_rate
            if rate >= self.forbidden_rate_thr:
                ts = state.all_event_times[-1] if state.all_event_times else datetime.now(timezone.utc)
                late_findings.extend(self._fire_if_new(
                    rule          = "FORBIDDEN_RATE",
                    severity      = Severity.HIGH,
                    actor         = username,
                    namespace     = "",
                    resource_name = "",
                    timestamp     = ts,
                    message       = (
                        f"High forbidden rate on secrets: {username} "
                        f"{state.forbidden_secret_events}/{state.total_secret_events} "
                        f"({rate:.0%}) forbidden responses"
                    ),
                    evidence      = [],
                    source_ips    = list(state.source_ips)[:5],
                    dedup_key     = f"RATE:{username}",
                    event_count   = state.total_secret_events,
                    extra         = {
                        "forbidden_count": state.forbidden_secret_events,
                        "total_count":     state.total_secret_events,
                        "rate":            round(rate, 3),
                    },
                ))

            # DENIED_THEN_ALLOW — actor was denied then later allowed
            if state.had_allow_after_deny:
                ts = state.all_event_times[-1] if state.all_event_times else datetime.now(timezone.utc)
                late_findings.extend(self._fire_if_new(
                    rule          = "DENIED_THEN_ALLOW",
                    severity      = Severity.HIGH,
                    actor         = username,
                    namespace     = "",
                    resource_name = "",
                    timestamp     = ts,
                    message       = (
                        f"Privilege escalation pattern: {username} was denied "
                        f"secret access then later succeeded — possible RBAC change "
                        f"or credential reuse"
                    ),
                    evidence      = [],
                    source_ips    = list(state.source_ips)[:5],
                    dedup_key     = f"DA:{username}",
                ))

        return late_findings

    def all_findings(self) -> list[Finding]:
        return sorted(self._findings, key=lambda f: (
            {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(
                f.severity.value, 5
            ),
            f.timestamp,
        ))

    def actor_states(self) -> dict:
        return self._actor_state

    # ── Private helpers ───────────────────────────────────────────────────

    def _get_state(self, username: str) -> ActorState:
        if username not in self._actor_state:
            self._actor_state[username] = ActorState(
                username        = username,
                burst_window    = self.burst_window,
                burst_threshold = self.burst_threshold,
            )
        return self._actor_state[username]

    def _fire_if_new(
        self,
        rule: str,
        severity: Severity,
        actor: str,
        namespace: str,
        resource_name: str,
        timestamp: datetime,
        message: str,
        evidence: list,
        source_ips: list,
        dedup_key: str,
        event_count: int = 1,
        extra: dict = None,
    ) -> list[Finding]:
        if dedup_key in self._finding_ids:
            return []
        self._finding_ids.add(dedup_key)

        f = Finding(
            finding_id    = str(uuid.uuid4())[:8],
            rule          = rule,
            severity      = severity,
            actor         = actor,
            namespace     = namespace,
            resource_name = resource_name,
            timestamp     = timestamp,
            message       = message,
            evidence      = evidence,
            nist_controls = NIST_MAP.get(rule, []),
            event_count   = event_count,
            source_ips    = list(source_ips)[:10],
            extra         = extra or {},
        )
        self._findings.append(f)
        return [f]


# ─── Report Writers ───────────────────────────────────────────────────────────

def write_json(findings: list[Finding], summary: AuditSummary, path: str) -> None:
    data = {
        "summary":  summary.__dict__,
        "findings": [f.to_dict() for f in findings],
    }
    Path(path).write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
    logging.getLogger("report").info(f"JSON written: {path}")


def write_csv(findings: list[Finding], path: str) -> None:
    fields = [
        "finding_id", "rule", "severity", "actor", "namespace",
        "resource_name", "timestamp", "message", "event_count",
        "nist_controls", "source_ips",
    ]
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        for f in findings:
            d = f.to_dict()
            d["nist_controls"] = "; ".join(d["nist_controls"])
            d["source_ips"]    = "; ".join(d["source_ips"])
            w.writerow(d)
    logging.getLogger("report").info(f"CSV written: {path}")


def write_html(findings: list[Finding], summary: AuditSummary, path: str) -> None:
    sev_colors = {
        "critical": "#dc2626",
        "high":     "#ea580c",
        "medium":   "#d97706",
        "low":      "#2563eb",
        "info":     "#6b7280",
    }

    def badge(sev: str) -> str:
        c = sev_colors.get(sev, "#6b7280")
        return (
            f'<span style="background:{c};color:#fff;padding:2px 8px;'
            f'border-radius:4px;font-size:11px;font-weight:bold">'
            f'{sev.upper()}</span>'
        )

    def pills(items: list) -> str:
        return " ".join(
            f'<span style="background:#f3f4f6;color:#374151;padding:1px 6px;'
            f'border-radius:3px;font-size:10px;margin:1px;display:inline-block">{i}</span>'
            for i in items
        )

    rows = []
    for f in findings:
        color = sev_colors.get(f.severity.value, "#6b7280")
        ev_count = f'<span style="color:#6b7280;font-size:11px">({f.event_count} events)</span>' if f.event_count > 1 else ""
        rows.append(f"""
          <tr style="border-left:4px solid {color}">
            <td style="padding:6px 8px;font-family:monospace;font-size:11px;color:#6b7280">{f.finding_id}</td>
            <td style="padding:6px 8px">{badge(f.severity.value)}</td>
            <td style="padding:6px 8px;font-weight:bold;font-size:12px">{f.rule}</td>
            <td style="padding:6px 8px;font-size:11px;color:#374151">{f.actor}</td>
            <td style="padding:6px 8px;font-size:11px">{f.namespace or '—'}</td>
            <td style="padding:6px 8px;font-size:12px">{f.message} {ev_count}</td>
            <td style="padding:6px 8px">{pills(f.nist_controls)}</td>
            <td style="padding:6px 8px;font-size:11px;color:#6b7280">{f.timestamp.strftime('%Y-%m-%d %H:%M:%S')}</td>
          </tr>""")

    # Rule breakdown
    by_rule = collections.Counter(f.rule for f in findings)
    rule_rows = "\n".join(
        f'<tr><td style="padding:4px 8px;font-size:12px">{rule}</td>'
        f'<td style="padding:4px 8px;font-size:12px;text-align:right">{count}</td></tr>'
        for rule, count in by_rule.most_common()
    )

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>K8s Secret Access Audit — {summary.log_source}</title>
<style>
  body  {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
           margin:0; padding:20px; background:#f9fafb; color:#111827; }}
  h1    {{ font-size:20px; color:#1e3a5f; margin-bottom:4px; }}
  .meta {{ color:#6b7280; font-size:13px; margin-bottom:24px; }}
  .cards {{ display:flex; gap:12px; flex-wrap:wrap; margin-bottom:24px; }}
  .card {{ background:white; border-radius:8px; padding:14px 18px;
           box-shadow:0 1px 3px rgba(0,0,0,.1); min-width:110px; }}
  .card .num {{ font-size:26px; font-weight:bold; }}
  .card .lbl {{ font-size:12px; color:#6b7280; margin-top:2px; }}
  .critical .num {{ color:#dc2626; }}
  .high .num     {{ color:#ea580c; }}
  .medium .num   {{ color:#d97706; }}
  .low .num      {{ color:#2563eb; }}
  .green .num    {{ color:#16a34a; }}
  table {{ width:100%; border-collapse:collapse; background:white;
           border-radius:8px; overflow:hidden;
           box-shadow:0 1px 3px rgba(0,0,0,.1); margin-bottom:24px; }}
  th  {{ background:#1e3a5f; color:white; padding:8px; text-align:left;
         font-size:12px; font-weight:600; }}
  td  {{ border-bottom:1px solid #e5e7eb; vertical-align:top; }}
  tr:nth-child(even) {{ background:#f9fafb; }}
  .split {{ display:flex; gap:16px; }}
  .split > div {{ flex:1; }}
  .nist {{ background:white; border-radius:8px; padding:16px;
           box-shadow:0 1px 3px rgba(0,0,0,.1); margin-top:16px; }}
  .nist h3 {{ margin:0 0 8px 0; font-size:14px; color:#1e3a5f; }}
  .nist p  {{ font-size:12px; color:#374151; margin:4px 0; }}
  .footer  {{ margin-top:20px; font-size:11px; color:#9ca3af; }}
</style>
</head>
<body>
<h1>Kubernetes Secret Access Anomaly Report</h1>
<div class="meta">
  Source: <strong>{summary.log_source}</strong> &nbsp;·&nbsp;
  Generated: <strong>{summary.analysis_timestamp}</strong> &nbsp;·&nbsp;
  Events: {summary.events_parsed:,} parsed, {summary.secret_events:,} secret events &nbsp;·&nbsp;
  Time range: {summary.time_range_start or '?'} → {summary.time_range_end or '?'}
</div>

<div class="cards">
  <div class="card"><div class="num">{summary.events_parsed:,}</div>
    <div class="lbl">Events Parsed</div></div>
  <div class="card"><div class="num">{summary.secret_events:,}</div>
    <div class="lbl">Secret Events</div></div>
  <div class="card"><div class="num">{summary.findings}</div>
    <div class="lbl">Total Findings</div></div>
  <div class="card critical"><div class="num">{summary.critical_count}</div>
    <div class="lbl">Critical</div></div>
  <div class="card high"><div class="num">{summary.high_count}</div>
    <div class="lbl">High</div></div>
  <div class="card medium"><div class="num">{summary.medium_count}</div>
    <div class="lbl">Medium</div></div>
  <div class="card low"><div class="num">{summary.low_count}</div>
    <div class="lbl">Low</div></div>
  <div class="card green"><div class="num">{summary.unique_actors}</div>
    <div class="lbl">Unique Actors</div></div>
</div>

<h2 style="font-size:16px;color:#1e3a5f;margin-bottom:8px">
  Findings ({len(findings)})
</h2>

<table>
  <thead>
    <tr>
      <th>ID</th><th>Severity</th><th>Rule</th><th>Actor</th>
      <th>Namespace</th><th>Message</th><th>NIST Controls</th><th>Timestamp</th>
    </tr>
  </thead>
  <tbody>
    {''.join(rows) if rows else '<tr><td colspan="8" style="text-align:center;padding:20px;color:#6b7280">No findings — all secret access appears normal</td></tr>'}
  </tbody>
</table>

<div class="split">
  <div>
    <h3 style="font-size:14px;color:#1e3a5f">Findings by Rule</h3>
    <table>
      <thead><tr><th>Rule</th><th>Count</th></tr></thead>
      <tbody>{rule_rows}</tbody>
    </table>
  </div>
  <div>
    <div class="nist">
      <h3>NIST 800-171 Controls Covered</h3>
      <p><strong>AC-3.1.1</strong> — Limit system access to authorized users and devices</p>
      <p><strong>AC-3.1.3</strong> — Control the flow of CUI per approved authorizations</p>
      <p><strong>SI-3.14.6</strong> — Monitor systems to detect attacks and indicators</p>
      <p><strong>SI-3.14.7</strong> — Identify unauthorized use of organizational systems</p>
      <p><strong>SC-3.13.8</strong> — Implement cryptographic mechanisms for CUI</p>
      <p><strong>CM-3.4.3</strong> — Track and control changes to baseline configurations</p>
      <p><strong>IA-3.5.1</strong> — Identify system users, processes, and devices</p>
      <p><strong>AU-3.3.1</strong> — Create and retain system audit records</p>
    </div>
  </div>
</div>

<div class="footer">
  Generated by k8s_secret_auditor.py v{VERSION} &nbsp;·&nbsp;
  Jason A. Slocomb &nbsp;·&nbsp;
  {len(findings)} findings across {summary.unique_actors} actors
</div>
</body>
</html>"""

    Path(path).write_text(html, encoding="utf-8")
    logging.getLogger("report").info(f"HTML written: {path}")


def print_console_summary(findings: list[Finding], summary: AuditSummary) -> None:
    log = logging.getLogger("console")
    log.info("═" * 70)
    log.info("  K8s Secret Access Anomaly Detector")
    log.info(f"  Source    : {summary.log_source}")
    log.info(f"  Generated : {summary.analysis_timestamp}")
    log.info(f"  Time range: {summary.time_range_start} → {summary.time_range_end}")
    log.info("─" * 70)
    log.info(f"  Events parsed     : {summary.events_parsed:,}")
    log.info(f"  Secret events     : {summary.secret_events:,}")
    log.info(f"  Unique actors     : {summary.unique_actors}")
    log.info(f"  Unique namespaces : {summary.unique_namespaces}")
    log.info("─" * 70)
    log.info(f"  Total findings    : {summary.findings}")
    log.info(f"    Critical        : {summary.critical_count}")
    log.info(f"    High            : {summary.high_count}")
    log.info(f"    Medium          : {summary.medium_count}")
    log.info(f"    Low             : {summary.low_count}")
    log.info("═" * 70)

    if findings:
        log.info("  Findings (severity order):")
        log.info("")
        for f in findings:
            sev   = f.severity.value.upper().ljust(8)
            count = f" [{f.event_count} events]" if f.event_count > 1 else ""
            log.info(f"  [{sev}] {f.rule:<22} {f.actor[:35]}")
            log.info(f"           {f.message[:80]}{count}")
            if f.nist_controls:
                log.info(f"           NIST: {', '.join(f.nist_controls)}")
            log.info("")

    log.info("═" * 70)


# ─── Synthetic Test Data Generator ───────────────────────────────────────────

def generate_test_log(path: str = None) -> list[str]:
    """
    Generate a realistic K8s audit log JSONL with known anomaly patterns.

    Returns list of JSON strings. If path is given, also writes to file.
    """
    now  = datetime.now(timezone.utc)
    events = []
    eid  = 0

    def evt(
        verb: str,
        username: str,
        namespace: str,
        name: str,
        resource: str = "secrets",
        subresource: str = "",
        code: int = 200,
        decision: str = "allow",
        groups: list = None,
        ts_offset_sec: int = 0,
        user_agent: str = "kubectl/v1.28.0",
        impersonate: bool = False,
    ) -> str:
        nonlocal eid
        eid += 1
        ts = now - timedelta(seconds=ts_offset_sec)
        is_sa = username.startswith("system:serviceaccount:")
        obj = {
            "kind":        "Event",
            "apiVersion":  "audit.k8s.io/v1",
            "level":       "Metadata",
            "auditID":     f"test-{eid:05d}",
            "stage":       "ResponseComplete",
            "requestURI":  f"/api/v1/namespaces/{namespace}/{resource}s/{name}".rstrip("/"),
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
                "resource":  resource,
                "namespace": namespace,
                "name":      name,
                "apiVersion": "v1",
            },
            "responseStatus": {"code": code},
            "requestReceivedTimestamp": ts.strftime("%Y-%m-%dT%H:%M:%S.000000Z"),
            "stageTimestamp":           ts.strftime("%Y-%m-%dT%H:%M:%S.001000Z"),
            "annotations": {
                "authorization.k8s.io/decision": decision,
                "authorization.k8s.io/reason":   "",
            },
        }
        if subresource:
            obj["objectRef"]["subresource"] = subresource
        if impersonate:
            obj["requestObject"] = {"impersonateUser": "admin"}
        return json.dumps(obj)

    # ── Normal baseline traffic ──────────────────────────────────────────────

    # Regular app service account reading its own secret
    for i in range(20):
        events.append(evt("get", "system:serviceaccount:app:my-app",
                          "app", "app-db-credentials", ts_offset_sec=7200 - i * 300))

    # Regular developer reading a secret during business hours
    for i in range(5):
        events.append(evt("get", "jsmith", "staging",
                          "staging-api-key", ts_offset_sec=3600 - i * 600,
                          groups=["system:authenticated", "developers"]))

    # ── ANOMALY 1: BURST_ACCESS — credential harvesting simulation ───────────
    # Service account reads 12 secrets in 30 seconds
    for i in range(12):
        events.append(evt("get", "system:serviceaccount:default:rogue-app",
                          "production", f"secret-{i:03d}", ts_offset_sec=30 - i * 2))

    # ── ANOMALY 2: UNUSUAL_HOUR — developer at 3 AM ──────────────────────────
    # 3:00 AM UTC access (outside 8-18 business hours)
    ts_3am = now.replace(hour=3, minute=0, second=0)
    obj_3am = {
        "kind": "Event", "apiVersion": "audit.k8s.io/v1",
        "level": "Metadata", "auditID": "test-03am",
        "stage": "ResponseComplete",
        "requestURI": "/api/v1/namespaces/production/secrets/prod-db-password",
        "verb": "get",
        "user": {"username": "bwilson", "groups": ["system:authenticated"]},
        "sourceIPs": ["203.0.113.77"],   # external IP
        "userAgent": "kubectl/v1.28.0",
        "objectRef": {"resource": "secrets", "namespace": "production",
                      "name": "prod-db-password", "apiVersion": "v1"},
        "responseStatus": {"code": 200},
        "requestReceivedTimestamp": ts_3am.strftime("%Y-%m-%dT%H:%M:%S.000000Z"),
        "stageTimestamp":           ts_3am.strftime("%Y-%m-%dT%H:%M:%S.001000Z"),
        "annotations": {"authorization.k8s.io/decision": "allow",
                        "authorization.k8s.io/reason": ""},
    }
    events.append(json.dumps(obj_3am))

    # ── ANOMALY 3: FORBIDDEN_PROBE — probing accessible secrets ──────────────
    for i in range(8):
        events.append(evt("get", "system:serviceaccount:test:probe-sa",
                          "production", f"prod-secret-{i}",
                          code=403, decision="forbid", ts_offset_sec=600 - i * 60))

    # ── ANOMALY 4: LIST_ENUMERATE ─────────────────────────────────────────────
    # List all secrets, then fetch specific ones
    events.append(evt("list", "system:serviceaccount:monitoring:enum-sa",
                      "production", "", ts_offset_sec=1800))
    for name in ["prod-aws-creds", "prod-db-pass", "prod-tls-key"]:
        events.append(evt("get", "system:serviceaccount:monitoring:enum-sa",
                          "production", name, ts_offset_sec=1790))

    # ── ANOMALY 5: SENSITIVE_NAME ─────────────────────────────────────────────
    events.append(evt("get", "system:serviceaccount:backup:velero",
                      "kube-system", "aws-creds-prod", ts_offset_sec=2400))
    events.append(evt("get", "jdoe", "kube-system", "kubeconfig-cluster-admin",
                      ts_offset_sec=100, groups=["system:authenticated"]))

    # ── ANOMALY 6: SECRET_DELETED ─────────────────────────────────────────────
    events.append(evt("delete", "system:serviceaccount:default:cleanup-job",
                      "production", "temp-exfil-creds", ts_offset_sec=50))

    # ── ANOMALY 7: SECRET_MODIFIED ────────────────────────────────────────────
    events.append(evt("patch", "suspicious-user", "production",
                      "prod-api-key", ts_offset_sec=200,
                      groups=["system:authenticated", "developers"]))

    # ── ANOMALY 8: MASS_LIST — cluster-wide ──────────────────────────────────
    events.append(evt("list", "system:serviceaccount:kube-system:cluster-scanner",
                      "", "", resource="secret", ts_offset_sec=900))

    # ── ANOMALY 9: WATCH_SECRETS ──────────────────────────────────────────────
    events.append(evt("watch", "system:serviceaccount:default:secret-watcher",
                      "production", "", ts_offset_sec=400))

    # ── ANOMALY 10: IMPERSONATION ─────────────────────────────────────────────
    events.append(evt("get", "rogue-developer", "production",
                      "admin-credentials", impersonate=True,
                      groups=["system:authenticated"], ts_offset_sec=150))

    # ── ANOMALY 11: EXEC after reading a secret ───────────────────────────────
    # First: exec into a pod
    exec_obj = {
        "kind": "Event", "apiVersion": "audit.k8s.io/v1",
        "level": "Metadata", "auditID": "test-exec-01",
        "stage": "ResponseComplete",
        "requestURI": "/api/v1/namespaces/production/pods/app-pod-abc/exec",
        "verb": "create",
        "user": {"username": "lateral-mover", "groups": ["system:authenticated"]},
        "sourceIPs": ["10.0.1.200"],
        "userAgent": "kubectl/v1.28.0",
        "objectRef": {"resource": "pods", "namespace": "production",
                      "name": "app-pod-abc", "subresource": "exec", "apiVersion": "v1"},
        "responseStatus": {"code": 101},
        "requestReceivedTimestamp": (now - timedelta(seconds=60)).strftime("%Y-%m-%dT%H:%M:%S.000000Z"),
        "stageTimestamp":           (now - timedelta(seconds=60)).strftime("%Y-%m-%dT%H:%M:%S.001000Z"),
        "annotations": {"authorization.k8s.io/decision": "allow", "authorization.k8s.io/reason": ""},
    }
    events.append(json.dumps(exec_obj))
    # Then: read a secret within 5 minutes
    events.append(evt("get", "lateral-mover", "production",
                      "prod-service-account-token", ts_offset_sec=30,
                      groups=["system:authenticated"]))

    # ── ANOMALY 12: CROSS_NAMESPACE ───────────────────────────────────────────
    # Actor with established history in "staging" suddenly reads from "production"
    for i in range(12):
        events.append(evt("get", "cross-ns-actor",
                          "staging", f"staging-secret-{i}",
                          ts_offset_sec=9000 - i * 600))
    # Now crosses into production
    events.append(evt("get", "cross-ns-actor",
                      "production", "prod-db-password", ts_offset_sec=10))

    # ── ANOMALY 13: NODE_OVERSTEP — kubelet reading too many secrets ──────────
    for i in range(8):
        events.append(evt("get", "system:node:worker-node-01",
                          "production", f"secret-for-pod-{i}",
                          groups=["system:nodes", "system:authenticated"],
                          ts_offset_sec=3000 - i * 100))

    # Shuffle by timestamp to simulate real log ordering
    events.sort(key=lambda e: json.loads(e).get("requestReceivedTimestamp", ""))

    if path:
        Path(path).write_text("\n".join(events) + "\n", encoding="utf-8")
        logging.getLogger("generator").info(
            f"Test audit log written: {path} ({len(events)} events)"
        )

    return events


# ─── CLI ──────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="k8s_secret_auditor",
        description="Kubernetes audit log analyzer — secret access anomaly detection",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    input_g = p.add_argument_group("Input")
    input_g.add_argument(
        "--log", "-l",
        default=os.environ.get("K8S_AUDIT_LOG", ""),
        metavar="FILE",
        help="Audit log file path, or '-' for stdin  [env: K8S_AUDIT_LOG]",
    )
    input_g.add_argument(
        "--namespace", "-n",
        default=os.environ.get("K8S_AUDIT_NAMESPACE", ""),
        metavar="NS[,NS]",
        help="Filter to specific namespaces (comma-separated)",
    )

    thresh_g = p.add_argument_group("Thresholds")
    thresh_g.add_argument(
        "--burst-window", type=int, default=DEFAULT_BURST_WINDOW_SEC,
        metavar="SEC",
        help=f"Burst detection sliding window in seconds  (default: {DEFAULT_BURST_WINDOW_SEC})",
    )
    thresh_g.add_argument(
        "--burst-threshold", type=int, default=DEFAULT_BURST_THRESHOLD,
        metavar="N",
        help=f"Reads within burst window to trigger alert  (default: {DEFAULT_BURST_THRESHOLD})",
    )
    thresh_g.add_argument(
        "--forbidden-count", type=int, default=DEFAULT_FORBIDDEN_COUNT,
        metavar="N",
        help=f"Consecutive 403s to trigger probe alert  (default: {DEFAULT_FORBIDDEN_COUNT})",
    )
    thresh_g.add_argument(
        "--forbidden-rate", type=float, default=DEFAULT_FORBIDDEN_RATE,
        metavar="RATIO",
        help=f"Forbidden ratio to trigger rate alert  (default: {DEFAULT_FORBIDDEN_RATE})",
    )
    thresh_g.add_argument(
        "--business-hours", default=f"{DEFAULT_BUSINESS_START}-{DEFAULT_BUSINESS_END}",
        metavar="H-H",
        help=f"Business hours UTC range  (default: {DEFAULT_BUSINESS_START}-{DEFAULT_BUSINESS_END})",
    )
    thresh_g.add_argument(
        "--exclude-actors",
        default="", metavar="USER[,USER]",
        help="Additional actors to exclude from analysis (comma-separated)",
    )

    output_g = p.add_argument_group("Output")
    output_g.add_argument(
        "--output-json", metavar="FILE",
        help="Write findings as JSON",
    )
    output_g.add_argument(
        "--output-csv", metavar="FILE",
        help="Write findings as CSV",
    )
    output_g.add_argument(
        "--output-html", metavar="FILE",
        help="Write findings as HTML report",
    )
    output_g.add_argument(
        "--log-level", default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
    )

    p.add_argument(
        "--dry-run", action="store_true",
        help="Run against built-in synthetic test data (no log file needed)",
    )
    p.add_argument(
        "--generate-test-log", metavar="FILE",
        help="Generate a synthetic test audit log and exit",
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    return p


def configure_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level),
        format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
        stream=sys.stderr,
    )


def parse_business_hours(spec: str) -> tuple[int, int]:
    try:
        parts = spec.split("-")
        return int(parts[0]), int(parts[1])
    except Exception:
        return DEFAULT_BUSINESS_START, DEFAULT_BUSINESS_END


def main() -> int:
    args = build_parser().parse_args()
    configure_logging(args.log_level)
    log  = logging.getLogger("main")

    # Generate test log and exit
    if args.generate_test_log:
        generate_test_log(args.generate_test_log)
        return 0

    # Parse thresholds
    biz_start, biz_end = parse_business_hours(args.business_hours)

    ns_filter = set()
    if args.namespace:
        ns_filter = {n.strip() for n in args.namespace.split(",") if n.strip()}

    exclude_actors = set()
    if args.exclude_actors:
        exclude_actors = {u.strip() for u in args.exclude_actors.split(",") if u.strip()}

    # Set up parser and detector
    parser   = AuditLogParser(namespace_filter=ns_filter)
    detector = SecretAnomalyDetector(
        burst_window     = args.burst_window,
        burst_threshold  = args.burst_threshold,
        forbidden_count  = args.forbidden_count,
        forbidden_rate   = args.forbidden_rate,
        business_start   = biz_start,
        business_end     = biz_end,
        namespace_filter = ns_filter,
        exclude_actors   = exclude_actors,
    )

    # Determine event source
    if args.dry_run:
        log.info("Dry run — using built-in synthetic test data")
        raw_lines = generate_test_log()
        def event_stream():
            for line in raw_lines:
                try:
                    obj = json.loads(line)
                    ev  = parser._parse_event(obj)
                    if ev:
                        yield ev
                except Exception:
                    pass
        log_source = "synthetic-test-data"
    elif args.log:
        log.info(f"Parsing audit log: {args.log}")
        def event_stream():
            yield from parser.parse_file(args.log)
        log_source = args.log
    else:
        log.error(
            "No log file specified. Use --log FILE, --log - for stdin, "
            "or --dry-run for synthetic test data."
        )
        return 1

    # Process events
    events_parsed = 0
    secret_events = 0
    actors        = set()
    namespaces    = set()
    timestamps    = []

    for ev in event_stream():
        events_parsed += 1
        if ev.is_secret:
            secret_events += 1
            actors.add(ev.username)
            if ev.namespace:
                namespaces.add(ev.namespace)
        timestamps.append(ev.timestamp)
        new_findings = detector.process_event(ev)
        for f in new_findings:
            log.debug(f"[{f.severity.value.upper()}] {f.rule}: {f.message[:80]}")

    # Post-hoc rules
    detector.finalize()

    # Build summary
    findings = detector.all_findings()
    now_str  = datetime.now(timezone.utc).isoformat()

    summary = AuditSummary(
        log_source          = log_source,
        analysis_timestamp  = now_str,
        events_parsed       = events_parsed,
        secret_events       = secret_events,
        findings            = len(findings),
        critical_count      = sum(1 for f in findings if f.severity == Severity.CRITICAL),
        high_count          = sum(1 for f in findings if f.severity == Severity.HIGH),
        medium_count        = sum(1 for f in findings if f.severity == Severity.MEDIUM),
        low_count           = sum(1 for f in findings if f.severity == Severity.LOW),
        unique_actors       = len(actors),
        unique_namespaces   = len(namespaces),
        time_range_start    = min(timestamps).isoformat() if timestamps else None,
        time_range_end      = max(timestamps).isoformat() if timestamps else None,
        thresholds          = {
            "burst_window_sec":  args.burst_window,
            "burst_threshold":   args.burst_threshold,
            "forbidden_count":   args.forbidden_count,
            "forbidden_rate":    args.forbidden_rate,
            "business_hours_utc": f"{biz_start:02d}:00-{biz_end:02d}:00",
        },
        nist_controls = sorted(set(
            ctrl
            for f in findings
            for ctrl in f.nist_controls
        )),
        top_actors = [
            {"actor": actor, "events": state.total_secret_events}
            for actor, state in sorted(
                detector.actor_states().items(),
                key=lambda x: x[1].total_secret_events,
                reverse=True,
            )[:10]
        ],
    )

    # Console output
    print_console_summary(findings, summary)

    # File outputs
    if args.output_json:
        write_json(findings, summary, args.output_json)
    if args.output_csv:
        write_csv(findings, args.output_csv)
    if args.output_html:
        write_html(findings, summary, args.output_html)

    # Exit codes: 2 = critical, 1 = high, 0 = clean/medium/low
    if summary.critical_count > 0:
        return 2
    if summary.high_count > 0:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
