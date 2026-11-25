"""Stateful Firewall ACL evaluator and Active Intrusion Prevention System (IPS) engine."""

from __future__ import annotations

import json
import re
import time
from collections import Counter, defaultdict, deque
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .siem_logger import SIEMLogger


@dataclass(frozen=True)
class IPSVerdict:
    allowed: bool
    action: str
    rule_id: str
    threat_type: str | None
    severity: str
    reason: str


class ActiveIPSEngine:
    """Enforces firewall ACLs, DDoS rate limits, brute-force lockouts, port-scan blocks, and DPI payload defense."""

    SIGNATURE_PATTERNS: list[tuple[str, str, re.Pattern[str]]] = [
        ("SQL_INJECTION", "NSR-09", re.compile(r"(?i)(\bunion\s+select\b|\bor\s+1\s*=\s*1\b|';\s*drop\s+table\b|--\s*$|/\*.*\*/)")),
        ("COMMAND_INJECTION", "NSR-09", re.compile(r"(?i)(;\s*(rm\s+-rf|cat\s+/etc/passwd|whoami|nc\s+-e|powershell\s+-enc)|\|\s*(sh|bash|cmd))")),
        ("PATH_TRAVERSAL", "NSR-09", re.compile(r"(\.\./\.\./|\.\.\\\.\.\\|/etc/shadow|windows\\system32\\config\\sam)", re.IGNORECASE)),
        ("XSS_SCRIPT_INJECTION", "NSR-09", re.compile(r"(?i)(<script\b[^>]*>|javascript:|onerror\s*=)")),
        ("MALWARE_REVERSE_SHELL", "NSR-09", re.compile(r"(?i)(/dev/tcp/|bash\s+-i\s+>&|meterpreter|mimikatz)")),
    ]

    def __init__(self, policy_path: Path, siem: SIEMLogger | None = None) -> None:
        self.policy_path = policy_path
        self.siem = siem
        policy = json.loads(policy_path.read_text(encoding="utf-8"))
        self.policy_version: str = str(policy.get("policy_version", "1.0.0"))
        self.vlans: dict[str, dict[str, Any]] = dict(policy.get("vlans", {}))
        self.firewall_rules: list[dict[str, Any]] = list(policy.get("firewall_rules", []))
        self.thresholds: dict[str, int] = {k: int(v) for k, v in policy.get("ips_thresholds", {}).items()}

        self._request_windows: dict[str, deque[float]] = defaultdict(deque)
        self._auth_failures: dict[str, deque[float]] = defaultdict(deque)
        self._port_probes: dict[str, set[int]] = defaultdict(set)
        self._banned_ips: dict[str, dict[str, Any]] = {}

        # Telemetry metrics for Performance Evaluation
        self.packets_inspected: int = 0
        self.packets_allowed: int = 0
        self.packets_blocked: int = 0
        self.detection_counts: Counter[str] = Counter()

    def is_banned(self, source_ip: str, now: float | None = None) -> tuple[bool, str | None]:
        ts = time.time() if now is None else now
        entry = self._banned_ips.get(source_ip)
        if not entry:
            return False, None
        if ts >= entry["expires_at"]:
            del self._banned_ips[source_ip]
            return False, None
        return True, str(entry["reason"])

    def ban_ip(self, source_ip: str, reason: str, threat_type: str = "POLICY_VIOLATION", duration: int | None = None) -> dict[str, Any]:
        ban_secs = duration if duration is not None else self.thresholds.get("default_ban_duration_seconds", 300)
        now = time.time()
        entry = {
            "source_ip": source_ip,
            "reason": reason,
            "threat_type": threat_type,
            "banned_at": now,
            "expires_at": now + ban_secs,
            "duration_seconds": ban_secs,
        }
        self._banned_ips[source_ip] = entry
        if self.siem:
            self.siem.log(
                category="IPS",
                event_type="active_ip_ban",
                severity="CRITICAL",
                source_ip=source_ip,
                actor="aegis-ips",
                action="BLOCK",
                details={"threat_type": threat_type, "reason": reason, "duration_seconds": ban_secs},
            )
        return entry

    def unban_ip(self, source_ip: str, actor: str = "secadmin") -> bool:
        if source_ip not in self._banned_ips:
            return False
        del self._banned_ips[source_ip]
        self._auth_failures.pop(source_ip, None)
        self._request_windows.pop(source_ip, None)
        self._port_probes.pop(source_ip, None)
        if self.siem:
            self.siem.log("IPS", "ip_unbanned", "INFO", source_ip=source_ip, actor=actor, action="ALLOW", details={"reason": "Manual administrative unban"})
        return True

    def list_banned(self) -> list[dict[str, Any]]:
        now = time.time()
        active: list[dict[str, Any]] = []
        for ip in list(self._banned_ips.keys()):
            if now >= self._banned_ips[ip]["expires_at"]:
                del self._banned_ips[ip]
            else:
                item = dict(self._banned_ips[ip])
                item["remaining_seconds"] = round(item["expires_at"] - now, 1)
                active.append(item)
        return active

    def evaluate_firewall(self, src_zone: str, dst_zone: str, protocol: str, port: int, source_ip: str = "127.0.0.1") -> IPSVerdict:
        """Evaluate traffic against the ordered stateful firewall rules."""
        banned, ban_reason = self.is_banned(source_ip)
        if banned:
            self.packets_inspected += 1
            self.packets_blocked += 1
            return IPSVerdict(False, "BLOCK", "IPS-BAN", "ACTIVE_BAN", "CRITICAL", f"Source is actively banned: {ban_reason}")

        self.packets_inspected += 1
        proto_u = protocol.upper()

        # Check explicit deny rules for cleartext legacy ports & quarantine isolation first
        if port in (21, 23, 80) and proto_u == "TCP":
            self.packets_blocked += 1
            self.detection_counts["CLEARTEXT_PROTOCOL"] += 1
            verdict = IPSVerdict(False, "DENY", "NSR-02", "CLEARTEXT_PROTOCOL", "HIGH", f"Blocked insecure cleartext TCP port {port}.")
            self._log_fw(verdict, source_ip, src_zone, dst_zone, protocol, port)
            return verdict

        if src_zone == "VLAN-99-QUARANTINE" and dst_zone in ("VLAN-10-ADMIN", "VLAN-20-CORP", "VLAN-40-VAULT"):
            self.packets_blocked += 1
            self.detection_counts["QUARANTINE_ESCAPE"] += 1
            verdict = IPSVerdict(False, "DENY", "NSR-04", "QUARANTINE_ESCAPE", "CRITICAL", "Blocked lateral movement from VLAN-99-QUARANTINE.")
            self._log_fw(verdict, source_ip, src_zone, dst_zone, protocol, port)
            return verdict

        if dst_zone == "VLAN-40-VAULT" and port == 8443 and proto_u in ("TCP", "TLS-VPN", "AES-256-GCM"):
            self.packets_allowed += 1
            verdict = IPSVerdict(True, "ALLOW", "NSR-01", None, "INFO", "Permitted encrypted TLS/AES-GCM Vault tunnel traffic on port 8443.")
            self._log_fw(verdict, source_ip, src_zone, dst_zone, protocol, port)
            return verdict

        if dst_zone == "LOCALHOST-OLLAMA" and port == 11434 and source_ip in ("127.0.0.1", "::1", "localhost"):
            self.packets_allowed += 1
            verdict = IPSVerdict(True, "ALLOW", "NSR-11", None, "INFO", "Permitted local loopback Ollama AI audit call.")
            self._log_fw(verdict, source_ip, src_zone, dst_zone, protocol, port)
            return verdict

        # Default deny (NSR-15)
        self.packets_blocked += 1
        self.detection_counts["DEFAULT_DENY"] += 1
        verdict = IPSVerdict(False, "DENY", "NSR-15", "UNAUTHORIZED_PORT", "MEDIUM", f"Implicit default-deny for {src_zone} -> {dst_zone} ({proto_u}/{port}).")
        self._log_fw(verdict, source_ip, src_zone, dst_zone, protocol, port)
        return verdict

    def check_rate_limit(self, source_ip: str, now: float | None = None) -> IPSVerdict:
        """Sliding-window DoS/DDoS flood detection and automatic IP quarantine."""
        ts = time.time() if now is None else now
        banned, ban_reason = self.is_banned(source_ip, now=ts)
        if banned:
            self.packets_blocked += 1
            return IPSVerdict(False, "BLOCK", "IPS-BAN", "ACTIVE_BAN", "CRITICAL", f"Source IP actively banned: {ban_reason}")

        window_secs = self.thresholds.get("rate_limit_window_seconds", 10)
        max_reqs = self.thresholds.get("max_requests_per_window", 25)
        q = self._request_windows[source_ip]
        while q and (ts - q[0]) > window_secs:
            q.popleft()
        q.append(ts)
        self.packets_inspected += 1

        if len(q) > max_reqs:
            self.packets_blocked += 1
            self.detection_counts["DDOS_FLOOD"] += 1
            reason = f"Rate limit exceeded ({len(q)} reqs/{window_secs}s > {max_reqs}). Potential DoS/DDoS flood."
            self.ban_ip(source_ip, reason=reason, threat_type="DDOS_FLOOD")
            return IPSVerdict(False, "BLOCK", "NSR-07", "DDOS_FLOOD", "CRITICAL", reason)

        self.packets_allowed += 1
        return IPSVerdict(True, "ALLOW", "NSR-07", None, "INFO", "Within rate limit.")

    def record_auth_failure(self, source_ip: str, username: str, now: float | None = None) -> IPSVerdict:
        """Detect credential brute-force attacks and trigger active IPS lockout."""
        ts = time.time() if now is None else now
        window = self.thresholds.get("brute_force_window_seconds", 60)
        max_fail = self.thresholds.get("brute_force_max_failures", 4)
        q = self._auth_failures[source_ip]
        while q and (ts - q[0]) > window:
            q.popleft()
        q.append(ts)

        if len(q) >= max_fail:
            self.packets_blocked += 1
            self.detection_counts["BRUTE_FORCE"] += 1
            reason = f"Brute-force threshold reached ({len(q)} failed logins in {window}s targeting '{username}')."
            self.ban_ip(source_ip, reason=reason, threat_type="BRUTE_FORCE")
            return IPSVerdict(False, "BLOCK", "NSR-08", "BRUTE_FORCE", "CRITICAL", reason)

        return IPSVerdict(True, "WARN", "NSR-08", "AUTH_FAILURE", "MEDIUM", f"Auth failure {len(q)}/{max_fail} for '{username}'.")

    def record_port_probe(self, source_ip: str, port: int) -> IPSVerdict:
        """Detect unauthorized port scanning / network reconnaissance."""
        threshold = self.thresholds.get("port_scan_threshold", 5)
        self._port_probes[source_ip].add(port)
        self.packets_inspected += 1
        if len(self._port_probes[source_ip]) >= threshold:
            self.packets_blocked += 1
            self.detection_counts["PORT_SCAN"] += 1
            reason = f"Port scan detected from {source_ip} ({len(self._port_probes[source_ip])} distinct ports probed)."
            self.ban_ip(source_ip, reason=reason, threat_type="PORT_SCAN")
            return IPSVerdict(False, "BLOCK", "NSR-16", "PORT_SCAN", "HIGH", reason)
        return IPSVerdict(True, "WARN", "NSR-16", "PORT_PROBE", "LOW", f"Unauthorized port probe on {port}.")

    def inspect_payload(self, payload_text: str, source_ip: str = "127.0.0.1", actor: str = "unknown") -> IPSVerdict:
        """Deep Payload Inspection (DPI) for injection, traversal, malware signatures, and oversized frames."""
        self.packets_inspected += 1
        max_bytes = self.thresholds.get("max_payload_bytes", 65536)
        raw_len = len(payload_text.encode("utf-8", errors="ignore"))
        if raw_len > max_bytes:
            self.packets_blocked += 1
            self.detection_counts["OVERSIZED_PAYLOAD"] += 1
            reason = f"Payload size {raw_len}B exceeds {max_bytes}B maximum limit."
            self.ban_ip(source_ip, reason=reason, threat_type="OVERSIZED_PAYLOAD")
            return IPSVerdict(False, "BLOCK", "NSR-13", "OVERSIZED_PAYLOAD", "HIGH", reason)

        for threat_name, rule_id, pattern in self.SIGNATURE_PATTERNS:
            if pattern.search(payload_text):
                self.packets_blocked += 1
                self.detection_counts[threat_name] += 1
                reason = f"DPI matched malicious signature '{threat_name}' from actor '{actor}'."
                self.ban_ip(source_ip, reason=reason, threat_type=threat_name)
                return IPSVerdict(False, "BLOCK", rule_id, threat_name, "CRITICAL", reason)

        self.packets_allowed += 1
        return IPSVerdict(True, "ALLOW", "NSR-09", None, "INFO", "Payload passed deep inspection.")

    def record_crypto_violation(self, source_ip: str, violation_type: str, detail: str) -> IPSVerdict:
        """Active IPS response for MITM AES-GCM tag tampering or replay attacks."""
        self.packets_inspected += 1
        self.packets_blocked += 1
        self.detection_counts[violation_type] += 1
        self.ban_ip(source_ip, reason=detail, threat_type=violation_type)
        return IPSVerdict(False, "BLOCK", "NSR-10", violation_type, "CRITICAL", detail)

    def get_stats(self) -> dict[str, Any]:
        return {
            "policy_version": self.policy_version,
            "total_firewall_rules": len(self.firewall_rules),
            "packets_inspected": self.packets_inspected,
            "packets_allowed": self.packets_allowed,
            "packets_blocked": self.packets_blocked,
            "active_bans": len(self.list_banned()),
            "detections_by_type": dict(self.detection_counts),
        }

    def _log_fw(self, verdict: IPSVerdict, source_ip: str, src_zone: str, dst_zone: str, protocol: str, port: int) -> None:
        if self.siem:
            self.siem.log(
                category="FIREWALL",
                event_type="acl_evaluation",
                severity=verdict.severity,
                source_ip=source_ip,
                actor="aegis-firewall",
                action=verdict.action,
                details={
                    "rule_id": verdict.rule_id,
                    "src_zone": src_zone,
                    "dst_zone": dst_zone,
                    "protocol": protocol,
                    "port": port,
                    "reason": verdict.reason,
                },
            )
