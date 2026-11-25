"""Tamper-evident SIEM event logger (SHA-256 hash chain) and 10-report security generator."""

from __future__ import annotations

import datetime
import hashlib
import json
import threading
from collections import Counter
from pathlib import Path
from typing import Any


class SIEMLogger:
    """Append-only JSONL SIEM logger with SHA-256 hash chaining for forensic integrity."""

    GENESIS_HASH = "0" * 64

    def __init__(self, log_file: Path) -> None:
        self.log_file = log_file
        self.log_file.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._last_hash = self._recover_last_hash()

    def _recover_last_hash(self) -> str:
        if not self.log_file.exists():
            return self.GENESIS_HASH
        last_line = ""
        with self.log_file.open("r", encoding="utf-8") as fh:
            for line in fh:
                stripped = line.strip()
                if stripped:
                    last_line = stripped
        if not last_line:
            return self.GENESIS_HASH
        try:
            return str(json.loads(last_line).get("entry_hash", self.GENESIS_HASH))
        except json.JSONDecodeError:
            return self.GENESIS_HASH

    @staticmethod
    def _compute_hash(record_without_hash: dict[str, Any]) -> str:
        canonical = json.dumps(record_without_hash, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(canonical).hexdigest()

    def log(
        self,
        category: str,
        event_type: str,
        severity: str = "INFO",
        source_ip: str = "127.0.0.1",
        actor: str = "system",
        action: str = "ALLOW",
        details: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Append a hash-chained security event to the SIEM log."""
        with self._lock:
            record: dict[str, Any] = {
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "category": category.upper(),
                "event_type": event_type,
                "severity": severity.upper(),
                "source_ip": source_ip,
                "actor": actor,
                "action": action.upper(),
                "details": details or {},
                "prev_hash": self._last_hash,
            }
            entry_hash = self._compute_hash(record)
            record["entry_hash"] = entry_hash
            with self.log_file.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(record, separators=(",", ":")) + "\n")
            self._last_hash = entry_hash
            return record

    def read_events(self, limit: int | None = None, category: str | None = None) -> list[dict[str, Any]]:
        if not self.log_file.exists():
            return []
        events: list[dict[str, Any]] = []
        with self.log_file.open("r", encoding="utf-8") as fh:
            for line in fh:
                stripped = line.strip()
                if not stripped:
                    continue
                try:
                    ev = json.loads(stripped)
                except json.JSONDecodeError:
                    continue
                if category and ev.get("category", "").upper() != category.upper():
                    continue
                events.append(ev)
        if limit is not None and limit > 0:
            return events[-limit:]
        return events

    def verify_chain(self) -> tuple[bool, int, str]:
        """Verify SHA-256 hash chain integrity across all SIEM log records."""
        if not self.log_file.exists():
            return True, 0, "No SIEM events recorded yet."
        prev = self.GENESIS_HASH
        count = 0
        with self.log_file.open("r", encoding="utf-8") as fh:
            for idx, line in enumerate(fh, start=1):
                stripped = line.strip()
                if not stripped:
                    continue
                try:
                    rec = json.loads(stripped)
                except json.JSONDecodeError:
                    return False, count, f"Corrupted JSON at line {idx}."
                if rec.get("prev_hash") != prev:
                    return False, count, f"Hash chain break at line {idx}: prev_hash mismatch."
                stored_hash = rec.get("entry_hash")
                body = {k: v for k, v in rec.items() if k != "entry_hash"}
                expected = self._compute_hash(body)
                if stored_hash != expected:
                    return False, count, f"Tampering detected at line {idx}: entry_hash mismatch."
                prev = stored_hash
                count += 1
        return True, count, f"Verified {count} SIEM events with intact SHA-256 hash chain."

    def summarize(self) -> dict[str, Any]:
        events = self.read_events()
        by_category = Counter(e.get("category", "UNKNOWN") for e in events)
        by_severity = Counter(e.get("severity", "INFO") for e in events)
        by_action = Counter(e.get("action", "ALLOW") for e in events)
        top_sources = Counter(e.get("source_ip", "unknown") for e in events).most_common(10)
        chain_ok, count, chain_msg = self.verify_chain()
        return {
            "total_events": len(events),
            "chain_intact": chain_ok,
            "chain_message": chain_msg,
            "by_category": dict(by_category),
            "by_severity": dict(by_severity),
            "by_action": dict(by_action),
            "top_sources": [{"source_ip": ip, "count": cnt} for ip, cnt in top_sources],
        }

    def generate_security_reports(
        self,
        ips_stats: dict[str, Any] | None = None,
        vuln_findings: list[dict[str, Any]] | None = None,
        incidents: list[dict[str, Any]] | None = None,
        backups: list[dict[str, Any]] | None = None,
    ) -> dict[str, dict[str, Any]]:
        """Generate all 10 required security reports specified in the Network Security CCP template."""
        events = self.read_events()
        auth_events = [e for e in events if e.get("category") == "AUTH"]
        fw_events = [e for e in events if e.get("category") == "FIREWALL"]
        traffic_events = [e for e in events if e.get("category") in ("VPN", "TRAFFIC", "TUNNEL")]
        ips_events = [e for e in events if e.get("category") == "IPS"]
        nac_rbac_events = [e for e in events if e.get("category") in ("NAC", "RBAC")]
        backup_events = [e for e in events if e.get("category") == "BACKUP"]
        chain_ok, chain_count, chain_msg = self.verify_chain()

        return {
            "1_user_authentication_report": {
                "title": "User Authentication Report",
                "total_attempts": len(auth_events),
                "successful": sum(1 for e in auth_events if e.get("action") == "ALLOW"),
                "failed": sum(1 for e in auth_events if e.get("action") in ("DENY", "BLOCK")),
                "mfa_verified": sum(1 for e in auth_events if e.get("details", {}).get("mfa_verified")),
                "recent_events": auth_events[-5:],
            },
            "2_firewall_activity_report": {
                "title": "Firewall Activity Report",
                "total_evaluations": len(fw_events),
                "allowed": sum(1 for e in fw_events if e.get("action") == "ALLOW"),
                "denied": sum(1 for e in fw_events if e.get("action") in ("DENY", "BLOCK")),
                "recent_events": fw_events[-5:],
            },
            "3_network_traffic_report": {
                "title": "Network Traffic Report",
                "tunnel_events": len(traffic_events),
                "encrypted_sessions": sum(1 for e in traffic_events if e.get("event_type") == "tunnel_established"),
                "total_bytes_transferred": sum(int(e.get("details", {}).get("bytes", 0)) for e in traffic_events),
                "protocol": "TLS 1.3 + X25519/HKDF + AES-256-GCM",
            },
            "4_intrusion_detection_report": {
                "title": "Intrusion Detection & Prevention Report",
                "total_alerts": len(ips_events),
                "critical_alerts": sum(1 for e in ips_events if e.get("severity") == "CRITICAL"),
                "high_alerts": sum(1 for e in ips_events if e.get("severity") == "HIGH"),
                "ips_engine_stats": ips_stats or {},
                "recent_alerts": ips_events[-5:],
            },
            "5_vulnerability_assessment_report": {
                "title": "Vulnerability Assessment Report",
                "total_findings": len(vuln_findings or []),
                "findings": vuln_findings or [],
            },
            "6_risk_assessment_report": {
                "title": "Risk Assessment Report",
                "methodology": "Risk = Likelihood x Impact",
                "critical_risks": sum(1 for e in ips_events if e.get("severity") == "CRITICAL"),
                "high_risks": sum(1 for e in ips_events if e.get("severity") == "HIGH"),
                "active_mitigations": [
                    "mTLS + AES-256-GCM VPN Tunneling",
                    "NAC Device Admission & Quarantine VLAN-99",
                    "RBAC Least Privilege (6 Roles) + TOTP MFA",
                    "Active IPS Rate Limiting, Brute-Force Lockout & DPI",
                    "Tamper-Evident SHA-256 Chained SIEM + Local Ollama qwen2.5 Auditing",
                ],
            },
            "7_access_control_report": {
                "title": "Access Control (NAC/RBAC) Report",
                "total_checks": len(nac_rbac_events),
                "permitted": sum(1 for e in nac_rbac_events if e.get("action") == "ALLOW"),
                "denied_or_quarantined": sum(1 for e in nac_rbac_events if e.get("action") in ("DENY", "QUARANTINE")),
                "recent_events": nac_rbac_events[-5:],
            },
            "8_security_incident_report": {
                "title": "Security Incident Report",
                "total_incidents": len(incidents or []),
                "incidents": incidents or [],
            },
            "9_compliance_audit_report": {
                "title": "Compliance Audit Report",
                "siem_chain_intact": chain_ok,
                "siem_verified_records": chain_count,
                "siem_chain_status": chain_msg,
                "controls_aligned": [
                    "CIA Triad & AAA Security Objectives",
                    "ISO/IEC 27001 Access Control & Cryptography",
                    "NIST SP 800-53 Audit Integrity & Incident Response",
                ],
            },
            "10_backup_recovery_report": {
                "title": "Backup & Recovery Report",
                "total_backups": len(backups or []),
                "backup_events": len(backup_events),
                "encryption": "AES-256-GCM + SHA-256 Integrity Manifest",
                "backups": backups or [],
            },
        }
